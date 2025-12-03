// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title TrinityShieldVerifier
 * @author Trinity Protocol Team
 * @notice Layer 8 of the Mathematical Defense Layer (MDL)
 * @dev Verifies SGX/TDX attestation reports for Trinity Shield enclaves
 * 
 * Security Model:
 * - DCAP quotes are verified off-chain by trusted relayers
 * - On-chain verification validates relayer signatures and quote hashes
 * - This hybrid approach balances gas costs with security
 * - Full DCAP verification happens off-chain with on-chain commitment
 */
contract TrinityShieldVerifier is Ownable, ReentrancyGuard {
    using ECDSA for bytes32;

    // =========================================================================
    // Constants
    // =========================================================================

    /// @notice DCAP Quote v3 minimum size
    uint256 public constant MIN_QUOTE_SIZE = 436;
    
    /// @notice ISV Enclave Report offset in quote
    uint256 public constant REPORT_OFFSET = 48;
    
    /// @notice MRENCLAVE offset within report (48 + 64)
    uint256 public constant MRENCLAVE_OFFSET = 112;
    
    /// @notice MRSIGNER offset within report (48 + 128)
    uint256 public constant MRSIGNER_OFFSET = 176;
    
    /// @notice Report data offset (48 + 320)
    uint256 public constant REPORT_DATA_OFFSET = 368;
    
    /// @notice Signature data length offset
    uint256 public constant SIG_LEN_OFFSET = 432;

    /// @notice Minimum attestation validity period
    uint256 public constant MIN_ATTESTATION_VALIDITY = 1 hours;

    /// @notice Default attestation validity period (24 hours)
    uint256 public constant DEFAULT_ATTESTATION_VALIDITY = 24 hours;

    /// @notice Maximum attestation validity period
    uint256 public constant MAX_ATTESTATION_VALIDITY = 7 days;
    
    /// @notice Maximum quote age for freshness check (10 minutes)
    uint256 public constant MAX_QUOTE_AGE = 10 minutes;

    // =========================================================================
    // State Variables
    // =========================================================================

    /// @notice Reference to Trinity Consensus Verifier
    address public consensusVerifier;

    /// @notice Approved enclave code hashes (MRENCLAVE values)
    mapping(bytes32 => bool) public approvedEnclaves;

    /// @notice Approved enclave signer hashes (MRSIGNER values)
    mapping(bytes32 => bool) public approvedSigners;

    /// @notice Validator address => attestation data
    mapping(address => AttestationData) public attestations;

    /// @notice Trusted attestation relayers (verify DCAP off-chain)
    mapping(address => bool) public trustedRelayers;

    /// @notice Used quote hashes (prevent replay)
    mapping(bytes32 => bool) public usedQuoteHashes;

    /// @notice Intel Root CA public key hash for verification
    bytes32 public intelRootCAHash;

    /// @notice Current attestation validity period
    uint256 public attestationValidity = DEFAULT_ATTESTATION_VALIDITY;

    /// @notice Nonce for replay protection per validator
    mapping(address => uint256) public validatorNonces;

    /// @notice Paused state for emergency
    bool public paused;

    // =========================================================================
    // Structs
    // =========================================================================

    /// @notice Attestation data for a validator
    struct AttestationData {
        bytes32 mrenclave;
        bytes32 mrsigner;
        bytes32 reportDataHash;
        uint256 attestedAt;
        uint256 expiresAt;
        uint8 chainId;
        bool valid;
    }

    /// @notice Parsed DCAP Quote structure
    struct ParsedQuote {
        uint16 version;
        bytes32 mrenclave;
        bytes32 mrsigner;
        bytes32 validatorBinding;   // First 32 bytes of report data
        bytes32 reportDataHash;     // Hash of full 64-byte report data
        uint32 signatureLength;
    }

    /// @notice Relayer attestation submission
    struct RelayerAttestation {
        address validator;
        uint8 chainId;
        uint256 nonce;
        bytes32 quoteHash;
        bytes32 mrenclave;
        bytes32 mrsigner;
        bytes32 reportDataHash;
        uint256 quoteTimestamp;
        bytes relayerSignature;
    }

    // =========================================================================
    // Events
    // =========================================================================

    event EnclaveApproved(bytes32 indexed mrenclave, string version, uint256 timestamp);
    event EnclaveRevoked(bytes32 indexed mrenclave, string reason, uint256 timestamp);
    event SignerApproved(bytes32 indexed mrsigner, uint256 timestamp);
    event SignerRevoked(bytes32 indexed mrsigner, uint256 timestamp);
    event RelayerAdded(address indexed relayer, uint256 timestamp);
    event RelayerRemoved(address indexed relayer, uint256 timestamp);
    
    event AttestationVerified(
        address indexed validator,
        bytes32 mrenclave,
        uint8 chainId,
        uint256 expiresAt
    );
    event AttestationRevoked(address indexed validator, string reason);
    
    event ConsensusVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event AttestationValidityUpdated(uint256 oldValidity, uint256 newValidity);
    event IntelRootCAUpdated(bytes32 oldHash, bytes32 newHash);
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    // =========================================================================
    // Errors
    // =========================================================================

    error ContractPaused();
    error InvalidQuoteFormat();
    error InvalidQuoteVersion();
    error QuoteTooShort();
    error SignatureLengthMismatch();
    error EnclaveNotApproved();
    error SignerNotApproved();
    error InvalidRelayerSignature();
    error UntrustedRelayer();
    error QuoteAlreadyUsed();
    error QuoteTooOld();
    error ReplayDetected();
    error InvalidChainId();
    error ZeroAddress();
    error InvalidValidity();
    error ValidatorNotAttested();
    error InvalidReportData();
    error NonceMismatch();

    // =========================================================================
    // Modifiers
    // =========================================================================

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    modifier onlyAttested(address validator) {
        if (!isAttested(validator)) revert ValidatorNotAttested();
        _;
    }

    // =========================================================================
    // Constructor
    // =========================================================================

    constructor(address _consensusVerifier) Ownable(msg.sender) {
        if (_consensusVerifier == address(0)) revert ZeroAddress();
        consensusVerifier = _consensusVerifier;
    }

    // =========================================================================
    // Core Functions
    // =========================================================================

    /**
     * @notice Submit attestation via trusted relayer
     * @dev Relayer verifies DCAP off-chain and signs the attestation
     * @param attestation Relayer-signed attestation data
     */
    function submitRelayerAttestation(
        RelayerAttestation calldata attestation
    ) external whenNotPaused nonReentrant returns (bool) {
        // Validate inputs
        if (attestation.validator == address(0)) revert ZeroAddress();
        if (attestation.chainId == 0 || attestation.chainId > 3) revert InvalidChainId();
        
        // Verify nonce for replay protection
        if (attestation.nonce != validatorNonces[attestation.validator] + 1) {
            revert NonceMismatch();
        }
        
        // Verify quote hasn't been used before
        if (usedQuoteHashes[attestation.quoteHash]) revert QuoteAlreadyUsed();
        
        // Verify quote freshness (must be recent)
        if (block.timestamp > attestation.quoteTimestamp + MAX_QUOTE_AGE) {
            revert QuoteTooOld();
        }
        
        // Verify relayer signature
        bytes32 attestationHash = keccak256(abi.encodePacked(
            attestation.validator,
            attestation.chainId,
            attestation.nonce,
            attestation.quoteHash,
            attestation.mrenclave,
            attestation.mrsigner,
            attestation.reportDataHash,
            attestation.quoteTimestamp
        ));
        
        bytes32 signedHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            attestationHash
        ));
        
        address relayer = signedHash.recover(attestation.relayerSignature);
        if (!trustedRelayers[relayer]) revert UntrustedRelayer();
        
        // Verify enclave identity is approved
        if (!approvedEnclaves[attestation.mrenclave]) revert EnclaveNotApproved();
        if (!approvedSigners[attestation.mrsigner]) revert SignerNotApproved();
        
        // Verify report data contains expected validator binding
        bytes32 expectedReportDataHash = keccak256(abi.encodePacked(
            attestation.validator,
            attestation.chainId,
            attestation.nonce
        ));
        if (attestation.reportDataHash != expectedReportDataHash) {
            revert InvalidReportData();
        }
        
        // Mark quote as used
        usedQuoteHashes[attestation.quoteHash] = true;
        
        // Update attestation record
        attestations[attestation.validator] = AttestationData({
            mrenclave: attestation.mrenclave,
            mrsigner: attestation.mrsigner,
            reportDataHash: attestation.reportDataHash,
            attestedAt: block.timestamp,
            expiresAt: block.timestamp + attestationValidity,
            chainId: attestation.chainId,
            valid: true
        });
        
        // Update nonce
        validatorNonces[attestation.validator] = attestation.nonce;
        
        emit AttestationVerified(
            attestation.validator,
            attestation.mrenclave,
            attestation.chainId,
            block.timestamp + attestationValidity
        );
        
        return true;
    }

    /**
     * @notice Direct quote submission with on-chain parsing
     * @dev PRODUCTION NOTE: Use submitRelayerAttestation for production. 
     *      Direct submission requires trusted timestamp oracle integration.
     * @param validator Address of the validator being attested
     * @param quote Raw DCAP quote from SGX Quoting Enclave
     * @param chainId Chain identifier (1=Arbitrum, 2=Solana, 3=TON)
     * @param nonce Replay protection nonce
     */
    function submitDirectAttestation(
        address validator,
        bytes calldata quote,
        uint8 chainId,
        uint256 nonce
    ) external whenNotPaused nonReentrant returns (bool) {
        // Validate inputs
        if (validator == address(0)) revert ZeroAddress();
        if (chainId == 0 || chainId > 3) revert InvalidChainId();
        if (nonce != validatorNonces[validator] + 1) revert NonceMismatch();
        
        // Parse and validate quote structure
        ParsedQuote memory parsed = _parseQuote(quote);
        
        // Verify quote version (must be v3 or higher for DCAP)
        if (parsed.version < 3) revert InvalidQuoteVersion();
        
        // Compute quote hash for replay protection
        bytes32 quoteHash = keccak256(quote);
        if (usedQuoteHashes[quoteHash]) revert QuoteAlreadyUsed();
        
        // Verify enclave identity is approved
        if (!approvedEnclaves[parsed.mrenclave]) revert EnclaveNotApproved();
        if (!approvedSigners[parsed.mrsigner]) revert SignerNotApproved();
        
        // Verify report data binding (first 32 bytes of report data = validator binding)
        // Report data layout: [validator_binding_hash(32)] [chain_id(1)] [nonce(8)] [reserved(23)]
        bytes32 expectedBinding = keccak256(abi.encodePacked(validator, chainId, nonce));
        if (parsed.validatorBinding != expectedBinding) {
            revert InvalidReportData();
        }
        
        // Mark quote as used
        usedQuoteHashes[quoteHash] = true;
        
        // Update attestation record
        attestations[validator] = AttestationData({
            mrenclave: parsed.mrenclave,
            mrsigner: parsed.mrsigner,
            reportDataHash: parsed.reportDataHash,
            attestedAt: block.timestamp,
            expiresAt: block.timestamp + attestationValidity,
            chainId: chainId,
            valid: true
        });
        
        // Update nonce
        validatorNonces[validator] = nonce;
        
        emit AttestationVerified(
            validator,
            parsed.mrenclave,
            chainId,
            block.timestamp + attestationValidity
        );
        
        return true;
    }

    /**
     * @notice Check if a validator has valid attestation
     */
    function isAttested(address validator) public view returns (bool) {
        AttestationData storage att = attestations[validator];
        return att.valid && att.expiresAt > block.timestamp;
    }

    /**
     * @notice Get attestation details for a validator
     */
    function getAttestation(address validator) external view returns (AttestationData memory) {
        return attestations[validator];
    }

    /**
     * @notice Verify that a vote came from an attested enclave
     */
    function verifyAttestedVote(
        address validator,
        bytes32 operationHash,
        bytes calldata signature
    ) external view onlyAttested(validator) returns (bool) {
        bytes32 messageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            operationHash
        ));
        
        address signer = messageHash.recover(signature);
        return signer == validator;
    }

    // =========================================================================
    // Admin Functions
    // =========================================================================

    function approveEnclave(bytes32 mrenclave, string calldata version) external onlyOwner {
        approvedEnclaves[mrenclave] = true;
        emit EnclaveApproved(mrenclave, version, block.timestamp);
    }

    function revokeEnclave(bytes32 mrenclave, string calldata reason) external onlyOwner {
        approvedEnclaves[mrenclave] = false;
        emit EnclaveRevoked(mrenclave, reason, block.timestamp);
    }

    function approveSigner(bytes32 mrsigner) external onlyOwner {
        approvedSigners[mrsigner] = true;
        emit SignerApproved(mrsigner, block.timestamp);
    }

    function revokeSigner(bytes32 mrsigner) external onlyOwner {
        approvedSigners[mrsigner] = false;
        emit SignerRevoked(mrsigner, block.timestamp);
    }

    function addRelayer(address relayer) external onlyOwner {
        if (relayer == address(0)) revert ZeroAddress();
        trustedRelayers[relayer] = true;
        emit RelayerAdded(relayer, block.timestamp);
    }

    function removeRelayer(address relayer) external onlyOwner {
        trustedRelayers[relayer] = false;
        emit RelayerRemoved(relayer, block.timestamp);
    }

    function revokeAttestation(address validator, string calldata reason) external onlyOwner {
        attestations[validator].valid = false;
        emit AttestationRevoked(validator, reason);
    }

    function setAttestationValidity(uint256 newValidity) external onlyOwner {
        if (newValidity < MIN_ATTESTATION_VALIDITY || newValidity > MAX_ATTESTATION_VALIDITY) {
            revert InvalidValidity();
        }
        uint256 oldValidity = attestationValidity;
        attestationValidity = newValidity;
        emit AttestationValidityUpdated(oldValidity, newValidity);
    }

    function setConsensusVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();
        address oldVerifier = consensusVerifier;
        consensusVerifier = newVerifier;
        emit ConsensusVerifierUpdated(oldVerifier, newVerifier);
    }

    function setIntelRootCA(bytes32 newHash) external onlyOwner {
        bytes32 oldHash = intelRootCAHash;
        intelRootCAHash = newHash;
        emit IntelRootCAUpdated(oldHash, newHash);
    }

    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // =========================================================================
    // Internal Functions
    // =========================================================================

    /**
     * @notice Parse raw DCAP quote into structured data
     * @dev Follows Intel SGX DCAP Quote v3 format
     *
     * Quote Layout:
     * - Header (48 bytes): version, att_key_type, tee_type, qe_svn, pce_svn, qe_vendor_id, user_data
     * - ISV Enclave Report (384 bytes): cpu_svn, misc_select, attributes, MRENCLAVE, MRSIGNER, etc.
     * - Report Data (64 bytes at offset 368): [validator_binding(32)][metadata(32)]
     * - Signature Data Length (4 bytes)
     * - Signature Data (variable)
     */
    function _parseQuote(bytes calldata quote) internal pure returns (ParsedQuote memory) {
        // Validate minimum size
        if (quote.length < MIN_QUOTE_SIZE) revert QuoteTooShort();
        
        ParsedQuote memory parsed;
        
        // Parse version from header (little-endian uint16 at offset 0)
        parsed.version = uint16(uint8(quote[0])) | (uint16(uint8(quote[1])) << 8);
        
        // Parse MRENCLAVE (32 bytes at offset 112)
        parsed.mrenclave = bytes32(quote[MRENCLAVE_OFFSET:MRENCLAVE_OFFSET + 32]);
        
        // Parse MRSIGNER (32 bytes at offset 176)
        parsed.mrsigner = bytes32(quote[MRSIGNER_OFFSET:MRSIGNER_OFFSET + 32]);
        
        // Parse Report Data (64 bytes at offset 368)
        // First 32 bytes = validator binding hash (keccak256(validator, chainId, nonce))
        // This matches the enclave's build_report_data() function
        parsed.validatorBinding = bytes32(quote[REPORT_DATA_OFFSET:REPORT_DATA_OFFSET + 32]);
        
        // Hash of full report data for storage
        parsed.reportDataHash = keccak256(quote[REPORT_DATA_OFFSET:REPORT_DATA_OFFSET + 64]);
        
        // Parse signature data length (little-endian uint32 at offset 432)
        parsed.signatureLength = uint32(uint8(quote[SIG_LEN_OFFSET])) |
                                (uint32(uint8(quote[SIG_LEN_OFFSET + 1])) << 8) |
                                (uint32(uint8(quote[SIG_LEN_OFFSET + 2])) << 16) |
                                (uint32(uint8(quote[SIG_LEN_OFFSET + 3])) << 24);
        
        // Verify quote has enough data for signature
        if (quote.length < MIN_QUOTE_SIZE + parsed.signatureLength) {
            revert SignatureLengthMismatch();
        }
        
        return parsed;
    }

    // =========================================================================
    // View Functions
    // =========================================================================

    function isEnclaveApproved(bytes32 mrenclave) external view returns (bool) {
        return approvedEnclaves[mrenclave];
    }

    function isSignerApproved(bytes32 mrsigner) external view returns (bool) {
        return approvedSigners[mrsigner];
    }

    function isRelayerTrusted(address relayer) external view returns (bool) {
        return trustedRelayers[relayer];
    }

    function isQuoteUsed(bytes32 quoteHash) external view returns (bool) {
        return usedQuoteHashes[quoteHash];
    }

    function timeUntilExpiration(address validator) external view returns (uint256) {
        AttestationData storage att = attestations[validator];
        if (!att.valid || att.expiresAt <= block.timestamp) {
            return 0;
        }
        return att.expiresAt - block.timestamp;
    }

    function getNextNonce(address validator) external view returns (uint256) {
        return validatorNonces[validator] + 1;
    }
}
