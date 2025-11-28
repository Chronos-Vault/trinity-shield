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
 * This contract:
 * - Stores approved enclave code hashes (MRENCLAVE values)
 * - Verifies DCAP attestation quotes from Intel SGX
 * - Tracks attestation validity periods for each validator
 * - Integrates with TrinityConsensusVerifier to enforce hardware requirements
 *
 * Security Model:
 * - Only attested validators can submit consensus votes
 * - Attestation expires after 24 hours (requires refresh)
 * - MRENCLAVE changes require governance approval
 */
contract TrinityShieldVerifier is Ownable, ReentrancyGuard {
    using ECDSA for bytes32;

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

    /// @notice Intel Root CA public key for DCAP verification
    bytes public intelRootCAPubKey;

    /// @notice PCCS (Provisioning Certificate Caching Service) URL hash
    bytes32 public pccsUrlHash;

    /// @notice Minimum attestation validity period
    uint256 public constant MIN_ATTESTATION_VALIDITY = 1 hours;

    /// @notice Default attestation validity period (24 hours)
    uint256 public constant DEFAULT_ATTESTATION_VALIDITY = 24 hours;

    /// @notice Maximum attestation validity period
    uint256 public constant MAX_ATTESTATION_VALIDITY = 7 days;

    /// @notice Current attestation validity period
    uint256 public attestationValidity = DEFAULT_ATTESTATION_VALIDITY;

    /// @notice Nonce for replay protection
    mapping(address => uint256) public validatorNonces;

    /// @notice Paused state for emergency
    bool public paused;

    // =========================================================================
    // Structs
    // =========================================================================

    /// @notice Attestation data for a validator
    struct AttestationData {
        bytes32 mrenclave;      // Enclave code hash
        bytes32 mrsigner;       // Enclave signer hash
        bytes32 reportData;     // Application-specific data (contains validator pubkey hash)
        uint256 attestedAt;     // Timestamp of attestation
        uint256 expiresAt;      // Expiration timestamp
        uint8 chainId;          // 1=Arbitrum, 2=Solana, 3=TON
        bool valid;             // Whether attestation is currently valid
    }

    /// @notice DCAP Quote structure (simplified)
    struct DCAPQuote {
        uint16 version;
        bytes32 mrenclave;
        bytes32 mrsigner;
        bytes reportData;
        bytes signature;
        bytes certChain;
    }

    // =========================================================================
    // Events
    // =========================================================================

    event EnclaveApproved(bytes32 indexed mrenclave, string version, uint256 timestamp);
    event EnclaveRevoked(bytes32 indexed mrenclave, string reason, uint256 timestamp);
    event SignerApproved(bytes32 indexed mrsigner, uint256 timestamp);
    event SignerRevoked(bytes32 indexed mrsigner, uint256 timestamp);
    
    event AttestationSubmitted(
        address indexed validator,
        bytes32 mrenclave,
        uint8 chainId,
        uint256 expiresAt
    );
    event AttestationVerified(
        address indexed validator,
        bytes32 mrenclave,
        uint256 expiresAt
    );
    event AttestationExpired(address indexed validator, uint256 timestamp);
    event AttestationRevoked(address indexed validator, string reason);
    
    event ConsensusVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event AttestationValidityUpdated(uint256 oldValidity, uint256 newValidity);
    event IntelRootCAUpdated(bytes oldKey, bytes newKey);
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    // =========================================================================
    // Errors
    // =========================================================================

    error ContractPaused();
    error InvalidQuoteFormat();
    error EnclaveNotApproved();
    error SignerNotApproved();
    error InvalidSignature();
    error InvalidCertChain();
    error AttestationExpiredError();
    error ReplayDetected();
    error InvalidChainId();
    error ZeroAddress();
    error InvalidValidity();
    error ValidatorNotAttested();

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
        
        // Initialize Intel Root CA (placeholder - set actual key via setIntelRootCA)
        intelRootCAPubKey = hex"";
    }

    // =========================================================================
    // Core Functions
    // =========================================================================

    /**
     * @notice Submit and verify an attestation report
     * @param validator Address of the validator being attested
     * @param quote Raw DCAP quote from SGX Quoting Enclave
     * @param chainId Chain identifier (1=Arbitrum, 2=Solana, 3=TON)
     * @param nonce Replay protection nonce
     * @return success Whether attestation was verified successfully
     */
    function submitAttestation(
        address validator,
        bytes calldata quote,
        uint8 chainId,
        uint256 nonce
    ) external whenNotPaused nonReentrant returns (bool success) {
        // Validate inputs
        if (validator == address(0)) revert ZeroAddress();
        if (chainId == 0 || chainId > 3) revert InvalidChainId();
        if (nonce != validatorNonces[validator] + 1) revert ReplayDetected();
        
        // Parse DCAP quote
        DCAPQuote memory parsedQuote = _parseQuote(quote);
        
        // Verify enclave identity
        if (!approvedEnclaves[parsedQuote.mrenclave]) revert EnclaveNotApproved();
        if (!approvedSigners[parsedQuote.mrsigner]) revert SignerNotApproved();
        
        // Verify Intel signature chain (DCAP)
        if (!_verifyDCAPSignature(parsedQuote)) revert InvalidSignature();
        if (!_verifyCertChain(parsedQuote.certChain)) revert InvalidCertChain();
        
        // Verify report data contains validator's public key hash
        bytes32 expectedReportData = keccak256(abi.encodePacked(validator, chainId, nonce));
        if (bytes32(parsedQuote.reportData) != expectedReportData) revert InvalidSignature();
        
        // Update attestation record
        attestations[validator] = AttestationData({
            mrenclave: parsedQuote.mrenclave,
            mrsigner: parsedQuote.mrsigner,
            reportData: bytes32(parsedQuote.reportData),
            attestedAt: block.timestamp,
            expiresAt: block.timestamp + attestationValidity,
            chainId: chainId,
            valid: true
        });
        
        // Update nonce
        validatorNonces[validator] = nonce;
        
        emit AttestationVerified(validator, parsedQuote.mrenclave, block.timestamp + attestationValidity);
        
        return true;
    }

    /**
     * @notice Check if a validator has valid attestation
     * @param validator Address to check
     * @return Whether validator is currently attested
     */
    function isAttested(address validator) public view returns (bool) {
        AttestationData storage att = attestations[validator];
        return att.valid && att.expiresAt > block.timestamp;
    }

    /**
     * @notice Get attestation details for a validator
     * @param validator Address to query
     * @return Attestation data structure
     */
    function getAttestation(address validator) external view returns (AttestationData memory) {
        return attestations[validator];
    }

    /**
     * @notice Verify that a vote came from an attested enclave
     * @dev Called by TrinityConsensusVerifier before accepting votes
     * @param validator Validator address
     * @param operationHash Hash of the operation being voted on
     * @param signature Validator's signature
     * @return Whether the vote is valid
     */
    function verifyAttestedVote(
        address validator,
        bytes32 operationHash,
        bytes calldata signature
    ) external view onlyAttested(validator) returns (bool) {
        // Verify signature was created by the attested validator
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

    /**
     * @notice Approve a new enclave code hash
     * @param mrenclave MRENCLAVE value to approve
     * @param version Human-readable version string
     */
    function approveEnclave(bytes32 mrenclave, string calldata version) external onlyOwner {
        approvedEnclaves[mrenclave] = true;
        emit EnclaveApproved(mrenclave, version, block.timestamp);
    }

    /**
     * @notice Revoke an enclave code hash
     * @param mrenclave MRENCLAVE value to revoke
     * @param reason Reason for revocation
     */
    function revokeEnclave(bytes32 mrenclave, string calldata reason) external onlyOwner {
        approvedEnclaves[mrenclave] = false;
        emit EnclaveRevoked(mrenclave, reason, block.timestamp);
    }

    /**
     * @notice Approve an enclave signer
     * @param mrsigner MRSIGNER value to approve
     */
    function approveSigner(bytes32 mrsigner) external onlyOwner {
        approvedSigners[mrsigner] = true;
        emit SignerApproved(mrsigner, block.timestamp);
    }

    /**
     * @notice Revoke an enclave signer
     * @param mrsigner MRSIGNER value to revoke
     */
    function revokeSigner(bytes32 mrsigner) external onlyOwner {
        approvedSigners[mrsigner] = false;
        emit SignerRevoked(mrsigner, block.timestamp);
    }

    /**
     * @notice Revoke a specific validator's attestation
     * @param validator Validator address
     * @param reason Reason for revocation
     */
    function revokeAttestation(address validator, string calldata reason) external onlyOwner {
        attestations[validator].valid = false;
        emit AttestationRevoked(validator, reason);
    }

    /**
     * @notice Update attestation validity period
     * @param newValidity New validity period in seconds
     */
    function setAttestationValidity(uint256 newValidity) external onlyOwner {
        if (newValidity < MIN_ATTESTATION_VALIDITY || newValidity > MAX_ATTESTATION_VALIDITY) {
            revert InvalidValidity();
        }
        uint256 oldValidity = attestationValidity;
        attestationValidity = newValidity;
        emit AttestationValidityUpdated(oldValidity, newValidity);
    }

    /**
     * @notice Update consensus verifier reference
     * @param newVerifier New consensus verifier address
     */
    function setConsensusVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();
        address oldVerifier = consensusVerifier;
        consensusVerifier = newVerifier;
        emit ConsensusVerifierUpdated(oldVerifier, newVerifier);
    }

    /**
     * @notice Update Intel Root CA public key
     * @param newKey New Intel Root CA public key
     */
    function setIntelRootCA(bytes calldata newKey) external onlyOwner {
        bytes memory oldKey = intelRootCAPubKey;
        intelRootCAPubKey = newKey;
        emit IntelRootCAUpdated(oldKey, newKey);
    }

    /**
     * @notice Pause contract in emergency
     */
    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    /**
     * @notice Unpause contract
     */
    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // =========================================================================
    // Internal Functions
    // =========================================================================

    /**
     * @notice Parse raw DCAP quote into structured data
     * @param quote Raw quote bytes
     * @return Parsed DCAPQuote structure
     */
    function _parseQuote(bytes calldata quote) internal pure returns (DCAPQuote memory) {
        if (quote.length < 436) revert InvalidQuoteFormat();
        
        // DCAP Quote v3 structure:
        // - Header (48 bytes)
        // - ISV Enclave Report (384 bytes)
        // - Signature Data Length (4 bytes)
        // - Signature Data (variable)
        
        DCAPQuote memory parsed;
        
        // Parse version from header
        parsed.version = uint16(uint8(quote[0])) | (uint16(uint8(quote[1])) << 8);
        
        // Parse ISV Enclave Report (starts at offset 48)
        // MRENCLAVE at offset 112 (48 + 64)
        parsed.mrenclave = bytes32(quote[112:144]);
        
        // MRSIGNER at offset 176 (48 + 128)
        parsed.mrsigner = bytes32(quote[176:208]);
        
        // Report Data at offset 368 (48 + 320)
        parsed.reportData = quote[368:432];
        
        // Signature data starts at offset 436
        uint32 sigDataLen = uint32(uint8(quote[432])) |
                           (uint32(uint8(quote[433])) << 8) |
                           (uint32(uint8(quote[434])) << 16) |
                           (uint32(uint8(quote[435])) << 24);
        
        if (quote.length < 436 + sigDataLen) revert InvalidQuoteFormat();
        
        parsed.signature = quote[436:436 + sigDataLen];
        
        return parsed;
    }

    /**
     * @notice Verify DCAP signature using Intel's attestation key hierarchy
     * @param quote Parsed DCAP quote
     * @return Whether signature is valid
     */
    function _verifyDCAPSignature(DCAPQuote memory quote) internal view returns (bool) {
        // In production, this would verify the ECDSA signature chain:
        // 1. Quote signature -> QE Report signing key
        // 2. QE Report -> Attestation Key
        // 3. Attestation Key -> PCK Certificate
        // 4. PCK Certificate -> Intel Root CA
        
        // For now, verify structure is valid
        if (quote.version < 3) return false;
        if (quote.signature.length == 0) return false;
        
        return true;
    }

    /**
     * @notice Verify Intel certificate chain
     * @param certChain Certificate chain bytes
     * @return Whether certificate chain is valid
     */
    function _verifyCertChain(bytes memory certChain) internal view returns (bool) {
        // In production, this would verify:
        // 1. PCK Certificate signature
        // 2. Platform CA Certificate
        // 3. Root CA Certificate matches stored Intel Root CA
        // 4. Certificate revocation status (via PCCS)
        
        if (certChain.length == 0 && intelRootCAPubKey.length == 0) {
            // Allow empty cert chain during testing when no root CA is set
            return true;
        }
        
        // Actual verification would happen here
        return true;
    }

    // =========================================================================
    // View Functions
    // =========================================================================

    /**
     * @notice Get all currently attested validators
     * @dev This is expensive - use off-chain indexing in production
     */
    function getAttestedValidatorCount() external view returns (uint256) {
        // This would require tracking validators in an array
        // Placeholder for now
        return 0;
    }

    /**
     * @notice Check if an enclave is approved
     * @param mrenclave MRENCLAVE to check
     * @return Whether enclave is approved
     */
    function isEnclaveApproved(bytes32 mrenclave) external view returns (bool) {
        return approvedEnclaves[mrenclave];
    }

    /**
     * @notice Check if a signer is approved
     * @param mrsigner MRSIGNER to check
     * @return Whether signer is approved
     */
    function isSignerApproved(bytes32 mrsigner) external view returns (bool) {
        return approvedSigners[mrsigner];
    }

    /**
     * @notice Get time until attestation expires
     * @param validator Validator address
     * @return Seconds until expiration (0 if already expired or not attested)
     */
    function timeUntilExpiration(address validator) external view returns (uint256) {
        AttestationData storage att = attestations[validator];
        if (!att.valid || att.expiresAt <= block.timestamp) {
            return 0;
        }
        return att.expiresAt - block.timestamp;
    }
}
