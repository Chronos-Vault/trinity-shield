// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title TrinityShieldVerifier V2
 * @author ChronosVault (chronosvault.org)
 * @notice Extended attestation verifier supporting both Intel SGX and AMD SEV-SNP
 * @dev Phase 4: Multi-TEE support for Trinity Protocol validators
 * 
 * NEW FEATURES (V2):
 * - AMD SEV-SNP attestation support for quantum-resistant TON validator
 * - Unified attestation interface for both TEE types
 * - TEE-specific measurement validation (MRENCLAVE vs MEASUREMENT)
 * - Hybrid quantum-classical key support
 */
contract TrinityShieldVerifierV2 is AccessControl, ReentrancyGuard {
    using ECDSA for bytes32;

    // Roles
    bytes32 public constant TRUSTED_RELAYER_ROLE = keccak256("TRUSTED_RELAYER");
    bytes32 public constant TEE_ADMIN_ROLE = keccak256("TEE_ADMIN");

    // TEE Types
    enum TEEType { SGX, SEV_SNP }

    // Attestation data structure
    struct Attestation {
        TEEType teeType;
        bool isValid;
        uint256 attestedAt;
        bytes32 measurement;      // MRENCLAVE for SGX, MEASUREMENT for SEV
        bytes32 reportData;       // First 32 bytes of report data (validator binding)
        bytes attestationReport;  // Raw attestation report
    }

    // SGX-specific approved values
    mapping(bytes32 => bool) public approvedMrenclave;
    mapping(bytes32 => bool) public approvedMrsigner;
    
    // SEV-SNP specific approved values
    mapping(bytes32 => bool) public approvedSevMeasurement;
    mapping(bytes32 => bool) public approvedSevIdKeyDigest;

    // Validator attestations
    mapping(address => Attestation) public validatorAttestations;
    
    // Quote hash tracking for replay protection
    mapping(bytes32 => bool) public usedQuoteHashes;

    // Configuration
    uint256 public attestationValidityPeriod = 24 hours;
    uint256 public constant MAX_QUOTE_AGE = 10 minutes;

    // Linked consensus verifier
    address public trinityConsensusVerifier;

    // Events
    event ValidatorAttested(
        address indexed validator,
        TEEType teeType,
        bytes32 measurement,
        uint256 timestamp
    );
    event AttestationExpired(address indexed validator, uint256 timestamp);
    event MrenclaveApproved(bytes32 indexed mrenclave, bool approved);
    event SevMeasurementApproved(bytes32 indexed measurement, bool approved);
    event TeeTypeUpdated(address indexed validator, TEEType oldType, TEEType newType);

    constructor(address _consensusVerifier) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(TEE_ADMIN_ROLE, msg.sender);
        trinityConsensusVerifier = _consensusVerifier;
    }

    // ========== SGX ATTESTATION (Same as V1) ==========

    /**
     * @notice Submit SGX attestation via trusted relayer
     * @param validator Validator address being attested
     * @param quoteHash Hash of the DCAP quote
     * @param mrenclave MRENCLAVE value from quote
     * @param reportData First 32 bytes of report data
     * @param timestamp Quote generation timestamp
     * @param relayerSignature Relayer's signature
     */
    function submitSGXAttestation(
        address validator,
        bytes32 quoteHash,
        bytes32 mrenclave,
        bytes32 reportData,
        uint256 timestamp,
        bytes calldata relayerSignature
    ) external nonReentrant {
        require(hasRole(TRUSTED_RELAYER_ROLE, msg.sender), "Not authorized relayer");
        require(!usedQuoteHashes[quoteHash], "Quote already used");
        require(block.timestamp - timestamp <= MAX_QUOTE_AGE, "Quote too old");
        require(approvedMrenclave[mrenclave], "MRENCLAVE not approved");
        
        // Verify report data contains validator address
        require(bytes32(uint256(uint160(validator))) == reportData, "Report data mismatch");
        
        // Verify relayer signature
        bytes32 messageHash = keccak256(abi.encodePacked(
            validator,
            quoteHash,
            mrenclave,
            reportData,
            timestamp,
            block.chainid
        ));
        address signer = messageHash.toEthSignedMessageHash().recover(relayerSignature);
        require(hasRole(TRUSTED_RELAYER_ROLE, signer), "Invalid relayer signature");
        
        // Record attestation
        usedQuoteHashes[quoteHash] = true;
        validatorAttestations[validator] = Attestation({
            teeType: TEEType.SGX,
            isValid: true,
            attestedAt: block.timestamp,
            measurement: mrenclave,
            reportData: reportData,
            attestationReport: ""
        });
        
        emit ValidatorAttested(validator, TEEType.SGX, mrenclave, block.timestamp);
    }

    // ========== AMD SEV-SNP ATTESTATION (NEW IN V2) ==========

    /**
     * @notice Submit AMD SEV-SNP attestation via trusted relayer
     * @dev SEV-SNP attestation structure differs from SGX
     * @param validator Validator address being attested
     * @param reportHash Hash of the attestation report
     * @param measurement SEV MEASUREMENT value
     * @param hostData Host data binding (equivalent to report data)
     * @param timestamp Report generation timestamp
     * @param idKeyDigest ID key digest for platform verification
     * @param relayerSignature Relayer's signature
     */
    function submitSEVAttestation(
        address validator,
        bytes32 reportHash,
        bytes32 measurement,
        bytes32 hostData,
        uint256 timestamp,
        bytes32 idKeyDigest,
        bytes calldata relayerSignature
    ) external nonReentrant {
        require(hasRole(TRUSTED_RELAYER_ROLE, msg.sender), "Not authorized relayer");
        require(!usedQuoteHashes[reportHash], "Report already used");
        require(block.timestamp - timestamp <= MAX_QUOTE_AGE, "Report too old");
        require(approvedSevMeasurement[measurement], "MEASUREMENT not approved");
        require(approvedSevIdKeyDigest[idKeyDigest], "ID key digest not approved");
        
        // Verify host data contains validator address
        require(bytes32(uint256(uint160(validator))) == hostData, "Host data mismatch");
        
        // Verify relayer signature
        bytes32 messageHash = keccak256(abi.encodePacked(
            validator,
            reportHash,
            measurement,
            hostData,
            timestamp,
            idKeyDigest,
            block.chainid
        ));
        address signer = messageHash.toEthSignedMessageHash().recover(relayerSignature);
        require(hasRole(TRUSTED_RELAYER_ROLE, signer), "Invalid relayer signature");
        
        // Record attestation
        usedQuoteHashes[reportHash] = true;
        validatorAttestations[validator] = Attestation({
            teeType: TEEType.SEV_SNP,
            isValid: true,
            attestedAt: block.timestamp,
            measurement: measurement,
            reportData: hostData,
            attestationReport: ""
        });
        
        emit ValidatorAttested(validator, TEEType.SEV_SNP, measurement, block.timestamp);
    }

    // ========== UNIFIED VALIDATION ==========

    /**
     * @notice Check if validator has valid attestation (any TEE type)
     * @param validator Address to check
     * @return True if attestation is valid and not expired
     */
    function checkAttestationValid(address validator) external view returns (bool) {
        Attestation storage att = validatorAttestations[validator];
        if (!att.isValid) return false;
        return block.timestamp <= att.attestedAt + attestationValidityPeriod;
    }

    /**
     * @notice Get validator attestation details
     * @param validator Address to query
     */
    function getValidatorAttestation(address validator) external view returns (
        TEEType teeType,
        bool isAttested,
        uint256 attestedAt,
        bytes32 measurement,
        uint256 expiresAt
    ) {
        Attestation storage att = validatorAttestations[validator];
        bool valid = att.isValid && block.timestamp <= att.attestedAt + attestationValidityPeriod;
        return (
            att.teeType,
            valid,
            att.attestedAt,
            att.measurement,
            att.attestedAt + attestationValidityPeriod
        );
    }

    /**
     * @notice Count attested validators for consensus check
     * @param validators Array of validator addresses
     * @return count Number of validators with valid attestations
     */
    function countAttestedValidators(address[] calldata validators) external view returns (uint256 count) {
        for (uint i = 0; i < validators.length; i++) {
            Attestation storage att = validatorAttestations[validators[i]];
            if (att.isValid && block.timestamp <= att.attestedAt + attestationValidityPeriod) {
                count++;
            }
        }
    }

    // ========== ADMIN FUNCTIONS ==========

    /**
     * @notice Approve/revoke SGX MRENCLAVE value
     */
    function setMrenclaveApproval(bytes32 mrenclave, bool approved) 
        external 
        onlyRole(TEE_ADMIN_ROLE) 
    {
        approvedMrenclave[mrenclave] = approved;
        emit MrenclaveApproved(mrenclave, approved);
    }

    /**
     * @notice Approve/revoke AMD SEV MEASUREMENT value
     */
    function setSevMeasurementApproval(bytes32 measurement, bool approved)
        external
        onlyRole(TEE_ADMIN_ROLE)
    {
        approvedSevMeasurement[measurement] = approved;
        emit SevMeasurementApproved(measurement, approved);
    }

    /**
     * @notice Approve/revoke AMD SEV ID key digest
     */
    function setSevIdKeyDigestApproval(bytes32 idKeyDigest, bool approved)
        external
        onlyRole(TEE_ADMIN_ROLE)
    {
        approvedSevIdKeyDigest[idKeyDigest] = approved;
    }

    /**
     * @notice Update attestation validity period
     */
    function setAttestationValidityPeriod(uint256 newPeriod)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(newPeriod >= 1 hours && newPeriod <= 7 days, "Invalid period");
        attestationValidityPeriod = newPeriod;
    }

    /**
     * @notice Add trusted relayer
     */
    function addTrustedRelayer(address relayer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(TRUSTED_RELAYER_ROLE, relayer);
    }

    /**
     * @notice Remove trusted relayer
     */
    function removeTrustedRelayer(address relayer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(TRUSTED_RELAYER_ROLE, relayer);
    }

    /**
     * @notice Invalidate validator attestation (emergency)
     */
    function invalidateAttestation(address validator)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        validatorAttestations[validator].isValid = false;
        emit AttestationExpired(validator, block.timestamp);
    }
}
