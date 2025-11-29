/**
 * Trinity Shield Relayer Bridge
 * 
 * Bridges the Rust TEE enclave (Layer 8) with on-chain Solidity contracts.
 * This is the critical integration layer that:
 * 
 * 1. Receives attestations from Trinity Shield (Rust/SGX/SEV)
 * 2. Formats them for TrinityShieldVerifierV2 (Solidity)
 * 3. Submits proofs to TrinityConsensusVerifier
 * 4. Monitors HTLCChronosBridge for operations needing consensus
 * 
 * ┌─────────────────┐                      ┌─────────────────────────┐
 * │ Trinity Shield  │ ──IPC──────────────► │ Relayer Bridge (this)   │
 * │ (Rust Enclave)  │ /run/trinity.sock    │                         │
 * └─────────────────┘                      │   - formatForChain()    │
 *                                          │   - submitAttestation() │
 *                                          │   - submitProof()       │
 *                                          └───────────┬─────────────┘
 *                                                      │ Ethers.js
 *                                                      ▼
 * ┌──────────────────────────────────────────────────────────────────┐
 * │                    Arbitrum Sepolia (EVM)                        │
 * │  ┌─────────────────────┐  ┌──────────────────────────────────┐   │
 * │  │ TrinityShieldV2     │  │ TrinityConsensusVerifier         │   │
 * │  │ submitSGXAttest...  │  │ submitArbitrumProof()            │   │
 * │  │ submitSEVAttest...  │  │ submitSolanaProof()              │   │
 * │  └─────────────────────┘  │ submitTONProof()                 │   │
 * │                           └──────────────────────────────────┘   │
 * │                                         │                         │
 * │                                         ▼                         │
 * │                           ┌──────────────────────────────────┐   │
 * │                           │ HTLCChronosBridge                │   │
 * │                           │ createHTLC() / claimHTLC()       │   │
 * │                           └──────────────────────────────────┘   │
 * └──────────────────────────────────────────────────────────────────┘
 */

import { ethers } from 'ethers';
import { TrinityShieldClient, AttestationManager } from './ipc-client';

// Contract addresses (Arbitrum Sepolia)
const DEPLOYED_CONTRACTS = {
  TrinityShieldVerifierV2: '0xf111D291afdf8F0315306F3f652d66c5b061F4e3',
  TrinityConsensusVerifier: '0x59396D58Fa856025bD5249E342729d5550Be151C',
  HTLCChronosBridge: '0xc0B9C6cfb6e39432977693d8f2EBd4F2B5f73824',
  ChronosVaultOptimized: '0xAE408eC592f0f865bA0012C480E8867e12B4F32D',
} as const;

// Chain IDs
const CHAIN_ID = {
  ARBITRUM: 1,
  SOLANA: 2,
  TON: 3,
} as const;

// ABIs (minimal for the functions we need)
const TRINITY_SHIELD_V2_ABI = [
  'function submitSGXAttestation(address validator, bytes32 quoteHash, bytes32 mrenclave, bytes32 reportData, uint256 timestamp, bytes relayerSignature) external',
  'function submitSEVAttestation(address validator, bytes32 reportHash, bytes32 measurement, bytes32 hostData, uint256 timestamp, bytes32 idKeyDigest, bytes relayerSignature) external',
  'function checkAttestationValid(address validator) external view returns (bool)',
  'function getValidatorAttestation(address validator) external view returns (uint8 teeType, bool isAttested, uint256 attestedAt, bytes32 measurement, uint256 expiresAt)',
  'function approvedMrenclave(bytes32) external view returns (bool)',
  'function approvedSevMeasurement(bytes32) external view returns (bool)',
];

const TRINITY_CONSENSUS_ABI = [
  'function submitArbitrumProof(bytes32 operationId, bytes32 merkleRoot, bytes32[] merkleProof, bytes signature, bytes attestation) external',
  'function submitSolanaProof(bytes32 operationId, bytes32 merkleRoot, bytes32[] merkleProof, bytes signature, bytes attestation) external',
  'function submitTONProof(bytes32 operationId, bytes32 merkleRoot, bytes32[] merkleProof, bytes signature, bytes attestation) external',
  'function validators(uint8 chainId) external view returns (address)',
  'function merkleRoots(uint8 chainId) external view returns (bytes32)',
  'function merkleNonces(uint8 chainId) external view returns (uint256)',
  'function operations(bytes32 operationId) external view returns (tuple(bytes32 operationId, address user, address vault, uint8 operationType, uint256 amount, address token, uint8 status, uint256 createdAt, uint256 expiresAt, uint8 chainConfirmations, bool arbitrumConfirmed, bool solanaConfirmed, bool tonConfirmed, uint256 fee, bytes32 data))',
];

interface RelayerConfig {
  rpcUrl: string;
  privateKey: string;  // Relayer's signing key (not validator key)
  socketPath?: string;
  chainId: 1 | 2 | 3;  // Which chain this relayer is for
}

interface AttestationSubmission {
  validator: string;
  quoteHash: string;
  mrenclave: string;
  mrsigner: string;
  reportData: string;
  timestamp: number;
}

interface ProofSubmission {
  operationId: string;
  leaf: string;
  merkleProof: string[];
  signature: string;
  attestation: string;
}

export class TrinityRelayerBridge {
  private provider: ethers.JsonRpcProvider;
  private wallet: ethers.Wallet;
  private shieldClient: TrinityShieldClient;
  private attestationManager: AttestationManager;
  private chainId: 1 | 2 | 3;
  
  // Contract instances
  private shieldVerifier: ethers.Contract;
  private consensusVerifier: ethers.Contract;

  constructor(config: RelayerConfig) {
    this.provider = new ethers.JsonRpcProvider(config.rpcUrl);
    this.wallet = new ethers.Wallet(config.privateKey, this.provider);
    this.shieldClient = new TrinityShieldClient(config.socketPath);
    this.attestationManager = new AttestationManager(this.shieldClient);
    this.chainId = config.chainId;

    // Initialize contract instances
    this.shieldVerifier = new ethers.Contract(
      DEPLOYED_CONTRACTS.TrinityShieldVerifierV2,
      TRINITY_SHIELD_V2_ABI,
      this.wallet
    );
    
    this.consensusVerifier = new ethers.Contract(
      DEPLOYED_CONTRACTS.TrinityConsensusVerifier,
      TRINITY_CONSENSUS_ABI,
      this.wallet
    );
  }

  /**
   * Initialize the relayer bridge
   */
  async initialize(): Promise<void> {
    // Verify enclave is running
    const available = await this.shieldClient.isAvailable();
    if (!available) {
      throw new Error('Trinity Shield enclave is not available');
    }

    // Get enclave public key and verify it matches on-chain validator
    const { public_key, chain_id } = await this.shieldClient.getPublicKey();
    const validatorAddress = this.publicKeyToAddress(public_key);
    
    const onChainValidator = await this.consensusVerifier.validators(chain_id);
    if (validatorAddress.toLowerCase() !== onChainValidator.toLowerCase()) {
      throw new Error(
        `Validator mismatch: enclave=${validatorAddress}, on-chain=${onChainValidator}`
      );
    }

    console.log(`[RelayerBridge] Initialized for chain ${chain_id}`);
    console.log(`[RelayerBridge] Validator: ${validatorAddress}`);
    console.log(`[RelayerBridge] Relayer: ${this.wallet.address}`);

    // Start attestation refresh
    this.attestationManager.startAutoRefresh(3600); // Every hour
  }

  /**
   * Convert enclave public key to Ethereum address
   */
  private publicKeyToAddress(publicKeyHex: string): string {
    // For secp256k1, hash the public key and take last 20 bytes
    const pubKeyBytes = ethers.getBytes('0x' + publicKeyHex);
    const hash = ethers.keccak256(pubKeyBytes);
    return '0x' + hash.slice(-40);
  }

  /**
   * Format report data for on-chain submission
   * The contract expects: reportData = bytes32(uint256(uint160(validator)))
   */
  private formatReportData(validatorAddress: string): string {
    // Convert address to bytes32 (right-padded with zeros)
    const addressBigInt = BigInt(validatorAddress);
    return ethers.zeroPadValue(ethers.toBeHex(addressBigInt), 32);
  }

  /**
   * Submit SGX attestation to TrinityShieldVerifierV2
   */
  async submitSGXAttestation(): Promise<ethers.TransactionReceipt> {
    // Get fresh attestation from enclave
    const attestation = await this.attestationManager.getAttestation();
    
    // Get validator address
    const { public_key } = await this.shieldClient.getPublicKey();
    const validatorAddress = this.publicKeyToAddress(public_key);
    
    // Format for on-chain
    const quoteHash = ethers.keccak256('0x' + attestation.quote);
    const mrenclave = '0x' + attestation.mrenclave;
    const reportData = this.formatReportData(validatorAddress);
    const timestamp = attestation.timestamp;

    // Sign the attestation as relayer
    const messageHash = ethers.solidityPackedKeccak256(
      ['address', 'bytes32', 'bytes32', 'bytes32', 'uint256', 'uint256'],
      [validatorAddress, quoteHash, mrenclave, reportData, timestamp, 421614] // Arbitrum Sepolia chainId
    );
    const signature = await this.wallet.signMessage(ethers.getBytes(messageHash));

    console.log(`[RelayerBridge] Submitting SGX attestation for ${validatorAddress}`);
    
    const tx = await this.shieldVerifier.submitSGXAttestation(
      validatorAddress,
      quoteHash,
      mrenclave,
      reportData,
      timestamp,
      signature
    );
    
    const receipt = await tx.wait();
    console.log(`[RelayerBridge] Attestation submitted: ${receipt.hash}`);
    
    return receipt;
  }

  /**
   * Submit AMD SEV-SNP attestation for TON validator
   */
  async submitSEVAttestation(idKeyDigest: string): Promise<ethers.TransactionReceipt> {
    const attestation = await this.attestationManager.getAttestation();
    
    const { public_key } = await this.shieldClient.getPublicKey();
    const validatorAddress = this.publicKeyToAddress(public_key);
    
    const reportHash = ethers.keccak256('0x' + attestation.quote);
    const measurement = '0x' + attestation.mrenclave; // For SEV, this is MEASUREMENT
    const hostData = this.formatReportData(validatorAddress);
    const timestamp = attestation.timestamp;

    const messageHash = ethers.solidityPackedKeccak256(
      ['address', 'bytes32', 'bytes32', 'bytes32', 'uint256', 'bytes32', 'uint256'],
      [validatorAddress, reportHash, measurement, hostData, timestamp, idKeyDigest, 421614]
    );
    const signature = await this.wallet.signMessage(ethers.getBytes(messageHash));

    console.log(`[RelayerBridge] Submitting SEV attestation for ${validatorAddress}`);
    
    const tx = await this.shieldVerifier.submitSEVAttestation(
      validatorAddress,
      reportHash,
      measurement,
      hostData,
      timestamp,
      idKeyDigest,
      signature
    );
    
    const receipt = await tx.wait();
    console.log(`[RelayerBridge] SEV attestation submitted: ${receipt.hash}`);
    
    return receipt;
  }

  /**
   * Submit consensus proof for an operation
   */
  async submitProof(
    operationId: string,
    operationType: 'deposit' | 'withdrawal' | 'transfer',
    vaultAddress: string,
    amount: string
  ): Promise<ethers.TransactionReceipt> {
    // Get signed vote from enclave
    const signedVote = await this.shieldClient.signVote({
      operation_id: operationId.replace('0x', ''),
      operation_type: operationType,
      vault: vaultAddress.replace('0x', ''),
      amount,
      chain_id: this.chainId,
    });

    // Get attestation for the proof
    const attestation = await this.attestationManager.getAttestation();
    
    // Build Merkle proof (simplified - in production this would be computed)
    const merkleProof: string[] = []; // Empty for now
    const merkleRoot = await this.consensusVerifier.merkleRoots(this.chainId);

    const signature = '0x' + signedVote.signature;
    const attestationBytes = '0x' + attestation.quote;

    console.log(`[RelayerBridge] Submitting proof for operation ${operationId}`);

    // Select correct submit function based on chain
    let tx;
    switch (this.chainId) {
      case CHAIN_ID.ARBITRUM:
        tx = await this.consensusVerifier.submitArbitrumProof(
          operationId, merkleRoot, merkleProof, signature, attestationBytes
        );
        break;
      case CHAIN_ID.SOLANA:
        tx = await this.consensusVerifier.submitSolanaProof(
          operationId, merkleRoot, merkleProof, signature, attestationBytes
        );
        break;
      case CHAIN_ID.TON:
        tx = await this.consensusVerifier.submitTONProof(
          operationId, merkleRoot, merkleProof, signature, attestationBytes
        );
        break;
    }

    const receipt = await tx.wait();
    console.log(`[RelayerBridge] Proof submitted: ${receipt.hash}`);

    return receipt;
  }

  /**
   * Check if validator attestation is valid on-chain
   */
  async checkAttestationStatus(): Promise<{
    isValid: boolean;
    expiresAt: number;
    measurement: string;
  }> {
    const { public_key } = await this.shieldClient.getPublicKey();
    const validatorAddress = this.publicKeyToAddress(public_key);
    
    const [teeType, isAttested, attestedAt, measurement, expiresAt] = 
      await this.shieldVerifier.getValidatorAttestation(validatorAddress);
    
    return {
      isValid: isAttested,
      expiresAt: Number(expiresAt),
      measurement: measurement,
    };
  }

  /**
   * Monitor pending operations and submit proofs
   */
  async monitorAndSubmitProofs(
    onOperationFound: (operationId: string) => Promise<boolean>
  ): Promise<void> {
    // This would connect to event logs in production
    // For now, it's a placeholder for the monitoring loop
    console.log('[RelayerBridge] Monitoring for pending operations...');
    
    // TODO: Subscribe to OperationCreated events
    // When found, call onOperationFound(operationId)
    // If returns true, submit proof
  }

  /**
   * Get enclave metrics
   */
  async getEnclaveMetrics() {
    return this.shieldClient.getMetrics();
  }

  /**
   * Shutdown the relayer
   */
  shutdown(): void {
    this.attestationManager.stopAutoRefresh();
    console.log('[RelayerBridge] Shutdown complete');
  }
}

// ============================================================
// Main Entry Point
// ============================================================

async function main() {
  const config: RelayerConfig = {
    rpcUrl: process.env.ARBITRUM_RPC_URL || 'https://sepolia-rollup.arbitrum.io/rpc',
    privateKey: process.env.PRIVATE_KEY || '',
    chainId: 1, // Arbitrum
  };

  if (!config.privateKey) {
    console.error('ERROR: PRIVATE_KEY environment variable required');
    process.exit(1);
  }

  const bridge = new TrinityRelayerBridge(config);
  
  try {
    await bridge.initialize();
    
    // Check current attestation status
    const status = await bridge.checkAttestationStatus();
    console.log('Attestation status:', status);
    
    // Submit fresh attestation if needed
    if (!status.isValid || status.expiresAt < Date.now() / 1000 + 3600) {
      console.log('Submitting fresh attestation...');
      await bridge.submitSGXAttestation();
    }
    
    // Get metrics
    const metrics = await bridge.getEnclaveMetrics();
    console.log('Enclave metrics:', metrics);
    
  } catch (error) {
    console.error('Bridge error:', error);
  } finally {
    bridge.shutdown();
  }
}

if (require.main === module) {
  main();
}

export { DEPLOYED_CONTRACTS, CHAIN_ID };
