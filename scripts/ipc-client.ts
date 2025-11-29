/**
 * Trinity Shield IPC Client
 * 
 * TypeScript client for communicating with the Rust enclave via Unix socket.
 * Used by the relayer service to:
 * - Request attestation quotes
 * - Submit votes for signing
 * - Update trusted time
 * - Get shield metrics
 */

import * as net from 'net';

const SOCKET_PATH = '/run/trinity-shield.sock';
const REQUEST_TIMEOUT = 30000; // 30 seconds

interface IpcRequest {
  method: string;
  params: Record<string, unknown>;
  id: number;
}

interface IpcResponse {
  result?: unknown;
  error?: {
    code: number;
    message: string;
  };
  id: number;
}

interface AttestationReport {
  quote: string;
  mrenclave: string;
  mrsigner: string;
  report_data: string;
  timestamp: number;
}

interface SignVoteRequest {
  operation_id: string;
  operation_type: 'deposit' | 'withdrawal' | 'transfer';
  vault: string;
  amount: string;
  chain_id: number;
}

interface SignedVote {
  vote_hash: string;
  signature: string;
  attestation_quote: string;
  timestamp: number;
}

interface ShieldMetrics {
  operations_processed: number;
  uptime_seconds: number;
  perimeter_stats: {
    requests_allowed: number;
    rate_limited: number;
    ip_blocked: number;
    ddos_blocked: number;
  };
  application_stats: {
    auth_success: number;
    auth_failed: number;
    authz_denied: number;
    validation_failed: number;
    votes_signed: number;
  };
  data_stats: {
    encryptions: number;
    decryptions: number;
    seals: number;
    unseals: number;
    integrity_failures: number;
  };
}

interface PingResponse {
  status: 'ok';
  version: string;
  chain_id: number;
}

export class TrinityShieldClient {
  private requestId = 0;
  private socketPath: string;

  constructor(socketPath: string = SOCKET_PATH) {
    this.socketPath = socketPath;
  }

  /**
   * Send an IPC request and wait for response
   */
  private async sendRequest<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    return new Promise((resolve, reject) => {
      const client = net.createConnection({ path: this.socketPath }, () => {
        const request: IpcRequest = {
          method,
          params,
          id: ++this.requestId,
        };
        
        client.write(JSON.stringify(request) + '\n');
      });

      let responseData = '';
      
      client.on('data', (data) => {
        responseData += data.toString();
        
        if (responseData.includes('\n')) {
          try {
            const response: IpcResponse = JSON.parse(responseData.trim());
            client.end();
            
            if (response.error) {
              reject(new Error(`IPC Error ${response.error.code}: ${response.error.message}`));
            } else {
              resolve(response.result as T);
            }
          } catch (e) {
            reject(new Error(`Failed to parse IPC response: ${e}`));
          }
        }
      });

      client.on('error', (err) => {
        reject(new Error(`IPC connection error: ${err.message}`));
      });

      client.on('timeout', () => {
        client.destroy();
        reject(new Error('IPC request timeout'));
      });

      client.setTimeout(REQUEST_TIMEOUT);
    });
  }

  /**
   * Ping the shield to check if it's running
   */
  async ping(): Promise<PingResponse> {
    return this.sendRequest<PingResponse>('ping');
  }

  /**
   * Generate a fresh attestation report
   */
  async generateAttestation(): Promise<AttestationReport> {
    return this.sendRequest<AttestationReport>('generate_attestation');
  }

  /**
   * Sign a consensus vote
   */
  async signVote(request: SignVoteRequest): Promise<SignedVote> {
    return this.sendRequest<SignedVote>('sign_vote', request);
  }

  /**
   * Update trusted time (for SGX enclaves)
   */
  async updateTime(timestamp: number): Promise<{ success: boolean }> {
    return this.sendRequest<{ success: boolean }>('update_time', { timestamp });
  }

  /**
   * Get shield metrics
   */
  async getMetrics(): Promise<ShieldMetrics> {
    return this.sendRequest<ShieldMetrics>('get_metrics');
  }

  /**
   * Get the enclave's public key
   */
  async getPublicKey(): Promise<{ public_key: string; chain_id: number }> {
    return this.sendRequest<{ public_key: string; chain_id: number }>('get_public_key');
  }

  /**
   * Seal data to enclave hardware
   */
  async sealData(data: string): Promise<{ sealed: string }> {
    return this.sendRequest<{ sealed: string }>('seal_data', { data });
  }

  /**
   * Unseal data from enclave hardware
   */
  async unsealData(sealed: string): Promise<{ data: string }> {
    return this.sendRequest<{ data: string }>('unseal_data', { sealed });
  }

  /**
   * Check if the shield is available
   */
  async isAvailable(): Promise<boolean> {
    try {
      const response = await this.ping();
      return response.status === 'ok';
    } catch {
      return false;
    }
  }
}

/**
 * Attestation Manager
 * 
 * Manages attestation lifecycle including:
 * - Periodic refresh before expiry
 * - Caching for performance
 * - Formatting for on-chain submission
 */
export class AttestationManager {
  private client: TrinityShieldClient;
  private cachedAttestation: AttestationReport | null = null;
  private cacheExpiry = 0;
  private refreshInterval: NodeJS.Timer | null = null;
  
  // Refresh 1 hour before expiry
  private readonly REFRESH_MARGIN = 60 * 60;
  // Attestation validity: 24 hours
  private readonly VALIDITY_PERIOD = 24 * 60 * 60;

  constructor(client: TrinityShieldClient) {
    this.client = client;
  }

  /**
   * Start automatic attestation refresh
   */
  startAutoRefresh(intervalSeconds: number = 3600) {
    this.refreshInterval = setInterval(async () => {
      try {
        await this.refresh();
        console.log('[AttestationManager] Attestation refreshed');
      } catch (e) {
        console.error('[AttestationManager] Failed to refresh attestation:', e);
      }
    }, intervalSeconds * 1000);
  }

  /**
   * Stop automatic refresh
   */
  stopAutoRefresh() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
  }

  /**
   * Get current attestation (from cache or fresh)
   */
  async getAttestation(): Promise<AttestationReport> {
    const now = Math.floor(Date.now() / 1000);
    
    // Check if cache is valid
    if (this.cachedAttestation && now < this.cacheExpiry - this.REFRESH_MARGIN) {
      return this.cachedAttestation;
    }
    
    // Refresh attestation
    return this.refresh();
  }

  /**
   * Force refresh attestation
   */
  async refresh(): Promise<AttestationReport> {
    const attestation = await this.client.generateAttestation();
    this.cachedAttestation = attestation;
    this.cacheExpiry = attestation.timestamp + this.VALIDITY_PERIOD;
    return attestation;
  }

  /**
   * Format attestation for on-chain submission
   */
  formatForChain(attestation: AttestationReport): {
    quoteHash: string;
    mrenclave: string;
    reportData: string;
    timestamp: number;
  } {
    // Take first 32 bytes of report data for the validator address
    const reportData32 = attestation.report_data.slice(0, 64); // 32 bytes = 64 hex chars
    
    // Hash the quote for on-chain verification
    const quoteHash = this.hashQuote(attestation.quote);
    
    return {
      quoteHash,
      mrenclave: attestation.mrenclave,
      reportData: '0x' + reportData32,
      timestamp: attestation.timestamp,
    };
  }

  private hashQuote(quote: string): string {
    // Use crypto module for hashing
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256').update(Buffer.from(quote, 'hex')).digest('hex');
    return '0x' + hash;
  }
}

/**
 * Relayer Service
 * 
 * Bridges the Rust enclave with the Ethereum smart contracts.
 * Handles:
 * - Attestation submission
 * - Vote relaying
 * - Time synchronization
 */
export class RelayerService {
  private client: TrinityShieldClient;
  private attestationManager: AttestationManager;
  private chainId: number;

  constructor(socketPath: string = SOCKET_PATH) {
    this.client = new TrinityShieldClient(socketPath);
    this.attestationManager = new AttestationManager(this.client);
    this.chainId = 0;
  }

  /**
   * Initialize the relayer
   */
  async initialize(): Promise<void> {
    // Check shield is available
    const available = await this.client.isAvailable();
    if (!available) {
      throw new Error('Trinity Shield is not available. Is the enclave running?');
    }

    // Get chain ID
    const { chain_id } = await this.client.getPublicKey();
    this.chainId = chain_id;

    // Start attestation auto-refresh
    this.attestationManager.startAutoRefresh();

    // Initial time sync
    await this.syncTime();

    console.log(`[RelayerService] Initialized for chain ${this.chainId}`);
  }

  /**
   * Sync trusted time with enclave
   */
  async syncTime(): Promise<void> {
    const timestamp = Math.floor(Date.now() / 1000);
    await this.client.updateTime(timestamp);
  }

  /**
   * Get attestation for on-chain submission
   */
  async getFormattedAttestation() {
    const attestation = await this.attestationManager.getAttestation();
    return this.attestationManager.formatForChain(attestation);
  }

  /**
   * Sign a vote and format for on-chain submission
   */
  async signAndFormatVote(
    operationId: string,
    operationType: 'deposit' | 'withdrawal' | 'transfer',
    vault: string,
    amount: string
  ) {
    const signedVote = await this.client.signVote({
      operation_id: operationId,
      operation_type: operationType,
      vault,
      amount,
      chain_id: this.chainId,
    });

    return {
      voteHash: '0x' + signedVote.vote_hash,
      signature: '0x' + signedVote.signature,
      attestationQuote: '0x' + signedVote.attestation_quote,
      timestamp: signedVote.timestamp,
    };
  }

  /**
   * Get current metrics
   */
  async getMetrics() {
    return this.client.getMetrics();
  }

  /**
   * Shutdown the relayer
   */
  shutdown(): void {
    this.attestationManager.stopAutoRefresh();
  }
}

// Main entry point for testing
if (require.main === module) {
  const client = new TrinityShieldClient();
  
  client.ping()
    .then((response) => {
      console.log('Shield ping response:', response);
    })
    .catch((error) => {
      console.error('Failed to connect to shield:', error.message);
      console.log('Make sure the Trinity Shield enclave is running.');
    });
}
