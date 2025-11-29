/**
 * Trinity Shield™ Attestation Monitor
 * 
 * Monitors validator attestation status and sends alerts
 * when attestations are expiring or have failed.
 */

import { ethers } from 'ethers';

interface ValidatorStatus {
  chainId: number;
  validator: string;
  isAttested: boolean;
  attestedAt: number;
  expiresAt: number;
  mrenclave: string;
  remainingTime: number;
  status: 'healthy' | 'warning' | 'critical' | 'expired';
}

interface AlertConfig {
  warningThresholdHours: number;
  criticalThresholdMinutes: number;
  webhookUrl?: string;
  emailRecipients?: string[];
}

const TRINITY_SHIELD_VERIFIER_ABI = [
  'function getValidatorAttestation(address validator) external view returns (bool isAttested, uint256 attestedAt, bytes32 mrenclave)',
  'function attestationValidityPeriod() external view returns (uint256)',
  'function checkAttestationValid(address validator) external view returns (bool)',
  'event ValidatorAttested(address indexed validator, bytes32 mrenclave, uint256 timestamp)',
  'event AttestationExpired(address indexed validator, uint256 timestamp)'
];

const VALIDATORS = {
  arbitrum: {
    chainId: 1,
    address: '0x3A92fD5b39Ec9598225DB5b9f15af0523445E3d8',
    name: 'Arbitrum Validator'
  },
  solana: {
    chainId: 2,
    address: '0x2554324ae222673F4C36D1Ae0E58C19fFFf69cd5',
    name: 'Solana Validator'
  },
  ton: {
    chainId: 3,
    address: '0x9662e22D1f037C7EB370DD0463c597C6cd69B4c4',
    name: 'TON Validator'
  }
};

const DEFAULT_ALERT_CONFIG: AlertConfig = {
  warningThresholdHours: 2,
  criticalThresholdMinutes: 30
};

export class AttestationMonitor {
  private provider: ethers.Provider;
  private verifierContract: ethers.Contract;
  private alertConfig: AlertConfig;

  constructor(
    rpcUrl: string,
    verifierAddress: string,
    alertConfig: AlertConfig = DEFAULT_ALERT_CONFIG
  ) {
    this.provider = new ethers.JsonRpcProvider(rpcUrl);
    this.verifierContract = new ethers.Contract(
      verifierAddress,
      TRINITY_SHIELD_VERIFIER_ABI,
      this.provider
    );
    this.alertConfig = alertConfig;
  }

  async getValidatorStatus(validatorAddress: string, chainId: number): Promise<ValidatorStatus> {
    try {
      const [isAttested, attestedAt, mrenclave] = await this.verifierContract.getValidatorAttestation(validatorAddress);
      const validityPeriod = await this.verifierContract.attestationValidityPeriod();
      
      const now = Math.floor(Date.now() / 1000);
      const expiresAt = Number(attestedAt) + Number(validityPeriod);
      const remainingTime = expiresAt - now;
      
      let status: ValidatorStatus['status'];
      if (!isAttested || remainingTime <= 0) {
        status = 'expired';
      } else if (remainingTime <= this.alertConfig.criticalThresholdMinutes * 60) {
        status = 'critical';
      } else if (remainingTime <= this.alertConfig.warningThresholdHours * 3600) {
        status = 'warning';
      } else {
        status = 'healthy';
      }

      return {
        chainId,
        validator: validatorAddress,
        isAttested,
        attestedAt: Number(attestedAt),
        expiresAt,
        mrenclave,
        remainingTime,
        status
      };
    } catch (error) {
      console.error(`Error fetching attestation for ${validatorAddress}:`, error);
      return {
        chainId,
        validator: validatorAddress,
        isAttested: false,
        attestedAt: 0,
        expiresAt: 0,
        mrenclave: '0x0',
        remainingTime: 0,
        status: 'expired'
      };
    }
  }

  async getAllValidatorStatuses(): Promise<ValidatorStatus[]> {
    const statuses = await Promise.all(
      Object.values(VALIDATORS).map(v => 
        this.getValidatorStatus(v.address, v.chainId)
      )
    );
    return statuses;
  }

  async getSystemHealth(): Promise<{
    overall: 'healthy' | 'degraded' | 'critical';
    attestedCount: number;
    totalValidators: number;
    validators: ValidatorStatus[];
  }> {
    const statuses = await this.getAllValidatorStatuses();
    const attestedCount = statuses.filter(s => s.isAttested && s.remainingTime > 0).length;
    const criticalCount = statuses.filter(s => s.status === 'critical' || s.status === 'expired').length;
    
    let overall: 'healthy' | 'degraded' | 'critical';
    if (attestedCount >= 2 && criticalCount === 0) {
      overall = 'healthy';
    } else if (attestedCount >= 2) {
      overall = 'degraded';
    } else {
      overall = 'critical';
    }

    return {
      overall,
      attestedCount,
      totalValidators: Object.keys(VALIDATORS).length,
      validators: statuses
    };
  }

  formatTimeRemaining(seconds: number): string {
    if (seconds <= 0) return 'EXPIRED';
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (hours > 0) {
      return `${hours}h ${minutes}m`;
    }
    return `${minutes}m`;
  }

  async printStatusReport(): Promise<void> {
    const health = await this.getSystemHealth();
    
    console.log('\n' + '='.repeat(60));
    console.log('TRINITY SHIELD ATTESTATION STATUS');
    console.log('='.repeat(60));
    console.log(`Time: ${new Date().toISOString()}`);
    console.log(`Overall Health: ${health.overall.toUpperCase()}`);
    console.log(`Attested Validators: ${health.attestedCount}/${health.totalValidators}`);
    console.log('-'.repeat(60));
    
    for (const status of health.validators) {
      const validator = Object.values(VALIDATORS).find(v => v.address === status.validator);
      const name = validator?.name || 'Unknown';
      const statusIcon = {
        healthy: '✅',
        warning: '⚠️',
        critical: '🚨',
        expired: '❌'
      }[status.status];
      
      console.log(`\n${statusIcon} ${name} (Chain ${status.chainId})`);
      console.log(`   Address: ${status.validator}`);
      console.log(`   Status: ${status.status.toUpperCase()}`);
      console.log(`   Attested: ${status.isAttested ? 'Yes' : 'No'}`);
      if (status.isAttested) {
        console.log(`   Attested At: ${new Date(status.attestedAt * 1000).toISOString()}`);
        console.log(`   Expires At: ${new Date(status.expiresAt * 1000).toISOString()}`);
        console.log(`   Time Remaining: ${this.formatTimeRemaining(status.remainingTime)}`);
      }
    }
    
    console.log('\n' + '='.repeat(60));
  }

  async sendAlert(status: ValidatorStatus): Promise<void> {
    const validator = Object.values(VALIDATORS).find(v => v.address === status.validator);
    const message = {
      type: status.status,
      validator: validator?.name || status.validator,
      chainId: status.chainId,
      remainingTime: this.formatTimeRemaining(status.remainingTime),
      timestamp: new Date().toISOString()
    };

    console.log(`[ALERT] ${status.status.toUpperCase()}: ${validator?.name} attestation ${status.status}`);
    
    if (this.alertConfig.webhookUrl) {
      try {
        await fetch(this.alertConfig.webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(message)
        });
      } catch (error) {
        console.error('Failed to send webhook alert:', error);
      }
    }
  }

  async startMonitoring(intervalSeconds: number = 300): Promise<void> {
    console.log('Starting Trinity Shield attestation monitoring...');
    console.log(`Check interval: ${intervalSeconds} seconds`);
    
    const check = async () => {
      const statuses = await this.getAllValidatorStatuses();
      for (const status of statuses) {
        if (status.status === 'warning' || status.status === 'critical' || status.status === 'expired') {
          await this.sendAlert(status);
        }
      }
    };

    await this.printStatusReport();
    await check();
    
    setInterval(async () => {
      await this.printStatusReport();
      await check();
    }, intervalSeconds * 1000);
  }
}

export async function runMonitor() {
  const rpcUrl = process.env.ARBITRUM_RPC_URL || 'https://sepolia-rollup.arbitrum.io/rpc';
  const verifierAddress = '0x2971c0c3139F89808F87b2445e53E5Fb83b6A002';
  
  const monitor = new AttestationMonitor(rpcUrl, verifierAddress, {
    warningThresholdHours: 2,
    criticalThresholdMinutes: 30,
    webhookUrl: process.env.ALERT_WEBHOOK_URL
  });

  await monitor.startMonitoring(300);
}

if (require.main === module) {
  runMonitor().catch(console.error);
}
