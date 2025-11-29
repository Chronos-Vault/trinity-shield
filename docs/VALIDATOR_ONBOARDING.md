# Trinity Shield™ Validator Onboarding Guide

**Version:** 3.5.20  
**Website:** [chronosvault.org](https://chronosvault.org)  
**Last Updated:** November 29, 2025

---

## Overview

This guide walks you through the process of becoming a Trinity Protocol validator with hardware-isolated security via Trinity Shield™.

### Validator Roles

| Chain | Role | TEE Type | Special Features |
|-------|------|----------|------------------|
| Arbitrum | Primary Security | Intel SGX | Main consensus validation |
| Solana | High-Frequency Monitoring | Intel SGX | <5s SLA, RPC failover |
| TON | Emergency Recovery | AMD SEV-SNP | Quantum-resistant cryptography |

---

## Prerequisites

### Hardware Requirements

#### Intel SGX Validators (Arbitrum/Solana)

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | Intel Xeon (Ice Lake) | Intel Xeon Scalable 3rd Gen |
| SGX EPC | 128 MB | 256 MB |
| RAM | 32 GB | 64 GB |
| Storage | 500 GB NVMe | 1 TB NVMe |
| Network | 1 Gbps | 10 Gbps |

**Required Features:**
- SGX2 support (EDMM)
- DCAP attestation capability
- Flexible Launch Control (FLC)

**BIOS Settings:**
```
Intel SGX: Enabled
SGX Launch Control Policy: Unlocked
SGX Factory Reset: No
Total SGX Memory Size: MAX
```

#### AMD SEV-SNP Validator (TON)

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | AMD EPYC (Milan) | AMD EPYC 7003 Series |
| SEV-SNP ASIDs | 15 | 509 |
| RAM | 64 GB | 128 GB (all encrypted) |
| Storage | 1 TB NVMe | 2 TB NVMe |
| Network | 1 Gbps | 10 Gbps |

**Required Features:**
- SEV-SNP enabled (not just SEV or SEV-ES)
- TSME (Transparent SME) disabled
- Secure Memory Encryption

---

## Software Setup

### 1. Install Base System

```bash
# Ubuntu 22.04 LTS recommended
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y \
    build-essential \
    cmake \
    libssl-dev \
    libcurl4-openssl-dev \
    protobuf-compiler \
    wget \
    git
```

### 2. Install Intel SGX SDK (for Arbitrum/Solana)

```bash
# Add Intel SGX repository
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | \
    sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
    sudo apt-key add -

# Install SGX packages
sudo apt update
sudo apt install -y \
    libsgx-epid \
    libsgx-quote-ex \
    libsgx-dcap-ql \
    libsgx-dcap-quote-verify \
    sgx-dcap-pccs

# Verify installation
sgx_sign --version
```

### 3. Install AMD SEV-SNP Tools (for TON)

```bash
# Clone SNP tools repository
git clone https://github.com/AMDESE/sev-tool.git
cd sev-tool
mkdir build && cd build
cmake ..
make
sudo make install

# Verify installation
sevtool --version
```

### 4. Install Trinity Shield Enclave

```bash
# Clone Trinity Shield repository
git clone https://github.com/Chronos-Vault/trinity-shield.git
cd trinity-shield

# Build enclave (SGX)
cargo build --release --features sgx --target x86_64-fortanix-unknown-sgx

# Or build enclave (SEV-SNP)
cargo build --release --features sev-snp
```

---

## Key Generation

### SGX Validator Keys

Keys are generated inside the enclave and sealed to the hardware:

```bash
# Generate keys (inside enclave)
./trinity-shield keygen --chain arbitrum

# Output:
# Validator Address: 0x3A92fD5b39Ec9598225DB5b9f15af0523445E3d8
# Public Key (Ed25519): ...
# Keys sealed to MRENCLAVE: 0xa1b2c3d4...
```

### SEV-SNP Validator Keys (Quantum-Resistant)

```bash
# Generate quantum-resistant keys
./trinity-shield keygen --chain ton --quantum

# Output:
# Validator Address: 0x9662e22D1f037C7EB370DD0463c597C6cd69B4c4
# Public Key (Dilithium-5): ...
# KEM Key (ML-KEM-1024): ...
# Keys encrypted with VCEK
```

---

## Attestation Setup

### 1. Configure PCCS (Intel SGX)

```bash
# Configure PCCS connection
sudo vim /etc/sgx_default_qcnl.conf

# Add:
PCCS_URL=https://pccs.chronosvault.org:8081/sgx/certification/v4/
USE_SECURE_CERT=TRUE
```

### 2. Generate Initial Attestation

```bash
# Generate attestation quote
./trinity-shield attest --chain arbitrum --output quote.bin

# Submit to chain
./trinity-shield submit-attestation \
    --chain arbitrum \
    --quote quote.bin \
    --contract 0x2971c0c3139F89808F87b2445e53E5Fb83b6A002
```

### 3. Verify On-Chain

```bash
# Check attestation status
cast call 0x2971c0c3139F89808F87b2445e53E5Fb83b6A002 \
    "checkAttestationValid(address)(bool)" \
    0x3A92fD5b39Ec9598225DB5b9f15af0523445E3d8 \
    --rpc-url https://sepolia-rollup.arbitrum.io/rpc

# Expected: true
```

---

## Staking Requirements

### Validator Bond

| Chain | Minimum Bond | Recommended |
|-------|--------------|-------------|
| Arbitrum | 5,000 USDC | 10,000 USDC |
| Solana | 5,000 USDC | 10,000 USDC |
| TON | 10,000 USDC | 25,000 USDC |

### Bond Deposit

```bash
# Approve USDC
cast send 0x4567853BE0d5780099E3542Df2e00C5B633E0161 \
    "approve(address,uint256)" \
    0xAe9bd988011583D87d6bbc206C19e4a9Bda04830 \
    10000000000 \
    --rpc-url $ARBITRUM_RPC_URL \
    --private-key $PRIVATE_KEY

# Register as keeper
cast send 0xAe9bd988011583D87d6bbc206C19e4a9Bda04830 \
    "registerKeeper(uint256)" \
    10000000000 \
    --rpc-url $ARBITRUM_RPC_URL \
    --private-key $PRIVATE_KEY
```

---

## Monitoring Setup

### Install Monitoring Agent

```bash
# Install Prometheus node exporter
sudo apt install prometheus-node-exporter

# Configure Trinity Shield metrics
cat > /etc/trinity-shield/monitoring.yaml << EOF
metrics:
  enabled: true
  port: 9100
  path: /metrics
alerts:
  attestation_warning: 7200  # 2 hours
  attestation_critical: 1800  # 30 minutes
EOF
```

### Alert Configuration

```yaml
# /etc/alertmanager/trinity-rules.yml
groups:
  - name: trinity-shield
    rules:
      - alert: AttestationExpiring
        expr: trinity_attestation_remaining_seconds < 7200
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Attestation expiring soon"
          
      - alert: AttestationCritical
        expr: trinity_attestation_remaining_seconds < 1800
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Attestation critically low"
```

---

## Operational Procedures

### Daily Checklist

1. ☐ Verify attestation status (should be > 18h remaining)
2. ☐ Check enclave health metrics
3. ☐ Review consensus participation logs
4. ☐ Verify bond balance

### Weekly Checklist

1. ☐ Review security alerts
2. ☐ Check firmware updates (BIOS, SGX/SEV microcode)
3. ☐ Test failover procedures
4. ☐ Backup sealed keys (encrypted)

### Monthly Checklist

1. ☐ Security audit review
2. ☐ Performance optimization
3. ☐ Capacity planning
4. ☐ Governance participation

---

## Emergency Procedures

### Attestation Failure

```bash
# 1. Check enclave status
./trinity-shield status

# 2. Regenerate attestation
./trinity-shield attest --force

# 3. If enclave corrupted, restore from backup
./trinity-shield restore --backup /path/to/sealed-backup
```

### Key Compromise

1. **Immediate:** Contact security team at security@chronosvault.org
2. **Within 1h:** Invoke emergency multi-sig to pause validator
3. **Within 24h:** Deploy new enclave with rotated keys
4. **Within 48h:** Complete incident report

### Hardware Failure

1. Activate backup validator
2. Transfer sealed keys via secure channel
3. Complete failover within 24-hour attestation window
4. Update on-chain validator registration

---

## Support

- **Documentation:** https://docs.chronosvault.org
- **GitHub Issues:** https://github.com/Chronos-Vault/trinity-shield/issues
- **Security:** security@chronosvault.org
- **Discord:** discord.gg/chronosvault

---

## Appendix: MRENCLAVE Values

| Version | Chain | MRENCLAVE |
|---------|-------|-----------|
| v1.0.0 | All | `0xa1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456` |
| v1.0.1-arbitrum | Arbitrum | `0xf0e1d2c3b4a5968778695a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d` |
| v1.0.1-solana | Solana | `0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef` |
| v1.0.1-ton | TON (SEV) | `0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890` |

---

*Trinity Shield™ - Mathematically Proven. Hardware Protected.*
