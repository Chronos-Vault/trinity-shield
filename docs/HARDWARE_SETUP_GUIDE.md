# Trinity Shield Hardware Setup Guide

Complete guide for setting up Intel SGX and AMD SEV servers for Trinity Protocol validators.

---

## Overview

Trinity Protocol requires hardware-isolated Trusted Execution Environments (TEE) for validator security. This guide covers:

- **Intel SGX** - For Arbitrum and Solana validators
- **AMD SEV-SNP** - For TON validator (quantum-resistant)

---

## System Requirements

### Minimum Hardware Specifications

| Component | Intel SGX Server | AMD SEV Server |
|-----------|------------------|----------------|
| **CPU** | Intel Xeon (Ice Lake+) with SGX2 | AMD EPYC (Milan/Genoa) with SEV-SNP |
| **RAM** | 32GB minimum (128GB recommended) | 64GB minimum (256GB recommended) |
| **EPC Size** | 64GB+ recommended | N/A |
| **Storage** | 500GB NVMe SSD | 500GB NVMe SSD |
| **Network** | 1Gbps dedicated | 1Gbps dedicated |
| **OS** | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |

### Recommended Cloud Providers

| Provider | SGX Support | SEV Support | Region Options |
|----------|-------------|-------------|----------------|
| **Azure** | DCsv3 series | SEV-SNP VMs | Global |
| **AWS** | i3en.metal (limited) | SEV not available | US, EU |
| **OVHcloud** | SGX dedicated | SEV dedicated | EU |
| **Equinix Metal** | c3.small.x86 | m3.small.x86 | Global |

---

## Part 1: Intel SGX Server Setup

### 1.1 Check SGX Support

```bash
# Check CPU capabilities
cpuid | grep -i sgx

# Expected output:
#    SGX: Software Guard Extensions supported = true
#    SGX_LC: SGX launch config supported = true
#    SGX2: SGX2 supported = true
```

### 1.2 Enable SGX in BIOS

1. Enter BIOS setup (usually F2, F10, or Del during boot)
2. Navigate to **Security** > **Intel Software Guard Extensions**
3. Set **SGX** to **Enabled** (not "Software Controlled")
4. Set **SGX Launch Control Policy** to **Unlocked**
5. Configure **PRMRR Size** to maximum (64GB+ recommended)
6. Save and reboot

### 1.3 Install SGX Software Stack

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Add Intel SGX repository
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | \
    sudo tee /etc/apt/sources.list.d/intel-sgx.list

# Add Intel signing key
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
    sudo gpg --dearmor -o /usr/share/keyrings/intel-sgx.gpg

# Install SGX packages
sudo apt update
sudo apt install -y \
    libsgx-enclave-common \
    libsgx-enclave-common-dev \
    libsgx-dcap-ql \
    libsgx-dcap-ql-dev \
    libsgx-dcap-default-qpl \
    libsgx-urts \
    sgx-aesm-service

# Start AESM service
sudo systemctl enable aesmd
sudo systemctl start aesmd
```

### 1.4 Install DCAP (Data Center Attestation Primitives)

```bash
# Install DCAP packages
sudo apt install -y \
    libsgx-dcap-quote-verify \
    libsgx-dcap-quote-verify-dev \
    libsgx-ae-qve \
    libsgx-pce-logic \
    libsgx-qe3-logic

# Configure PCCS (Provisioning Certificate Caching Service)
# For production, register at https://api.portal.trustedservices.intel.com/
# For testing, use Azure PCCS or Intel's public PCCS

# Create PCCS config
sudo mkdir -p /etc/sgx_default_qcnl_conf
cat << 'EOF' | sudo tee /etc/sgx_default_qcnl_conf/sgx_default_qcnl.conf
{
  "pccs_url": "https://localhost:8081/sgx/certification/v4/",
  "use_secure_cert": false,
  "collateral_service": "https://api.trustedservices.intel.com/sgx/certification/v4/",
  "retry_times": 6,
  "retry_delay": 10,
  "pck_cache_expire_hours": 168,
  "verify_collateral_cache_expire_hours": 168,
  "local_pck_url": "",
  "local_collateral_url": ""
}
EOF
```

### 1.5 Verify SGX Installation

```bash
# Check SGX device
ls -la /dev/sgx*

# Expected:
# crw------- 1 root root 10, 125 ... /dev/sgx_enclave
# crw------- 1 root root 10, 126 ... /dev/sgx_provision

# Run self-test
/opt/intel/sgxsdk/bin/sgx_sign -version

# Check AESM status
sudo systemctl status aesmd
```

---

## Part 2: AMD SEV-SNP Server Setup

### 2.1 Check SEV Support

```bash
# Check CPU capabilities
dmesg | grep -i sev

# Expected output:
# SEV: SEV-SNP API:1.52 build:6
# SEV: SEV-SNP supported

# Check SEV kernel module
lsmod | grep ccp
```

### 2.2 Configure BIOS for SEV-SNP

1. Enter BIOS setup
2. Navigate to **AMD CBS** > **CPU Common Options** > **SEV-ES ASID Space Limit**
3. Set to maximum (e.g., 509)
4. Enable **Secure Nested Paging (SNP)**
5. Set **Minimum SEV non-ES ASID** appropriately
6. Save and reboot

### 2.3 Install SEV Kernel and Tools

```bash
# Install latest kernel with SEV support
sudo apt install -y linux-image-generic-hwe-22.04

# Install SEV tools
sudo apt install -y \
    sev-tool \
    qemu-system-x86 \
    libvirt-daemon-system

# Load SEV kernel module
sudo modprobe ccp

# Verify SEV status
sudo sev-tool --export_cert_chain
```

### 2.4 Configure SEV for Virtual Machines

```bash
# Create SEV policy file
cat << 'EOF' | sudo tee /etc/sev-policy.json
{
  "policy": {
    "debug": false,
    "migrate_ma": false,
    "smt": true,
    "abi_major": 1,
    "abi_minor": 52
  }
}
EOF

# Configure libvirt for SEV
sudo virsh capabilities | grep -A 20 sev
```

### 2.5 Verify SEV Installation

```bash
# Check SEV device
ls -la /dev/sev

# Expected:
# crw------- 1 root root 10, 124 ... /dev/sev

# Get platform info
sudo sev-tool --platform_status

# Expected output shows:
# Platform State: WORKING
# Owner: none
# Guest Count: 0
```

---

## Part 3: Trinity Shield Deployment

### 3.1 Clone Trinity Shield Repository

```bash
# Clone repository
git clone https://github.com/Chronos-Vault/trinity-shield.git
cd trinity-shield

# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install additional tools
rustup component add rust-src
cargo install cargo-sgx
```

### 3.2 Build Trinity Shield (SGX Mode)

```bash
# For Intel SGX (Arbitrum/Solana validators)
cargo build --release --features sgx

# Sign enclave
/opt/intel/sgxsdk/bin/sgx_sign sign \
    -key Enclave_private.pem \
    -enclave target/release/libtrinityshield.so \
    -out target/release/trinity_shield.signed.so \
    -config Enclave.config.xml

# Get MRENCLAVE value (needed for on-chain registration)
/opt/intel/sgxsdk/bin/sgx_sign dump \
    -enclave target/release/trinity_shield.signed.so \
    -dumpfile enclave_info.txt

grep "enclave_hash" enclave_info.txt
# Save this hash - you'll register it on TrinityShieldVerifierV2
```

### 3.3 Build Trinity Shield (SEV Mode)

```bash
# For AMD SEV (TON validator with quantum crypto)
cargo build --release --features sev,quantum

# Generate measurement
sudo sev-tool --generate_launch_measure \
    --firmware /usr/share/OVMF/OVMF_CODE.fd \
    --kernel target/release/trinity_shield

# Get MEASUREMENT value (needed for on-chain registration)
# Save this - you'll register it on TrinityShieldVerifierV2
```

### 3.4 Configure Trinity Shield

```bash
# Create configuration file
cat << 'EOF' > config.toml
[validator]
chain_id = 1  # 1=Arbitrum, 2=Solana, 3=TON
ethereum_address = "0xYOUR_VALIDATOR_ADDRESS"
private_key_sealed = true

[network]
arbitrum_rpc = "https://sepolia-rollup.arbitrum.io/rpc"
solana_rpc = "https://api.devnet.solana.com"
ton_rpc = "https://testnet.toncenter.com/api/v2/jsonRPC"

[contracts]
consensus_verifier = "0x59396D58Fa856025bD5249E342729d5550Be151C"
shield_verifier = "0xf111D291afdf8F0315306F3f652d66c5b061F4e3"

[ipc]
socket_path = "/run/trinity-shield.sock"

[attestation]
refresh_interval_hours = 24
auto_reattesttest = true

[quantum]
enabled = true  # Set true for TON validator
algorithm = "dilithium5"
EOF

# Set permissions
chmod 600 config.toml
```

### 3.5 Run Trinity Shield

```bash
# Create systemd service
cat << 'EOF' | sudo tee /etc/systemd/system/trinity-shield.service
[Unit]
Description=Trinity Shield TEE Validator
After=network.target aesmd.service

[Service]
Type=simple
User=trinity
Group=trinity
WorkingDirectory=/opt/trinity-shield
ExecStart=/opt/trinity-shield/target/release/trinity_shield
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

# Create trinity user
sudo useradd -r -s /bin/false trinity
sudo usermod -aG sgx trinity  # For SGX
sudo usermod -aG kvm trinity  # For SEV

# Start service
sudo systemctl daemon-reload
sudo systemctl enable trinity-shield
sudo systemctl start trinity-shield

# Check status
sudo systemctl status trinity-shield
journalctl -u trinity-shield -f
```

---

## Part 4: Relayer Bridge Setup

### 4.1 Install Node.js Dependencies

```bash
# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Navigate to scripts
cd trinity-shield/scripts

# Install dependencies
npm install
```

### 4.2 Configure Relayer

```bash
# Create .env file
cat << 'EOF' > .env
# Blockchain RPCs
ARBITRUM_RPC_URL=https://sepolia-rollup.arbitrum.io/rpc
SOLANA_RPC_URL=https://api.devnet.solana.com
TON_RPC_URL=https://testnet.toncenter.com/api/v2/jsonRPC

# Contract Addresses
TRINITY_CONSENSUS_VERIFIER=0x59396D58Fa856025bD5249E342729d5550Be151C
TRINITY_SHIELD_VERIFIER=0xf111D291afdf8F0315306F3f652d66c5b061F4e3

# Relayer Private Key (for submitting proofs)
RELAYER_PRIVATE_KEY=0xYOUR_RELAYER_PRIVATE_KEY

# IPC Socket
TRINITY_SHIELD_SOCKET=/run/trinity-shield.sock
EOF

chmod 600 .env
```

### 4.3 Run Relayer Bridge

```bash
# Create systemd service for relayer
cat << 'EOF' | sudo tee /etc/systemd/system/trinity-relayer.service
[Unit]
Description=Trinity Shield Relayer Bridge
After=network.target trinity-shield.service

[Service]
Type=simple
User=trinity
Group=trinity
WorkingDirectory=/opt/trinity-shield/scripts
ExecStart=/usr/bin/npx tsx relayer-bridge.ts
Restart=always
RestartSec=10
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

# Start relayer
sudo systemctl daemon-reload
sudo systemctl enable trinity-relayer
sudo systemctl start trinity-relayer
```

---

## Part 5: On-Chain Registration

### 5.1 Register Validator Address

```bash
# Using cast (foundry)
cast send 0x59396D58Fa856025bD5249E342729d5550Be151C \
    "registerValidator(address,uint8)" \
    YOUR_VALIDATOR_ADDRESS \
    1 \  # Chain ID (1=Arbitrum, 2=Solana, 3=TON)
    --rpc-url https://sepolia-rollup.arbitrum.io/rpc \
    --private-key YOUR_ADMIN_KEY
```

### 5.2 Register MRENCLAVE/MEASUREMENT

```bash
# For SGX validators
cast send 0xf111D291afdf8F0315306F3f652d66c5b061F4e3 \
    "approveMrenclave(bytes32)" \
    YOUR_MRENCLAVE_HASH \
    --rpc-url https://sepolia-rollup.arbitrum.io/rpc \
    --private-key YOUR_ADMIN_KEY

# For SEV validators
cast send 0xf111D291afdf8F0315306F3f652d66c5b061F4e3 \
    "approveMeasurement(bytes32)" \
    YOUR_MEASUREMENT_HASH \
    --rpc-url https://sepolia-rollup.arbitrum.io/rpc \
    --private-key YOUR_ADMIN_KEY
```

### 5.3 Submit Initial Attestation

```bash
# The relayer will automatically submit attestations
# Verify attestation was registered:
cast call 0xf111D291afdf8F0315306F3f652d66c5b061F4e3 \
    "validatorAttestations(address)(uint8,bool,uint256,bytes32)" \
    YOUR_VALIDATOR_ADDRESS \
    --rpc-url https://sepolia-rollup.arbitrum.io/rpc
```

---

## Part 6: Monitoring and Maintenance

### 6.1 Health Checks

```bash
# Check enclave health
curl -s http://localhost:8080/health | jq

# Check attestation status
curl -s http://localhost:8080/attestation | jq

# Check consensus participation
curl -s http://localhost:8080/consensus/stats | jq
```

### 6.2 Log Monitoring

```bash
# Watch Trinity Shield logs
journalctl -u trinity-shield -f

# Watch Relayer logs
journalctl -u trinity-relayer -f

# Search for errors
journalctl -u trinity-shield --since "1 hour ago" | grep -i error
```

### 6.3 Attestation Renewal

Attestations should be renewed every 24 hours (automatic with `auto_reattest = true`).

```bash
# Manual attestation refresh
curl -X POST http://localhost:8080/attestation/refresh

# Check last attestation time
cast call 0xf111D291afdf8F0315306F3f652d66c5b061F4e3 \
    "validatorAttestations(address)" \
    YOUR_VALIDATOR_ADDRESS \
    --rpc-url https://sepolia-rollup.arbitrum.io/rpc
```

---

## Security Checklist

Before going live, ensure:

- [ ] BIOS settings secured with password
- [ ] SGX/SEV enabled with maximum security settings
- [ ] Firewall configured (only required ports open)
- [ ] SSH key-only authentication
- [ ] Fail2ban installed and configured
- [ ] Unattended upgrades enabled for security patches
- [ ] Private keys sealed inside enclave
- [ ] MRENCLAVE/MEASUREMENT registered on-chain
- [ ] Attestation verified on TrinityShieldVerifierV2
- [ ] Monitoring and alerting configured

---

## Troubleshooting

### SGX Issues

```bash
# "SGX not supported"
# - Check BIOS settings
# - Ensure SGX is enabled (not "Software Controlled")

# "AESM service not running"
sudo systemctl restart aesmd
journalctl -u aesmd -f

# "Out of EPC memory"
# - Increase PRMRR size in BIOS
# - Check enclave memory usage
```

### SEV Issues

```bash
# "SEV not available"
# - Check BIOS settings
# - Ensure SEV-SNP is enabled
# - Check kernel version (5.19+ recommended)

# "Platform in invalid state"
sudo sev-tool --factory_reset
sudo reboot
```

### Connection Issues

```bash
# IPC socket not found
ls -la /run/trinity-shield.sock
sudo systemctl restart trinity-shield

# RPC connection failed
# - Check network connectivity
# - Verify RPC URLs in config
# - Check rate limits
```

---

## Support

- **Documentation**: [github.com/Chronos-Vault/trinity-shield/docs](https://github.com/Chronos-Vault/trinity-shield/docs)
- **Issues**: [github.com/Chronos-Vault/trinity-shield/issues](https://github.com/Chronos-Vault/trinity-shield/issues)
- **Email**: validators@chronosvault.org

---

*Trinity Protocol v3.5.20 - "Mathematically Proven. Hardware Protected."*
