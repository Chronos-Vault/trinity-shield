#!/bin/bash
#
# Trinity Shield™ Validator Setup Script
# Automates the setup of a new validator node
#
# Usage: ./validator-setup.sh --chain [arbitrum|solana|ton] --tee [sgx|sev-snp]
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
TRINITY_SHIELD_VERSION="3.5.20"
TRINITY_SHIELD_REPO="https://github.com/Chronos-Vault/trinity-shield.git"
PCCS_URL="https://pccs.chronosvault.org:8081/sgx/certification/v4/"

# Contract addresses
SHIELD_VERIFIER="0x2971c0c3139F89808F87b2445e53E5Fb83b6A002"
CONSENSUS_VERIFIER="0x59396D58Fa856025bD5249E342729d5550Be151C"
KEEPER_REGISTRY="0xAe9bd988011583D87d6bbc206C19e4a9Bda04830"

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           TRINITY SHIELD™ VALIDATOR SETUP                    ║"
    echo "║         Mathematically Proven. Hardware Protected.           ║"
    echo "║                   Version ${TRINITY_SHIELD_VERSION}                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_system_requirements() {
    log_info "Checking system requirements..."
    
    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine OS version"
        exit 1
    fi
    
    . /etc/os-release
    if [[ "$ID" != "ubuntu" || "$VERSION_ID" != "22.04" ]]; then
        log_warning "Recommended: Ubuntu 22.04 LTS. Current: $PRETTY_NAME"
    fi
    
    # Check CPU
    if [[ "$TEE_TYPE" == "sgx" ]]; then
        if ! grep -q sgx /proc/cpuinfo; then
            log_error "Intel SGX not detected in CPU"
            exit 1
        fi
        log_success "Intel SGX detected"
    elif [[ "$TEE_TYPE" == "sev-snp" ]]; then
        if ! grep -q sev /proc/cpuinfo; then
            log_error "AMD SEV not detected in CPU"
            exit 1
        fi
        log_success "AMD SEV detected"
    fi
    
    # Check memory
    TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $TOTAL_MEM -lt 32 ]]; then
        log_warning "Minimum 32GB RAM recommended. Current: ${TOTAL_MEM}GB"
    fi
    
    log_success "System requirements check passed"
}

install_dependencies() {
    log_info "Installing dependencies..."
    
    apt update && apt upgrade -y
    
    apt install -y \
        build-essential \
        cmake \
        libssl-dev \
        libcurl4-openssl-dev \
        protobuf-compiler \
        wget \
        git \
        curl \
        jq \
        pkg-config \
        libclang-dev
    
    # Install Rust
    if ! command -v rustc &> /dev/null; then
        log_info "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env
    fi
    
    log_success "Dependencies installed"
}

install_sgx() {
    log_info "Installing Intel SGX SDK..."
    
    # Add Intel repository
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | \
        tee /etc/apt/sources.list.d/intel-sgx.list
    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
        apt-key add -
    
    apt update
    
    apt install -y \
        libsgx-epid \
        libsgx-quote-ex \
        libsgx-dcap-ql \
        libsgx-dcap-quote-verify \
        libsgx-urts \
        sgx-dcap-pccs
    
    # Configure PCCS
    cat > /etc/sgx_default_qcnl.conf << EOF
# PCCS configuration for Trinity Shield
PCCS_URL=${PCCS_URL}
USE_SECURE_CERT=TRUE
RETRY_TIMES=6
RETRY_DELAY=10
EOF
    
    # Start AESM service
    systemctl enable aesmd
    systemctl start aesmd
    
    log_success "Intel SGX installed and configured"
}

install_sev_snp() {
    log_info "Installing AMD SEV-SNP tools..."
    
    # Install SEV tool
    git clone https://github.com/AMDESE/sev-tool.git /opt/sev-tool
    cd /opt/sev-tool
    mkdir build && cd build
    cmake ..
    make -j$(nproc)
    make install
    
    # Verify SEV is enabled
    if ! sevtool --export_cert_chain /tmp/certs; then
        log_error "SEV-SNP not properly configured"
        exit 1
    fi
    
    log_success "AMD SEV-SNP tools installed"
}

clone_trinity_shield() {
    log_info "Cloning Trinity Shield repository..."
    
    if [[ -d /opt/trinity-shield ]]; then
        log_info "Removing existing installation..."
        rm -rf /opt/trinity-shield
    fi
    
    git clone $TRINITY_SHIELD_REPO /opt/trinity-shield
    cd /opt/trinity-shield
    git checkout v${TRINITY_SHIELD_VERSION} || log_warning "Version tag not found, using main"
    
    log_success "Trinity Shield cloned"
}

build_enclave() {
    log_info "Building Trinity Shield enclave..."
    
    cd /opt/trinity-shield
    
    if [[ "$TEE_TYPE" == "sgx" ]]; then
        # Install SGX target
        rustup target add x86_64-fortanix-unknown-sgx
        
        # Build for SGX
        cargo build --release --features sgx --target x86_64-fortanix-unknown-sgx
        
        log_success "SGX enclave built"
    elif [[ "$TEE_TYPE" == "sev-snp" ]]; then
        # Build for SEV-SNP
        cargo build --release --features sev-snp
        
        log_success "SEV-SNP enclave built"
    fi
}

generate_keys() {
    log_info "Generating validator keys inside enclave..."
    
    cd /opt/trinity-shield
    
    QUANTUM_FLAG=""
    if [[ "$CHAIN" == "ton" ]]; then
        QUANTUM_FLAG="--quantum"
    fi
    
    ./target/release/trinity-shield keygen --chain $CHAIN $QUANTUM_FLAG > /tmp/keygen-output.txt
    
    VALIDATOR_ADDRESS=$(grep "Validator Address" /tmp/keygen-output.txt | awk '{print $3}')
    
    log_success "Keys generated for validator: $VALIDATOR_ADDRESS"
    
    # Securely delete temp file
    shred -u /tmp/keygen-output.txt
}

setup_systemd_service() {
    log_info "Setting up systemd service..."
    
    cat > /etc/systemd/system/trinity-shield.service << EOF
[Unit]
Description=Trinity Shield Validator
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/trinity-shield
ExecStart=/opt/trinity-shield/target/release/trinity-shield run --chain ${CHAIN}
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable trinity-shield
    
    log_success "Systemd service configured"
}

setup_monitoring() {
    log_info "Setting up monitoring..."
    
    # Install Prometheus node exporter
    apt install -y prometheus-node-exporter
    
    # Create monitoring config
    mkdir -p /etc/trinity-shield
    cat > /etc/trinity-shield/monitoring.yaml << EOF
metrics:
  enabled: true
  port: 9100
  path: /metrics
alerts:
  attestation_warning: 7200
  attestation_critical: 1800
chain: ${CHAIN}
tee_type: ${TEE_TYPE}
EOF

    systemctl restart prometheus-node-exporter
    
    log_success "Monitoring configured"
}

print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              SETUP COMPLETE                                   ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Chain: $CHAIN"
    echo "TEE Type: $TEE_TYPE"
    echo "Shield Verifier: $SHIELD_VERIFIER"
    echo ""
    echo "Next steps:"
    echo "1. Generate attestation: trinity-shield attest --chain $CHAIN"
    echo "2. Submit attestation on-chain"
    echo "3. Register as keeper with bond"
    echo "4. Start validator: systemctl start trinity-shield"
    echo ""
    echo "Documentation: https://docs.chronosvault.org"
    echo ""
}

# Parse arguments
CHAIN=""
TEE_TYPE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --chain)
            CHAIN="$2"
            shift 2
            ;;
        --tee)
            TEE_TYPE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 --chain [arbitrum|solana|ton] --tee [sgx|sev-snp]"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate arguments
if [[ -z "$CHAIN" ]]; then
    log_error "Chain not specified. Use --chain [arbitrum|solana|ton]"
    exit 1
fi

if [[ ! "$CHAIN" =~ ^(arbitrum|solana|ton)$ ]]; then
    log_error "Invalid chain: $CHAIN. Must be arbitrum, solana, or ton"
    exit 1
fi

# Auto-detect TEE type if not specified
if [[ -z "$TEE_TYPE" ]]; then
    if [[ "$CHAIN" == "ton" ]]; then
        TEE_TYPE="sev-snp"
    else
        TEE_TYPE="sgx"
    fi
    log_info "Auto-detected TEE type: $TEE_TYPE"
fi

if [[ ! "$TEE_TYPE" =~ ^(sgx|sev-snp)$ ]]; then
    log_error "Invalid TEE type: $TEE_TYPE. Must be sgx or sev-snp"
    exit 1
fi

# Main execution
print_banner
check_root
check_system_requirements
install_dependencies

if [[ "$TEE_TYPE" == "sgx" ]]; then
    install_sgx
else
    install_sev_snp
fi

clone_trinity_shield
build_enclave
generate_keys
setup_systemd_service
setup_monitoring
print_summary
