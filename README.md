# Trinity Shield™

**Layer 8 of the Mathematical Defense Layer (MDL) for Trinity Protocol**

*"Mathematically Proven. Hardware Protected."*

## Overview

Trinity Shield™ is a production-ready Rust implementation of hardware-isolated security for multi-chain consensus validators. It provides three integrated defense layers running inside Intel SGX/AMD SEV trusted execution environments.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    TRINITY SHIELD™                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │ PERIMETER SHIELD│  │APPLICATION SHIELD│  │ DATA SHIELD │ │
│  │                 │  │                 │  │             │ │
│  │ • Rate Limiting │  │ • Auth (Multi-  │  │ • AES-256-  │ │
│  │ • DDoS Protect  │  │   chain sigs)   │  │   GCM Enc   │ │
│  │ • IP Filtering  │  │ • Authorization │  │ • Key Seal  │ │
│  │ • Request Valid │  │ • Input Valid   │  │ • Integrity │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                   CONSENSUS ENGINE                          │
│         2-of-3 Multi-Chain Consensus (Lean-Proven)         │
├─────────────────────────────────────────────────────────────┤
│                 ATTESTATION SERVICE                         │
│           SGX Remote Attestation (DCAP/EPID)               │
└─────────────────────────────────────────────────────────────┘
```

## Features

### Perimeter Shield
- **Rate Limiting**: Token bucket algorithm with per-source tracking
- **DDoS Protection**: Circuit breaker pattern with exponential backoff
- **IP Filtering**: Allowlist/blocklist with CIDR support
- **Request Validation**: Size limits, injection detection, format validation

### Application Shield
- **Multi-Chain Authentication**: Ed25519 (Solana), Secp256k1 (Arbitrum), Dilithium5 (TON)
- **Role-Based Authorization**: Capability tokens with expiry
- **Session Management**: Secure session handling with timeouts
- **Input Validation**: Schema validation, address format checking

### Data Shield
- **Encryption**: AES-256-GCM and ChaCha20-Poly1305
- **Key Sealing**: Hardware-bound keys (MRENCLAVE/MRSIGNER policy)
- **Integrity**: Merkle proofs and HMAC verification
- **Key Management**: Rotation, wrapping, and hierarchical derivation

### Consensus Engine
- **2-of-3 Voting**: Byzantine fault-tolerant consensus
- **Lean-Proven Rules**: Operations validated against formal proofs
- **Multi-Chain**: Arbitrum (security), Solana (monitoring), TON (recovery)
- **Replay Protection**: Nonce tracking and operation timeouts

### Attestation Service
- **Remote Attestation**: SGX quote generation and verification
- **DCAP Support**: Local verification without Intel dependency
- **Quote Caching**: Automatic refresh before expiry

## Building

### Standard Build
```bash
cargo build --release
```

### SGX Enclave Build
```bash
cargo build --release --features sgx --target x86_64-fortanix-unknown-sgx
```

### Simulation Mode (for testing)
```bash
cargo build --release --features simulation
```

## Usage

```rust
use trinity_shield::{TrinityShield, ShieldConfig, ChainId};

// Create shield for Arbitrum validator
let config = ShieldConfig::for_chain(ChainId::Arbitrum);
let shield = TrinityShield::new(config)?;

// Process incoming request
let validated = shield.process_request(&request_bytes, &source)?;

// Sign a consensus vote
let signed_vote = shield.sign_vote(&operation)?;

// Generate attestation for on-chain verification
let attestation = shield.generate_attestation()?;
```

## Security Model

Trinity Shield operates on a **zero-trust** model:

1. **Defense in Depth**: Three independent security layers
2. **Hardware Isolation**: Keys sealed to SGX enclave
3. **Fail-Secure**: All failures default to rejection
4. **Audit Trail**: All operations logged (without sensitive data)
5. **Quantum Resistance**: TON chain uses ML-KEM-1024 and Dilithium-5

## Lean Proof Integration

Trinity Shield's consensus rules are formally verified using Lean 4:

- 58 of 78 theorems proven (74% complete)
- Operation validation rules match Lean specifications
- Continuous verification in CI pipeline

See [TRINITY_SHIELD_LEAN_INTEGRATION.md](docs/TRINITY_SHIELD_LEAN_INTEGRATION.md) for details.

## Benchmarks

Run benchmarks:
```bash
cargo bench --features std
```

Expected performance on modern hardware:
- SHA-256 (1KB): ~150 MB/s
- AES-256-GCM (1KB): ~1 GB/s (with AES-NI)
- Rate limiter check: ~5M ops/sec
- Signature verification: ~15K ops/sec

## Testing

```bash
# Unit tests
cargo test

# With coverage
cargo tarpaulin --out Html
```

## License

MIT License - See [LICENSE](LICENSE)

## Links

- Website: https://chronosvault.org
- Documentation: https://docs.chronosvault.org
- GitHub: https://github.com/Chronos-Vault/trinity-shield
- Contact: chronosvault@chronosvault.org

---

*Trinity Shield™ is part of the Trinity Protocol by ChronosVault.*
