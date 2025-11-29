---
title: "Building Trinity Shield: Our Custom TEE Solution for Multi-Chain Security"
published: true
description: "A deep dive into how we built Trinity Shield - the Layer 8 hardware security that connects our Rust enclaves to Solidity smart contracts for vault and HTLC protection."
tags: rust, blockchain, security, solidity
series: trinity-protocol
---

# Building Trinity Shield: Layer 8 Hardware Security

*Part 2 of our Trinity Protocol series - How we connected Rust TEE enclaves to Solidity contracts*

---

In our [previous post](https://dev.to/chronosvault), we introduced Trinity Protocol's 2-of-3 consensus model. Today, we're diving deep into **Trinity Shield** - the Layer 8 hardware security component we just finished building.

## Why We Built Our Own TEE Solution

We evaluated existing options:
- **Oasis ROFL** - Great, but too generic for our needs
- **Phala Network** - Good TEE solution, but different trust model
- **Cloud TEEs** - Vendor lock-in concerns

Our requirements were specific:
1. **Lean proof integration** - Enclave code must match formally verified specs
2. **Multi-TEE support** - Intel SGX for speed, AMD SEV for quantum resistance
3. **Custom attestation** - Report data must bind to our Solidity contracts
4. **Three independent chains** - Arbitrum, Solana, TON validators

So we built **Trinity Shield** from scratch in Rust.

---

## The Architecture We Built

```
┌─────────────────────────────────────────────────────────────────┐
│                    TRINITY SHIELD (RUST)                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              PERIMETER SHIELD                            │   │
│  │  Rate limiting │ DDoS protection │ IP filtering          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           │                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │             APPLICATION SHIELD                           │   │
│  │  Multi-chain auth │ Lean validation │ Vote signing       │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           │                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                DATA SHIELD                               │   │
│  │  AES-256-GCM │ Hardware sealing │ ML-KEM-1024            │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           │                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              HARDWARE ENCLAVE                            │   │
│  │                                                          │   │
│  │   Intel SGX          │      AMD SEV-SNP                  │   │
│  │   ─────────          │      ────────────                 │   │
│  │   Arbitrum validator │      TON validator                │   │
│  │   Solana validator   │      Quantum-resistant            │   │
│  │   Ed25519/Secp256k1  │      Dilithium-5 signatures       │   │
│  │                                                          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Component #1: The IPC Bridge

The biggest challenge was connecting the Rust enclave to our TypeScript relayer. We built a Unix socket IPC server:

```rust
// trinity-shield/src/ipc.rs

pub const SOCKET_PATH: &str = "/run/trinity-shield.sock";

#[derive(Serialize, Deserialize)]
pub struct IpcRequest {
    pub method: String,      // "sign_vote", "generate_attestation", etc.
    pub params: Value,       // JSON parameters
    pub id: u64,             // Request correlation
}

impl IpcServer {
    pub async fn start(self) -> ShieldResult<()> {
        let listener = UnixListener::bind(SOCKET_PATH)?;
        
        loop {
            let (stream, _) = listener.accept().await?;
            // Handle JSON-RPC style requests
            let response = self.handle_request(&request);
            stream.write_all(&response)?;
        }
    }
}
```

The TypeScript relayer connects to the enclave:

```typescript
// trinity-shield/scripts/ipc-client.ts

export class TrinityShieldClient {
  async signVote(request: SignVoteRequest): Promise<SignedVote> {
    return this.sendRequest<SignedVote>('sign_vote', request);
  }
  
  async generateAttestation(): Promise<AttestationReport> {
    return this.sendRequest<AttestationReport>('generate_attestation');
  }
}
```

---

## Key Component #2: Solidity Contract Integration

The critical insight: **the attestation report data must exactly match what the Solidity contract expects**.

Our TrinityShieldVerifierV2.sol checks:

```solidity
function submitSGXAttestation(
    address validator,
    bytes32 quoteHash,
    bytes32 mrenclave,
    bytes32 reportData,
    uint256 timestamp,
    bytes calldata relayerSignature
) external {
    // CRITICAL: Report data must contain validator address
    require(
        bytes32(uint256(uint160(validator))) == reportData,
        "Report data mismatch"
    );
    
    // Verify enclave code is approved
    require(approvedMrenclave[mrenclave], "MRENCLAVE not approved");
    
    // Record valid attestation
    validatorAttestations[validator] = Attestation({
        teeType: TEEType.SGX,
        isValid: true,
        attestedAt: block.timestamp,
        measurement: mrenclave
    });
}
```

So our Rust code must produce matching output:

```rust
// trinity-shield/src/types.rs

impl AttestationQuote {
    /// Create report data matching Solidity's expected format
    pub fn create_report_data(
        validator_address: [u8; 20], 
        chain_id: u8, 
        nonce: u64
    ) -> [u8; 64] {
        let mut data = [0u8; 64];
        
        // Solidity: bytes32(uint256(uint160(validator)))
        // = address right-padded to 32 bytes
        data[12..32].copy_from_slice(&validator_address);
        
        // Additional binding data
        data[32] = chain_id;
        data[33..41].copy_from_slice(&nonce.to_le_bytes());
        
        data
    }
}
```

This binding is what makes the whole system trustworthy - the hardware attestation cryptographically commits to the validator's Ethereum address.

---

## Key Component #3: Quantum-Resistant Signatures (TON)

TON serves as our recovery chain with a 48-hour delay. In a post-quantum future, an attacker could:

1. See a transaction on Arbitrum
2. Break the classical signature with a quantum computer
3. Front-run the recovery on TON

Our solution: **CRYSTALS-Dilithium-5** for TON validator signatures:

```rust
// trinity-shield/src/quantum.rs

/// NIST Level 5 security (equivalent to AES-256)
pub const DILITHIUM_SIG_SIZE: usize = 4627;
pub const DILITHIUM_PK_SIZE: usize = 2592;

pub struct QuantumSigner {
    public_key: DilithiumPublicKey,
    secret_key: DilithiumSecretKey,  // Zeroized on drop!
}

impl QuantumSigner {
    pub fn sign(&self, message: &[u8]) -> ShieldResult<Signature> {
        let sig = dilithium5::detached_sign(message, &self.secret_key);
        Ok(Signature::Dilithium(sig.as_bytes().to_vec()))
    }
}
```

We also added **ML-KEM-1024** for key encapsulation:

```rust
pub struct QuantumKeyExchange {
    public_key: MlKemPublicKey,
    secret_key: MlKemSecretKey,
}

impl QuantumKeyExchange {
    pub fn encapsulate(&self, peer_pk: &MlKemPublicKey) 
        -> ShieldResult<(Vec<u8>, [u8; 32])> 
    {
        let (shared_secret, ciphertext) = kyber1024::encapsulate(&peer_pk);
        Ok((ciphertext, shared_secret))
    }
}
```

---

## The Complete Flow

Here's how it all connects:

```
┌─────────┐                                              
│  User   │ 1. createHTLC() / vault operation            
└────┬────┘                                              
     │                                                   
     ▼                                                   
┌────────────────────────────┐                           
│ TrinityConsensusVerifier   │ On-chain operation created
│ (Arbitrum Sepolia)         │                           
└────────────────────────────┘                           
     │                                                   
     │ Event: OperationCreated                           
     │                                                   
     ├─────────────────┬─────────────────┐               
     ▼                 ▼                 ▼               
┌─────────┐      ┌─────────┐      ┌─────────┐           
│Arbitrum │      │ Solana  │      │   TON   │           
│ Relayer │      │ Relayer │      │ Relayer │           
└────┬────┘      └────┬────┘      └────┬────┘           
     │                │                │                 
     │ IPC: /run/trinity-shield.sock                    
     ▼                ▼                ▼                 
┌─────────┐      ┌─────────┐      ┌─────────┐           
│  SGX    │      │  SGX    │      │  SEV    │           
│ Enclave │      │ Enclave │      │ Enclave │           
└────┬────┘      └────┬────┘      └────┬────┘           
     │                │                │                 
     │ 2. Validate against Lean proofs                  
     │ 3. Sign vote with enclave key                    
     │ 4. Generate hardware attestation                 
     │                │                │                 
     ▼                ▼                ▼                 
┌─────────────────────────────────────────────┐         
│          TrinityShieldVerifierV2            │         
│  submitSGXAttestation() / submitSEVAttest() │         
└─────────────────────────────────────────────┘         
                      │                                  
                      ▼                                  
┌─────────────────────────────────────────────┐         
│          TrinityConsensusVerifier           │         
│  submitArbitrumProof()                      │         
│  submitSolanaProof()                        │         
│  submitTONProof()                           │         
└─────────────────────────────────────────────┘         
                      │                                  
                      │ 5. Check: chainConfirmations >= 2
                      ▼                                  
┌─────────────────────────────────────────────┐         
│            _executeOperation()              │         
│  Vault withdrawal / HTLC claim / Transfer   │         
└─────────────────────────────────────────────┘         
```

---

## How HTLC Uses Trinity Consensus

Our `HTLCChronosBridge.sol` creates operations that require 2-of-3 validator approval:

```solidity
function createHTLC(
    address recipient,
    address tokenAddress,
    uint256 amount,
    bytes32 secretHash,
    uint256 timelock,
    bytes32 destChain
) external payable returns (bytes32 swapId, bytes32 operationId) {
    
    // Standard HTLC validation...
    require(amount >= MIN_HTLC_AMOUNT, "Amount below minimum");
    require(timelock >= block.timestamp + MIN_TIMELOCK, "Timelock too short");
    
    // CREATE TRINITY OPERATION
    // This is where Layer 8 kicks in!
    operationId = trinityBridge.createOperation{value: TRINITY_FEE}(
        address(this),
        ITrinityConsensusVerifier.OperationType.TRANSFER,
        amount,
        IERC20(tokenAddress),
        timelock
    );
    
    // Store HTLC data linked to Trinity operation
    htlcSwaps[swapId] = HTLCSwap({
        sender: msg.sender,
        recipient: recipient,
        amount: amount,
        secretHash: secretHash,
        timelock: timelock,
        state: HTLCState.PENDING,
        trinityOperationId: operationId  // <-- Link to consensus
    });
}
```

The claim function checks Trinity consensus before releasing funds:

```solidity
function claimHTLC(bytes32 swapId, bytes32 secret) external {
    HTLCSwap storage swap = htlcSwaps[swapId];
    
    // Standard HTLC checks
    require(swap.state == HTLCState.PENDING, "Invalid state");
    require(keccak256(abi.encodePacked(secret)) == swap.secretHash, "Wrong secret");
    require(block.timestamp <= swap.timelock, "HTLC expired");
    
    // TRINITY CONSENSUS CHECK
    (,, uint8 confirmations,,, bool executed) = 
        trinityBridge.getOperation(swap.trinityOperationId);
    
    require(confirmations >= 2, "Insufficient consensus");  // 2-of-3!
    require(!executed, "Already executed");
    
    // Release funds
    swap.state = HTLCState.CLAIMED;
    IERC20(swap.token).safeTransfer(swap.recipient, swap.amount);
}
```

---

## Deployed Contract Addresses

All contracts are live on **Arbitrum Sepolia** testnet:

| Contract | Address |
|----------|---------|
| TrinityConsensusVerifier | `0x59396D58Fa856025bD5249E342729d5550Be151C` |
| TrinityShieldVerifierV2 | `0xf111D291afdf8F0315306F3f652d66c5b061F4e3` |
| HTLCChronosBridge | `0xc0B9C6cfb6e39432977693d8f2EBd4F2B5f73824` |
| ChronosVaultOptimized | `0xAE408eC592f0f865bA0012C480E8867e12B4F32D` |

---

## Files We Built

**Trinity Shield (Rust TEE)** - [github.com/Chronos-Vault/trinity-shield](https://github.com/Chronos-Vault/trinity-shield)

```
trinity-shield/
├── Cargo.toml           # Quantum features, SGX SDK v2.x
├── src/
│   ├── lib.rs           # Main enclave orchestrator
│   ├── ipc.rs           # Unix socket server (NEW)
│   ├── quantum.rs       # Dilithium-5 + ML-KEM-1024 (NEW)
│   ├── error.rs         # Error types
│   ├── types.rs         # Report data binding
│   ├── perimeter.rs     # Rate limiting, DDoS
│   ├── application.rs   # Auth, validation
│   └── data.rs          # Encryption, sealing
└── scripts/
    ├── ipc-client.ts    # TypeScript IPC client (NEW)
    └── relayer-bridge.ts # Contract integration (NEW)
```

**Smart Contracts** - [github.com/Chronos-Vault/chronos-vault-contracts](https://github.com/Chronos-Vault/chronos-vault-contracts)

```
contracts/ethereum/
├── TrinityConsensusVerifier.sol   # 2-of-3 consensus
├── TrinityShieldVerifierV2.sol    # SGX + SEV attestation
├── HTLCChronosBridge.sol          # Atomic swaps
└── ChronosVaultOptimized.sol      # ERC-4626 vault
```

---

## What's Next

1. **Security Audit** - Professional review before mainnet
2. **Hardware Setup** - Intel SGX + AMD SEV servers
3. **Validator Onboarding** - Community operators
4. **Mainnet Deployment** - Arbitrum One, Solana, TON

---

## Try It Yourself

```bash
# Clone the repos
git clone https://github.com/Chronos-Vault/trinity-shield
git clone https://github.com/Chronos-Vault/chronos-vault-contracts

# Run Trinity Shield (simulation mode)
cd trinity-shield
cargo build --features simulation

# Test the contracts
cd ../chronos-vault-contracts
npm install
npx hardhat test
```

---

## The Tagline

> **"Mathematically Proven. Hardware Protected."**

We built Trinity Shield because security can't be an afterthought. Every vault operation, every HTLC swap, every cross-chain transfer now has 8 layers of defense - with hardware attestation proving the code running is exactly what we verified.

---

**Questions?** Drop a comment or reach out:
- Website: [chronosvault.org](https://chronosvault.org)
- Email: chronosvault@chronosvault.org
- GitHub: [github.com/Chronos-Vault](https://github.com/Chronos-Vault)

*What security model does your protocol use? Let us know in the comments!*
