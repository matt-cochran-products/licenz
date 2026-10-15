# Licenz (Open Source Library) - Gap Analysis

The open source `licenz` library serves as a transparency/trust mechanism, showing the verification mechanisms publicly so security teams can audit.

---

## Purpose

The OSS library should demonstrate:
- How hardware fingerprinting works
- How cryptographic verification works
- How time-tampering protection works
- That there's "no black box" in the client

**Not everything needs to be in OSS** - proprietary features can stay in licenz-saas.

---

## Current Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| Hardware Fingerprinting | Implemented | MAC, disk ID, hostname, machine ID with weighted scoring |
| RSA-SHA256 Signatures | Implemented | 2048/3072/4096-bit keys supported |
| Time-Tampering Protection | Implemented | Clock drift detection, encrypted state, multi-location storage |
| Security Witness Pattern | Implemented | Attestation-based (observe facts, don't enforce policy) |
| Encrypted State Storage | Implemented | AES-256-GCM with Argon2id key derivation |
| Container Detection | Implemented | Docker, K8s, AWS, GCP, Azure |
| Binary License Format | Implemented | Compact format with magic header |
| Feature Flags | Implemented | Configurable compilation |

---

## Gaps to Address

### High Priority

| Gap | Description | Rationale |
|-----|-------------|-----------|
| **Pluggable Crypto (Strategy Pattern)** | Configurable encryption/signing algorithms | Future-proof for quantum-resistant algorithms. Allow users to select RSA, Ed25519, or future algorithms |
| **Ed25519 Signatures** | Add Ed25519 as first alternative to RSA | Modern, faster, smaller signatures. First implementation of pluggable crypto |
| **Sneakernet File Format** | Document/implement .req/.resp file format | Critical for airgap activation workflow. Users need to understand how offline activation works |
| **Support Bundle Format** | Basic diagnostic export format | Show what data is collected for troubleshooting (not the decoder) |

### Medium Priority

| Gap | Description | Rationale |
|-----|-------------|-----------|
| **Example Implementation** | Reference implementation showing verification | Help users understand integration patterns |
| **Hardware Binding Documentation** | Detailed docs on fingerprinting algorithms | Security teams want to know exactly how binding works |
| **Time Validation Documentation** | Explain monotonic clock approach | Transparency on anti-tampering mechanisms |

### Future / Optional

| Gap | Description | Rationale |
|-----|-------------|-----------|
| **Post-Quantum Algorithms** | Dilithium3, Kyber via strategy pattern | NIST-approved PQC when mainstream adoption occurs |
| **TPM Integration** | Trusted Platform Module support | High-security environments may require this |
| **Custom Hardware Sources** | Extensible fingerprint sources | Allow users to add their own identifiers |

### Post-Quantum Roadmap (Future)
When quantum-resistant algorithms are needed:
1. **Dilithium3** - NIST-approved post-quantum signature (via `pqcrypto-dilithium`)
2. **Kyber** - Key encapsulation mechanism for hybrid encryption
3. **Hybrid modes** - RSA+Dilithium for transition period

The strategy pattern ensures these can be added without breaking existing licenses.

---

## What Should Stay Internal (licenz-saas only)

| Feature | Why Internal |
|---------|--------------|
| License Generation Logic | Signing keys should never be on client |
| Policy Enforcement Rules | Business logic, not verification mechanism |
| Support Bundle Decoder | Proprietary analysis tooling |
| Anomaly Detection Algorithms | Competitive advantage |
| Revocation Server Integration | SaaS service, not client concern |

---

## Recommended Actions

### 1. Implement Pluggable Crypto (Strategy Pattern)
**Location**: New `src/crypto/` module
- Define `SignatureAlgorithm` trait with `sign()` and `verify()` methods
- Define `EncryptionAlgorithm` trait for symmetric encryption
- Create implementations:
  - `RsaSha256Signer` (current algorithm)
  - `Ed25519Signer` (new)
  - Future: `Dilithium3Signer` (post-quantum)
  - Future: `Kyber` for key encapsulation (post-quantum)
- License format includes algorithm identifier
- Verifier auto-selects based on license metadata

```rust
// Example trait design
pub trait SignatureAlgorithm {
    fn algorithm_id(&self) -> &str;
    fn sign(&self, data: &[u8], private_key: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool>;
}

pub trait EncryptionAlgorithm {
    fn algorithm_id(&self) -> &str;
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>>;
}
```

### 2. Add Ed25519 Support (First Strategy Implementation)
**Location**: `src/crypto/ed25519.rs`
- Add `ed25519-dalek` crate
- Implement `SignatureAlgorithm` trait for Ed25519
- Smaller keys (32 bytes vs 2048+ bits for RSA)
- Faster signing and verification

### 3. Document Sneakernet Format
**Location**: New `src/sneakernet.rs` or documentation
- Define `.req` file format (hardware fingerprint + request metadata)
- Define `.resp` file format (signed license response)
- Provide examples of the workflow

### 4. Add Support Bundle Generation
**Location**: New `src/support_bundle.rs`
- Export hardware fingerprint
- Export clock state (sanitized)
- Export recent verification results
- Encrypted with a caller-supplied random secret key (v2); see SECURITY.md for migration

### 5. Enhance Documentation
**Location**: `README.md`, docs/
- Detailed hardware fingerprinting algorithm explanation
- Time-tampering protection mechanism
- Security model and threat coverage
- Integration examples
- Pluggable crypto architecture and extension guide

---

## Files to Modify

| File | Change |
|------|--------|
| `Cargo.toml` | Add `ed25519-dalek`, future: `pqcrypto-dilithium` |
| New: `src/crypto/mod.rs` | Pluggable crypto traits and registry |
| New: `src/crypto/rsa.rs` | RSA-SHA256 strategy (extract from current) |
| New: `src/crypto/ed25519.rs` | Ed25519 strategy implementation |
| `src/keys.rs` | Refactor to use crypto strategies |
| `src/verifier.rs` | Refactor to use crypto strategies |
| `src/license.rs` | Add algorithm identifier field |
| `src/lib.rs` | Export new modules |
| New: `src/sneakernet.rs` | Request/response file handling |
| New: `src/support_bundle.rs` | Diagnostic export |
| `README.md` | Enhanced documentation + crypto extension guide |
