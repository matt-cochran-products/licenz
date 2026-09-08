# Security model (licenz-core)

This document describes **what this crate implements today**. Integrator-owned controls (passphrase policy, TLS pinning, TPM extensions) are in [IMPLEMENTATION_FMECA.md](IMPLEMENTATION_FMECA.md).

## Scope and trust boundaries

| In scope (this crate) | Out of scope |
| ----------------------- | ------------ |
| RSA / Ed25519 / ML-DSA-65 license signatures (per build features) | Policy: whether to allow use when attestation shows anomalies |
| Hardware binding comparison vs [`HardwareInfo`](src/hardware.rs) | TPM PCR quotes, measured boot, remote attestation verification |
| [`LicenseState`](src/anti_tamper.rs) HMAC at rest (32-byte app secret) | Where the integrator stores that secret |
| Encrypted private-key backup: Argon2id + AES-256-GCM, format **version 1** | User passphrase strength beyond minimum checks |
| Online client: HTTPS-only, JWS envelope, JWKS or PEM verifier key | API backend compromise, JWS signing key lifecycle |
| Strict online errors: transport / HTTP failure → `Err` (no silent `Unknown` from network) | Corporate TLS inspection (see IMPLEMENTATION_FMECA) |

## Deliberate choice: OS-visible binding by default

Default binding uses **MAC addresses, disk identifiers, hostname, machine id** exposed by the OS. This is **not** TPM-backed attestation.

**Why:** portable installs without a TPM stack, predictable CI, and support for VMs/containers where TPM semantics vary.

**Residual:** a motivated local attacker can often spoof OS-visible IDs more easily than forging a verified TPM quote. **Remediation:** implement [`HardwareEnvironment`](src/hardware.rs) in your application or a companion crate (e.g. populate `HardwareBinding.custom` from TPM or enclave material) and enforce it at issuance and verification. See [IMPLEMENTATION_FMECA.md](IMPLEMENTATION_FMECA.md) (rows **HB-***).

## Normative controls

### Signatures and license formats

- Licenses are validated with the configured public key material; algorithm is selected from the license payload (`CryptoVerifier` / `LicenseVerifier`).

### Hardware binding

- [`LicenseVerifier`](src/verifier.rs) / [`CryptoVerifier`](src/verifier.rs) call [`HardwareEnvironment::snapshot`](src/hardware.rs).
- Default: [`DefaultHardwareEnvironment`](src/hardware.rs) → [`detect_hardware`](src/hardware.rs).
- Override: [`with_hardware_environment`](src/verifier.rs) or [`with_hardware_info`](src/verifier.rs).

### Persistent state

- [`LicenseState::save`](src/anti_tamper.rs) / [`LicenseState::load`](src/anti_tamper.rs) require a **32-byte HMAC key**; files use the `hmac1:` line format only.

### Encrypted key backup

- [`EncryptedKeyStore`](src/encrypted_store.rs): **version byte 1**, Argon2id KDF, AES-256-GCM. Other versions are rejected.

### Private-key file export and restoration

- Both key-pair exporters and encrypted-backup restoration create a fresh private file before writing, then atomically replace the destination. On Unix the file is mode **0600 from creation**. Existing symlinks are replaced, not followed; existing hard links and open descriptors retain the old contents. Public-key export failure does not expose the private key.
- Callers must control the destination directory. On non-Unix platforms, configure a private directory ACL; file mode bits are not an ACL substitute. Atomic replacement requires write access to the directory even when replacing an existing file.

### Support-bundle encryption migration (0.4.0)

Encrypted support bundles now require a **random 32-byte secret key** supplied by the caller. Hardware fingerprints are public identifiers and must never be used as encryption keys. `SupportBundle::generate_encryption_key()` uses the operating-system RNG; generate a fresh key for each support exchange and protect it with the application's secret storage.

```rust,no_run
use licenz_core::support_bundle::SupportBundle;
use std::path::Path;
use zeroize::Zeroizing;

let key = Zeroizing::new(SupportBundle::generate_encryption_key());
let bundle = SupportBundle::generate();
bundle.save_encrypted(Path::new("support.lsbx"), &key)?;
// Deliver the file to support. Share `key` separately over an authenticated,
// confidential channel, never in the bundle, metadata, logs or public tickets.
// The recipient retrieves that same secret from their protected channel:
let received = SupportBundle::load_encrypted(Path::new("support.lsbx"), &key)?;
# Ok::<(), licenz_core::error::LicenseError>(())
```

The binary envelope is `LSBX || 0x02 || nonce[12] || AES-256-GCM(ciphertext || tag[16])`. The first five bytes are authenticated additional data. The decrypted JSON retains its independent version **1**. `encrypt`, `decrypt`, and `save_encrypted` now require the key argument; `load` accepts plaintext JSON only and directs encrypted callers to `load_encrypted(path, key)`. Importing ciphertext never silently falls back to plaintext.

Legacy encrypted envelope **v1 is rejected**, including on the originating machine. Its hardware-derived encryption did not provide confidentiality. Regenerate diagnostic bundles using v2; updating software cannot retroactively protect copies already shared. There is no automatic legacy decrypt or key derivation fallback.

### Offline activation input limits

Request and response imports bound reads before allocating complete files. Text input has an outer budget covering Base64, CRLF line wrapping and markers; whitespace counts toward that budget. Normalized Base64 and decoded bytes have separate bounds. Binary frames accept at most two MiB of JSON and reject trailing bytes. Exports reject JSON beyond the same payload budget so successful exports remain importable. Existing valid binary and wrapped/plain Base64 formats remain supported.

### Online revocation and sync

- [`OnlineCheckConfig`](src/online_check/mod.rs): `server_url` **must** start with `https://`; empty API keys rejected.
- Exactly **one** of `jwks_url` or `jws_verifying_key_pem` must be set (XOR).
- Successful HTTP responses must be JSON `{"jws":"<compact-JWS>"}`. Payloads verify as **RS256**, **PS256**, or **EdDSA**. JWKS path requires `kid` on the JWS header.
- JWS `exp` claim is **always validated** (prevents indefinitely-valid responses). `aud` is validated when `expected_audience` is configured.
- [`check_revocation_batch`](src/online_check/mod.rs): network failure or non-success HTTP → **`Err`**. [`RevocationStatus::Unknown`](src/online_check/mod.rs) applies only after successful JWS verification when the server's status string is unrecognized.
- [`sync_report`](src/online_check/mod.rs): same JWS envelope; claims deserialize to [`SyncResponse`](src/online_check/mod.rs).

### Admin unlock

- [`generate_challenge_from_state`](src/unlock.rs) persists an HMAC-protected `PendingChallenge` (nonce, timestamp, unlock type, fingerprint hash) as a one-time token.
- [`validate_response_code`](src/unlock.rs) loads and **deletes** the pending challenge (replay prevention), reconstructs the signed message, and verifies the signature using `CryptoRegistry` (RSA-SHA256 or Ed25519).
- Response format: `[timestamp(8)] || [unlock_type(1)] || [signature(variable)]`.

The issuer can use `unlock::sign_unlock_response` to produce the full signed payload. The issuer must authenticate and authorize the requester before signing; the helper receives the nonce and fingerprint from the client's persisted challenge. Legacy compact hash codes are not signatures and are not accepted. CLI transport prefixes the hexadecimal encoding of the complete payload with `hex:`; the verifying public key and algorithm are independently configured, never accepted from that payload.

### Feature flags

| Flag | Gated modules / deps |
|------|---------------------|
| `hardware-detect` (default) | `sysinfo`, `mac_address`, `hostname` — OS-visible probes in `detect_hardware()` |
| `online-check` | `reqwest`, `jsonwebtoken` — `online_check` module |
| `cloud-metadata` | `url` — cloud instance-ID detection |
| `post-quantum` | `ml-dsa` (FIPS 204), `ml-kem` (FIPS 203) — ML-DSA-65 / ML-KEM-768 algorithms and hybrid modes |

### Security witness

- [`WitnessConfig`](src/witness.rs): if `check_clock` or `check_state_files` is **true**, `state_integrity_key` **must** be `Some`. Defaults keep both checks **off** so simple examples run without a key; enable them in production with a stable per-installation secret.

## Provider API contract (HTTP)

**Revocation (batch)** — POST `…/api/v1/licenses/check-revocation`  
Response body:

```json
{ "jws": "<compact-JWS>" }
```

JWS payload JSON (claims) matches [`CheckRevocationResponse`](src/online_check/mod.rs): `results[]` with `serial`, `status`, optional `revoked_at`, and `checked_at`.

**Sync** — POST `…/api/v1/licenses/sync`  
Response body: same `jws` wrapper; claims match [`SyncResponse`](src/online_check/mod.rs): `status`, optional `message`, `server_time`.

## References

- Integrator checklist and FMECA-style tables: [IMPLEMENTATION_FMECA.md](IMPLEMENTATION_FMECA.md)
