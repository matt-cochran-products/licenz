# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-05-18

### Fixed

- **Custom hardware binding keys silently ignored** — `verify_hardware_binding()` now checks all keys in `HardwareBinding.custom`, not just `machine_id`. Unrecognised keys previously passed silently; they now fail with `CustomMismatch`.
- **Missing `machine_id` silently passed** — When a license requires `machine_id` but the host cannot detect one, verification now fails instead of silently passing.
- **`SecurityWitness` only supported RSA** — `SecurityWitness::new()` now auto-detects Ed25519 (and post-quantum) keys via `CryptoVerifier`. New constructors: `from_crypto_verifier()`, `from_legacy_verifier()`, `from_pem_file()`.
- **Witness `is_valid` accepted partial hardware matches** — `is_valid` now requires all binding factors to match (`unmatched_factors.is_empty()`), consistent with `verify_hardware_binding()`.
- **Non-deterministic JSON serialization** — `LicenseData.metadata` and `HardwareBinding.custom` changed from `HashMap` to `BTreeMap` for stable key ordering across processes.
- **No license file size limit** — `load_license()` now rejects files larger than 1 MiB (`MAX_LICENSE_FILE_SIZE`) before reading into memory.

### Added

- `HardwareInfo.custom` field (`BTreeMap<String, String>`) for integrator-supplied hardware identifiers (TPM, dongles, etc.)
- `WitnessVerifier` internal enum supporting both `LicenseVerifier` (RSA) and `CryptoVerifier` (multi-algorithm)
- `MAX_LICENSE_FILE_SIZE` public constant (re-exported from `verifier`)
- 49 new unit tests covering all fixed behaviours, edge cases, and regression paths (163 total)

### Breaking Changes

- `LicenseData.metadata` type changed from `HashMap<String, String>` to `BTreeMap<String, String>`
- `HardwareBinding.custom` type changed from `HashMap<String, Vec<String>>` to `BTreeMap<String, Vec<String>>`
- Custom hardware binding keys that were previously ignored are now enforced — licenses relying on the old silent-pass behaviour will be rejected

## [0.2.0] - 2026-04-14

Initial public release.

### Features

- **Offline Verification** — RSA-SHA256 / Ed25519 license signatures, no server required
- **Hardware Binding** — MAC address, hostname, disk ID, machine ID fingerprinting
- **Anti-Tamper Detection** — Clock manipulation, state file integrity (HMAC)
- **Security Witness Pattern** — Attestation-only design; reports facts, your app decides policy
- **Expiration Management** — Automatic expiration checking with grace periods
- **Environment Detection** — VM, container, cloud provider awareness
- **Encrypted Key Store** — Argon2id + AES-256-GCM private key backup
- **Admin Unlock** — Challenge-response with real signature verification and replay prevention
- **Sneakernet Activation** — Offline activation via portable request/response files

### Optional Features

- `hardware-detect` (default) — OS-visible hardware probes via `sysinfo`, `mac_address`, `hostname`
- `online-check` — Online revocation checking and license sync (reqwest + JWS verification with `exp`/`aud` validation)
- `cloud-metadata` — Cloud instance-ID detection (AWS, GCP, Azure)
- `post-quantum` — ML-DSA-65 (FIPS 204) and ML-KEM-768 (FIPS 203) signatures and hybrid modes

### Security

- RSA default key size is 3072 bits
- Private key fields are encapsulated (accessor methods only)
- Private key material uses `Zeroizing<String>` (cleared on drop)
- Private key file permissions checked on load (Unix: errors if group/other readable)
- JWS `exp` claim always validated; `aud` validated when configured
- Sneakernet checksums use `BTreeMap` for deterministic computation
- `HardwareBindingMismatch` errors do not leak expected/actual values

[Unreleased]: https://github.com/matt-cochran/licenz/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/matt-cochran/licenz/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/matt-cochran/licenz/releases/tag/v0.2.0
