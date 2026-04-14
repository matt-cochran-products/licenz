# Implementation FMECA (integrators)

Use this checklist when **embedding `licenz-core`**. It complements [SECURITY.md](SECURITY.md), which describes **library behavior** only.

## Themes (summary)

| Theme | Failure modes → mitigations (owner) |
| ----- | ------------------------------------- |
| **Secrets** | API keys, HMAC state key, backup passphrase in repo → secret manager, build-time injection, no plaintext in VCS |
| **Passphrase & backups** | Weak passphrase, stolen backup file → org policy, offline storage, rotation, `validate_passphrase` hints |
| **TLS trust** | Corporate SSL inspection, user-installed rogue CA → certificate / SPKI pinning, custom `reqwest` TLS, or mTLS; not built into this crate |
| **Deployment** | Patched binary, debugger, rooted device → code signing, integrity monitoring, RASP (outside this crate) |
| **Server** | JWS signing key leak, bad JWKS rotation → HSM, monitoring, short-lived keys |
| **Strong device identity** | OS fingerprint too weak for threat model → custom [`HardwareEnvironment`](src/hardware.rs), TPM quote + **your** verifier, Nitro attestation, or TPM-backed mTLS |

## Hardware binding (fingerprint vs TPM)

| ID | Failure mode | Effect | Cause | Detection (typical) | Severity | Remediation |
| -- | ------------ | ------ | ----- | ------------------- | -------- | ----------- |
| HB-1 | Naive license sharing | License on wrong machine | Different MAC/disk/host | `verify_hardware` / witness | Low–Med | Default OS probe |
| HB-2 | Spoofed OS-visible IDs | Forged `HardwareInfo` passes | Admin hooks, VM config | Hard to distinguish from legit VM | Med–High | Custom [`HardwareEnvironment`](src/hardware.rs); TPM-derived values in `HardwareBinding.custom` + server-side quote verification |
| HB-3 | No boot-integrity proof | Modified stack undetected | No PCR policy | N/A in core | Med (model-dependent) | TPM quote + golden PCRs (**integrator**); optional `licenz-tpm`-style crate |

## Certificate pinning (when you need it)

**Pinning** means the client checks the server cert (or SPKI hash) against expected values, not only “any OS-trusted CA.” Use it when users may face **TLS interception** or **custom CAs**. This crate uses default TLS verification via `reqwest`; pinning is an **application** concern.

## Passphrase and encrypted backups

The crate enforces minimum length and KDF strength (Argon2id). **Entropy rules, rotation, and storage** of passphrases and backup media are **integrator** responsibilities.

## Suggested implementation order

1. Fix **secrets** and **HTTPS/JWS** config for online calls.  
2. Choose **state_integrity_key** storage (OS keychain, DPAPI, etc.).  
3. Decide if default **hardware** probe is enough; if not, ship **`HardwareEnvironment`**.  
4. Add **pinning** / **mTLS** only if your threat model requires it.
