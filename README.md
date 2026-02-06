# licenz

[![Crates.io](https://img.shields.io/crates/v/licenz-core.svg)](https://crates.io/crates/licenz-core)
[![Documentation](https://docs.rs/licenz-core/badge.svg)](https://docs.rs/licenz-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Offline software license verification for Rust.**

Cryptographically signed licenses that work without a server. Verify licenses offline, bind to hardware, detect tampering.

```rust
use licenz_core::{SecurityWitness, WitnessConfig};

const PUBLIC_KEY: &str = include_str!("keys/public.pem");

fn main() -> anyhow::Result<()> {
    let witness = SecurityWitness::new(PUBLIC_KEY)?;
    let attestation = witness.attest("license.lic", &WitnessConfig::default())?;

    if !attestation.is_valid {
        eprintln!("License invalid: {:?}", attestation.signature_error);
        std::process::exit(1);
    }

    println!("Licensed to: {}", attestation.expiration.days_remaining);
    Ok(())
}
```

## Features

- **Offline Verification** - No server required, works air-gapped
- **RSA-SHA256 Signatures** - Cryptographically signed, tamper-proof
- **Hardware Binding** - Tie licenses to MAC address, hostname, disk ID
- **Expiration Management** - Automatic expiration checking
- **Anti-Tamper Detection** - Clock manipulation, state file tampering
- **Environment Detection** - VM, container, cloud provider awareness
- **Security Witness Pattern** - Clean separation of attestation and enforcement

## Installation

```toml
[dependencies]
licenz-core = "0.1"
```

## Architecture: Security Witness Pattern

This library follows the **Security Witness Pattern**, separating:

| Layer | Responsibility | This Crate |
|-------|----------------|------------|
| **Attestation** | Observe, measure, report facts | Yes |
| **Enforcement** | Decide, act on attestations | Your app / licenz-policy |

The library tells you *what it observes*. Your application decides *what to do about it*.

```rust
let attestation = witness.attest("license.lic", &config)?;

// Attestation provides facts:
println!("Signature valid: {}", attestation.signature_valid);
println!("Days remaining: {}", attestation.expiration.days_remaining);
println!("Hardware match: {:?}%", attestation.hardware.match_percentage);
println!("Anomalies: {:?}", attestation.anomalies);

// Your app decides the response:
if !attestation.is_valid {
    // Exit? Degrade? Warn? Your choice.
}
```

## Quick Start

> **Most users should use [licenz-cli](https://github.com/outboundlabs/licenz-cli-release)** for key generation and license creation. The examples below show the Rust API for programmatic use cases (e.g. building your own license server).

### Generate Keys (one-time setup)

```rust
use licenz_core::{KeyPair, KeySize};

let keypair = KeyPair::generate(KeySize::Bits2048)?;
keypair.save_to_files("private.pem", "public.pem")?;
```

### Create a License (your license server)

```rust
use licenz_core::{LicenseGenerator, LicenseData, KeyPair};

let keypair = KeyPair::load_from_files("private.pem", "public.pem")?;
let generator = LicenseGenerator::new(keypair.private_key);

let license = LicenseData::builder()
    .id("LIC-001")
    .serial("SN-12345")
    .customer_id("ACME Corp")
    .product_id("MyApp")
    .valid_days(365)
    .feature("basic")
    .feature("premium")
    .mac_address("AA:BB:CC:DD:EE:FF")  // Optional hardware binding
    .build()?;

let signed = generator.generate(license)?;
generator.save_binary(&signed, "license.lic")?;
```

### Verify a License (your application)

```rust
use licenz_core::{SecurityWitness, WitnessConfig};

const PUBLIC_KEY: &str = include_str!("public.pem");

fn main() -> anyhow::Result<()> {
    let witness = SecurityWitness::new(PUBLIC_KEY)?;
    let attestation = witness.attest("license.lic", &WitnessConfig::default())?;

    if !attestation.is_valid {
        eprintln!("License validation failed");
        if let Some(err) = &attestation.signature_error {
            eprintln!("  Signature: {}", err);
        }
        if let Some(issue) = &attestation.expiration.issue {
            eprintln!("  Expiration: {:?}", issue);
        }
        std::process::exit(1);
    }

    // Check specific features
    // (You'll need to load the license data separately for feature checks)
    let verifier = licenz_core::LicenseVerifier::from_pem(PUBLIC_KEY)?;
    let license = verifier.load_and_validate("license.lic")?;

    if license.data.has_feature("premium") {
        println!("Premium features enabled!");
    }

    Ok(())
}
```

## Feature Flags

| Flag | Description | Default |
|------|-------------|---------|
| `cloud-metadata` | Cloud container detection (AWS, GCP, Azure) | |
| `post-quantum` | Post-quantum cryptography (Dilithium3, Kyber768) | |

```toml
# Standard usage (includes hardware binding, online validation, all crypto)
licenz-core = "0.1"

# With post-quantum cryptography
licenz-core = { version = "0.1", features = ["post-quantum"] }
```

## Security Model

### What This Library Provides

- **Cryptographic verification** - RSA-2048/3072/4096 signatures
- **Tamper detection** - Clock manipulation, state file integrity
- **Hardware fingerprinting** - Multi-factor hardware binding
- **Attestation** - Detailed observations about license state

### What This Library Does NOT Provide

- **Obfuscation** - Code is open source and auditable
- **Anti-debugging** - No runtime protection
- **Enforcement** - Library reports facts, doesn't make decisions

For enforcement (exit on failure, configurable thresholds, etc.), use the `licenz-policy` crate or implement your own policy layer.

### Threat Model

This library is designed for **honest customers in controlled environments**, not adversarial reverse engineering. It prevents:

- Casual copying of license files
- Clock manipulation to extend expiration
- License sharing across machines (via hardware binding)
- Accidental use of expired licenses

It does NOT prevent:

- Determined attackers with debuggers
- Binary patching
- Memory manipulation

For high-security needs, combine with code signing, integrity checking, and server-side validation.

## Used By

- [graxon.ai](https://graxon.ai) - Air-gapped workflow engine
- [cctx.ai](https://cctx.ai) - Coding utility MCP toolset

## Use Cases

- **Desktop Software** - Applications that need to work offline
- **On-Premise Deployments** - Enterprise software behind firewalls
- **Air-Gapped Environments** - Defense, manufacturing, healthcare
- **Embedded Systems** - IoT devices without reliable connectivity
- **Developer Tools** - CLI tools, IDE plugins, build tools

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

This crate is the open-source, auditable verification layer of the [licenz.dev](https://licenz.dev) platform. It's published as source so customers and security teams can inspect the attestation logic. Bug fixes and improvements are welcome, but the scope is intentionally narrow — attestation only, no enforcement.

## Related

- [licenz-cli](https://github.com/outboundlabs/licenz-cli-release) - CLI tool for key generation, license creation, and management (free, closed source)
- [licenz-policy](https://github.com/outboundlabs/licenz-saas) - Policy enforcement layer (closed source)
- [licenz.dev](https://licenz.dev) - Managed license management platform
