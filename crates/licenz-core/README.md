# licenz-core

Core library for the Licenz system. Provides license generation and verification capabilities.

## Features

- **RSA-SHA256 Digital Signatures**
- **Hardware Binding** (MAC, hostname, disk ID)
- **Binary and JSON license formats**
- **Offline verification**

## Usage

### Generate and Verify

```rust
use licenz_core::{
    KeyPair, KeySize, LicenseGenerator, LicenseVerifier, LicenseData
};

// Generate keys
let keypair = KeyPair::generate(KeySize::Bits2048)?;

// Create license
let generator = LicenseGenerator::new(keypair.private_key);
let license = LicenseData::builder()
    .id("LIC-001")
    .serial("SN-12345")
    .customer_id("ACME")
    .product_id("MyApp")
    .valid_days(365)
    .feature("premium")
    .build()?;

let signed = generator.generate(license)?;
generator.save_binary(&signed, "license.lic".as_ref())?;

// Verify license
let verifier = LicenseVerifier::new(keypair.public_key);
verifier.load_and_validate("license.lic".as_ref())?;
```

## Feature Flags

- `hardware-binding` (default) - Hardware detection for license binding
- `verify-only` - Minimal build with only verification code
- `generate` - Include generation capabilities

## License

MIT
