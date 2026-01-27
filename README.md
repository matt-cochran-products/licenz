# 🔐 licenz

**Offline-first software license management for Rust.**

Self-hostable. No phone-home required. Works air-gapped.

```rust
const PUBLIC_KEY: &str = include_str!("../public.pem");

fn main() {
    let license = licenz::require_license("license.lic", PUBLIC_KEY)
        .expect("Valid license required");
    
    println!("Licensed to: {}", license.customer_id);
    
    if license.has_feature("premium") {
        enable_premium_features();
    }
}
```

## Why licenz?

| Feature | licenz | Keygen.sh | Cryptlex |
|---------|--------|-----------|----------|
| **Offline validation** | ✅ Full | Partial | ✅ Full |
| **Self-hostable** | ✅ Yes | ❌ No | ❌ No |
| **Open source** | ✅ MIT | ❌ No | ❌ No |
| **Rust-native** | ✅ Core | SDK only | ❌ No |
| **Price** | Free | $99+/mo | $49+/mo |

## Features

- 🔒 **RSA-SHA256 signatures** - Cryptographically secure, tamper-proof
- 💻 **Hardware binding** - Tie licenses to specific machines
- 📴 **Offline validation** - No internet required after activation
- ⏰ **Expiration management** - Time-limited licenses with grace periods
- 🎛️ **Feature flags** - `has_feature("premium")` for tiered licensing
- 🐳 **Container-aware** - Works in Docker, Kubernetes, cloud VMs
- 🔄 **Auto-renewal** - Short-lived licenses that refresh each billing cycle

## Quick Start

### Installation

```bash
cargo add licenz-core
```

### Generate Keys (once)

```bash
cargo install licenz-cli
licenz keygen --output ./keys
```

### Generate a License (server-side)

```rust
use licenz::{KeyPair, LicenseGenerator, LicenseData};

let keypair = KeyPair::from_pem_files("keys/private.pem", "keys/public.pem")?;
let generator = LicenseGenerator::new(keypair.private_key);

let license = LicenseData::builder()
    .id("LIC-001")
    .customer_id("customer@example.com")
    .product_id("my-app")
    .valid_days(35)
    .feature("basic")
    .feature("premium")
    .build()?;

let signed = generator.generate(license)?;
generator.save_binary(&signed, "license.lic")?;
```

### Verify a License (client-side)

```rust
use licenz::{require_license, ValidatedLicense};

// Embed public key at compile time
const PUBLIC_KEY: &str = include_str!("../keys/public.pem");

fn main() {
    let license = require_license("license.lic", PUBLIC_KEY)
        .expect("Valid license required");
    
    // Feature gating
    if license.has_feature("premium") {
        enable_premium();
    }
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         YOUR SETUP                               │
└─────────────────────────────────────────────────────────────────┘

  ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
  │   Stripe    │         │  Your       │         │  Customer   │
  │   Paddle    │────────▶│  License    │────────▶│  App        │
  │   etc.      │ webhook │  Server     │ license │  (offline)  │
  └─────────────┘         └─────────────┘         └─────────────┘
                                │                        │
                                │ signs with             │ verifies with
                                │ PRIVATE key            │ PUBLIC key
                                │                        │
                                ▼                        ▼
                          [private.pem]            [public.pem]
                          (keep secret!)           (embed in binary)
```

## Crates

| Crate | Description |
|-------|-------------|
| `licenz-core` | Core library - license generation & verification |
| `licenz-cli` | Command-line tool for key/license management |
| `licenz-server` | HTTP server with webhook handlers |

## Documentation

- [Fly.io Deployment Guide](docs/FLY_IO_DEPLOYMENT.md)
- [Hardware Binding](docs/HARDWARE_BINDING.md)
- [License Renewal](docs/LICENSE_RENEWAL.md)
- [Payment Provider Integration](docs/PAYMENT_ABSTRACTION.md)
- [Security Analysis (FMECA)](FMECA_ROUND_2.md)

## CLI Usage

```bash
# Generate key pair
licenz keygen --bits 2048 --output ./keys

# Generate license
licenz generate \
  --key keys/private.pem \
  --customer "user@example.com" \
  --product "my-app" \
  --features basic,premium \
  --days 365 \
  --output license.lic

# Verify license
licenz verify --key keys/public.pem --license license.lic

# Show license info
licenz info --license license.lic

# Get hardware fingerprint
licenz hardware
```

## HTTP Server

```bash
# Start server
licenz-server --private-key keys/private.pem --public-key keys/public.pem

# Or with environment variables
export LICENZ_PRIVATE_KEY="$(cat keys/private.pem)"
export LICENZ_PUBLIC_KEY="$(cat keys/public.pem)"
licenz-server
```

**Endpoints:**
- `GET /health` - Health check
- `POST /api/v1/licenses/generate` - Generate license
- `POST /api/v1/licenses/verify` - Verify license
- `POST /api/v1/licenses/refresh` - Refresh expiring license
- `POST /webhooks/stripe` - Stripe webhook handler
- `POST /webhooks/paddle` - Paddle webhook handler

## Hosted Version

Don't want to run your own server?

**[licenz.dev](https://licenz.dev)** - Hosted license management starting at $29/mo

- Dashboard UI
- Automatic Stripe/Paddle integration
- Email delivery
- Analytics
- No DevOps required

## Security

- Private keys never leave your server
- Public keys embedded in client binaries at compile time
- RSA-2048+ with SHA-256 signatures
- Hardware fingerprinting prevents license sharing
- Clock manipulation detection
- Binary format resists tampering

See [FMECA_ROUND_2.md](FMECA_ROUND_2.md) for detailed security analysis.

## License

MIT License - Use it however you want.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## Support

- 📖 [Documentation](https://licenz.dev/docs)
- 💬 [GitHub Discussions](https://github.com/yourorg/licenz/discussions)
- 🐛 [Issue Tracker](https://github.com/yourorg/licenz/issues)
- 📧 [Email Support](mailto:support@licenz.dev) (hosted customers)
