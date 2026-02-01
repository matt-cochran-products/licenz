# 🔐 licenz

**Licenses that enforce themselves.**

Self-enforcing software licenses that work offline. No server. No phone home. Air-gap ready.

```bash
# Install
cargo install licenz-cli

# Generate keys
licenz keygen --output ./keys

# Create license
licenz generate \
  --key keys/private.pem \
  --customer "acme-corp" \
  --features premium,api \
  --credits api_calls:100000 \
  --days 365 \
  --output license.lic

# Validate (works offline)
licenz verify --key keys/public.pem --license license.lic
```

## Why licenz?

Traditional licensing: `License key → Call server → "Is it valid?"`

**licenz**: The license IS the contract. Everything—expiry, features, limits, usage—is cryptographically signed and embedded in the license file.

| Feature | licenz | Keygen.sh | Cryptlex |
|---------|--------|-----------|----------|
| **Offline validation** | ✅ Full | ✅ Full | ⚠️ Cached |
| **Offline usage tracking** | ✅ Yes | ❌ No | ❌ No |
| **Self-enforcing limits** | ✅ Yes | ❌ Server-side | ❌ Server-side |
| **Air-gap ready** | ✅ Full | ⚠️ Partial | ⚠️ Partial |
| **Open source** | ✅ MIT | ⚠️ Fair Source | ❌ No |
| **No server required** | ✅ Yes | ❌ No | ❌ No |
| **Price (no server)** | **Free** | N/A | N/A |

## Features

- 🔒 **Self-enforcing** - Expiry, features, limits embedded and signed
- 📊 **Usage tracking** - Tamper-proof receipts, cryptographic proofs
- 💰 **Prepaid credits** - Enforce offline, sync when convenient
- 🚦 **Rate limiting** - Throttle via metadata
- 📴 **Air-gap ready** - Works on submarines, aircraft, factory floors
- 🐳 **Runs anywhere** - Docker, Kubernetes, embedded, edge
- 🌐 **Any language** - Rust library + CLI for all other languages

## Quick Start

### Rust

```rust
use licenz_core::{require_license, ValidatedLicense};

const PUBLIC_KEY: &str = include_str!("../keys/public.pem");

fn main() {
    let license = require_license("license.lic", PUBLIC_KEY)
        .expect("Valid license required");
    
    if license.has_feature("premium") {
        enable_premium_features();
    }
}
```

### Other Languages (via CLI)

```python
# Python
import subprocess
subprocess.run(['licenz', 'verify', '--key', 'keys/public.pem', '--license', 'license.lic'])
```

```javascript
// Node.js
const { execSync } = require('child_process');
execSync('licenz verify --key keys/public.pem --license license.lic');
```

See [Language Integration](docs/getting-started/language-integration.md) for detailed examples.

## Documentation

### Getting Started
- [Installation](docs/getting-started/installation.md)
- [Quick Start](docs/getting-started/quick-start.md)
- [Language Integration](docs/getting-started/language-integration.md)

### Guides
- [Hardware Binding](docs/guides/hardware-binding.md) - Tie licenses to specific machines
- [Usage Tracking](docs/guides/usage-tracking.md) - Track and enforce usage limits
- [Air-Gapped Deployment](docs/guides/air-gapped-deployment.md) - Deploy without internet
- [Docker & Kubernetes](docs/guides/docker-kubernetes.md) - Container deployments

### Reference
- [CLI Commands](docs/reference/cli-commands.md) - Complete CLI reference
- [Rust API](docs/reference/rust-api.md) - Library documentation
- [License Format](docs/reference/license-format.md) - Binary format specification

### FAQ
- [General Questions](docs/faq/general.md)
- [Usage Tracking](docs/faq/usage-tracking.md)
- [Security](docs/faq/security.md)
- [Deployment](docs/faq/deployment.md)
- [Troubleshooting](docs/faq/troubleshooting.md)

## Use Cases

- **Defense / Government** - Classified networks, air-gapped by law
- **Manufacturing** - Factory floor OT networks
- **Maritime** - Ships, oil rigs, submarines
- **Aviation** - Aircraft systems
- **Healthcare** - Medical devices, isolated networks
- **Desktop Software** - Apps that should work without internet

## Roadmap

- [x] Core Rust library with cryptographic validation
- [x] CLI tool for key generation, license creation, usage tracking
- [x] Offline usage tracking with hash-chained receipts
- [ ] Native language bindings (Python, Node.js, Go)
- [ ] Managed service (licenz.dev) with dashboard
- [ ] Payment provider webhooks (Stripe, Paddle, LemonSqueezy)

## Contributing

Contributions welcome! We'd love help with:
- Native language bindings
- Additional CLI features
- Documentation improvements
- Security audits
- Real-world testing in air-gapped environments

## License

MIT License - Use it however you want.

## Support

- 💬 [GitHub Discussions](https://github.com/licenz-dev/licenz/discussions)
- 🐛 [Issue Tracker](https://github.com/licenz-dev/licenz/issues)
- 📖 [Documentation](docs/)
