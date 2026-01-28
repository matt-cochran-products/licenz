# licenz Documentation

Complete documentation for licenz - self-enforcing offline software licenses.

## 📚 Table of Contents

### Getting Started

**New to licenz?** Start here:

1. **[Quick Start](getting-started/quick-start.md)** - Get up and running in 5 minutes
2. **[Installation](getting-started/installation.md)** - Install the CLI and library
3. **[Language Integration](getting-started/language-integration.md)** - Use with Python, Node.js, Go, etc.

### Core Concepts

Understand how licenz works:

- **[How It Works](concepts/how-it-works.md)** - Self-enforcing licenses explained
- **[License Structure](concepts/license-structure.md)** - What's in a license file
- **[Cryptographic Validation](concepts/cryptographic-validation.md)** - Signature verification
- **[Usage Tracking](concepts/usage-tracking.md)** - Hash chains and receipts

### Guides

Step-by-step tutorials for common tasks:

#### Basic Operations
- **[Generating Keys](guides/generating-keys.md)** - Create RSA key pairs
- **[Creating Licenses](guides/creating-licenses.md)** - Generate signed licenses
- **[Validating Licenses](guides/validating-licenses.md)** - Verify in your app

#### Advanced Features
- **[Hardware Binding](guides/hardware-binding.md)** - Tie licenses to specific machines
- **[Usage Limits & Credits](guides/usage-limits.md)** - Prepaid credits, quotas
- **[Rate Limiting](guides/rate-limiting.md)** - Throttle API calls
- **[Seat Management](guides/seat-management.md)** - Concurrent user limits
- **[Feature Flags](guides/feature-flags.md)** - Tiered licensing

#### Deployment
- **[Air-Gapped Environments](guides/air-gapped.md)** - Deploy without internet
- **[Docker & Kubernetes](guides/docker-kubernetes.md)** - Container deployments
- **[Embedded Systems](guides/embedded.md)** - IoT, edge devices
- **[Cloud Deployments](guides/cloud.md)** - AWS, GCP, Azure

#### Integration
- **[Stripe Integration](guides/stripe-integration.md)** - Webhook handling (requires server)
- **[Paddle Integration](guides/paddle-integration.md)** - Webhook handling (requires server)
- **[License Renewal](guides/license-renewal.md)** - Subscription workflows

### Reference

Complete API and CLI documentation:

#### CLI Reference
- **[CLI Commands](reference/cli-commands.md)** - All commands and options
- **[keygen](reference/cli/keygen.md)** - Generate key pairs
- **[generate](reference/cli/generate.md)** - Create licenses
- **[verify](reference/cli/verify.md)** - Validate licenses
- **[info](reference/cli/info.md)** - Inspect license details
- **[hardware](reference/cli/hardware.md)** - Get hardware fingerprint
- **[usage](reference/cli/usage.md)** - Track and manage usage

#### Library Reference
- **[Rust API](reference/rust-api.md)** - Complete library documentation
- **[LicenseData](reference/rust/license-data.md)** - License structure
- **[LicenseGenerator](reference/rust/generator.md)** - Creating licenses
- **[LicenseVerifier](reference/rust/verifier.md)** - Validating licenses
- **[Hardware Detection](reference/rust/hardware.md)** - Hardware binding
- **[Error Handling](reference/rust/errors.md)** - Error types

#### File Formats
- **[License File Format](reference/license-format.md)** - Binary format spec
- **[Usage Database Format](reference/usage-format.md)** - Local storage
- **[Key Formats](reference/key-formats.md)** - PEM, DER, PKCS#8

### FAQ

Quick answers to common questions:

- **[General](faq/general.md)** - What is licenz? Language support?
- **[Usage Tracking](faq/usage-tracking.md)** - Hash chains, credits, throttling
- **[Security](faq/security.md)** - Tampering, clock manipulation
- **[Deployment](faq/deployment.md)** - Docker, K8s, air-gapped
- **[Troubleshooting](faq/troubleshooting.md)** - Common errors and fixes

Or browse the **[complete FAQ](FAQ.md)** with all questions in one place.

### Examples

Real-world code examples:

- **[Rust Examples](../examples/rust_example.rs)** - Native library usage
- **[Python Examples](../examples/python_example.py)** - CLI integration
- **[Node.js Examples](../examples/node_example.js)** - CLI integration
- **[Shell Script Examples](../examples/api_example.sh)** - Bash integration

### Architecture

Deep dives into design decisions:

- **[Architecture Overview](architecture/overview.md)** - System design
- **[Cryptographic Design](architecture/cryptography.md)** - Signatures, hash chains
- **[Offline-First Design](architecture/offline-first.md)** - Why no server?
- **[Security Model](architecture/security.md)** - Threat model, mitigations
- **[Performance](architecture/performance.md)** - Benchmarks, optimization

## 🚀 Quick Links

**Just want to...**

- **Get started quickly?** → [Quick Start](getting-started/quick-start.md)
- **Integrate with Python/Node?** → [Language Integration](getting-started/language-integration.md)
- **Bind to hardware?** → [Hardware Binding](guides/hardware-binding.md)
- **Track usage offline?** → [Usage Limits](guides/usage-limits.md)
- **Deploy air-gapped?** → [Air-Gapped Guide](guides/air-gapped.md)
- **See all CLI commands?** → [CLI Reference](reference/cli-commands.md)
- **Understand how it works?** → [How It Works](concepts/how-it-works.md)

## 📖 Reading Paths

### For Developers Integrating licenz

1. [Quick Start](getting-started/quick-start.md) - Get it working
2. [Language Integration](getting-started/language-integration.md) - Your language
3. [Creating Licenses](guides/creating-licenses.md) - Generate licenses
4. [Validating Licenses](guides/validating-licenses.md) - Verify in your app
5. [FAQ](FAQ.md) - Common questions

### For Understanding the Architecture

1. [How It Works](concepts/how-it-works.md) - Core concepts
2. [Cryptographic Validation](concepts/cryptographic-validation.md) - Security
3. [Usage Tracking](concepts/usage-tracking.md) - Hash chains
4. [Architecture Overview](architecture/overview.md) - Design decisions
5. [Security Model](architecture/security.md) - Threat model

### For Air-Gapped Deployments

1. [Air-Gapped Guide](guides/air-gapped.md) - Complete workflow
2. [Hardware Binding](guides/hardware-binding.md) - Lock to machines
3. [Usage Tracking](concepts/usage-tracking.md) - Offline tracking
4. [FAQ: Deployment](faq/deployment.md) - Common questions

## 🤝 Contributing to Docs

Found an error? Want to improve the docs?

- 🐛 [Report issues](https://github.com/licenz-dev/licenz/issues)
- 💬 [Ask questions](https://github.com/licenz-dev/licenz/discussions)
- ✏️ Submit pull requests

## 📝 Documentation Status

| Section | Status | Notes |
|---------|--------|-------|
| Getting Started | ✅ Complete | - |
| Guides | 🚧 In Progress | Hardware binding done, others planned |
| Reference | 📝 Planned | CLI reference exists, API docs needed |
| FAQ | ✅ Complete | All questions answered |
| Examples | ✅ Complete | Rust, Python, Node.js, Shell |
| Architecture | 📝 Planned | Design docs coming soon |
