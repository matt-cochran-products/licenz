# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.1] - 2024-02-02

### Added
- Initial release
- RSA-SHA256 license signing and verification
- Hardware binding (MAC address, hostname, disk ID)
- Binary and JSON license formats
- Expiration management with grace periods
- Security Witness Pattern for clean attestation/enforcement separation
- `SecurityWitness` for comprehensive license attestation
- `SecurityAttestation` with detailed observations:
  - Signature validity
  - Expiration status
  - Hardware match percentage
  - Clock manipulation detection
  - State file integrity
  - Environment detection (VM, container, cloud)
- Anti-tamper detection:
  - Clock drift monitoring
  - Multi-location state files
  - State file integrity checksums
- `load_license!` macro for compile-time key embedding

### Security
- All policy decisions moved to enforcement layer
- No hardcoded thresholds in core library
- Attestation-only design (reports facts, doesn't decide)

[Unreleased]: https://github.com/outboundlabs/licenz/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/outboundlabs/licenz/releases/tag/v0.1.0
