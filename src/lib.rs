//! # Licenz Core
//!
//! A powerful offline software license management library for Rust.
//!
//! ## Security Witness Pattern
//!
//! This library follows the Security Witness Pattern, separating:
//!
//! - **Attestation** (this crate): Observes, measures, and reports facts about licenses
//! - **Enforcement** (licenz-policy): Decides and enforces based on attestations
//!
//! The core library is open source and auditable. All verification logic is transparent.
//! Policy enforcement is handled by the separate `licenz-policy` crate.
//!
//! ## Features
//!
//! - **Offline License Validation**: Generate licenses that can be verified without internet connectivity
//! - **Hardware Binding**: Bind licenses to specific hardware identifiers (MAC address, disk ID, hostname)
//! - **Digital Signatures**: Secure licenses with RSA-SHA256 cryptographic signatures
//! - **Expiration Management**: Set and enforce license expiration dates
//! - **Binary Format**: Compact, tamper-resistant binary license format
//! - **JSON Support**: Legacy JSON format for backward compatibility
//! - **Security Witness**: Comprehensive attestation of license and system state
//!
//! ## Quick Start
//!
//! ### Generating a License (Server-Side)
//!
//! ```rust,no_run
//! use licenz_core::{KeyPair, KeySize, LicenseGenerator, LicenseData};
//!
//! // Generate RSA key pair
//! let keypair = KeyPair::generate(KeySize::Bits2048).unwrap();
//!
//! // Create a license generator
//! let generator = LicenseGenerator::new(keypair.private_key);
//!
//! // Build license data
//! let license_data = LicenseData::builder()
//!     .id("LIC-001")
//!     .serial("SN-12345")
//!     .customer_id("ACME-CORP")
//!     .product_id("MY-APP")
//!     .valid_days(365)
//!     .feature("basic")
//!     .feature("premium")
//!     .build()
//!     .unwrap();
//!
//! // Generate signed license
//! let signed_license = generator.generate(license_data).unwrap();
//!
//! // Save to binary file
//! generator.save_binary(&signed_license, "license.lic".as_ref()).unwrap();
//! ```
//!
//! ### Attestation (Recommended - Security Witness Pattern)
//!
//! ```rust,ignore
//! use licenz_core::{SecurityWitness, WitnessConfig};
//!
//! // Public key embedded at compile time
//! const PUBLIC_KEY: &str = include_str!("../keys/public.pem");
//!
//! fn main() {
//!     let witness = SecurityWitness::new(PUBLIC_KEY).unwrap();
//!     let attestation = witness.attest("license.lic", &WitnessConfig::default()).unwrap();
//!
//!     // Attestation provides facts - your app decides what to do
//!     println!("Signature valid: {}", attestation.signature_valid);
//!     println!("Days remaining: {}", attestation.expiration.days_remaining);
//!     println!("Anomalies: {:?}", attestation.anomalies);
//!
//!     // Pass to licenz-policy for enforcement, or handle yourself
//!     if !attestation.is_valid {
//!         eprintln!("License invalid");
//!         std::process::exit(1);
//!     }
//! }
//! ```
//!
//! ### Legacy: Direct Validation (Deprecated)
//!
//! ```rust,ignore
//! use licenz_core::require_license;
//!
//! // This pattern is deprecated - use SecurityWitness + licenz-policy instead
//! let license = require_license("license.lic", PUBLIC_KEY)
//!     .expect("Valid license required to run");
//! ```
//!
//! ## Feature Flags
//!
//! - `hardware-binding` (default): Enable hardware detection for license binding
//! - `verify-only`: Include only verification code (smaller binary for client apps)
//! - `generate`: Include license generation code (for server/admin apps)
//! - `online-check`: Enable online license validation (revocation check, sync)

pub mod anti_tamper;
pub mod container;
pub mod encrypted_store;
pub mod error;
pub mod generator;
pub mod guard;
pub mod hardware;
pub mod keys;
pub mod license;
pub mod state_manager;
pub mod verifier;
pub mod witness;

#[cfg(feature = "online-check")]
pub mod online_check;

// Re-export main types
pub use anti_tamper::{ClockStatus, HardwareFingerprint, LicenseState, MatchResult};
pub use container::{ContainerBinding, InstanceIdSource, RuntimeEnvironment};
pub use encrypted_store::{validate_passphrase, EncryptedKeyStore, MIN_PASSPHRASE_LENGTH};
pub use error::{LicenseError, Result};
pub use generator::LicenseGenerator;
pub use guard::{
    require_license, require_license_with_verifier, validate_license_bytes, ValidatedLicense,
};
pub use hardware::{detect_hardware, HardwareInfo};
pub use keys::{parse_private_key, parse_public_key, KeyPair, KeySize};
pub use license::{HardwareBinding, LicenseData, LicenseDataBuilder, LicenseFormat, SignedLicense};
pub use state_manager::{StateManager, StateObservations};
pub use verifier::{detect_license_format, LicenseVerifier, ValidationResult};

// Security Witness Pattern exports
pub use witness::{
    ClockAttestation, ClockStatusAttestation, EnvironmentAttestation, ExpirationAttestation,
    ExpirationIssue, HardwareAttestation, SecurityAnomaly, SecurityAttestation, SecurityWitness,
    StateFileAttestation, StateFileObservation, StateFileStatus, WitnessConfig,
};

#[cfg(feature = "online-check")]
pub use online_check::{
    check_revocation, check_revocation_batch, check_revocation_by_serial, sync_report,
    OnlineCheckConfig, RevocationCheckResult, RevocationStatus, SyncReport, SyncResponse,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Create a public key variable that can be set at compile time
///
/// Use this with cargo build flags:
/// ```bash
/// LICENZ_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n..." cargo build
/// ```
#[cfg(feature = "verify-only")]
pub fn embedded_public_key() -> Option<&'static str> {
    option_env!("LICENZ_PUBLIC_KEY")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_workflow() {
        // Generate keys
        let keypair = KeyPair::generate(KeySize::Bits2048).unwrap();

        // Create generator and verifier
        let generator = LicenseGenerator::new(keypair.private_key.clone());
        let verifier = LicenseVerifier::new(keypair.public_key);

        // Create license
        let data = LicenseData::builder()
            .id("TEST-001")
            .serial("SN-12345")
            .customer_id("TEST-CUSTOMER")
            .product_id("TEST-PRODUCT")
            .valid_days(365)
            .feature("basic")
            .feature("premium")
            .build()
            .unwrap();

        // Generate signed license
        let signed = generator.generate(data).unwrap();

        // Verify
        assert!(verifier.validate(&signed).is_ok());

        // Check features
        assert!(signed.data.has_feature("basic"));
        assert!(signed.data.has_feature("PREMIUM")); // Case insensitive
        assert!(!signed.data.has_feature("enterprise"));
    }

    #[test]
    fn test_hardware_binding() {
        let binding = HardwareBinding::new()
            .with_mac_address("AA:BB:CC:DD:EE:FF")
            .with_hostname("test-server")
            .with_disk_id("DISK-001");

        assert!(!binding.is_empty());
        assert_eq!(binding.mac_addresses.len(), 1);
        assert_eq!(binding.hostnames.len(), 1);
        assert_eq!(binding.disk_ids.len(), 1);
    }

    #[test]
    fn test_validated_license_guard() {
        let keypair = KeyPair::generate(KeySize::Bits2048).unwrap();
        let generator = LicenseGenerator::new(keypair.private_key.clone());

        let data = LicenseData::builder()
            .id("GUARD-TEST")
            .serial("SN-GUARD")
            .customer_id("Guard Customer")
            .product_id("GuardApp")
            .valid_days(365)
            .feature("test_feature")
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();
        let binary = generator.export_binary(&signed).unwrap();
        let public_key = keypair.export_public_pem().unwrap();

        // Use the guard pattern
        let validated = validate_license_bytes(&binary, &public_key).unwrap();

        assert_eq!(validated.customer_id, "Guard Customer");
        assert!(validated.has_feature("test_feature"));
    }
}
