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
//! let generator = LicenseGenerator::new(keypair.into_private_key());
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
//! - `cloud-metadata`: Enable cloud container detection (AWS, GCP, Azure)
//! - `post-quantum`: Enable post-quantum cryptography (ML-DSA-65/FIPS 204, ML-KEM-768/FIPS 203)

pub mod anti_tamper;
pub mod container;
pub mod crypto;
pub mod encrypted_store;
pub mod error;
pub mod generator;
pub mod guard;
pub mod hardware;
pub mod keys;
pub mod license;
pub mod sneakernet;
pub mod state_manager;
pub mod support_bundle;
pub mod unlock;
pub mod verifier;
pub mod witness;

#[cfg(feature = "online-check")]
pub mod online_check;

// Re-export main types
pub use anti_tamper::{
    ClockStatus, HardwareFingerprint, LicenseState, MatchResult, STATE_HMAC_PREFIX,
};
pub use container::{ContainerBinding, InstanceIdSource, RuntimeEnvironment};
pub use encrypted_store::{
    validate_passphrase, EncryptedKeyStore, ENCRYPTED_STORE_VERSION, MIN_PASSPHRASE_LENGTH,
};
pub use error::{LicenseError, Result};
pub use generator::{CryptoGenerator, LicenseGenerator};
pub use guard::{
    require_license, require_license_with_verifier, validate_license_bytes, ValidatedLicense,
};
pub use hardware::{
    default_hardware_environment, detect_hardware, DefaultHardwareEnvironment,
    FixedHardwareEnvironment, HardwareEnvironment, HardwareInfo,
};
pub use keys::{parse_private_key, parse_public_key, CryptoKeyPair, KeyPair, KeySize};
pub use license::{HardwareBinding, LicenseData, LicenseDataBuilder, LicenseFormat, SignedLicense};
pub use state_manager::{StateManager, StateObservations};
pub use verifier::{
    detect_license_format, CryptoVerifier, LicenseVerifier, ValidationResult,
    MAX_LICENSE_FILE_SIZE,
};

// Cryptographic algorithm exports
pub use crypto::{algorithm_ids, CryptoRegistry, EncryptionAlgorithm, SignatureAlgorithm};

// Security Witness Pattern exports
pub use witness::{
    ClockAttestation, ClockStatusAttestation, EnvironmentAttestation, ExpirationAttestation,
    ExpirationIssue, HardwareAttestation, SecurityAnomaly, SecurityAttestation, SecurityWitness,
    StateFileAttestation, StateFileObservation, StateFileStatus, WitnessConfig,
};

// Sneakernet (offline activation) exports
pub use sneakernet::{
    detect_format as detect_sneakernet_format, ActivationRequest, ActivationRequestBuilder,
    ActivationResponse, SneakernetFormat, MAX_SNEAKERNET_JSON_PAYLOAD, REQUEST_MAGIC,
    REQUEST_TEXT_PREFIX, REQUEST_TEXT_SUFFIX, REQUEST_VERSION, RESPONSE_MAGIC,
    RESPONSE_TEXT_PREFIX, RESPONSE_TEXT_SUFFIX, RESPONSE_VERSION,
};

// Support bundle exports
pub use support_bundle::{
    ClockState, ClockStatusSummary, EnvironmentInfo, HardwareMatchStatus, HardwareSummary,
    LicenseStatusSummary, RuntimeEnvironmentSummary, StateFileLocation, StateFileLocationStatus,
    StateFileSummary, SupportBundle, SupportBundleBuilder, VerificationEvent,
    VerificationEventType, BUNDLE_VERSION, ENCRYPTED_BUNDLE_MAGIC,
};

// Admin unlock exports
pub use unlock::{
    generate_challenge_from_state, get_lockout_status, validate_response_code, LockoutStatus,
    UnlockChallenge, UnlockResult, UnlockType,
};

#[cfg(feature = "online-check")]
pub use online_check::{
    check_revocation, check_revocation_batch, check_revocation_by_serial, sync_report,
    OnlineCheckConfig, RevocationCheckResult, RevocationStatus, SyncReport, SyncResponse,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Get a public key embedded at compile time via environment variable.
///
/// Use this with cargo build flags:
/// ```bash
/// LICENZ_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n..." cargo build
/// ```
///
/// Returns `None` if `LICENZ_PUBLIC_KEY` was not set during compilation.
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
        let generator = LicenseGenerator::new(keypair.private_key().clone());
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
        let generator = LicenseGenerator::new(keypair.private_key().clone());

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

    #[test]
    fn test_crypto_workflow_ed25519() {
        // Generate Ed25519 keys using the new crypto module
        let keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();

        // Create generator using the new CryptoGenerator
        let generator = CryptoGenerator::from_keypair(&keypair);

        // Create license
        let data = LicenseData::builder()
            .id("ED25519-TEST")
            .serial("SN-ED25519")
            .customer_id("Ed25519 Customer")
            .product_id("Ed25519 Product")
            .valid_days(365)
            .feature("feature1")
            .feature("feature2")
            .build()
            .unwrap();

        // Generate signed license
        let signed = generator.generate(data).unwrap();
        assert_eq!(signed.algorithm, algorithm_ids::ED25519);

        // Export to binary
        let binary = generator.export_binary(&signed).unwrap();

        // Create verifier with Ed25519 public key
        let mut keys = std::collections::HashMap::new();
        keys.insert(
            algorithm_ids::ED25519.to_string(),
            keypair.public_key_pem.clone(),
        );
        let verifier = CryptoVerifier::new(keys);

        // Parse and validate
        let parsed = verifier.parse_license(&binary).unwrap();
        assert!(verifier.validate(&parsed).is_ok());

        // Verify features
        assert!(parsed.data.has_feature("feature1"));
        assert!(parsed.data.has_feature("FEATURE2")); // Case insensitive
    }

    #[test]
    fn test_crypto_workflow_multi_algorithm() {
        // Test that a system can handle licenses from multiple algorithms

        // Generate keys for both algorithms
        let rsa_keypair = CryptoKeyPair::generate(algorithm_ids::RSA_SHA256).unwrap();
        let ed25519_keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();

        // Create a verifier that supports both
        let mut keys = std::collections::HashMap::new();
        keys.insert(
            algorithm_ids::RSA_SHA256.to_string(),
            rsa_keypair.public_key_pem.clone(),
        );
        keys.insert(
            algorithm_ids::ED25519.to_string(),
            ed25519_keypair.public_key_pem.clone(),
        );
        let verifier = CryptoVerifier::new(keys);

        // Generate RSA license (legacy customer)
        let rsa_generator = CryptoGenerator::from_keypair(&rsa_keypair);
        let rsa_data = LicenseData::builder()
            .id("RSA-LEGACY-001")
            .serial("SN-RSA-LEGACY")
            .customer_id("Legacy RSA Customer")
            .product_id("PROD-001")
            .valid_days(365)
            .build()
            .unwrap();
        let rsa_license = rsa_generator.generate(rsa_data).unwrap();

        // Generate Ed25519 license (new customer)
        let ed25519_generator = CryptoGenerator::from_keypair(&ed25519_keypair);
        let ed25519_data = LicenseData::builder()
            .id("ED25519-NEW-001")
            .serial("SN-ED25519-NEW")
            .customer_id("New Ed25519 Customer")
            .product_id("PROD-001")
            .valid_days(365)
            .build()
            .unwrap();
        let ed25519_license = ed25519_generator.generate(ed25519_data).unwrap();

        // Both licenses should validate with the same verifier
        assert!(verifier.validate(&rsa_license).is_ok());
        assert!(verifier.validate(&ed25519_license).is_ok());

        // Algorithm should be correctly identified
        assert_eq!(rsa_license.algorithm, algorithm_ids::RSA_SHA256);
        assert_eq!(ed25519_license.algorithm, algorithm_ids::ED25519);
    }

    #[test]
    fn test_backward_compatibility_rsa() {
        // Ensure the legacy API still works for RSA
        let keypair = KeyPair::generate(KeySize::Bits2048).unwrap();
        let generator = LicenseGenerator::new(keypair.private_key().clone());
        let verifier = LicenseVerifier::new(keypair.public_key);

        let data = LicenseData::builder()
            .id("LEGACY-RSA-TEST")
            .serial("SN-LEGACY-RSA")
            .customer_id("Legacy Customer")
            .product_id("Legacy Product")
            .valid_days(365)
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();

        // Should use RSA-SHA256
        assert_eq!(signed.algorithm, "RSA-SHA256");

        // Legacy verifier should still work
        assert!(verifier.validate(&signed).is_ok());

        // Binary round-trip should work
        let binary = generator.export_binary(&signed).unwrap();
        let parsed = verifier.parse_license(&binary).unwrap();
        assert!(verifier.validate(&parsed).is_ok());
    }

    #[test]
    fn test_algorithm_registry() {
        // Verify the algorithm registry works correctly
        let supported = CryptoRegistry::supported_signature_algorithms();
        assert!(supported.contains(&algorithm_ids::RSA_SHA256));
        assert!(supported.contains(&algorithm_ids::ED25519));

        // Get algorithms by ID
        let rsa = CryptoRegistry::get_signature_algorithm(algorithm_ids::RSA_SHA256).unwrap();
        assert_eq!(rsa.algorithm_id(), algorithm_ids::RSA_SHA256);

        let ed25519 = CryptoRegistry::get_signature_algorithm(algorithm_ids::ED25519).unwrap();
        assert_eq!(ed25519.algorithm_id(), algorithm_ids::ED25519);

        // Default should be RSA for backward compatibility
        let default = CryptoRegistry::default_signature_algorithm();
        assert_eq!(default.algorithm_id(), algorithm_ids::RSA_SHA256);
    }
}
