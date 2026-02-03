//! License guard pattern for enforced validation
//!
//! This module provides a type-safe way to ensure licenses are always validated
//! before their data is accessed.

use crate::error::Result;
use crate::license::{LicenseData, SignedLicense};
use crate::verifier::LicenseVerifier;
use std::ops::Deref;
use std::path::Path;

/// A validated license guard that ensures the license was verified before access.
///
/// This pattern makes it impossible to access license data without first validating it.
/// The only way to construct a `ValidatedLicense` is through the validation methods,
/// which guarantees the license has been cryptographically verified.
///
/// # Example
///
/// ```rust,ignore
/// use licenz_core::{require_license, LicenseVerifier};
///
/// // This is the ONLY way to get license data
/// let license = require_license("license.lic", PUBLIC_KEY)?;
///
/// // Now you can safely access the data
/// println!("Licensed to: {}", license.customer_id);
/// if license.has_feature("premium") {
///     enable_premium();
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ValidatedLicense {
    /// The verified license
    inner: SignedLicense,

    /// Validation timestamp
    validated_at: chrono::DateTime<chrono::Utc>,
}

impl ValidatedLicense {
    /// Create a new validated license (internal use only)
    fn new(license: SignedLicense) -> Self {
        Self {
            inner: license,
            validated_at: chrono::Utc::now(),
        }
    }

    /// Get the underlying license data
    pub fn data(&self) -> &LicenseData {
        &self.inner.data
    }

    /// Get when this license was validated
    pub fn validated_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.validated_at
    }

    /// Check if a feature is enabled
    pub fn has_feature(&self, feature: &str) -> bool {
        self.inner.data.has_feature(feature)
    }

    /// Get days remaining
    pub fn days_remaining(&self) -> i64 {
        self.inner.data.days_remaining()
    }

    /// Get the raw signed license (for serialization, etc.)
    pub fn into_inner(self) -> SignedLicense {
        self.inner
    }
}

// Allow direct access to common fields via Deref
impl Deref for ValidatedLicense {
    type Target = LicenseData;

    fn deref(&self) -> &Self::Target {
        &self.inner.data
    }
}

/// Require a valid license to proceed.
///
/// This is the primary entry point for license validation. It loads the license
/// from the specified path, verifies it against the provided public key, and
/// returns a `ValidatedLicense` that can be used to access the license data.
///
/// # Arguments
///
/// * `license_path` - Path to the license file
/// * `public_key_pem` - PEM-encoded public key
///
/// # Returns
///
/// Returns `Ok(ValidatedLicense)` if the license is valid, or an error if:
/// - The license file cannot be read
/// - The public key is invalid
/// - The signature verification fails
/// - The license has expired
/// - Hardware binding doesn't match
///
/// # Example
///
/// ```rust,ignore
/// const PUBLIC_KEY: &str = include_str!("../public.pem");
///
/// fn main() {
///     let license = licenz_core::require_license("license.lic", PUBLIC_KEY)
///         .expect("Valid license required");
///
///     println!("Welcome, {}!", license.customer_id);
/// }
/// ```
pub fn require_license(
    license_path: impl AsRef<Path>,
    public_key_pem: &str,
) -> Result<ValidatedLicense> {
    let verifier = LicenseVerifier::from_pem(public_key_pem)?;
    let license = verifier.load_and_validate(license_path.as_ref())?;
    Ok(ValidatedLicense::new(license))
}

/// Require a valid license with custom verifier options.
///
/// Use this when you need more control over the verification process,
/// such as providing custom hardware info for testing.
pub fn require_license_with_verifier(
    license_path: impl AsRef<Path>,
    verifier: &LicenseVerifier,
) -> Result<ValidatedLicense> {
    let license = verifier.load_and_validate(license_path.as_ref())?;
    Ok(ValidatedLicense::new(license))
}

/// Validate license bytes directly (for API/network use)
pub fn validate_license_bytes(
    license_bytes: &[u8],
    public_key_pem: &str,
) -> Result<ValidatedLicense> {
    let verifier = LicenseVerifier::from_pem(public_key_pem)?;
    let license = verifier.parse_license(license_bytes)?;
    verifier.validate(&license)?;
    Ok(ValidatedLicense::new(license))
}

/// Macro to load and validate a license at compile time.
///
/// This macro ensures that:
/// 1. The public key exists at compile time (include_str! fails otherwise)
/// 2. License validation happens early in the program
///
/// Returns `Result<ValidatedLicense>` - the caller decides how to handle errors.
///
/// # Usage
///
/// ```rust,ignore
/// // In main.rs
/// let license = licenz_core::load_license!("license.lic")?;
/// ```
///
/// Or with a custom key path:
///
/// ```rust,ignore
/// let license = licenz_core::load_license!("license.lic", "keys/public.pem")?;
/// ```
///
/// # Note
///
/// For policy enforcement (exit on failure, custom thresholds, etc.),
/// use `licenz-policy` crate's `PolicyEnforcer` instead.
#[macro_export]
macro_rules! load_license {
    ($license_path:expr) => {{
        const PUBLIC_KEY: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/public.pem"));
        $crate::require_license($license_path, PUBLIC_KEY)
    }};

    ($license_path:expr, $key_path:expr) => {{
        const PUBLIC_KEY: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/", $key_path));
        $crate::require_license($license_path, PUBLIC_KEY)
    }};
}

/// **DEPRECATED**: Use `load_license!` instead, which returns a Result.
///
/// This macro calls `std::process::exit(1)` on failure, which is an enforcement
/// decision. The Security Witness Pattern recommends separating attestation
/// (this crate) from enforcement (licenz-policy crate).
#[macro_export]
#[deprecated(
    since = "0.2.0",
    note = "Use load_license! macro or licenz-policy crate for enforcement"
)]
macro_rules! require_valid_license {
    ($license_path:expr) => {{
        const PUBLIC_KEY: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/public.pem"));

        match $crate::require_license($license_path, PUBLIC_KEY) {
            Ok(license) => license,
            Err(e) => {
                eprintln!("License validation failed: {}", e);
                eprintln!("Please ensure you have a valid license file.");
                std::process::exit(1);
            }
        }
    }};

    ($license_path:expr, $key_path:expr) => {{
        const PUBLIC_KEY: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/", $key_path));

        match $crate::require_license($license_path, PUBLIC_KEY) {
            Ok(license) => license,
            Err(e) => {
                eprintln!("License validation failed: {}", e);
                eprintln!("Please ensure you have a valid license file.");
                std::process::exit(1);
            }
        }
    }};
}

/// Feature gate macro for conditional code execution.
///
/// # Example
///
/// ```rust,ignore
/// let license = require_valid_license!("license.lic");
///
/// feature_gate!(license, "premium", {
///     // This code only runs if "premium" feature is licensed
///     enable_premium_features();
/// });
///
/// feature_gate!(license, "enterprise", {
///     enable_sso();
///     enable_audit_logging();
/// } else {
///     show_upgrade_prompt();
/// });
/// ```
#[macro_export]
macro_rules! feature_gate {
    ($license:expr, $feature:expr, $enabled:block) => {
        if $license.has_feature($feature) {
            $enabled
        }
    };

    ($license:expr, $feature:expr, $enabled:block else $disabled:block) => {
        if $license.has_feature($feature) {
            $enabled
        } else {
            $disabled
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyPair, KeySize, LicenseData, LicenseGenerator};

    fn create_test_license() -> (String, Vec<u8>) {
        let keypair = KeyPair::generate(KeySize::Bits2048).unwrap();
        let generator = LicenseGenerator::new(keypair.private_key.clone());

        let data = LicenseData::builder()
            .id("TEST-001")
            .serial("SN-12345")
            .customer_id("Test Customer")
            .product_id("TestApp")
            .valid_days(365)
            .feature("basic")
            .feature("premium")
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();
        let binary = generator.export_binary(&signed).unwrap();
        let public_key = keypair.export_public_pem().unwrap();

        (public_key, binary)
    }

    #[test]
    fn test_validated_license_access() {
        let (public_key, binary) = create_test_license();

        let license = validate_license_bytes(&binary, &public_key).unwrap();

        // Can access data through guard
        assert_eq!(license.customer_id, "Test Customer");
        assert!(license.has_feature("basic"));
        assert!(license.has_feature("premium"));
        assert!(!license.has_feature("enterprise"));
    }

    #[test]
    fn test_validated_license_deref() {
        let (public_key, binary) = create_test_license();

        let license = validate_license_bytes(&binary, &public_key).unwrap();

        // Deref allows direct field access
        assert_eq!(license.product_id, "TestApp");
        assert_eq!(license.serial, "SN-12345");
    }
}
