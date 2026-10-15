//! License verification functionality (client-side)
//!
//! This module provides license verification using the pluggable cryptographic
//! architecture. It automatically selects the appropriate signature algorithm
//! based on the algorithm identifier stored in the license.
//!
//! # Example
//!
//! ```rust,ignore
//! use licenz_core::verifier::{CryptoVerifier, LicenseVerifier};
//!
//! // New algorithm-agnostic verifier (recommended)
//! let verifier = CryptoVerifier::from_pem(public_key_pem).unwrap();
//! let result = verifier.validate(&license);
//!
//! // Legacy RSA-only verifier (backward compatible)
//! let verifier = LicenseVerifier::from_pem(public_key_pem).unwrap();
//! ```

use crate::crypto::{algorithm_ids, CryptoRegistry, SignatureAlgorithm};
use crate::error::{LicenseError, Result};
use crate::hardware::{
    default_hardware_environment, verify_hardware_binding, FixedHardwareEnvironment,
    HardwareBindingError, HardwareEnvironment, HardwareInfo,
};
use crate::keys::parse_public_key;
use crate::license::{LicenseFormat, SignedLicense, BINARY_MAGIC, BINARY_VERSION};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use rsa::pkcs1v15::VerifyingKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::Sha256;
use std::path::Path;
use std::sync::Arc;

/// Maximum license file size (1 MiB). No legitimate license should exceed this.
pub const MAX_LICENSE_FILE_SIZE: u64 = 1024 * 1024;

/// License verifier for validating licenses
#[derive(Clone)]
pub struct LicenseVerifier {
    public_key: RsaPublicKey,
    hardware_env: Arc<dyn HardwareEnvironment>,
}

impl LicenseVerifier {
    /// Create a new license verifier with a public key
    pub fn new(public_key: RsaPublicKey) -> Self {
        Self {
            public_key,
            hardware_env: default_hardware_environment(),
        }
    }

    /// Create a new license verifier from a PEM string
    pub fn from_pem(pem: &str) -> Result<Self> {
        let public_key = parse_public_key(pem)?;
        Ok(Self::new(public_key))
    }

    /// Create a new license verifier from a PEM file
    pub fn from_pem_file(path: &Path) -> Result<Self> {
        let pem = std::fs::read_to_string(path)?;
        Self::from_pem(&pem)
    }

    /// Set custom hardware info (useful for testing or manual override)
    pub fn with_hardware_info(mut self, info: HardwareInfo) -> Self {
        self.hardware_env = Arc::new(FixedHardwareEnvironment(info));
        self
    }

    /// Use a custom [`HardwareEnvironment`] (e.g. TPM-backed probe in your crate).
    pub fn with_hardware_environment(mut self, env: Arc<dyn HardwareEnvironment>) -> Self {
        self.hardware_env = env;
        self
    }

    fn get_hardware_info(&self) -> HardwareInfo {
        self.hardware_env.snapshot()
    }

    /// Load a license from a file (auto-detects format)
    pub fn load_license(&self, path: &Path) -> Result<SignedLicense> {
        let bytes = read_license_file(path)?;
        self.parse_license(&bytes)
    }

    /// Parse a license from bytes (auto-detects format)
    pub fn parse_license(&self, data: &[u8]) -> Result<SignedLicense> {
        let format = detect_license_format(data);

        match format {
            LicenseFormat::Binary => self.parse_binary_license(data),
            LicenseFormat::Json => self.parse_json_license(data),
        }
    }

    /// Parse a binary format license
    fn parse_binary_license(&self, data: &[u8]) -> Result<SignedLicense> {
        if data.len() < 9 {
            return Err(LicenseError::InvalidLicenseFormat(
                "Binary license too short".into(),
            ));
        }

        // Verify magic header
        if &data[0..4] != BINARY_MAGIC {
            return Err(LicenseError::InvalidLicenseFormat(
                "Invalid magic header".into(),
            ));
        }

        // Check version
        let version = data[4];
        if version > BINARY_VERSION {
            return Err(LicenseError::InvalidLicenseFormat(format!(
                "Unsupported license version: {}",
                version
            )));
        }

        // Read length
        let len = u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;

        if len > data.len() - 9 {
            return Err(LicenseError::InvalidLicenseFormat(
                "Binary license data truncated".into(),
            ));
        }

        // Deserialize the license from JSON
        serde_json::from_slice(&data[9..9 + len])
            .map_err(|e| LicenseError::InvalidLicenseFormat(e.to_string()))
    }

    /// Parse a JSON format license
    fn parse_json_license(&self, data: &[u8]) -> Result<SignedLicense> {
        serde_json::from_slice(data).map_err(|e| LicenseError::InvalidLicenseFormat(e.to_string()))
    }

    /// Verify the cryptographic signature of a license
    pub fn verify_signature(&self, license: &SignedLicense) -> Result<()> {
        // Serialize the data the same way it was signed
        let data_bytes = serde_json::to_vec(&license.data)
            .map_err(|e| LicenseError::SerializationError(e.to_string()))?;

        // Decode the signature
        let signature_bytes = BASE64.decode(&license.signature).map_err(|e| {
            LicenseError::InvalidLicenseFormat(format!("Invalid signature encoding: {}", e))
        })?;

        // Create verifying key
        let verifying_key = VerifyingKey::<Sha256>::new(self.public_key.clone());

        // Parse signature
        let signature =
            rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice()).map_err(|e| {
                LicenseError::VerificationFailed(format!("Invalid signature format: {}", e))
            })?;

        // Verify
        verifying_key.verify(&data_bytes, &signature).map_err(|e| {
            LicenseError::VerificationFailed(format!("Signature verification failed: {}", e))
        })
    }

    /// Verify that the license has not expired
    pub fn verify_expiration(&self, license: &SignedLicense) -> Result<()> {
        let now = Utc::now();

        if now < license.data.valid_from {
            return Err(LicenseError::NotYetValid(
                license
                    .data
                    .valid_from
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
            ));
        }

        if now > license.data.valid_until {
            return Err(LicenseError::LicenseExpired(
                license
                    .data
                    .valid_until
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Verify hardware binding
    pub fn verify_hardware(&self, license: &SignedLicense) -> Result<()> {
        let hardware = self.get_hardware_info();

        verify_hardware_binding(&license.data.hardware_binding, &hardware).map_err(|e| {
            tracing::debug!("Hardware binding check failed: {}", e);
            match e {
                HardwareBindingError::MacAddressMismatch { .. } => {
                    LicenseError::HardwareBindingMismatch {
                        field: "mac_address".to_string(),
                    }
                }
                HardwareBindingError::HostnameMismatch { .. } => {
                    LicenseError::HardwareBindingMismatch {
                        field: "hostname".to_string(),
                    }
                }
                HardwareBindingError::DiskIdMismatch { .. } => {
                    LicenseError::HardwareBindingMismatch {
                        field: "disk_id".to_string(),
                    }
                }
                HardwareBindingError::CustomMismatch { key, .. } => {
                    LicenseError::HardwareBindingMismatch { field: key }
                }
            }
        })
    }

    /// Perform full license validation
    ///
    /// This verifies:
    /// 1. Cryptographic signature
    /// 2. Expiration date
    /// 3. Hardware binding (if enabled)
    pub fn validate(&self, license: &SignedLicense) -> Result<()> {
        self.verify_signature(license)?;
        self.verify_expiration(license)?;
        self.verify_hardware(license)?;
        Ok(())
    }

    /// Load and validate a license from a file
    pub fn load_and_validate(&self, path: &Path) -> Result<SignedLicense> {
        let license = self.load_license(path)?;
        self.validate(&license)?;
        Ok(license)
    }
}

/// Read a license file with size-limit protection against oversized inputs.
fn read_license_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MAX_LICENSE_FILE_SIZE {
        return Err(LicenseError::InvalidLicenseFormat(format!(
            "License file exceeds maximum size of {} bytes (got {} bytes)",
            MAX_LICENSE_FILE_SIZE,
            metadata.len()
        )));
    }
    Ok(std::fs::read(path)?)
}

/// Detect the format of a license file
pub fn detect_license_format(data: &[u8]) -> LicenseFormat {
    if data.len() >= 4 && &data[0..4] == BINARY_MAGIC {
        LicenseFormat::Binary
    } else {
        LicenseFormat::Json
    }
}

/// Validation result with detailed status
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Is the license valid?
    pub is_valid: bool,

    /// Signature verification status
    pub signature_valid: bool,

    /// Expiration status
    pub expiration_valid: bool,

    /// Hardware binding status
    pub hardware_valid: bool,

    /// Days remaining until expiration
    pub days_remaining: i64,

    /// Error message if invalid
    pub error: Option<String>,
}

impl LicenseVerifier {
    /// Perform detailed validation and return a result
    pub fn validate_detailed(&self, license: &SignedLicense) -> ValidationResult {
        let mut result = ValidationResult {
            is_valid: false,
            signature_valid: false,
            expiration_valid: false,
            hardware_valid: false,
            days_remaining: license.data.days_remaining(),
            error: None,
        };

        // Check signature
        match self.verify_signature(license) {
            Ok(_) => result.signature_valid = true,
            Err(e) => {
                result.error = Some(e.to_string());
                return result;
            }
        }

        // Check expiration
        match self.verify_expiration(license) {
            Ok(_) => result.expiration_valid = true,
            Err(e) => {
                result.error = Some(e.to_string());
                return result;
            }
        }

        // Check hardware
        match self.verify_hardware(license) {
            Ok(_) => result.hardware_valid = true,
            Err(e) => {
                result.error = Some(e.to_string());
                return result;
            }
        }

        result.is_valid = true;
        result
    }
}

/// Algorithm-agnostic license verifier that automatically selects the correct algorithm
///
/// This verifier uses the algorithm identifier stored in the license to select
/// the appropriate signature verification algorithm. This enables support for
/// multiple signature algorithms (RSA-SHA256, Ed25519, etc.) with automatic detection.
///
/// # Example
///
/// ```rust,ignore
/// use licenz_core::verifier::CryptoVerifier;
/// use std::collections::HashMap;
///
/// // Create verifier with multiple public keys
/// let mut keys = HashMap::new();
/// keys.insert("RSA-SHA256".to_string(), rsa_public_key_pem.to_string());
/// keys.insert("Ed25519".to_string(), ed25519_public_key_pem.to_string());
///
/// let verifier = CryptoVerifier::new(keys);
/// let result = verifier.validate(&license);
/// ```
#[derive(Clone)]
pub struct CryptoVerifier {
    /// Map of algorithm ID to public key PEM
    public_keys: std::collections::HashMap<String, String>,
    hardware_env: Arc<dyn HardwareEnvironment>,
}

impl CryptoVerifier {
    /// Create a new crypto verifier with multiple public keys
    ///
    /// # Arguments
    /// * `public_keys` - Map of algorithm ID to public key PEM
    pub fn new(public_keys: std::collections::HashMap<String, String>) -> Self {
        Self {
            public_keys,
            hardware_env: default_hardware_environment(),
        }
    }

    /// Create a verifier from a single PEM string, auto-detecting the algorithm
    ///
    /// This tries to parse the key as RSA first (for backward compatibility),
    /// then falls back to Ed25519.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let mut keys = std::collections::HashMap::new();

        // Try RSA first (most common, backward compatible)
        if parse_public_key(pem).is_ok() {
            keys.insert(algorithm_ids::RSA_SHA256.to_string(), pem.to_string());
            return Ok(Self::new(keys));
        }

        // Try Ed25519 by checking if the key can be parsed
        // We check by looking at the PEM structure and attempting verification
        let ed25519_signer = crate::crypto::ed25519::Ed25519Signer::new();
        let verify_result: Result<()> = ed25519_signer.verify(b"test", &[0u8; 64], pem);

        // If the error message mentions "verification failed" it means the key parsed OK
        // but the signature was invalid (as expected with a dummy signature)
        match verify_result {
            Ok(()) => {
                // Unlikely but possible - key worked
                keys.insert(algorithm_ids::ED25519.to_string(), pem.to_string());
                return Ok(Self::new(keys));
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("verification failed")
                    || err_str.contains("Signature verification failed")
                {
                    // Key parsed successfully, just signature was wrong (expected)
                    keys.insert(algorithm_ids::ED25519.to_string(), pem.to_string());
                    return Ok(Self::new(keys));
                }
                // Key parsing failed, continue to fallback
            }
        }

        // Fallback: if the PEM contains PUBLIC KEY marker, default to RSA
        let pem_normalized = pem.replace("\\n", "\n");
        if pem_normalized.contains("PUBLIC KEY") {
            keys.insert(algorithm_ids::RSA_SHA256.to_string(), pem.to_string());
            return Ok(Self::new(keys));
        }

        Err(LicenseError::InvalidKeyFormat(
            "Could not determine public key type".into(),
        ))
    }

    /// Create a verifier from a PEM file
    pub fn from_pem_file(path: &Path) -> Result<Self> {
        let pem = std::fs::read_to_string(path)?;
        Self::from_pem(&pem)
    }

    /// Add a public key for a specific algorithm
    pub fn with_public_key(mut self, algorithm_id: &str, pem: &str) -> Self {
        self.public_keys
            .insert(algorithm_id.to_string(), pem.to_string());
        self
    }

    /// Set custom hardware info (useful for testing or manual override)
    pub fn with_hardware_info(mut self, info: HardwareInfo) -> Self {
        self.hardware_env = Arc::new(FixedHardwareEnvironment(info));
        self
    }

    /// Use a custom [`HardwareEnvironment`].
    pub fn with_hardware_environment(mut self, env: Arc<dyn HardwareEnvironment>) -> Self {
        self.hardware_env = env;
        self
    }

    fn get_hardware_info(&self) -> HardwareInfo {
        self.hardware_env.snapshot()
    }

    /// Get the public key for a specific algorithm
    fn get_public_key(&self, algorithm_id: &str) -> Result<&str> {
        self.public_keys
            .get(algorithm_id)
            .map(|s| s.as_str())
            .ok_or_else(|| {
                LicenseError::InvalidKeyFormat(format!(
                    "No public key configured for algorithm: {}",
                    algorithm_id
                ))
            })
    }

    /// Load a license from a file (auto-detects format)
    pub fn load_license(&self, path: &Path) -> Result<SignedLicense> {
        let bytes = read_license_file(path)?;
        self.parse_license(&bytes)
    }

    /// Parse a license from bytes (auto-detects format)
    pub fn parse_license(&self, data: &[u8]) -> Result<SignedLicense> {
        let format = detect_license_format(data);

        match format {
            LicenseFormat::Binary => self.parse_binary_license(data),
            LicenseFormat::Json => self.parse_json_license(data),
        }
    }

    /// Parse a binary format license
    fn parse_binary_license(&self, data: &[u8]) -> Result<SignedLicense> {
        if data.len() < 9 {
            return Err(LicenseError::InvalidLicenseFormat(
                "Binary license too short".into(),
            ));
        }

        // Verify magic header
        if &data[0..4] != BINARY_MAGIC {
            return Err(LicenseError::InvalidLicenseFormat(
                "Invalid magic header".into(),
            ));
        }

        // Check version
        let version = data[4];
        if version > BINARY_VERSION {
            return Err(LicenseError::InvalidLicenseFormat(format!(
                "Unsupported license version: {}",
                version
            )));
        }

        // Read length
        let len = u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;

        if len > data.len() - 9 {
            return Err(LicenseError::InvalidLicenseFormat(
                "Binary license data truncated".into(),
            ));
        }

        // Deserialize the license from JSON
        serde_json::from_slice(&data[9..9 + len])
            .map_err(|e| LicenseError::InvalidLicenseFormat(e.to_string()))
    }

    /// Parse a JSON format license
    fn parse_json_license(&self, data: &[u8]) -> Result<SignedLicense> {
        serde_json::from_slice(data).map_err(|e| LicenseError::InvalidLicenseFormat(e.to_string()))
    }

    /// Verify the cryptographic signature of a license
    ///
    /// Automatically selects the algorithm based on the license's algorithm field.
    pub fn verify_signature(&self, license: &SignedLicense) -> Result<()> {
        // Serialize the data the same way it was signed
        let data_bytes = serde_json::to_vec(&license.data)
            .map_err(|e| LicenseError::SerializationError(e.to_string()))?;

        // Decode the signature
        let signature_bytes = BASE64.decode(&license.signature).map_err(|e| {
            LicenseError::InvalidLicenseFormat(format!("Invalid signature encoding: {}", e))
        })?;

        // Get the algorithm and public key
        let algorithm = CryptoRegistry::get_signature_algorithm(&license.algorithm)?;
        let public_key_pem = self.get_public_key(&license.algorithm)?;

        // Verify using the appropriate algorithm
        algorithm.verify(&data_bytes, &signature_bytes, public_key_pem)
    }

    /// Verify that the license has not expired
    pub fn verify_expiration(&self, license: &SignedLicense) -> Result<()> {
        let now = Utc::now();

        if now < license.data.valid_from {
            return Err(LicenseError::NotYetValid(
                license
                    .data
                    .valid_from
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
            ));
        }

        if now > license.data.valid_until {
            return Err(LicenseError::LicenseExpired(
                license
                    .data
                    .valid_until
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Verify hardware binding
    pub fn verify_hardware(&self, license: &SignedLicense) -> Result<()> {
        let hardware = self.get_hardware_info();

        verify_hardware_binding(&license.data.hardware_binding, &hardware).map_err(|e| {
            tracing::debug!("Hardware binding check failed: {}", e);
            match e {
                HardwareBindingError::MacAddressMismatch { .. } => {
                    LicenseError::HardwareBindingMismatch {
                        field: "mac_address".to_string(),
                    }
                }
                HardwareBindingError::HostnameMismatch { .. } => {
                    LicenseError::HardwareBindingMismatch {
                        field: "hostname".to_string(),
                    }
                }
                HardwareBindingError::DiskIdMismatch { .. } => {
                    LicenseError::HardwareBindingMismatch {
                        field: "disk_id".to_string(),
                    }
                }
                HardwareBindingError::CustomMismatch { key, .. } => {
                    LicenseError::HardwareBindingMismatch { field: key }
                }
            }
        })
    }

    /// Perform full license validation
    ///
    /// This verifies:
    /// 1. Cryptographic signature (algorithm auto-selected from license)
    /// 2. Expiration date
    /// 3. Hardware binding (if enabled)
    pub fn validate(&self, license: &SignedLicense) -> Result<()> {
        self.verify_signature(license)?;
        self.verify_expiration(license)?;
        self.verify_hardware(license)?;
        Ok(())
    }

    /// Load and validate a license from a file
    pub fn load_and_validate(&self, path: &Path) -> Result<SignedLicense> {
        let license = self.load_license(path)?;
        self.validate(&license)?;
        Ok(license)
    }

    /// Perform detailed validation and return a result
    pub fn validate_detailed(&self, license: &SignedLicense) -> ValidationResult {
        let mut result = ValidationResult {
            is_valid: false,
            signature_valid: false,
            expiration_valid: false,
            hardware_valid: false,
            days_remaining: license.data.days_remaining(),
            error: None,
        };

        // Check signature
        match self.verify_signature(license) {
            Ok(_) => result.signature_valid = true,
            Err(e) => {
                result.error = Some(e.to_string());
                return result;
            }
        }

        // Check expiration
        match self.verify_expiration(license) {
            Ok(_) => result.expiration_valid = true,
            Err(e) => {
                result.error = Some(e.to_string());
                return result;
            }
        }

        // Check hardware
        match self.verify_hardware(license) {
            Ok(_) => result.hardware_valid = true,
            Err(e) => {
                result.error = Some(e.to_string());
                return result;
            }
        }

        result.is_valid = true;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_maximum_binary_lengths_return_errors_for_both_verifiers() {
        let keys = create_test_keypair();
        let legacy = LicenseVerifier::new(keys.public_key);
        let modern = CryptoVerifier::new(std::collections::HashMap::new());
        for length in [u32::MAX, u32::MAX - 8, 1, 1024] {
            let mut bytes = b"FLIC\x01".to_vec();
            bytes.extend_from_slice(&length.to_le_bytes());
            assert!(legacy.parse_license(&bytes).is_err());
            assert!(modern.parse_license(&bytes).is_err());
        }
    }

    use crate::generator::LicenseGenerator;
    use crate::keys::{KeyPair, KeySize};
    use crate::license::LicenseData;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate(KeySize::Bits2048).unwrap()
    }

    #[test]
    fn test_license_verification() {
        let keypair = create_test_keypair();
        let generator = LicenseGenerator::new(keypair.private_key().clone());
        let verifier = LicenseVerifier::new(keypair.public_key);

        let data = LicenseData::builder()
            .id("TEST-001")
            .serial("SN-12345")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();

        assert!(verifier.verify_signature(&signed).is_ok());
        assert!(verifier.verify_expiration(&signed).is_ok());
        assert!(verifier.validate(&signed).is_ok());
    }

    #[test]
    fn test_binary_round_trip() {
        let keypair = create_test_keypair();
        let generator = LicenseGenerator::new(keypair.private_key().clone());
        let verifier = LicenseVerifier::new(keypair.public_key);

        let data = LicenseData::builder()
            .id("TEST-001")
            .serial("SN-12345")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .feature("basic")
            .feature("premium")
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();
        let binary = generator.export_binary(&signed).unwrap();

        let parsed = verifier.parse_license(&binary).unwrap();

        assert_eq!(parsed.data.id, signed.data.id);
        assert_eq!(parsed.data.serial, signed.data.serial);
        assert_eq!(parsed.data.features.len(), 2);
    }

    #[test]
    fn test_json_round_trip() {
        let keypair = create_test_keypair();
        let generator = LicenseGenerator::new(keypair.private_key().clone());
        let verifier = LicenseVerifier::new(keypair.public_key);

        let data = LicenseData::builder()
            .id("TEST-001")
            .serial("SN-12345")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();
        let json = generator.export_json(&signed).unwrap();

        let parsed = verifier.parse_license(json.as_bytes()).unwrap();

        assert_eq!(parsed.data.id, signed.data.id);
        assert!(verifier.validate(&parsed).is_ok());
    }

    // CryptoVerifier tests

    #[test]
    fn test_crypto_verifier_rsa() {
        use crate::generator::CryptoGenerator;
        use crate::keys::CryptoKeyPair;

        let keypair = CryptoKeyPair::generate(algorithm_ids::RSA_SHA256).unwrap();
        let generator = CryptoGenerator::from_keypair(&keypair);

        let mut keys = std::collections::HashMap::new();
        keys.insert(
            algorithm_ids::RSA_SHA256.to_string(),
            keypair.public_key_pem.clone(),
        );
        let verifier = CryptoVerifier::new(keys);

        let data = LicenseData::builder()
            .id("CRYPTO-RSA-001")
            .serial("SN-CRYPTO-RSA")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();
        assert_eq!(signed.algorithm, algorithm_ids::RSA_SHA256);

        assert!(verifier.verify_signature(&signed).is_ok());
        assert!(verifier.verify_expiration(&signed).is_ok());
        assert!(verifier.validate(&signed).is_ok());
    }

    #[test]
    fn test_crypto_verifier_ed25519() {
        use crate::generator::CryptoGenerator;
        use crate::keys::CryptoKeyPair;

        let keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
        let generator = CryptoGenerator::from_keypair(&keypair);

        let mut keys = std::collections::HashMap::new();
        keys.insert(
            algorithm_ids::ED25519.to_string(),
            keypair.public_key_pem.clone(),
        );
        let verifier = CryptoVerifier::new(keys);

        let data = LicenseData::builder()
            .id("CRYPTO-ED25519-001")
            .serial("SN-CRYPTO-ED25519")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();
        assert_eq!(signed.algorithm, algorithm_ids::ED25519);

        assert!(verifier.verify_signature(&signed).is_ok());
        assert!(verifier.verify_expiration(&signed).is_ok());
        assert!(verifier.validate(&signed).is_ok());
    }

    #[test]
    fn test_crypto_verifier_multi_algorithm() {
        use crate::generator::CryptoGenerator;
        use crate::keys::CryptoKeyPair;

        // Generate keys for both algorithms
        let rsa_keypair = CryptoKeyPair::generate(algorithm_ids::RSA_SHA256).unwrap();
        let ed25519_keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();

        // Create generators
        let rsa_generator = CryptoGenerator::from_keypair(&rsa_keypair);
        let ed25519_generator = CryptoGenerator::from_keypair(&ed25519_keypair);

        // Create verifier with both public keys
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

        // Generate RSA license
        let rsa_data = LicenseData::builder()
            .id("MULTI-RSA-001")
            .serial("SN-MULTI-RSA")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .build()
            .unwrap();
        let rsa_license = rsa_generator.generate(rsa_data).unwrap();

        // Generate Ed25519 license
        let ed25519_data = LicenseData::builder()
            .id("MULTI-ED25519-001")
            .serial("SN-MULTI-ED25519")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .build()
            .unwrap();
        let ed25519_license = ed25519_generator.generate(ed25519_data).unwrap();

        // Verify both licenses with the same verifier
        assert!(verifier.validate(&rsa_license).is_ok());
        assert!(verifier.validate(&ed25519_license).is_ok());

        // Ensure algorithm detection works correctly
        assert_eq!(rsa_license.algorithm, algorithm_ids::RSA_SHA256);
        assert_eq!(ed25519_license.algorithm, algorithm_ids::ED25519);
    }

    #[test]
    fn test_crypto_verifier_binary_round_trip() {
        use crate::generator::CryptoGenerator;
        use crate::keys::CryptoKeyPair;

        let keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
        let generator = CryptoGenerator::from_keypair(&keypair);

        let mut keys = std::collections::HashMap::new();
        keys.insert(
            algorithm_ids::ED25519.to_string(),
            keypair.public_key_pem.clone(),
        );
        let verifier = CryptoVerifier::new(keys);

        let data = LicenseData::builder()
            .id("BINARY-ED25519-001")
            .serial("SN-BINARY-ED25519")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .feature("basic")
            .feature("premium")
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();
        let binary = generator.export_binary(&signed).unwrap();

        let parsed = verifier.parse_license(&binary).unwrap();

        assert_eq!(parsed.data.id, signed.data.id);
        assert_eq!(parsed.data.serial, signed.data.serial);
        assert_eq!(parsed.data.features.len(), 2);
        assert_eq!(parsed.algorithm, algorithm_ids::ED25519);
        assert!(verifier.validate(&parsed).is_ok());
    }

    #[test]
    fn test_crypto_verifier_wrong_key() {
        use crate::generator::CryptoGenerator;
        use crate::keys::CryptoKeyPair;

        let keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
        let wrong_keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();

        let generator = CryptoGenerator::from_keypair(&keypair);

        // Use wrong public key
        let mut keys = std::collections::HashMap::new();
        keys.insert(
            algorithm_ids::ED25519.to_string(),
            wrong_keypair.public_key_pem.clone(),
        );
        let verifier = CryptoVerifier::new(keys);

        let data = LicenseData::builder()
            .id("WRONG-KEY-001")
            .serial("SN-WRONG-KEY")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();

        // Should fail verification with wrong key
        assert!(verifier.verify_signature(&signed).is_err());
        assert!(verifier.validate(&signed).is_err());
    }

    #[test]
    fn test_crypto_verifier_missing_algorithm_key() {
        use crate::generator::CryptoGenerator;
        use crate::keys::CryptoKeyPair;

        let keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
        let generator = CryptoGenerator::from_keypair(&keypair);

        // Only configure RSA key, but license uses Ed25519
        let rsa_keypair = CryptoKeyPair::generate(algorithm_ids::RSA_SHA256).unwrap();
        let mut keys = std::collections::HashMap::new();
        keys.insert(
            algorithm_ids::RSA_SHA256.to_string(),
            rsa_keypair.public_key_pem.clone(),
        );
        let verifier = CryptoVerifier::new(keys);

        let data = LicenseData::builder()
            .id("MISSING-ALG-001")
            .serial("SN-MISSING-ALG")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();

        // Should fail because verifier doesn't have Ed25519 key
        let result = verifier.verify_signature(&signed);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No public key configured"));
    }

    #[test]
    fn test_crypto_verifier_detailed_validation() {
        use crate::generator::CryptoGenerator;
        use crate::keys::CryptoKeyPair;

        let keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
        let generator = CryptoGenerator::from_keypair(&keypair);

        let mut keys = std::collections::HashMap::new();
        keys.insert(
            algorithm_ids::ED25519.to_string(),
            keypair.public_key_pem.clone(),
        );
        let verifier = CryptoVerifier::new(keys);

        let data = LicenseData::builder()
            .id("DETAILED-001")
            .serial("SN-DETAILED")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();

        let result = verifier.validate_detailed(&signed);

        assert!(result.is_valid);
        assert!(result.signature_valid);
        assert!(result.expiration_valid);
        assert!(result.hardware_valid);
        assert!(result.days_remaining > 0);
        assert!(result.error.is_none());
    }

    // ========================================================================
    // Fix: Max license file size check
    // ========================================================================

    #[test]
    fn load_license_rejects_oversized_file() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("huge.lic");

        // Write a file larger than MAX_LICENSE_FILE_SIZE
        let oversized = vec![0u8; (MAX_LICENSE_FILE_SIZE as usize) + 1];
        std::fs::write(&path, &oversized).unwrap();

        let keypair = crate::KeyPair::generate(crate::KeySize::Bits2048).unwrap();
        let verifier = LicenseVerifier::new(keypair.public_key.clone());

        let err = verifier.load_license(&path).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum size"),
            "error should mention size: {}",
            err
        );
    }

    #[test]
    fn crypto_verifier_load_license_rejects_oversized_file() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("huge.lic");

        let oversized = vec![0u8; (MAX_LICENSE_FILE_SIZE as usize) + 1];
        std::fs::write(&path, &oversized).unwrap();

        let keypair = crate::CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
        let mut keys = std::collections::HashMap::new();
        keys.insert(
            algorithm_ids::ED25519.to_string(),
            keypair.public_key_pem.clone(),
        );
        let verifier = CryptoVerifier::new(keys);

        let err = verifier.load_license(&path).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum size"));
    }

    #[test]
    fn load_license_accepts_file_at_limit() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("at_limit.lic");

        // File exactly at limit should be read (will fail on parse, not on size)
        let data = vec![b'{'; MAX_LICENSE_FILE_SIZE as usize];
        std::fs::write(&path, &data).unwrap();

        let keypair = crate::KeyPair::generate(crate::KeySize::Bits2048).unwrap();
        let verifier = LicenseVerifier::new(keypair.public_key.clone());

        // Should fail on parsing, not on file size
        let err = verifier.load_license(&path).unwrap_err();
        assert!(!err.to_string().contains("exceeds maximum size"));
    }

    // ========================================================================
    // Fix: BTreeMap deterministic serialization
    // ========================================================================

    #[test]
    fn metadata_btreemap_serializes_deterministically() {
        let mut data1 = LicenseData::builder()
            .id("DET-001")
            .serial("SN-DET")
            .customer_id("C")
            .product_id("P")
            .valid_days(1)
            .build()
            .unwrap();

        // Insert multiple metadata keys
        data1.metadata.insert("zebra".to_string(), "z".to_string());
        data1.metadata.insert("alpha".to_string(), "a".to_string());
        data1.metadata.insert("middle".to_string(), "m".to_string());

        let bytes1 = serde_json::to_vec(&data1).unwrap();
        let bytes2 = serde_json::to_vec(&data1).unwrap();

        // Same process, same data — must be identical
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn metadata_btreemap_keys_appear_in_sorted_order() {
        let mut data = LicenseData::builder()
            .id("DET-002")
            .serial("SN-DET2")
            .customer_id("C")
            .product_id("P")
            .valid_days(1)
            .build()
            .unwrap();

        data.metadata.insert("zebra".to_string(), "z".to_string());
        data.metadata.insert("alpha".to_string(), "a".to_string());

        let json = serde_json::to_string(&data).unwrap();
        let alpha_pos = json.find("\"alpha\"").unwrap();
        let zebra_pos = json.find("\"zebra\"").unwrap();
        assert!(alpha_pos < zebra_pos);
    }

    #[test]
    fn license_with_metadata_round_trips_through_sign_verify() {
        let keypair = crate::KeyPair::generate(crate::KeySize::Bits2048).unwrap();
        let generator = crate::LicenseGenerator::new(keypair.private_key().clone());

        let mut data = LicenseData::builder()
            .id("META-001")
            .serial("SN-META")
            .customer_id("C")
            .product_id("P")
            .valid_days(365)
            .build()
            .unwrap();

        data.metadata
            .insert("key_z".to_string(), "val_z".to_string());
        data.metadata
            .insert("key_a".to_string(), "val_a".to_string());
        data.metadata
            .insert("key_m".to_string(), "val_m".to_string());

        let signed = generator.generate(data).unwrap();

        let verifier = LicenseVerifier::new(keypair.public_key.clone());
        assert!(verifier.validate(&signed).is_ok());
    }

    // Post-quantum verifier tests (feature-gated)
    #[cfg(feature = "post-quantum")]
    mod pq_tests {
        use super::*;
        use crate::crypto::algorithm_ids;
        use crate::generator::CryptoGenerator;
        use crate::keys::CryptoKeyPair;

        #[test]
        fn test_crypto_verifier_ml_dsa_65() {
            let keypair = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();
            let generator = CryptoGenerator::from_keypair(&keypair);

            let mut keys = std::collections::HashMap::new();
            keys.insert(
                algorithm_ids::ML_DSA_65.to_string(),
                keypair.public_key_pem.clone(),
            );
            let verifier = CryptoVerifier::new(keys);

            let data = LicenseData::builder()
                .id("PQ-VERIFY-001")
                .serial("SN-PQ-VERIFY")
                .customer_id("CUST-001")
                .product_id("PROD-001")
                .valid_days(365)
                .feature("quantum-safe")
                .build()
                .unwrap();

            let signed = generator.generate(data).unwrap();
            assert_eq!(signed.algorithm, algorithm_ids::ML_DSA_65);

            assert!(verifier.verify_signature(&signed).is_ok());
            assert!(verifier.verify_expiration(&signed).is_ok());
            assert!(verifier.validate(&signed).is_ok());
        }

        #[test]
        fn test_crypto_verifier_hybrid_ed25519_ml_dsa() {
            let keypair = CryptoKeyPair::generate(algorithm_ids::HYBRID_ED25519_ML_DSA_65).unwrap();
            let generator = CryptoGenerator::from_keypair(&keypair);

            let mut keys = std::collections::HashMap::new();
            keys.insert(
                algorithm_ids::HYBRID_ED25519_ML_DSA_65.to_string(),
                keypair.public_key_pem.clone(),
            );
            let verifier = CryptoVerifier::new(keys);

            let data = LicenseData::builder()
                .id("PQ-HYBRID-VERIFY-001")
                .serial("SN-PQ-HYBRID-VERIFY")
                .customer_id("CUST-001")
                .product_id("PROD-001")
                .valid_days(365)
                .feature("hybrid-security")
                .build()
                .unwrap();

            let signed = generator.generate(data).unwrap();
            assert_eq!(signed.algorithm, algorithm_ids::HYBRID_ED25519_ML_DSA_65);

            assert!(verifier.verify_signature(&signed).is_ok());
            assert!(verifier.validate(&signed).is_ok());
        }

        #[test]
        fn test_crypto_verifier_hybrid_rsa_ml_dsa() {
            let keypair = CryptoKeyPair::generate(algorithm_ids::HYBRID_RSA_ML_DSA_65).unwrap();
            let generator = CryptoGenerator::from_keypair(&keypair);

            let mut keys = std::collections::HashMap::new();
            keys.insert(
                algorithm_ids::HYBRID_RSA_ML_DSA_65.to_string(),
                keypair.public_key_pem.clone(),
            );
            let verifier = CryptoVerifier::new(keys);

            let data = LicenseData::builder()
                .id("PQ-HYBRID-RSA-VERIFY-001")
                .serial("SN-PQ-HYBRID-RSA-VERIFY")
                .customer_id("CUST-001")
                .product_id("PROD-001")
                .valid_days(365)
                .build()
                .unwrap();

            let signed = generator.generate(data).unwrap();
            assert_eq!(signed.algorithm, algorithm_ids::HYBRID_RSA_ML_DSA_65);

            assert!(verifier.verify_signature(&signed).is_ok());
            assert!(verifier.validate(&signed).is_ok());
        }

        #[test]
        fn test_pq_verifier_binary_round_trip() {
            let keypair = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();
            let generator = CryptoGenerator::from_keypair(&keypair);

            let mut keys = std::collections::HashMap::new();
            keys.insert(
                algorithm_ids::ML_DSA_65.to_string(),
                keypair.public_key_pem.clone(),
            );
            let verifier = CryptoVerifier::new(keys);

            let data = LicenseData::builder()
                .id("PQ-BINARY-VERIFY-001")
                .serial("SN-PQ-BINARY-VERIFY")
                .customer_id("CUST-001")
                .product_id("PROD-001")
                .valid_days(365)
                .feature("quantum-safe")
                .feature("binary-format")
                .build()
                .unwrap();

            let signed = generator.generate(data).unwrap();
            let binary = generator.export_binary(&signed).unwrap();

            let parsed = verifier.parse_license(&binary).unwrap();

            assert_eq!(parsed.data.id, signed.data.id);
            assert_eq!(parsed.algorithm, algorithm_ids::ML_DSA_65);
            assert!(verifier.validate(&parsed).is_ok());
        }

        #[test]
        fn test_pq_verifier_wrong_key() {
            let keypair = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();
            let wrong_keypair = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();

            let generator = CryptoGenerator::from_keypair(&keypair);

            // Use wrong public key
            let mut keys = std::collections::HashMap::new();
            keys.insert(
                algorithm_ids::ML_DSA_65.to_string(),
                wrong_keypair.public_key_pem.clone(),
            );
            let verifier = CryptoVerifier::new(keys);

            let data = LicenseData::builder()
                .id("PQ-WRONG-KEY-001")
                .serial("SN-PQ-WRONG-KEY")
                .customer_id("CUST-001")
                .product_id("PROD-001")
                .valid_days(365)
                .build()
                .unwrap();

            let signed = generator.generate(data).unwrap();

            // Should fail verification with wrong key
            assert!(verifier.verify_signature(&signed).is_err());
        }

        #[test]
        fn test_pq_verifier_multi_algorithm() {
            // Generate keys for multiple algorithms including PQ
            let rsa_keypair = CryptoKeyPair::generate(algorithm_ids::RSA_SHA256).unwrap();
            let ed25519_keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
            let ml_dsa_keypair = CryptoKeyPair::generate(algorithm_ids::ML_DSA_65).unwrap();
            let hybrid_keypair =
                CryptoKeyPair::generate(algorithm_ids::HYBRID_ED25519_ML_DSA_65).unwrap();

            // Create verifier with all public keys
            let mut keys = std::collections::HashMap::new();
            keys.insert(
                algorithm_ids::RSA_SHA256.to_string(),
                rsa_keypair.public_key_pem.clone(),
            );
            keys.insert(
                algorithm_ids::ED25519.to_string(),
                ed25519_keypair.public_key_pem.clone(),
            );
            keys.insert(
                algorithm_ids::ML_DSA_65.to_string(),
                ml_dsa_keypair.public_key_pem.clone(),
            );
            keys.insert(
                algorithm_ids::HYBRID_ED25519_ML_DSA_65.to_string(),
                hybrid_keypair.public_key_pem.clone(),
            );
            let verifier = CryptoVerifier::new(keys);

            // Generate and verify licenses with each algorithm
            for (keypair, alg_name) in [
                (&rsa_keypair, "RSA"),
                (&ed25519_keypair, "Ed25519"),
                (&ml_dsa_keypair, "ML-DSA-65"),
                (&hybrid_keypair, "Hybrid"),
            ] {
                let generator = CryptoGenerator::from_keypair(keypair);
                let data = LicenseData::builder()
                    .id(format!("MULTI-{}-001", alg_name))
                    .serial(format!("SN-MULTI-{}", alg_name))
                    .customer_id("CUST-001")
                    .product_id("PROD-001")
                    .valid_days(365)
                    .build()
                    .unwrap();

                let signed = generator.generate(data).unwrap();
                assert!(
                    verifier.validate(&signed).is_ok(),
                    "Failed to verify {} license",
                    alg_name
                );
            }
        }

        #[test]
        fn test_pq_verifier_detailed_validation() {
            let keypair = CryptoKeyPair::generate(algorithm_ids::HYBRID_ED25519_ML_DSA_65).unwrap();
            let generator = CryptoGenerator::from_keypair(&keypair);

            let mut keys = std::collections::HashMap::new();
            keys.insert(
                algorithm_ids::HYBRID_ED25519_ML_DSA_65.to_string(),
                keypair.public_key_pem.clone(),
            );
            let verifier = CryptoVerifier::new(keys);

            let data = LicenseData::builder()
                .id("PQ-DETAILED-001")
                .serial("SN-PQ-DETAILED")
                .customer_id("CUST-001")
                .product_id("PROD-001")
                .valid_days(365)
                .build()
                .unwrap();

            let signed = generator.generate(data).unwrap();
            let result = verifier.validate_detailed(&signed);

            assert!(result.is_valid);
            assert!(result.signature_valid);
            assert!(result.expiration_valid);
            assert!(result.hardware_valid);
            assert!(result.days_remaining > 0);
            assert!(result.error.is_none());
        }
    }
}
