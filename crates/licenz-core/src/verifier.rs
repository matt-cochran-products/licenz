//! License verification functionality (client-side)

use crate::error::{LicenseError, Result};
use crate::hardware::{detect_hardware, verify_hardware_binding, HardwareBindingError, HardwareInfo};
use crate::keys::parse_public_key;
use crate::license::{LicenseFormat, SignedLicense, BINARY_MAGIC, BINARY_VERSION};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use rsa::pkcs1v15::VerifyingKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::Sha256;
use std::path::Path;

/// License verifier for validating licenses
#[derive(Clone)]
pub struct LicenseVerifier {
    public_key: RsaPublicKey,
    hardware_info: Option<HardwareInfo>,
}

impl LicenseVerifier {
    /// Create a new license verifier with a public key
    pub fn new(public_key: RsaPublicKey) -> Self {
        Self {
            public_key,
            hardware_info: None,
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
        self.hardware_info = Some(info);
        self
    }

    /// Get the current hardware info (auto-detected if not manually set)
    fn get_hardware_info(&self) -> HardwareInfo {
        self.hardware_info.clone().unwrap_or_else(detect_hardware)
    }

    /// Load a license from a file (auto-detects format)
    pub fn load_license(&self, path: &Path) -> Result<SignedLicense> {
        let bytes = std::fs::read(path)?;
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

        if data.len() < 9 + len {
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
        serde_json::from_slice(data)
            .map_err(|e| LicenseError::InvalidLicenseFormat(e.to_string()))
    }

    /// Verify the cryptographic signature of a license
    pub fn verify_signature(&self, license: &SignedLicense) -> Result<()> {
        // Serialize the data the same way it was signed
        let data_bytes = serde_json::to_vec(&license.data)
            .map_err(|e| LicenseError::SerializationError(e.to_string()))?;

        // Decode the signature
        let signature_bytes = BASE64
            .decode(&license.signature)
            .map_err(|e| LicenseError::InvalidLicenseFormat(format!("Invalid signature encoding: {}", e)))?;

        // Create verifying key
        let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(self.public_key.clone());

        // Parse signature
        let signature = rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice())
            .map_err(|e| LicenseError::VerificationFailed(format!("Invalid signature format: {}", e)))?;

        // Verify
        verifying_key
            .verify(&data_bytes, &signature)
            .map_err(|e| LicenseError::VerificationFailed(format!("Signature verification failed: {}", e)))
    }

    /// Verify that the license has not expired
    pub fn verify_expiration(&self, license: &SignedLicense) -> Result<()> {
        let now = Utc::now();

        if now < license.data.valid_from {
            return Err(LicenseError::NotYetValid(
                license.data.valid_from.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            ));
        }

        if now > license.data.valid_until {
            return Err(LicenseError::LicenseExpired(
                license.data.valid_until.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            ));
        }

        Ok(())
    }

    /// Verify hardware binding
    pub fn verify_hardware(&self, license: &SignedLicense) -> Result<()> {
        let hardware = self.get_hardware_info();

        verify_hardware_binding(&license.data.hardware_binding, &hardware)
            .map_err(|e| match e {
                HardwareBindingError::MacAddressMismatch { expected, found } => {
                    LicenseError::HardwareBindingMismatch {
                        field: "mac_address".to_string(),
                        expected,
                        actual: found.join(", "),
                    }
                }
                HardwareBindingError::HostnameMismatch { expected, found } => {
                    LicenseError::HardwareBindingMismatch {
                        field: "hostname".to_string(),
                        expected,
                        actual: found,
                    }
                }
                HardwareBindingError::DiskIdMismatch { expected, found } => {
                    LicenseError::HardwareBindingMismatch {
                        field: "disk_id".to_string(),
                        expected,
                        actual: found.join(", "),
                    }
                }
                HardwareBindingError::CustomMismatch { key, expected, found } => {
                    LicenseError::HardwareBindingMismatch {
                        field: key,
                        expected,
                        actual: found,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::LicenseGenerator;
    use crate::keys::{KeyPair, KeySize};
    use crate::license::LicenseData;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate(KeySize::Bits2048).unwrap()
    }

    #[test]
    fn test_license_verification() {
        let keypair = create_test_keypair();
        let generator = LicenseGenerator::new(keypair.private_key.clone());
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
        let generator = LicenseGenerator::new(keypair.private_key.clone());
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
        let generator = LicenseGenerator::new(keypair.private_key.clone());
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
}
