//! License generation functionality (server-side)
//!
//! This module provides license generation using the pluggable cryptographic
//! architecture. It supports multiple signature algorithms (RSA-SHA256, Ed25519, etc.).
//!
//! # Example
//!
//! ```rust,ignore
//! use licenz_core::generator::{CryptoGenerator, LicenseGenerator};
//! use licenz_core::crypto::algorithm_ids;
//!
//! // New algorithm-agnostic generator (recommended)
//! let generator = CryptoGenerator::new(private_key_pem, algorithm_ids::ED25519);
//! let license = generator.generate(license_data).unwrap();
//!
//! // Legacy RSA-only generator (backward compatible)
//! let generator = LicenseGenerator::new(rsa_private_key);
//! ```

use crate::crypto::CryptoRegistry;
use crate::error::{LicenseError, Result};
use crate::keys::parse_private_key;
use crate::license::{LicenseData, SignedLicense, BINARY_MAGIC, BINARY_VERSION};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::RsaPrivateKey;
use sha2::Sha256;
use std::io::Write;
use std::path::Path;

/// License generator for creating and signing licenses
pub struct LicenseGenerator {
    private_key: RsaPrivateKey,
}

impl LicenseGenerator {
    /// Create a new license generator with a private key
    pub fn new(private_key: RsaPrivateKey) -> Self {
        Self { private_key }
    }

    /// Create a new license generator from a PEM string
    pub fn from_pem(pem: &str) -> Result<Self> {
        let private_key = parse_private_key(pem)?;
        Ok(Self::new(private_key))
    }

    /// Create a new license generator from a PEM file
    pub fn from_pem_file(path: &Path) -> Result<Self> {
        let pem = std::fs::read_to_string(path)?;
        Self::from_pem(&pem)
    }

    /// Generate a signed license from license data
    pub fn generate(&self, data: LicenseData) -> Result<SignedLicense> {
        // Serialize the data to sign
        let data_bytes = serde_json::to_vec(&data)
            .map_err(|e| LicenseError::SerializationError(e.to_string()))?;

        // Sign the data
        let signature = self.sign(&data_bytes)?;

        Ok(SignedLicense {
            data,
            signature: BASE64.encode(&signature),
            algorithm: "RSA-SHA256".to_string(),
        })
    }

    /// Sign arbitrary data
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::<Sha256>::new_unprefixed(self.private_key.clone());
        let mut rng = rand::rngs::OsRng;

        let signature = signing_key.sign_with_rng(&mut rng, data);

        Ok(signature.to_bytes().to_vec())
    }

    /// Export a signed license to binary format
    pub fn export_binary(&self, license: &SignedLicense) -> Result<Vec<u8>> {
        let mut output = Vec::new();

        // Write magic header
        output.write_all(BINARY_MAGIC)?;

        // Write version
        output.write_all(&[BINARY_VERSION])?;

        // Serialize the license as JSON (more robust than bincode for complex types)
        let encoded = serde_json::to_vec(license)
            .map_err(|e| LicenseError::SerializationError(e.to_string()))?;

        // Write length as u32 little-endian
        let len = encoded.len() as u32;
        output.write_all(&len.to_le_bytes())?;

        // Write the encoded license
        output.write_all(&encoded)?;

        Ok(output)
    }

    /// Export a signed license to JSON format (legacy)
    pub fn export_json(&self, license: &SignedLicense) -> Result<String> {
        serde_json::to_string_pretty(license)
            .map_err(|e| LicenseError::SerializationError(e.to_string()))
    }

    /// Save a license to a binary file
    pub fn save_binary(&self, license: &SignedLicense, path: &Path) -> Result<()> {
        let binary = self.export_binary(license)?;
        std::fs::write(path, binary)?;
        Ok(())
    }

    /// Save a license to a JSON file (legacy)
    pub fn save_json(&self, license: &SignedLicense, path: &Path) -> Result<()> {
        let json = self.export_json(license)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

/// Algorithm-agnostic license generator that supports multiple signature algorithms
///
/// This generator uses the pluggable cryptographic architecture to support
/// different signature algorithms (RSA-SHA256, Ed25519, etc.).
///
/// # Example
///
/// ```rust,ignore
/// use licenz_core::generator::CryptoGenerator;
/// use licenz_core::crypto::algorithm_ids;
/// use licenz_core::keys::CryptoKeyPair;
///
/// // Generate keys
/// let keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
///
/// // Create generator
/// let generator = CryptoGenerator::new(&keypair.private_key_pem, algorithm_ids::ED25519);
///
/// // Generate license
/// let license = generator.generate(license_data).unwrap();
/// assert_eq!(license.algorithm, "Ed25519");
/// ```
pub struct CryptoGenerator {
    /// Private key in PEM format
    private_key_pem: String,
    /// Algorithm identifier
    algorithm_id: String,
}

impl CryptoGenerator {
    /// Create a new crypto generator with the specified algorithm
    ///
    /// # Arguments
    /// * `private_key_pem` - The private key in PEM format
    /// * `algorithm_id` - The algorithm to use (e.g., "RSA-SHA256", "Ed25519")
    pub fn new(private_key_pem: &str, algorithm_id: &str) -> Self {
        Self {
            private_key_pem: private_key_pem.to_string(),
            algorithm_id: algorithm_id.to_string(),
        }
    }

    /// Create a generator from a PEM file
    pub fn from_pem_file(path: &Path, algorithm_id: &str) -> Result<Self> {
        let pem = std::fs::read_to_string(path)?;
        Ok(Self::new(&pem, algorithm_id))
    }

    /// Create a generator from a CryptoKeyPair
    pub fn from_keypair(keypair: &crate::keys::CryptoKeyPair) -> Self {
        Self::new(&keypair.private_key_pem, &keypair.algorithm_id)
    }

    /// Get the algorithm ID
    pub fn algorithm_id(&self) -> &str {
        &self.algorithm_id
    }

    /// Generate a signed license from license data
    pub fn generate(&self, data: LicenseData) -> Result<SignedLicense> {
        // Serialize the data to sign
        let data_bytes = serde_json::to_vec(&data)
            .map_err(|e| LicenseError::SerializationError(e.to_string()))?;

        // Get the algorithm and sign
        let algorithm = CryptoRegistry::get_signature_algorithm(&self.algorithm_id)?;
        let signature = algorithm.sign(&data_bytes, &self.private_key_pem)?;

        Ok(SignedLicense {
            data,
            signature: BASE64.encode(&signature),
            algorithm: self.algorithm_id.clone(),
        })
    }

    /// Export a signed license to binary format
    pub fn export_binary(&self, license: &SignedLicense) -> Result<Vec<u8>> {
        let mut output = Vec::new();

        // Write magic header
        output.write_all(BINARY_MAGIC)?;

        // Write version
        output.write_all(&[BINARY_VERSION])?;

        // Serialize the license as JSON
        let encoded = serde_json::to_vec(license)
            .map_err(|e| LicenseError::SerializationError(e.to_string()))?;

        // Write length as u32 little-endian
        let len = encoded.len() as u32;
        output.write_all(&len.to_le_bytes())?;

        // Write the encoded license
        output.write_all(&encoded)?;

        Ok(output)
    }

    /// Export a signed license to JSON format
    pub fn export_json(&self, license: &SignedLicense) -> Result<String> {
        serde_json::to_string_pretty(license)
            .map_err(|e| LicenseError::SerializationError(e.to_string()))
    }

    /// Save a license to a binary file
    pub fn save_binary(&self, license: &SignedLicense, path: &Path) -> Result<()> {
        let binary = self.export_binary(license)?;
        std::fs::write(path, binary)?;
        Ok(())
    }

    /// Save a license to a JSON file
    pub fn save_json(&self, license: &SignedLicense, path: &Path) -> Result<()> {
        let json = self.export_json(license)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm_ids;
    use crate::keys::KeyPair;
    use crate::keys::KeySize;

    #[test]
    fn test_license_generation() {
        let keypair = KeyPair::generate(KeySize::Bits2048).unwrap();
        let generator = LicenseGenerator::new(keypair.private_key);

        let data = LicenseData::builder()
            .id("TEST-001")
            .serial("SN-12345")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .feature("basic")
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();

        assert!(!signed.signature.is_empty());
        assert_eq!(signed.algorithm, "RSA-SHA256");
    }

    #[test]
    fn test_binary_export() {
        let keypair = KeyPair::generate(KeySize::Bits2048).unwrap();
        let generator = LicenseGenerator::new(keypair.private_key);

        let data = LicenseData::builder()
            .id("TEST-001")
            .serial("SN-12345")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();
        let binary = generator.export_binary(&signed).unwrap();

        // Check magic header
        assert_eq!(&binary[0..4], BINARY_MAGIC);
        assert_eq!(binary[4], BINARY_VERSION);
    }

    #[test]
    fn test_crypto_generator_rsa() {
        use crate::keys::CryptoKeyPair;

        let keypair = CryptoKeyPair::generate(algorithm_ids::RSA_SHA256).unwrap();
        let generator = CryptoGenerator::from_keypair(&keypair);

        let data = LicenseData::builder()
            .id("CRYPTO-RSA-001")
            .serial("SN-CRYPTO-RSA")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .feature("basic")
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();

        assert!(!signed.signature.is_empty());
        assert_eq!(signed.algorithm, algorithm_ids::RSA_SHA256);
    }

    #[test]
    fn test_crypto_generator_ed25519() {
        use crate::keys::CryptoKeyPair;

        let keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
        let generator = CryptoGenerator::from_keypair(&keypair);

        let data = LicenseData::builder()
            .id("CRYPTO-ED25519-001")
            .serial("SN-CRYPTO-ED25519")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .feature("basic")
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();

        assert!(!signed.signature.is_empty());
        assert_eq!(signed.algorithm, algorithm_ids::ED25519);

        // Verify the signature is valid
        let algorithm = CryptoRegistry::get_signature_algorithm(algorithm_ids::ED25519).unwrap();
        let data_bytes = serde_json::to_vec(&signed.data).unwrap();
        let sig_bytes = BASE64.decode(&signed.signature).unwrap();
        assert!(algorithm
            .verify(&data_bytes, &sig_bytes, &keypair.public_key_pem)
            .is_ok());
    }

    #[test]
    fn test_crypto_generator_binary_export() {
        use crate::keys::CryptoKeyPair;

        let keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
        let generator = CryptoGenerator::from_keypair(&keypair);

        let data = LicenseData::builder()
            .id("BINARY-ED25519-001")
            .serial("SN-BINARY-ED25519")
            .customer_id("CUST-001")
            .product_id("PROD-001")
            .valid_days(365)
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();
        let binary = generator.export_binary(&signed).unwrap();

        // Check magic header
        assert_eq!(&binary[0..4], BINARY_MAGIC);
        assert_eq!(binary[4], BINARY_VERSION);
    }

    // Post-quantum generator tests (feature-gated)
    #[cfg(feature = "post-quantum")]
    mod pq_tests {
        use super::*;
        use crate::crypto::algorithm_ids;
        use crate::keys::CryptoKeyPair;

        #[test]
        fn test_crypto_generator_dilithium3() {
            let keypair = CryptoKeyPair::generate(algorithm_ids::DILITHIUM3).unwrap();
            let generator = CryptoGenerator::from_keypair(&keypair);

            let data = LicenseData::builder()
                .id("PQ-DILITHIUM-001")
                .serial("SN-PQ-DILITHIUM")
                .customer_id("CUST-001")
                .product_id("PROD-001")
                .valid_days(365)
                .feature("quantum-safe")
                .build()
                .unwrap();

            let signed = generator.generate(data).unwrap();

            assert!(!signed.signature.is_empty());
            assert_eq!(signed.algorithm, algorithm_ids::DILITHIUM3);

            // Dilithium3 signatures are ~3293 bytes, base64 encoded is ~4400 chars
            assert!(signed.signature.len() > 4000);
        }

        #[test]
        fn test_crypto_generator_hybrid_ed25519_dilithium() {
            let keypair =
                CryptoKeyPair::generate(algorithm_ids::HYBRID_ED25519_DILITHIUM3).unwrap();
            let generator = CryptoGenerator::from_keypair(&keypair);

            let data = LicenseData::builder()
                .id("PQ-HYBRID-001")
                .serial("SN-PQ-HYBRID")
                .customer_id("CUST-001")
                .product_id("PROD-001")
                .valid_days(365)
                .feature("hybrid-security")
                .build()
                .unwrap();

            let signed = generator.generate(data).unwrap();

            assert!(!signed.signature.is_empty());
            assert_eq!(signed.algorithm, algorithm_ids::HYBRID_ED25519_DILITHIUM3);
        }

        #[test]
        fn test_crypto_generator_hybrid_rsa_dilithium() {
            let keypair = CryptoKeyPair::generate(algorithm_ids::HYBRID_RSA_DILITHIUM3).unwrap();
            let generator = CryptoGenerator::from_keypair(&keypair);

            let data = LicenseData::builder()
                .id("PQ-HYBRID-RSA-001")
                .serial("SN-PQ-HYBRID-RSA")
                .customer_id("CUST-001")
                .product_id("PROD-001")
                .valid_days(365)
                .feature("hybrid-rsa-security")
                .build()
                .unwrap();

            let signed = generator.generate(data).unwrap();

            assert!(!signed.signature.is_empty());
            assert_eq!(signed.algorithm, algorithm_ids::HYBRID_RSA_DILITHIUM3);
        }

        #[test]
        fn test_pq_license_binary_export() {
            let keypair = CryptoKeyPair::generate(algorithm_ids::DILITHIUM3).unwrap();
            let generator = CryptoGenerator::from_keypair(&keypair);

            let data = LicenseData::builder()
                .id("PQ-BINARY-001")
                .serial("SN-PQ-BINARY")
                .customer_id("CUST-001")
                .product_id("PROD-001")
                .valid_days(365)
                .build()
                .unwrap();

            let signed = generator.generate(data).unwrap();
            let binary = generator.export_binary(&signed).unwrap();

            // Check magic header
            assert_eq!(&binary[0..4], BINARY_MAGIC);
            assert_eq!(binary[4], BINARY_VERSION);

            // Binary should be larger due to PQ signature (~3293 bytes signature + overhead)
            // Dilithium3 signature: 3293 bytes, base64 encoded: ~4412 chars
            // License data + JSON overhead: ~350 bytes
            // Total expected: ~4700+ bytes
            assert!(
                binary.len() > 4500,
                "Expected binary > 4500 bytes, got {} bytes. Signature len: {}",
                binary.len(),
                signed.signature.len()
            );
        }
    }
}
