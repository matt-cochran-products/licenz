//! License generation functionality (server-side)

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

        let signature = signing_key
            .sign_with_rng(&mut rng, data);

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
