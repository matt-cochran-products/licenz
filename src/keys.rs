//! Key management for license signing and verification
//!
//! This module provides key management functionality that works with the
//! pluggable cryptographic architecture. It maintains backward compatibility
//! with RSA keys while supporting new algorithms like Ed25519.
//!
//! # Example
//!
//! ```rust,no_run
//! use licenz_core::keys::{CryptoKeyPair, KeyPair, KeySize};
//! use licenz_core::crypto::algorithm_ids;
//!
//! // Legacy RSA key pair (backward compatible)
//! let rsa_keypair = KeyPair::generate(KeySize::Bits2048).unwrap();
//!
//! // New algorithm-agnostic key pair
//! let ed25519_keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
//! let rsa_keypair = CryptoKeyPair::generate(algorithm_ids::RSA_SHA256).unwrap();
//! ```

use crate::crypto::{algorithm_ids, CryptoRegistry, SignatureAlgorithm};
use crate::error::{LicenseError, Result};
use pem::{encode, Pem};
use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::path::Path;

/// Supported RSA key sizes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeySize {
    #[default]
    Bits2048,
    Bits3072,
    Bits4096,
}

impl KeySize {
    pub fn bits(&self) -> usize {
        match self {
            KeySize::Bits2048 => 2048,
            KeySize::Bits3072 => 3072,
            KeySize::Bits4096 => 4096,
        }
    }
}

/// RSA key pair for license signing
pub struct KeyPair {
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
}

impl KeyPair {
    /// Generate a new RSA key pair
    pub fn generate(size: KeySize) -> Result<Self> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, size.bits())
            .map_err(|e| LicenseError::KeyGenerationFailed(e.to_string()))?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Export the private key as PEM string
    pub fn export_private_pem(&self) -> Result<String> {
        let der = self
            .private_key
            .to_pkcs8_der()
            .map_err(|e| LicenseError::InvalidKeyFormat(e.to_string()))?;

        let pem = Pem::new("PRIVATE KEY", der.as_bytes());
        Ok(encode(&pem))
    }

    /// Export the public key as PEM string
    pub fn export_public_pem(&self) -> Result<String> {
        let der = self
            .public_key
            .to_public_key_der()
            .map_err(|e| LicenseError::InvalidKeyFormat(e.to_string()))?;

        let pem = Pem::new("PUBLIC KEY", der.as_bytes());
        Ok(encode(&pem))
    }

    /// Save the key pair to files
    pub fn save_to_files(&self, private_path: &Path, public_path: &Path) -> Result<()> {
        std::fs::write(private_path, self.export_private_pem()?)?;
        std::fs::write(public_path, self.export_public_pem()?)?;
        Ok(())
    }

    /// Load a key pair from files
    pub fn load_from_files(private_path: &Path, public_path: &Path) -> Result<Self> {
        let private_pem = std::fs::read_to_string(private_path)?;
        let public_pem = std::fs::read_to_string(public_path)?;

        let private_key = parse_private_key(&private_pem)?;
        let public_key = parse_public_key(&public_pem)?;

        Ok(Self {
            private_key,
            public_key,
        })
    }
}

/// Parse a private key from PEM format
pub fn parse_private_key(pem_str: &str) -> Result<RsaPrivateKey> {
    // Handle escaped newlines (from LDFLAGS injection)
    let pem_str = pem_str.replace("\\n", "\n");

    // Try PKCS#8 format first
    if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(&pem_str) {
        return Ok(key);
    }

    // Try PKCS#1 format
    if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(&pem_str) {
        return Ok(key);
    }

    Err(LicenseError::InvalidKeyFormat(
        "Could not parse private key (tried PKCS#8 and PKCS#1 formats)".into(),
    ))
}

/// Parse a public key from PEM format
pub fn parse_public_key(pem_str: &str) -> Result<RsaPublicKey> {
    // Handle escaped newlines (from LDFLAGS injection or env vars)
    let pem_str = pem_str.replace("\\n", "\n");

    // Try SPKI format first (most common)
    if let Ok(key) = RsaPublicKey::from_public_key_pem(&pem_str) {
        return Ok(key);
    }

    // Try PKCS#1 format
    if let Ok(key) = RsaPublicKey::from_pkcs1_pem(&pem_str) {
        return Ok(key);
    }

    Err(LicenseError::InvalidKeyFormat(
        "Could not parse public key (tried SPKI and PKCS#1 formats)".into(),
    ))
}

/// Extract the public key from a private key
pub fn extract_public_key(private_key: &RsaPrivateKey) -> RsaPublicKey {
    RsaPublicKey::from(private_key)
}

/// Algorithm-agnostic key pair that works with any supported signature algorithm
///
/// This struct provides a unified interface for key management across different
/// cryptographic algorithms (RSA, Ed25519, etc.).
#[derive(Debug, Clone)]
pub struct CryptoKeyPair {
    /// The private key in PEM format
    pub private_key_pem: String,
    /// The public key in PEM format
    pub public_key_pem: String,
    /// The algorithm identifier (e.g., "RSA-SHA256", "Ed25519")
    pub algorithm_id: String,
}

impl CryptoKeyPair {
    /// Generate a new key pair using the specified algorithm
    ///
    /// # Arguments
    /// * `algorithm_id` - The algorithm to use (e.g., "RSA-SHA256", "Ed25519")
    ///
    /// # Example
    /// ```rust,no_run
    /// use licenz_core::keys::CryptoKeyPair;
    /// use licenz_core::crypto::algorithm_ids;
    ///
    /// let keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
    /// ```
    pub fn generate(algorithm_id: &str) -> Result<Self> {
        let algorithm = CryptoRegistry::get_signature_algorithm(algorithm_id)?;
        let (private_key_pem, public_key_pem) = algorithm.generate_keypair()?;
        Ok(Self {
            private_key_pem,
            public_key_pem,
            algorithm_id: algorithm_id.to_string(),
        })
    }

    /// Create from existing PEM keys
    ///
    /// # Arguments
    /// * `private_key_pem` - The private key in PEM format
    /// * `public_key_pem` - The public key in PEM format
    /// * `algorithm_id` - The algorithm identifier
    pub fn from_pem(private_key_pem: String, public_key_pem: String, algorithm_id: &str) -> Self {
        Self {
            private_key_pem,
            public_key_pem,
            algorithm_id: algorithm_id.to_string(),
        }
    }

    /// Load a key pair from files
    ///
    /// # Arguments
    /// * `private_path` - Path to the private key PEM file
    /// * `public_path` - Path to the public key PEM file
    /// * `algorithm_id` - The algorithm identifier
    pub fn load_from_files(
        private_path: &Path,
        public_path: &Path,
        algorithm_id: &str,
    ) -> Result<Self> {
        let private_key_pem = std::fs::read_to_string(private_path)?;
        let public_key_pem = std::fs::read_to_string(public_path)?;
        Ok(Self::from_pem(
            private_key_pem,
            public_key_pem,
            algorithm_id,
        ))
    }

    /// Save the key pair to files
    pub fn save_to_files(&self, private_path: &Path, public_path: &Path) -> Result<()> {
        std::fs::write(private_path, &self.private_key_pem)?;
        std::fs::write(public_path, &self.public_key_pem)?;
        Ok(())
    }

    /// Sign data using this key pair's private key
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let algorithm = CryptoRegistry::get_signature_algorithm(&self.algorithm_id)?;
        algorithm.sign(data, &self.private_key_pem)
    }

    /// Verify a signature using this key pair's public key
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        let algorithm = CryptoRegistry::get_signature_algorithm(&self.algorithm_id)?;
        algorithm.verify(data, signature, &self.public_key_pem)
    }

    /// Get the signature algorithm for this key pair
    pub fn get_algorithm(&self) -> Result<&'static dyn SignatureAlgorithm> {
        CryptoRegistry::get_signature_algorithm(&self.algorithm_id)
    }

    /// Convert a legacy RSA KeyPair to a CryptoKeyPair
    pub fn from_rsa_keypair(keypair: &KeyPair) -> Result<Self> {
        Ok(Self {
            private_key_pem: keypair.export_private_pem()?,
            public_key_pem: keypair.export_public_pem()?,
            algorithm_id: algorithm_ids::RSA_SHA256.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = KeyPair::generate(KeySize::Bits2048).unwrap();

        let private_pem = keypair.export_private_pem().unwrap();
        let public_pem = keypair.export_public_pem().unwrap();

        assert!(private_pem.contains("PRIVATE KEY"));
        assert!(public_pem.contains("PUBLIC KEY"));
    }

    #[test]
    fn test_key_round_trip() {
        let keypair = KeyPair::generate(KeySize::Bits2048).unwrap();

        let private_pem = keypair.export_private_pem().unwrap();
        let public_pem = keypair.export_public_pem().unwrap();

        let parsed_private = parse_private_key(&private_pem).unwrap();
        let parsed_public = parse_public_key(&public_pem).unwrap();

        assert_eq!(keypair.private_key, parsed_private);
        assert_eq!(keypair.public_key, parsed_public);
    }

    #[test]
    fn test_crypto_keypair_rsa() {
        let keypair = CryptoKeyPair::generate(algorithm_ids::RSA_SHA256).unwrap();
        assert_eq!(keypair.algorithm_id, algorithm_ids::RSA_SHA256);
        assert!(keypair.private_key_pem.contains("PRIVATE KEY"));
        assert!(keypair.public_key_pem.contains("PUBLIC KEY"));

        // Test sign and verify
        let data = b"test message for RSA";
        let signature = keypair.sign(data).unwrap();
        assert!(keypair.verify(data, &signature).is_ok());
    }

    #[test]
    fn test_crypto_keypair_ed25519() {
        let keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
        assert_eq!(keypair.algorithm_id, algorithm_ids::ED25519);
        assert!(keypair.private_key_pem.contains("PRIVATE KEY"));
        assert!(keypair.public_key_pem.contains("PUBLIC KEY"));

        // Test sign and verify
        let data = b"test message for Ed25519";
        let signature = keypair.sign(data).unwrap();
        assert!(keypair.verify(data, &signature).is_ok());

        // Ed25519 signatures are always 64 bytes
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_crypto_keypair_from_rsa_keypair() {
        let rsa_keypair = KeyPair::generate(KeySize::Bits2048).unwrap();
        let crypto_keypair = CryptoKeyPair::from_rsa_keypair(&rsa_keypair).unwrap();

        assert_eq!(crypto_keypair.algorithm_id, algorithm_ids::RSA_SHA256);

        // Test that signing works
        let data = b"conversion test";
        let signature = crypto_keypair.sign(data).unwrap();
        assert!(crypto_keypair.verify(data, &signature).is_ok());
    }
}
