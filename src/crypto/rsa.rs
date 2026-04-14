//! RSA-SHA256 signature algorithm implementation.
//!
//! This module implements the `SignatureAlgorithm` trait for RSA with SHA-256,
//! providing backward compatibility with existing RSA-signed licenses.

use super::SignatureAlgorithm;
use crate::error::{LicenseError, Result};
use pem::{encode, Pem};
use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

/// Default RSA key size in bits
pub const DEFAULT_KEY_SIZE: usize = 3072;

/// Supported RSA key sizes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RsaKeySize {
    Bits2048,
    #[default]
    Bits3072,
    Bits4096,
}

impl RsaKeySize {
    pub fn bits(&self) -> usize {
        match self {
            RsaKeySize::Bits2048 => 2048,
            RsaKeySize::Bits3072 => 3072,
            RsaKeySize::Bits4096 => 4096,
        }
    }
}

/// RSA-SHA256 signature algorithm implementation
pub struct RsaSigner {
    key_size: RsaKeySize,
}

impl Default for RsaSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl RsaSigner {
    /// Create a new RSA signer with default key size (2048 bits)
    pub fn new() -> Self {
        Self {
            key_size: RsaKeySize::default(),
        }
    }

    /// Create a new RSA signer with a specific key size
    pub fn with_key_size(key_size: RsaKeySize) -> Self {
        Self { key_size }
    }

    /// Parse a private key from PEM format
    fn parse_private_key(pem_str: &str) -> Result<RsaPrivateKey> {
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
            "Could not parse RSA private key (tried PKCS#8 and PKCS#1 formats)".into(),
        ))
    }

    /// Parse a public key from PEM format
    fn parse_public_key(pem_str: &str) -> Result<RsaPublicKey> {
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
            "Could not parse RSA public key (tried SPKI and PKCS#1 formats)".into(),
        ))
    }
}

impl SignatureAlgorithm for RsaSigner {
    fn algorithm_id(&self) -> &'static str {
        super::algorithm_ids::RSA_SHA256
    }

    fn sign(&self, data: &[u8], private_key_pem: &str) -> Result<Vec<u8>> {
        let private_key = Self::parse_private_key(private_key_pem)?;
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let mut rng = OsRng;

        let signature = signing_key.sign_with_rng(&mut rng, data);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8], public_key_pem: &str) -> Result<()> {
        let public_key = Self::parse_public_key(public_key_pem)?;
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);

        let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(|e| {
            LicenseError::VerificationFailed(format!("Invalid RSA signature format: {}", e))
        })?;

        verifying_key.verify(data, &sig).map_err(|e| {
            LicenseError::VerificationFailed(format!("RSA signature verification failed: {}", e))
        })
    }

    fn generate_keypair(&self) -> Result<(String, String)> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, self.key_size.bits())
            .map_err(|e| LicenseError::KeyGenerationFailed(e.to_string()))?;
        let public_key = RsaPublicKey::from(&private_key);

        let private_der = private_key
            .to_pkcs8_der()
            .map_err(|e| LicenseError::InvalidKeyFormat(e.to_string()))?;
        let public_der = public_key
            .to_public_key_der()
            .map_err(|e| LicenseError::InvalidKeyFormat(e.to_string()))?;

        let private_pem = encode(&Pem::new("PRIVATE KEY", private_der.as_bytes()));
        let public_pem = encode(&Pem::new("PUBLIC KEY", public_der.as_bytes()));

        Ok((private_pem, public_pem))
    }

    fn extract_public_key(&self, private_key_pem: &str) -> Result<String> {
        let private_key = Self::parse_private_key(private_key_pem)?;
        let public_key = RsaPublicKey::from(&private_key);

        let public_der = public_key
            .to_public_key_der()
            .map_err(|e| LicenseError::InvalidKeyFormat(e.to_string()))?;
        let public_pem = encode(&Pem::new("PUBLIC KEY", public_der.as_bytes()));

        Ok(public_pem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_signer_algorithm_id() {
        let signer = RsaSigner::new();
        assert_eq!(signer.algorithm_id(), "RSA-SHA256");
    }

    #[test]
    fn test_rsa_generate_keypair() {
        let signer = RsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        assert!(private_pem.contains("PRIVATE KEY"));
        assert!(public_pem.contains("PUBLIC KEY"));
    }

    #[test]
    fn test_rsa_sign_and_verify() {
        let signer = RsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(!signature.is_empty());
        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_rsa_verify_wrong_data() {
        let signer = RsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let wrong_data = b"Goodbye, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(wrong_data, &signature, &public_pem).is_err());
    }

    #[test]
    fn test_rsa_verify_wrong_key() {
        let signer = RsaSigner::new();
        let (private_pem, _) = signer.generate_keypair().unwrap();
        let (_, other_public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(data, &signature, &other_public_pem).is_err());
    }

    #[test]
    fn test_rsa_extract_public_key() {
        let signer = RsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let extracted = signer.extract_public_key(&private_pem).unwrap();
        assert_eq!(extracted, public_pem);
    }

    #[test]
    fn test_rsa_key_sizes() {
        assert_eq!(RsaKeySize::Bits2048.bits(), 2048);
        assert_eq!(RsaKeySize::Bits3072.bits(), 3072);
        assert_eq!(RsaKeySize::Bits4096.bits(), 4096);
    }

    #[test]
    fn test_rsa_with_custom_key_size() {
        let signer = RsaSigner::with_key_size(RsaKeySize::Bits2048);
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Test data";
        let signature = signer.sign(data, &private_pem).unwrap();
        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }
}
