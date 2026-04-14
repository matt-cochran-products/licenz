//! Ed25519 signature algorithm implementation.
//!
//! This module implements the `SignatureAlgorithm` trait for Ed25519,
//! providing a modern, fast, and secure alternative to RSA.
//!
//! Ed25519 advantages:
//! - Much smaller keys and signatures than RSA
//! - Faster signing and verification
//! - No padding schemes or key size choices needed
//! - Strong security with 128-bit security level

use super::SignatureAlgorithm;
use crate::error::{LicenseError, Result};
use ed25519_dalek::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH,
};
use pem::{encode, parse, Pem};
use rand::rngs::OsRng;

/// Ed25519 signature algorithm implementation
pub struct Ed25519Signer;

impl Default for Ed25519Signer {
    fn default() -> Self {
        Self::new()
    }
}

impl Ed25519Signer {
    /// Create a new Ed25519 signer
    pub fn new() -> Self {
        Self
    }

    /// Parse an Ed25519 private key from PEM format
    ///
    /// Supports PKCS#8 format ("PRIVATE KEY") and raw Ed25519 format ("ED25519 PRIVATE KEY")
    fn parse_private_key(pem_str: &str) -> Result<SigningKey> {
        // Handle escaped newlines
        let pem_str = pem_str.replace("\\n", "\n");

        // Try PKCS#8 PEM first (standard format)
        if let Ok(key) = SigningKey::from_pkcs8_pem(&pem_str) {
            return Ok(key);
        }

        // Try raw Ed25519 private key format
        let pem = parse(&pem_str)
            .map_err(|e| LicenseError::InvalidKeyFormat(format!("Failed to parse PEM: {}", e)))?;

        match pem.tag() {
            "ED25519 PRIVATE KEY" => {
                let key_bytes: [u8; SECRET_KEY_LENGTH] =
                    pem.contents().try_into().map_err(|_| {
                        LicenseError::InvalidKeyFormat(format!(
                            "Invalid Ed25519 private key length: expected {}, got {}",
                            SECRET_KEY_LENGTH,
                            pem.contents().len()
                        ))
                    })?;
                Ok(SigningKey::from_bytes(&key_bytes))
            }
            "PRIVATE KEY" => {
                // PKCS#8 DER that the pem crate parsed but ed25519-dalek rejected above;
                // this shouldn't normally happen, but give a clear error
                Err(LicenseError::InvalidKeyFormat(
                    "PKCS#8 private key parsed as PEM but could not be decoded as Ed25519".into(),
                ))
            }
            tag => Err(LicenseError::InvalidKeyFormat(format!(
                "Unexpected PEM tag for Ed25519 private key: {}",
                tag
            ))),
        }
    }

    /// Parse an Ed25519 public key from PEM format
    fn parse_public_key(pem_str: &str) -> Result<VerifyingKey> {
        // Handle escaped newlines
        let pem_str = pem_str.replace("\\n", "\n");

        // Try SPKI PEM first (standard format)
        if let Ok(key) = VerifyingKey::from_public_key_pem(&pem_str) {
            return Ok(key);
        }

        // Try raw Ed25519 public key format
        let pem = parse(&pem_str)
            .map_err(|e| LicenseError::InvalidKeyFormat(format!("Failed to parse PEM: {}", e)))?;

        match pem.tag() {
            "ED25519 PUBLIC KEY" => {
                let key_bytes: [u8; 32] = pem.contents().try_into().map_err(|_| {
                    LicenseError::InvalidKeyFormat(format!(
                        "Invalid Ed25519 public key length: expected 32, got {}",
                        pem.contents().len()
                    ))
                })?;
                VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
                    LicenseError::InvalidKeyFormat(format!("Invalid Ed25519 public key: {}", e))
                })
            }
            "PUBLIC KEY" => Err(LicenseError::InvalidKeyFormat(
                "SPKI public key parsed as PEM but could not be decoded as Ed25519".into(),
            )),
            tag => Err(LicenseError::InvalidKeyFormat(format!(
                "Unexpected PEM tag for Ed25519 public key: {}",
                tag
            ))),
        }
    }

    /// Encode a private key to PKCS#8 PEM format
    fn encode_private_key_pkcs8(signing_key: &SigningKey) -> Result<String> {
        let der = signing_key.to_pkcs8_der().map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to encode PKCS#8 private key: {}", e))
        })?;
        Ok(encode(&Pem::new("PRIVATE KEY", der.as_bytes())))
    }

    /// Encode a public key to SPKI PEM format
    fn encode_public_key_spki(verifying_key: &VerifyingKey) -> Result<String> {
        let der = verifying_key.to_public_key_der().map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to encode SPKI public key: {}", e))
        })?;
        Ok(encode(&Pem::new("PUBLIC KEY", der.as_bytes())))
    }
}

impl SignatureAlgorithm for Ed25519Signer {
    fn algorithm_id(&self) -> &'static str {
        super::algorithm_ids::ED25519
    }

    fn sign(&self, data: &[u8], private_key_pem: &str) -> Result<Vec<u8>> {
        let signing_key = Self::parse_private_key(private_key_pem)?;
        let signature: Signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8], public_key_pem: &str) -> Result<()> {
        let verifying_key = Self::parse_public_key(public_key_pem)?;

        let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| {
            LicenseError::VerificationFailed(format!(
                "Invalid Ed25519 signature length: expected 64, got {}",
                signature.len()
            ))
        })?;

        let signature = Signature::from_bytes(&sig_bytes);

        verifying_key.verify(data, &signature).map_err(|e| {
            LicenseError::VerificationFailed(format!(
                "Ed25519 signature verification failed: {}",
                e
            ))
        })
    }

    fn generate_keypair(&self) -> Result<(String, String)> {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let private_pem = Self::encode_private_key_pkcs8(&signing_key)?;
        let public_pem = Self::encode_public_key_spki(&verifying_key)?;

        Ok((private_pem, public_pem))
    }

    fn extract_public_key(&self, private_key_pem: &str) -> Result<String> {
        let signing_key = Self::parse_private_key(private_key_pem)?;
        let verifying_key = signing_key.verifying_key();
        Self::encode_public_key_spki(&verifying_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_signer_algorithm_id() {
        let signer = Ed25519Signer::new();
        assert_eq!(signer.algorithm_id(), "Ed25519");
    }

    #[test]
    fn test_ed25519_generate_keypair() {
        let signer = Ed25519Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        assert!(private_pem.contains("PRIVATE KEY"));
        assert!(public_pem.contains("PUBLIC KEY"));
    }

    #[test]
    fn test_ed25519_sign_and_verify() {
        let signer = Ed25519Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        // Ed25519 signatures are always 64 bytes
        assert_eq!(signature.len(), 64);
        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_ed25519_verify_wrong_data() {
        let signer = Ed25519Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let wrong_data = b"Goodbye, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(wrong_data, &signature, &public_pem).is_err());
    }

    #[test]
    fn test_ed25519_verify_wrong_key() {
        let signer = Ed25519Signer::new();
        let (private_pem, _) = signer.generate_keypair().unwrap();
        let (_, other_public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(data, &signature, &other_public_pem).is_err());
    }

    #[test]
    fn test_ed25519_extract_public_key() {
        let signer = Ed25519Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let extracted = signer.extract_public_key(&private_pem).unwrap();
        assert_eq!(extracted, public_pem);
    }

    #[test]
    fn test_ed25519_signature_size() {
        let signer = Ed25519Signer::new();
        let (private_pem, _) = signer.generate_keypair().unwrap();

        let data = b"Test data of various lengths to ensure consistent signature size";
        let signature = signer.sign(data, &private_pem).unwrap();

        // Ed25519 signatures are always exactly 64 bytes
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_ed25519_key_round_trip() {
        let signer = Ed25519Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        // Parse and re-encode to verify round-trip
        let signing_key = Ed25519Signer::parse_private_key(&private_pem).unwrap();
        let verifying_key = Ed25519Signer::parse_public_key(&public_pem).unwrap();

        // Verify the keys work after parsing
        let data = b"Round trip test";
        let signature: Signature = signing_key.sign(data);
        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    #[test]
    fn test_ed25519_empty_data() {
        let signer = Ed25519Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"";
        let signature = signer.sign(data, &private_pem).unwrap();
        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_ed25519_large_data() {
        let signer = Ed25519Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = vec![0xABu8; 10000];
        let signature = signer.sign(&data, &private_pem).unwrap();
        assert!(signer.verify(&data, &signature, &public_pem).is_ok());
    }
}
