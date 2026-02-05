//! Dilithium3 post-quantum signature algorithm implementation.
//!
//! This module implements the `SignatureAlgorithm` trait for Dilithium3,
//! a lattice-based digital signature scheme selected by NIST for
//! post-quantum cryptography standardization (FIPS 204 / ML-DSA).
//!
//! Dilithium3 provides NIST Level 3 security (equivalent to AES-192),
//! offering a balance between security and performance.
//!
//! Key and signature sizes:
//! - Public key: ~1,952 bytes
//! - Private key: ~4,000 bytes
//! - Signature: ~3,293 bytes
//!
//! These are significantly larger than classical algorithms like Ed25519
//! (32/64/64 bytes) but provide quantum resistance.

use super::SignatureAlgorithm;
use crate::error::{LicenseError, Result};
use pem::{encode, parse, Pem};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

/// PEM tag for Dilithium3 private keys
const DILITHIUM3_PRIVATE_KEY_TAG: &str = "DILITHIUM3 PRIVATE KEY";

/// PEM tag for Dilithium3 public keys
const DILITHIUM3_PUBLIC_KEY_TAG: &str = "DILITHIUM3 PUBLIC KEY";

/// Dilithium3 signature algorithm implementation
///
/// Private key format: `[sk_len (4 bytes LE)] || [secret_key] || [public_key]`
/// This combined format allows reliable public key extraction.
pub struct Dilithium3Signer;

impl Default for Dilithium3Signer {
    fn default() -> Self {
        Self::new()
    }
}

impl Dilithium3Signer {
    /// Create a new Dilithium3 signer
    pub fn new() -> Self {
        Self
    }

    /// Parse a Dilithium3 private key from PEM format
    /// Supports both combined format (sk + pk) and legacy format (sk only)
    fn parse_private_key(pem_str: &str) -> Result<dilithium3::SecretKey> {
        // Handle escaped newlines
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse Dilithium3 PEM: {}", e))
        })?;

        if pem.tag() != DILITHIUM3_PRIVATE_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                DILITHIUM3_PRIVATE_KEY_TAG,
                pem.tag()
            )));
        }

        let contents = pem.contents();
        let sk_len = dilithium3::secret_key_bytes();
        let pk_len = dilithium3::public_key_bytes();
        let combined_len = 4 + sk_len + pk_len;

        // Check if this is the combined format (has length prefix)
        if contents.len() == combined_len && contents.len() >= 4 {
            let stored_sk_len = u32::from_le_bytes([contents[0], contents[1], contents[2], contents[3]]) as usize;
            if stored_sk_len == sk_len {
                // Combined format: extract just the secret key
                let sk_bytes = &contents[4..4 + sk_len];
                return dilithium3::SecretKey::from_bytes(sk_bytes).map_err(|e| {
                    LicenseError::InvalidKeyFormat(format!("Invalid Dilithium3 private key: {:?}", e))
                });
            }
        }

        // Legacy format: just the secret key bytes
        dilithium3::SecretKey::from_bytes(contents).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Invalid Dilithium3 private key: {:?}", e))
        })
    }

    /// Parse a Dilithium3 public key from PEM format
    fn parse_public_key(pem_str: &str) -> Result<dilithium3::PublicKey> {
        // Handle escaped newlines
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse Dilithium3 PEM: {}", e))
        })?;

        if pem.tag() != DILITHIUM3_PUBLIC_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                DILITHIUM3_PUBLIC_KEY_TAG,
                pem.tag()
            )));
        }

        dilithium3::PublicKey::from_bytes(pem.contents()).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Invalid Dilithium3 public key: {:?}", e))
        })
    }

    /// Encode a private key to PEM format (combined format with public key)
    fn encode_private_key(secret_key: &dilithium3::SecretKey, public_key: &dilithium3::PublicKey) -> String {
        let sk_bytes = secret_key.as_bytes();
        let pk_bytes = public_key.as_bytes();

        // Combined format: [sk_len (4 bytes LE)] || [secret_key] || [public_key]
        let mut combined = Vec::with_capacity(4 + sk_bytes.len() + pk_bytes.len());
        combined.extend_from_slice(&(sk_bytes.len() as u32).to_le_bytes());
        combined.extend_from_slice(sk_bytes);
        combined.extend_from_slice(pk_bytes);

        encode(&Pem::new(DILITHIUM3_PRIVATE_KEY_TAG, combined))
    }

    /// Encode a public key to PEM format
    fn encode_public_key(public_key: &dilithium3::PublicKey) -> String {
        let bytes = public_key.as_bytes();
        encode(&Pem::new(DILITHIUM3_PUBLIC_KEY_TAG, bytes))
    }

    /// Extract public key bytes from combined private key PEM
    fn extract_public_key_bytes(pem_str: &str) -> Result<Vec<u8>> {
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse Dilithium3 PEM: {}", e))
        })?;

        if pem.tag() != DILITHIUM3_PRIVATE_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                DILITHIUM3_PRIVATE_KEY_TAG,
                pem.tag()
            )));
        }

        let contents = pem.contents();
        let sk_len = dilithium3::secret_key_bytes();
        let pk_len = dilithium3::public_key_bytes();
        let combined_len = 4 + sk_len + pk_len;

        // Check if this is the combined format
        if contents.len() == combined_len && contents.len() >= 4 {
            let stored_sk_len = u32::from_le_bytes([contents[0], contents[1], contents[2], contents[3]]) as usize;
            if stored_sk_len == sk_len {
                // Combined format: extract the public key
                let pk_bytes = &contents[4 + sk_len..];
                return Ok(pk_bytes.to_vec());
            }
        }

        // Legacy format: cannot extract public key
        Err(LicenseError::InvalidKeyFormat(
            "Cannot extract public key from legacy private key format. Please regenerate the keypair.".to_string()
        ))
    }
}

impl SignatureAlgorithm for Dilithium3Signer {
    fn algorithm_id(&self) -> &'static str {
        super::algorithm_ids::DILITHIUM3
    }

    fn sign(&self, data: &[u8], private_key_pem: &str) -> Result<Vec<u8>> {
        let secret_key = Self::parse_private_key(private_key_pem)?;
        let signature = dilithium3::detached_sign(data, &secret_key);
        Ok(signature.as_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8], public_key_pem: &str) -> Result<()> {
        let public_key = Self::parse_public_key(public_key_pem)?;

        let sig = dilithium3::DetachedSignature::from_bytes(signature).map_err(|e| {
            LicenseError::VerificationFailed(format!(
                "Invalid Dilithium3 signature format: {:?}",
                e
            ))
        })?;

        dilithium3::verify_detached_signature(&sig, data, &public_key).map_err(|_| {
            LicenseError::VerificationFailed("Dilithium3 signature verification failed".to_string())
        })
    }

    fn generate_keypair(&self) -> Result<(String, String)> {
        let (public_key, secret_key) = dilithium3::keypair();

        // Use combined format that includes public key in private key PEM
        let private_pem = Self::encode_private_key(&secret_key, &public_key);
        let public_pem = Self::encode_public_key(&public_key);

        Ok((private_pem, public_pem))
    }

    fn extract_public_key(&self, private_key_pem: &str) -> Result<String> {
        // Extract public key from the combined private key format
        let pk_bytes = Self::extract_public_key_bytes(private_key_pem)?;
        let public_key = dilithium3::PublicKey::from_bytes(&pk_bytes).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!(
                "Failed to parse extracted public key: {:?}",
                e
            ))
        })?;

        Ok(Self::encode_public_key(&public_key))
    }
}

/// Get the size of Dilithium3 keys and signatures
pub mod sizes {
    use pqcrypto_dilithium::dilithium3;

    /// Size of the public key in bytes
    pub fn public_key_bytes() -> usize {
        dilithium3::public_key_bytes()
    }

    /// Size of the secret key in bytes
    pub fn secret_key_bytes() -> usize {
        dilithium3::secret_key_bytes()
    }

    /// Size of the signature in bytes
    pub fn signature_bytes() -> usize {
        dilithium3::signature_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium3_signer_algorithm_id() {
        let signer = Dilithium3Signer::new();
        assert_eq!(signer.algorithm_id(), "Dilithium3");
    }

    #[test]
    fn test_dilithium3_generate_keypair() {
        let signer = Dilithium3Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        assert!(private_pem.contains(DILITHIUM3_PRIVATE_KEY_TAG));
        assert!(public_pem.contains(DILITHIUM3_PUBLIC_KEY_TAG));
    }

    #[test]
    fn test_dilithium3_sign_and_verify() {
        let signer = Dilithium3Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, Post-Quantum World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        // Dilithium3 signatures are around 3293 bytes
        assert!(signature.len() > 3000);
        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_dilithium3_verify_wrong_data() {
        let signer = Dilithium3Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let wrong_data = b"Goodbye, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(wrong_data, &signature, &public_pem).is_err());
    }

    #[test]
    fn test_dilithium3_verify_wrong_key() {
        let signer = Dilithium3Signer::new();
        let (private_pem, _) = signer.generate_keypair().unwrap();
        let (_, other_public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(data, &signature, &other_public_pem).is_err());
    }

    #[test]
    fn test_dilithium3_extract_public_key() {
        let signer = Dilithium3Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let extracted = signer.extract_public_key(&private_pem).unwrap();

        // Verify that the extracted public key works for verification
        let data = b"Test data";
        let signature = signer.sign(data, &private_pem).unwrap();
        assert!(signer.verify(data, &signature, &extracted).is_ok());

        // The extracted key should match the original
        assert_eq!(extracted, public_pem);
    }

    #[test]
    fn test_dilithium3_key_sizes() {
        // Dilithium3 key sizes per NIST specification
        assert!(sizes::public_key_bytes() > 1900); // ~1952 bytes
        assert!(sizes::secret_key_bytes() > 3900); // ~4000 bytes
        assert!(sizes::signature_bytes() > 3200); // ~3293 bytes
    }

    #[test]
    fn test_dilithium3_empty_data() {
        let signer = Dilithium3Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"";
        let signature = signer.sign(data, &private_pem).unwrap();
        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_dilithium3_large_data() {
        let signer = Dilithium3Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = vec![0xABu8; 100_000];
        let signature = signer.sign(&data, &private_pem).unwrap();
        assert!(signer.verify(&data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_dilithium3_key_round_trip() {
        let signer = Dilithium3Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        // Parse and verify keys can be re-parsed
        let _sk = Dilithium3Signer::parse_private_key(&private_pem).unwrap();
        let _pk = Dilithium3Signer::parse_public_key(&public_pem).unwrap();

        // Verify signing still works after parsing
        let data = b"Round trip test";
        let signature = signer.sign(data, &private_pem).unwrap();
        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }
}
