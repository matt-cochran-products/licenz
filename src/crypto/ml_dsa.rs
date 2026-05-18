//! ML-DSA-65 post-quantum signature algorithm implementation.
//!
//! This module implements the `SignatureAlgorithm` trait for ML-DSA-65
//! (formerly Dilithium3), a lattice-based digital signature scheme
//! standardized by NIST as FIPS 204.
//!
//! ML-DSA-65 provides NIST Level 3 security (equivalent to AES-192),
//! offering a balance between security and performance.
//!
//! Key and signature sizes:
//! - Public key: 1,952 bytes
//! - Private key (seed): 32 bytes
//! - Signature: 3,309 bytes
//!
//! These are significantly larger than classical algorithms like Ed25519
//! (32/64/64 bytes) but provide quantum resistance.

use super::SignatureAlgorithm;
use crate::error::{LicenseError, Result};
use ml_dsa::{
    Generate, Keypair, MlDsa65, Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use pem::{encode, parse, Pem};

/// PEM tag for ML-DSA-65 private keys
const ML_DSA_65_PRIVATE_KEY_TAG: &str = "ML-DSA-65 PRIVATE KEY";

/// PEM tag for ML-DSA-65 public keys
const ML_DSA_65_PUBLIC_KEY_TAG: &str = "ML-DSA-65 PUBLIC KEY";

/// ML-DSA-65 signature algorithm implementation
pub struct MlDsa65Signer;

impl Default for MlDsa65Signer {
    fn default() -> Self {
        Self::new()
    }
}

impl MlDsa65Signer {
    /// Create a new ML-DSA-65 signer
    pub fn new() -> Self {
        Self
    }

    /// Parse an ML-DSA-65 private key from PEM format.
    ///
    /// The PEM contains the 32-byte seed from which the full signing key
    /// is deterministically derived via `MlDsa65::from_seed()`.
    fn parse_private_key(pem_str: &str) -> Result<SigningKey<MlDsa65>> {
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse ML-DSA-65 PEM: {}", e))
        })?;

        if pem.tag() != ML_DSA_65_PRIVATE_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                ML_DSA_65_PRIVATE_KEY_TAG,
                pem.tag()
            )));
        }

        let seed_bytes: &ml_dsa::Seed = pem.contents().try_into().map_err(|_| {
            LicenseError::InvalidKeyFormat(format!(
                "Invalid ML-DSA-65 seed length: expected 32, got {}",
                pem.contents().len()
            ))
        })?;

        Ok(SigningKey::<MlDsa65>::from_seed(seed_bytes))
    }

    /// Parse an ML-DSA-65 public key from PEM format
    fn parse_public_key(pem_str: &str) -> Result<VerifyingKey<MlDsa65>> {
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse ML-DSA-65 PEM: {}", e))
        })?;

        if pem.tag() != ML_DSA_65_PUBLIC_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                ML_DSA_65_PUBLIC_KEY_TAG,
                pem.tag()
            )));
        }

        let encoded = pem.contents();
        let encoded_key: &ml_dsa::EncodedVerifyingKey<MlDsa65> =
            encoded.try_into().map_err(|_| {
                LicenseError::InvalidKeyFormat(format!(
                    "Invalid ML-DSA-65 public key length: got {}",
                    encoded.len()
                ))
            })?;

        Ok(VerifyingKey::<MlDsa65>::decode(encoded_key))
    }

    /// Encode a private key seed to PEM format.
    ///
    /// Stores the 32-byte seed from which the signing key can be reconstructed.
    fn encode_private_key(signing_key: &SigningKey<MlDsa65>) -> String {
        let seed = signing_key.to_seed();
        encode(&Pem::new(ML_DSA_65_PRIVATE_KEY_TAG, seed.as_slice()))
    }

    /// Encode a public key to PEM format
    fn encode_public_key(verifying_key: &VerifyingKey<MlDsa65>) -> String {
        let encoded = verifying_key.encode();
        encode(&Pem::new(ML_DSA_65_PUBLIC_KEY_TAG, encoded.as_slice()))
    }
}

impl SignatureAlgorithm for MlDsa65Signer {
    fn algorithm_id(&self) -> &'static str {
        super::algorithm_ids::ML_DSA_65
    }

    fn sign(&self, data: &[u8], private_key_pem: &str) -> Result<Vec<u8>> {
        let signing_key = Self::parse_private_key(private_key_pem)?;
        let signature: Signature<MlDsa65> = signing_key.sign(data);
        let encoded = signature.encode();
        Ok(encoded.as_slice().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8], public_key_pem: &str) -> Result<()> {
        let verifying_key = Self::parse_public_key(public_key_pem)?;

        let sig = Signature::<MlDsa65>::try_from(signature).map_err(|e| {
            LicenseError::VerificationFailed(format!("Invalid ML-DSA-65 signature format: {}", e))
        })?;

        verifying_key.verify(data, &sig).map_err(|_| {
            LicenseError::VerificationFailed("ML-DSA-65 signature verification failed".to_string())
        })
    }

    fn generate_keypair(&self) -> Result<(String, String)> {
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
        let signing_key = SigningKey::<MlDsa65>::generate_from_rng(&mut rng);

        let private_pem = Self::encode_private_key(&signing_key);
        let public_pem = Self::encode_public_key(&signing_key.verifying_key());

        Ok((private_pem, public_pem))
    }

    fn extract_public_key(&self, private_key_pem: &str) -> Result<String> {
        let signing_key = Self::parse_private_key(private_key_pem)?;
        let verifying_key = signing_key.verifying_key();
        Ok(Self::encode_public_key(&verifying_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_65_signer_algorithm_id() {
        let signer = MlDsa65Signer::new();
        assert_eq!(signer.algorithm_id(), "ML-DSA-65");
    }

    #[test]
    fn test_ml_dsa_65_generate_keypair() {
        let signer = MlDsa65Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        assert!(private_pem.contains(ML_DSA_65_PRIVATE_KEY_TAG));
        assert!(public_pem.contains(ML_DSA_65_PUBLIC_KEY_TAG));
    }

    #[test]
    fn test_ml_dsa_65_sign_and_verify() {
        let signer = MlDsa65Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, Post-Quantum World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        // ML-DSA-65 signatures are around 3309 bytes
        assert!(signature.len() > 3000);
        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_ml_dsa_65_verify_wrong_data() {
        let signer = MlDsa65Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let wrong_data = b"Goodbye, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(wrong_data, &signature, &public_pem).is_err());
    }

    #[test]
    fn test_ml_dsa_65_verify_wrong_key() {
        let signer = MlDsa65Signer::new();
        let (private_pem, _) = signer.generate_keypair().unwrap();
        let (_, other_public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(data, &signature, &other_public_pem).is_err());
    }

    #[test]
    fn test_ml_dsa_65_empty_data() {
        let signer = MlDsa65Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"";
        let signature = signer.sign(data, &private_pem).unwrap();
        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_ml_dsa_65_large_data() {
        let signer = MlDsa65Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = vec![0xABu8; 100_000];
        let signature = signer.sign(&data, &private_pem).unwrap();
        assert!(signer.verify(&data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_ml_dsa_65_key_round_trip() {
        let signer = MlDsa65Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        // Parse and verify keys can be re-parsed
        let _sk = MlDsa65Signer::parse_private_key(&private_pem).unwrap();
        let _pk = MlDsa65Signer::parse_public_key(&public_pem).unwrap();

        // Verify signing still works after parsing
        let data = b"Round trip test";
        let signature = signer.sign(data, &private_pem).unwrap();
        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_ml_dsa_65_extract_public_key() {
        let signer = MlDsa65Signer::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let extracted = signer.extract_public_key(&private_pem).unwrap();
        assert_eq!(extracted, public_pem);
    }
}
