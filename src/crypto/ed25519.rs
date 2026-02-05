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
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
};
use pem::{encode, parse, Pem};
use rand::rngs::OsRng;

/// OID for Ed25519 in PKCS#8 format
const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

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
    /// Supports both PKCS#8 format and raw Ed25519 private key format
    fn parse_private_key(pem_str: &str) -> Result<SigningKey> {
        // Handle escaped newlines
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str)
            .map_err(|e| LicenseError::InvalidKeyFormat(format!("Failed to parse PEM: {}", e)))?;

        match pem.tag() {
            "PRIVATE KEY" => {
                // PKCS#8 format - extract the raw key from the DER structure
                let der = pem.contents();
                Self::extract_ed25519_key_from_pkcs8(der)
            }
            "ED25519 PRIVATE KEY" => {
                // Raw Ed25519 private key
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
            tag => Err(LicenseError::InvalidKeyFormat(format!(
                "Unexpected PEM tag for Ed25519 private key: {}",
                tag
            ))),
        }
    }

    /// Extract Ed25519 private key from PKCS#8 DER encoding
    fn extract_ed25519_key_from_pkcs8(der: &[u8]) -> Result<SigningKey> {
        // PKCS#8 structure:
        // SEQUENCE {
        //   INTEGER (version)
        //   SEQUENCE { OID, ... }
        //   OCTET STRING (private key, wrapped in another OCTET STRING)
        // }

        // Find the Ed25519 OID to verify this is the right key type
        if !der.windows(ED25519_OID.len()).any(|w| w == ED25519_OID) {
            return Err(LicenseError::InvalidKeyFormat(
                "Not an Ed25519 private key (OID not found)".into(),
            ));
        }

        // The private key is at the end, wrapped in OCTET STRING tags
        // Look for the pattern: 04 22 04 20 [32 bytes of key]
        // where 04 is OCTET STRING tag, 22 is outer length (34), 04 is inner tag, 20 is inner length (32)
        // Need to allow checking up to position der.len()-36 (inclusive), so use saturating_sub(35)
        for i in 0..=der.len().saturating_sub(36) {
            if i + 35 < der.len()
                && der[i] == 0x04
                && der[i + 1] == 0x22
                && der[i + 2] == 0x04
                && der[i + 3] == 0x20
            {
                let key_start = i + 4;
                let key_bytes: [u8; SECRET_KEY_LENGTH] = der[key_start..key_start + 32]
                    .try_into()
                    .map_err(|_| LicenseError::InvalidKeyFormat("Invalid key extraction".into()))?;
                return Ok(SigningKey::from_bytes(&key_bytes));
            }
        }

        // Alternative: just the inner OCTET STRING (04 20 [32 bytes])
        for i in 0..=der.len().saturating_sub(34) {
            if i + 33 < der.len() && der[i] == 0x04 && der[i + 1] == 0x20 {
                let key_start = i + 2;
                let key_bytes: [u8; SECRET_KEY_LENGTH] = der[key_start..key_start + 32]
                    .try_into()
                    .map_err(|_| LicenseError::InvalidKeyFormat("Invalid key extraction".into()))?;
                return Ok(SigningKey::from_bytes(&key_bytes));
            }
        }

        Err(LicenseError::InvalidKeyFormat(
            "Could not extract Ed25519 private key from PKCS#8".into(),
        ))
    }

    /// Parse an Ed25519 public key from PEM format
    fn parse_public_key(pem_str: &str) -> Result<VerifyingKey> {
        // Handle escaped newlines
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str)
            .map_err(|e| LicenseError::InvalidKeyFormat(format!("Failed to parse PEM: {}", e)))?;

        match pem.tag() {
            "PUBLIC KEY" => {
                // SPKI format - extract the raw key from the DER structure
                let der = pem.contents();
                Self::extract_ed25519_key_from_spki(der)
            }
            "ED25519 PUBLIC KEY" => {
                // Raw Ed25519 public key
                let key_bytes: [u8; PUBLIC_KEY_LENGTH] =
                    pem.contents().try_into().map_err(|_| {
                        LicenseError::InvalidKeyFormat(format!(
                            "Invalid Ed25519 public key length: expected {}, got {}",
                            PUBLIC_KEY_LENGTH,
                            pem.contents().len()
                        ))
                    })?;
                VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
                    LicenseError::InvalidKeyFormat(format!("Invalid Ed25519 public key: {}", e))
                })
            }
            tag => Err(LicenseError::InvalidKeyFormat(format!(
                "Unexpected PEM tag for Ed25519 public key: {}",
                tag
            ))),
        }
    }

    /// Extract Ed25519 public key from SPKI DER encoding
    fn extract_ed25519_key_from_spki(der: &[u8]) -> Result<VerifyingKey> {
        // SPKI structure:
        // SEQUENCE {
        //   SEQUENCE { OID, ... }
        //   BIT STRING (public key)
        // }

        // Find the Ed25519 OID
        if !der.windows(ED25519_OID.len()).any(|w| w == ED25519_OID) {
            return Err(LicenseError::InvalidKeyFormat(
                "Not an Ed25519 public key (OID not found)".into(),
            ));
        }

        // The public key is at the end as a BIT STRING
        // Look for: 03 21 00 [32 bytes of key]
        // where 03 is BIT STRING tag, 21 is length (33), 00 is unused bits
        for i in 0..=der.len().saturating_sub(35) {
            if i + 34 < der.len() && der[i] == 0x03 && der[i + 1] == 0x21 && der[i + 2] == 0x00 {
                let key_start = i + 3;
                let key_bytes: [u8; PUBLIC_KEY_LENGTH] = der[key_start..key_start + 32]
                    .try_into()
                    .map_err(|_| LicenseError::InvalidKeyFormat("Invalid key extraction".into()))?;
                return VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
                    LicenseError::InvalidKeyFormat(format!("Invalid Ed25519 public key: {}", e))
                });
            }
        }

        Err(LicenseError::InvalidKeyFormat(
            "Could not extract Ed25519 public key from SPKI".into(),
        ))
    }

    /// Encode a private key to PKCS#8 PEM format
    fn encode_private_key_pkcs8(signing_key: &SigningKey) -> String {
        // Build PKCS#8 structure manually
        // SEQUENCE {
        //   INTEGER 0 (version)
        //   SEQUENCE { OID 1.3.101.112 (Ed25519) }
        //   OCTET STRING { OCTET STRING { private key } }
        // }
        let private_bytes = signing_key.to_bytes();

        // Inner OCTET STRING: 04 20 [32 bytes]
        let mut inner_octet = vec![0x04, 0x20];
        inner_octet.extend_from_slice(&private_bytes);

        // Outer OCTET STRING: 04 22 [inner]
        let mut outer_octet = vec![0x04, 0x22];
        outer_octet.extend_from_slice(&inner_octet);

        // Algorithm identifier SEQUENCE: 30 05 06 03 2b 65 70
        let algorithm_id = vec![0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

        // Version INTEGER: 02 01 00
        let version = vec![0x02, 0x01, 0x00];

        // Build the full SEQUENCE
        let mut content = Vec::new();
        content.extend_from_slice(&version);
        content.extend_from_slice(&algorithm_id);
        content.extend_from_slice(&outer_octet);

        // Wrap in outer SEQUENCE
        let mut der = vec![0x30, content.len() as u8];
        der.extend_from_slice(&content);

        encode(&Pem::new("PRIVATE KEY", der))
    }

    /// Encode a public key to SPKI PEM format
    fn encode_public_key_spki(verifying_key: &VerifyingKey) -> String {
        // Build SPKI structure manually
        // SEQUENCE {
        //   SEQUENCE { OID 1.3.101.112 (Ed25519) }
        //   BIT STRING { public key }
        // }
        let public_bytes = verifying_key.to_bytes();

        // BIT STRING: 03 21 00 [32 bytes]
        let mut bit_string = vec![0x03, 0x21, 0x00];
        bit_string.extend_from_slice(&public_bytes);

        // Algorithm identifier SEQUENCE: 30 05 06 03 2b 65 70
        let algorithm_id = vec![0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

        // Build the full SEQUENCE
        let mut content = Vec::new();
        content.extend_from_slice(&algorithm_id);
        content.extend_from_slice(&bit_string);

        // Wrap in outer SEQUENCE
        let mut der = vec![0x30, content.len() as u8];
        der.extend_from_slice(&content);

        encode(&Pem::new("PUBLIC KEY", der))
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

        let private_pem = Self::encode_private_key_pkcs8(&signing_key);
        let public_pem = Self::encode_public_key_spki(&verifying_key);

        Ok((private_pem, public_pem))
    }

    fn extract_public_key(&self, private_key_pem: &str) -> Result<String> {
        let signing_key = Self::parse_private_key(private_key_pem)?;
        let verifying_key = signing_key.verifying_key();
        Ok(Self::encode_public_key_spki(&verifying_key))
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
