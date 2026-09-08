//! Hybrid signature mode combining classical and post-quantum algorithms.
//!
//! This module provides hybrid signers that combine a classical signature algorithm
//! (RSA or Ed25519) with a post-quantum algorithm (ML-DSA-65) for defense in depth.
//!
//! # Why Hybrid Mode?
//!
//! - **Defense in Depth**: Even if one algorithm is broken, the other provides security
//! - **Crypto Agility**: Smooth transition path to post-quantum cryptography
//! - **Standards Compliance**: Follows NIST recommendations for hybrid approaches
//! - **Backward Compatibility**: Existing infrastructure can verify the classical signature
//!
//! # Security Model
//!
//! A hybrid signature is valid only if BOTH the classical and post-quantum signatures
//! verify successfully. This provides security as long as at least one algorithm remains secure.
//!
//! # Signature Format
//!
//! Hybrid signatures are concatenated with a length prefix:
//! ```text
//! [classical_sig_len (4 bytes, LE)] || [classical_signature] || [pq_signature]
//! ```
//!
//! # Key Format
//!
//! Hybrid keys use a custom multi-key PEM format:
//! ```text
//! -----BEGIN HYBRID PRIVATE KEY-----
//! ... base64 encoded: [classical_key_len (4 bytes)] || [classical_key] || [pq_key] ...
//! -----END HYBRID PRIVATE KEY-----
//! ```

use super::{ed25519::Ed25519Signer, ml_dsa::MlDsa65Signer, rsa::RsaSigner, SignatureAlgorithm};
use crate::error::{LicenseError, Result};
use pem::{encode, parse, Pem};

/// PEM tags for hybrid keys
const HYBRID_RSA_ML_DSA_PRIVATE_KEY_TAG: &str = "HYBRID RSA-ML-DSA-65 PRIVATE KEY";
const HYBRID_RSA_ML_DSA_PUBLIC_KEY_TAG: &str = "HYBRID RSA-ML-DSA-65 PUBLIC KEY";
const HYBRID_ED25519_ML_DSA_PRIVATE_KEY_TAG: &str = "HYBRID ED25519-ML-DSA-65 PRIVATE KEY";
const HYBRID_ED25519_ML_DSA_PUBLIC_KEY_TAG: &str = "HYBRID ED25519-ML-DSA-65 PUBLIC KEY";

/// Hybrid RSA + ML-DSA-65 signer
pub struct HybridRsaMlDsaSigner {
    rsa_signer: RsaSigner,
    ml_dsa_signer: MlDsa65Signer,
}

impl Default for HybridRsaMlDsaSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl HybridRsaMlDsaSigner {
    pub fn new() -> Self {
        Self {
            rsa_signer: RsaSigner::new(),
            ml_dsa_signer: MlDsa65Signer::new(),
        }
    }

    fn parse_private_key(pem_str: &str) -> Result<(String, String)> {
        let pem_str = pem_str.replace("\\n", "\n");
        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse hybrid private key PEM: {}", e))
        })?;
        if pem.tag() != HYBRID_RSA_ML_DSA_PRIVATE_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                HYBRID_RSA_ML_DSA_PRIVATE_KEY_TAG,
                pem.tag()
            )));
        }
        decode_hybrid_key(pem.contents())
    }

    fn parse_public_key(pem_str: &str) -> Result<(String, String)> {
        let pem_str = pem_str.replace("\\n", "\n");
        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse hybrid public key PEM: {}", e))
        })?;
        if pem.tag() != HYBRID_RSA_ML_DSA_PUBLIC_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                HYBRID_RSA_ML_DSA_PUBLIC_KEY_TAG,
                pem.tag()
            )));
        }
        decode_hybrid_key(pem.contents())
    }
}

impl SignatureAlgorithm for HybridRsaMlDsaSigner {
    fn algorithm_id(&self) -> &'static str {
        super::algorithm_ids::HYBRID_RSA_ML_DSA_65
    }

    fn sign(&self, data: &[u8], private_key_pem: &str) -> Result<Vec<u8>> {
        let (rsa_private, ml_dsa_private) = Self::parse_private_key(private_key_pem)?;
        let rsa_sig = self.rsa_signer.sign(data, &rsa_private)?;
        let ml_dsa_sig = self.ml_dsa_signer.sign(data, &ml_dsa_private)?;
        Ok(encode_hybrid_signature(&rsa_sig, &ml_dsa_sig))
    }

    fn verify(&self, data: &[u8], signature: &[u8], public_key_pem: &str) -> Result<()> {
        let (rsa_public, ml_dsa_public) = Self::parse_public_key(public_key_pem)?;
        let (rsa_sig, ml_dsa_sig) = decode_hybrid_signature(signature)?;
        // BOTH signatures must verify
        self.rsa_signer.verify(data, &rsa_sig, &rsa_public)?;
        self.ml_dsa_signer
            .verify(data, &ml_dsa_sig, &ml_dsa_public)?;
        Ok(())
    }

    fn generate_keypair(&self) -> Result<(String, String)> {
        let (rsa_private, rsa_public) = self.rsa_signer.generate_keypair()?;
        let (ml_dsa_private, ml_dsa_public) = self.ml_dsa_signer.generate_keypair()?;

        let private_bytes = encode_hybrid_key(&rsa_private, &ml_dsa_private);
        let public_bytes = encode_hybrid_key(&rsa_public, &ml_dsa_public);

        let private_pem = encode(&Pem::new(HYBRID_RSA_ML_DSA_PRIVATE_KEY_TAG, private_bytes));
        let public_pem = encode(&Pem::new(HYBRID_RSA_ML_DSA_PUBLIC_KEY_TAG, public_bytes));

        Ok((private_pem, public_pem))
    }

    fn extract_public_key(&self, private_key_pem: &str) -> Result<String> {
        let (rsa_private, ml_dsa_private) = Self::parse_private_key(private_key_pem)?;
        let rsa_public = self.rsa_signer.extract_public_key(&rsa_private)?;
        // ML-DSA-65 cannot extract public key from private key alone
        // The hybrid format stores both, so we can try; but MlDsa65Signer::extract_public_key
        // will return an error. For hybrid, we rely on the key pair being stored together.
        let ml_dsa_public = self.ml_dsa_signer.extract_public_key(&ml_dsa_private)?;
        let public_bytes = encode_hybrid_key(&rsa_public, &ml_dsa_public);
        let public_pem = encode(&Pem::new(HYBRID_RSA_ML_DSA_PUBLIC_KEY_TAG, public_bytes));
        Ok(public_pem)
    }
}

/// Hybrid Ed25519 + ML-DSA-65 signer
pub struct HybridEd25519MlDsaSigner {
    ed25519_signer: Ed25519Signer,
    ml_dsa_signer: MlDsa65Signer,
}

impl Default for HybridEd25519MlDsaSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl HybridEd25519MlDsaSigner {
    pub fn new() -> Self {
        Self {
            ed25519_signer: Ed25519Signer::new(),
            ml_dsa_signer: MlDsa65Signer::new(),
        }
    }

    fn parse_private_key(pem_str: &str) -> Result<(String, String)> {
        let pem_str = pem_str.replace("\\n", "\n");
        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse hybrid private key PEM: {}", e))
        })?;
        if pem.tag() != HYBRID_ED25519_ML_DSA_PRIVATE_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                HYBRID_ED25519_ML_DSA_PRIVATE_KEY_TAG,
                pem.tag()
            )));
        }
        decode_hybrid_key(pem.contents())
    }

    fn parse_public_key(pem_str: &str) -> Result<(String, String)> {
        let pem_str = pem_str.replace("\\n", "\n");
        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse hybrid public key PEM: {}", e))
        })?;
        if pem.tag() != HYBRID_ED25519_ML_DSA_PUBLIC_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                HYBRID_ED25519_ML_DSA_PUBLIC_KEY_TAG,
                pem.tag()
            )));
        }
        decode_hybrid_key(pem.contents())
    }
}

impl SignatureAlgorithm for HybridEd25519MlDsaSigner {
    fn algorithm_id(&self) -> &'static str {
        super::algorithm_ids::HYBRID_ED25519_ML_DSA_65
    }

    fn sign(&self, data: &[u8], private_key_pem: &str) -> Result<Vec<u8>> {
        let (ed25519_private, ml_dsa_private) = Self::parse_private_key(private_key_pem)?;
        let ed25519_sig = self.ed25519_signer.sign(data, &ed25519_private)?;
        let ml_dsa_sig = self.ml_dsa_signer.sign(data, &ml_dsa_private)?;
        Ok(encode_hybrid_signature(&ed25519_sig, &ml_dsa_sig))
    }

    fn verify(&self, data: &[u8], signature: &[u8], public_key_pem: &str) -> Result<()> {
        let (ed25519_public, ml_dsa_public) = Self::parse_public_key(public_key_pem)?;
        let (ed25519_sig, ml_dsa_sig) = decode_hybrid_signature(signature)?;
        // BOTH signatures must verify
        self.ed25519_signer
            .verify(data, &ed25519_sig, &ed25519_public)?;
        self.ml_dsa_signer
            .verify(data, &ml_dsa_sig, &ml_dsa_public)?;
        Ok(())
    }

    fn generate_keypair(&self) -> Result<(String, String)> {
        let (ed25519_private, ed25519_public) = self.ed25519_signer.generate_keypair()?;
        let (ml_dsa_private, ml_dsa_public) = self.ml_dsa_signer.generate_keypair()?;

        let private_bytes = encode_hybrid_key(&ed25519_private, &ml_dsa_private);
        let public_bytes = encode_hybrid_key(&ed25519_public, &ml_dsa_public);

        let private_pem = encode(&Pem::new(
            HYBRID_ED25519_ML_DSA_PRIVATE_KEY_TAG,
            private_bytes,
        ));
        let public_pem = encode(&Pem::new(
            HYBRID_ED25519_ML_DSA_PUBLIC_KEY_TAG,
            public_bytes,
        ));

        Ok((private_pem, public_pem))
    }

    fn extract_public_key(&self, private_key_pem: &str) -> Result<String> {
        let (ed25519_private, ml_dsa_private) = Self::parse_private_key(private_key_pem)?;
        let ed25519_public = self.ed25519_signer.extract_public_key(&ed25519_private)?;
        let ml_dsa_public = self.ml_dsa_signer.extract_public_key(&ml_dsa_private)?;
        let public_bytes = encode_hybrid_key(&ed25519_public, &ml_dsa_public);
        let public_pem = encode(&Pem::new(
            HYBRID_ED25519_ML_DSA_PUBLIC_KEY_TAG,
            public_bytes,
        ));
        Ok(public_pem)
    }
}

// ============================================================================
// Shared helpers
// ============================================================================

/// Decode a hybrid key from bytes into two PEM strings
fn decode_hybrid_key(bytes: &[u8]) -> Result<(String, String)> {
    if bytes.len() < 4 {
        return Err(LicenseError::InvalidKeyFormat(
            "Hybrid key too short".to_string(),
        ));
    }

    let classical_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;

    if classical_len > bytes.len() - 4 {
        return Err(LicenseError::InvalidKeyFormat(
            "Hybrid key truncated".to_string(),
        ));
    }

    let classical_pem = String::from_utf8(bytes[4..4 + classical_len].to_vec()).map_err(|e| {
        LicenseError::InvalidKeyFormat(format!("Invalid classical key encoding: {}", e))
    })?;

    let pq_pem = String::from_utf8(bytes[4 + classical_len..].to_vec())
        .map_err(|e| LicenseError::InvalidKeyFormat(format!("Invalid PQ key encoding: {}", e)))?;

    Ok((classical_pem, pq_pem))
}

/// Encode two PEM keys into a hybrid key format
fn encode_hybrid_key(classical_pem: &str, pq_pem: &str) -> Vec<u8> {
    let classical_bytes = classical_pem.as_bytes();
    let pq_bytes = pq_pem.as_bytes();

    let mut result = Vec::with_capacity(4 + classical_bytes.len() + pq_bytes.len());
    result.extend_from_slice(&(classical_bytes.len() as u32).to_le_bytes());
    result.extend_from_slice(classical_bytes);
    result.extend_from_slice(pq_bytes);

    result
}

/// Encode a hybrid signature (classical + PQ)
fn encode_hybrid_signature(classical_sig: &[u8], pq_sig: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(4 + classical_sig.len() + pq_sig.len());
    result.extend_from_slice(&(classical_sig.len() as u32).to_le_bytes());
    result.extend_from_slice(classical_sig);
    result.extend_from_slice(pq_sig);
    result
}

/// Decode a hybrid signature into its components
fn decode_hybrid_signature(sig: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if sig.len() < 4 {
        return Err(LicenseError::VerificationFailed(
            "Hybrid signature too short".to_string(),
        ));
    }

    let classical_len = u32::from_le_bytes([sig[0], sig[1], sig[2], sig[3]]) as usize;

    if classical_len > sig.len() - 4 {
        return Err(LicenseError::VerificationFailed(
            "Hybrid signature truncated".to_string(),
        ));
    }

    let classical_sig = sig[4..4 + classical_len].to_vec();
    let pq_sig = sig[4 + classical_len..].to_vec();

    Ok((classical_sig, pq_sig))
}

/// Utility functions for working with hybrid signatures
pub mod utils {
    use super::*;

    /// Check if a signature is in hybrid format
    pub fn is_hybrid_signature(signature: &[u8], expected_classical_size: usize) -> bool {
        if signature.len() < 4 {
            return false;
        }

        let classical_len =
            u32::from_le_bytes([signature[0], signature[1], signature[2], signature[3]]) as usize;

        classical_len == expected_classical_size && classical_len < signature.len() - 4
    }

    /// Get the classical signature from a hybrid signature
    pub fn extract_classical_signature(signature: &[u8]) -> Result<Vec<u8>> {
        let (classical, _) = decode_hybrid_signature(signature)?;
        Ok(classical)
    }

    /// Get the PQ signature from a hybrid signature
    pub fn extract_pq_signature(signature: &[u8]) -> Result<Vec<u8>> {
        let (_, pq) = decode_hybrid_signature(signature)?;
        Ok(pq)
    }

    /// Estimate the size of a hybrid signature given the component algorithm names
    pub fn estimate_signature_size(classical_algorithm: &str) -> usize {
        let classical_size = match classical_algorithm {
            "RSA-SHA256" => 384, // 3072-bit RSA (new default)
            "Ed25519" => 64,
            _ => 384,
        };

        let ml_dsa_size = 3309; // ML-DSA-65 signature size

        4 + classical_size + ml_dsa_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_hybrid_lengths_reject_overflow_and_truncation() {
        for length in [u32::MAX, u32::MAX - 3, 1, 1024] {
            let bytes = length.to_le_bytes();
            assert!(decode_hybrid_key(&bytes).is_err());
            assert!(decode_hybrid_signature(&bytes).is_err());
            assert!(!utils::is_hybrid_signature(&bytes, length as usize));
        }
        let encoded = encode_hybrid_signature(b"classical", b"postquantum");
        assert_eq!(
            decode_hybrid_signature(&encoded).unwrap(),
            (b"classical".to_vec(), b"postquantum".to_vec())
        );
        assert_eq!(
            decode_hybrid_key(&encode_hybrid_key("classical", "pq")).unwrap(),
            ("classical".into(), "pq".into())
        );
    }

    // ==================== HybridRsaMlDsaSigner Tests ====================

    #[test]
    fn test_hybrid_rsa_ml_dsa_algorithm_id() {
        let signer = HybridRsaMlDsaSigner::new();
        assert_eq!(signer.algorithm_id(), "Hybrid-RSA-ML-DSA-65");
    }

    #[test]
    fn test_hybrid_rsa_ml_dsa_generate_keypair() {
        let signer = HybridRsaMlDsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        assert!(private_pem.contains(HYBRID_RSA_ML_DSA_PRIVATE_KEY_TAG));
        assert!(public_pem.contains(HYBRID_RSA_ML_DSA_PUBLIC_KEY_TAG));
    }

    #[test]
    fn test_hybrid_rsa_ml_dsa_sign_and_verify() {
        let signer = HybridRsaMlDsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, Hybrid World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signature.len() > 3500);
        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_hybrid_rsa_ml_dsa_verify_wrong_data() {
        let signer = HybridRsaMlDsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let wrong_data = b"Goodbye, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(wrong_data, &signature, &public_pem).is_err());
    }

    #[test]
    fn test_hybrid_rsa_ml_dsa_verify_wrong_key() {
        let signer = HybridRsaMlDsaSigner::new();
        let (private_pem, _) = signer.generate_keypair().unwrap();
        let (_, other_public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(data, &signature, &other_public_pem).is_err());
    }

    // ==================== HybridEd25519MlDsaSigner Tests ====================

    #[test]
    fn test_hybrid_ed25519_ml_dsa_algorithm_id() {
        let signer = HybridEd25519MlDsaSigner::new();
        assert_eq!(signer.algorithm_id(), "Hybrid-Ed25519-ML-DSA-65");
    }

    #[test]
    fn test_hybrid_ed25519_ml_dsa_generate_keypair() {
        let signer = HybridEd25519MlDsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        assert!(private_pem.contains(HYBRID_ED25519_ML_DSA_PRIVATE_KEY_TAG));
        assert!(public_pem.contains(HYBRID_ED25519_ML_DSA_PUBLIC_KEY_TAG));
    }

    #[test]
    fn test_hybrid_ed25519_ml_dsa_sign_and_verify() {
        let signer = HybridEd25519MlDsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, Hybrid World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signature.len() > 3300);
        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_hybrid_ed25519_ml_dsa_verify_wrong_data() {
        let signer = HybridEd25519MlDsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let wrong_data = b"Goodbye, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(wrong_data, &signature, &public_pem).is_err());
    }

    #[test]
    fn test_hybrid_ed25519_ml_dsa_verify_wrong_key() {
        let signer = HybridEd25519MlDsaSigner::new();
        let (private_pem, _) = signer.generate_keypair().unwrap();
        let (_, other_public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(data, &signature, &other_public_pem).is_err());
    }

    // ==================== Utility Tests ====================

    #[test]
    fn test_extract_signature_components() {
        let signer = HybridEd25519MlDsaSigner::new();
        let (private_pem, _) = signer.generate_keypair().unwrap();

        let data = b"Test data";
        let signature = signer.sign(data, &private_pem).unwrap();

        let classical = utils::extract_classical_signature(&signature).unwrap();
        let pq = utils::extract_pq_signature(&signature).unwrap();

        assert_eq!(classical.len(), 64); // Ed25519
        assert!(pq.len() > 3200); // ML-DSA-65
    }

    #[test]
    fn test_is_hybrid_signature() {
        let signer = HybridEd25519MlDsaSigner::new();
        let (private_pem, _) = signer.generate_keypair().unwrap();

        let data = b"Test data";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(utils::is_hybrid_signature(&signature, 64));
        assert!(!utils::is_hybrid_signature(&signature, 256));
    }

    #[test]
    fn test_hybrid_tampered_classical_signature() {
        let signer = HybridEd25519MlDsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Test data";
        let mut signature = signer.sign(data, &private_pem).unwrap();

        signature[10] ^= 0xFF;
        assert!(signer.verify(data, &signature, &public_pem).is_err());
    }

    #[test]
    fn test_hybrid_tampered_pq_signature() {
        let signer = HybridEd25519MlDsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Test data";
        let mut signature = signer.sign(data, &private_pem).unwrap();

        let last_idx = signature.len() - 1;
        signature[last_idx] ^= 0xFF;
        assert!(signer.verify(data, &signature, &public_pem).is_err());
    }

    #[test]
    fn test_hybrid_empty_data() {
        let signer = HybridEd25519MlDsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"";
        let signature = signer.sign(data, &private_pem).unwrap();
        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_hybrid_large_data() {
        let signer = HybridEd25519MlDsaSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = vec![0xABu8; 100_000];
        let signature = signer.sign(&data, &private_pem).unwrap();
        assert!(signer.verify(&data, &signature, &public_pem).is_ok());
    }
}
