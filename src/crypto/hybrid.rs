//! Hybrid signature mode combining classical and post-quantum algorithms.
//!
//! This module provides hybrid signers that combine a classical signature algorithm
//! (RSA or Ed25519) with a post-quantum algorithm (Dilithium3) for defense in depth.
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

use super::{
    dilithium::Dilithium3Signer, ed25519::Ed25519Signer, rsa::RsaSigner, SignatureAlgorithm,
};
use crate::error::{LicenseError, Result};
use pem::{encode, parse, Pem};

/// PEM tags for hybrid keys
const HYBRID_RSA_DILITHIUM_PRIVATE_KEY_TAG: &str = "HYBRID RSA-DILITHIUM3 PRIVATE KEY";
const HYBRID_RSA_DILITHIUM_PUBLIC_KEY_TAG: &str = "HYBRID RSA-DILITHIUM3 PUBLIC KEY";
const HYBRID_ED25519_DILITHIUM_PRIVATE_KEY_TAG: &str = "HYBRID ED25519-DILITHIUM3 PRIVATE KEY";
const HYBRID_ED25519_DILITHIUM_PUBLIC_KEY_TAG: &str = "HYBRID ED25519-DILITHIUM3 PUBLIC KEY";

/// Hybrid RSA + Dilithium3 signer
///
/// Signs data with both RSA-SHA256 and Dilithium3, requiring both signatures
/// to verify for the overall verification to succeed.
pub struct HybridRsaDilithiumSigner {
    rsa_signer: RsaSigner,
    dilithium_signer: Dilithium3Signer,
}

impl Default for HybridRsaDilithiumSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl HybridRsaDilithiumSigner {
    /// Create a new hybrid RSA + Dilithium3 signer
    pub fn new() -> Self {
        Self {
            rsa_signer: RsaSigner::new(),
            dilithium_signer: Dilithium3Signer::new(),
        }
    }

    /// Parse a hybrid private key into its component keys
    fn parse_private_key(pem_str: &str) -> Result<(String, String)> {
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse hybrid private key PEM: {}", e))
        })?;

        if pem.tag() != HYBRID_RSA_DILITHIUM_PRIVATE_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                HYBRID_RSA_DILITHIUM_PRIVATE_KEY_TAG,
                pem.tag()
            )));
        }

        Self::decode_hybrid_key(pem.contents())
    }

    /// Parse a hybrid public key into its component keys
    fn parse_public_key(pem_str: &str) -> Result<(String, String)> {
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse hybrid public key PEM: {}", e))
        })?;

        if pem.tag() != HYBRID_RSA_DILITHIUM_PUBLIC_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                HYBRID_RSA_DILITHIUM_PUBLIC_KEY_TAG,
                pem.tag()
            )));
        }

        Self::decode_hybrid_key(pem.contents())
    }

    /// Decode a hybrid key from bytes into two PEM strings
    fn decode_hybrid_key(bytes: &[u8]) -> Result<(String, String)> {
        if bytes.len() < 4 {
            return Err(LicenseError::InvalidKeyFormat(
                "Hybrid key too short".to_string(),
            ));
        }

        let classical_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;

        if bytes.len() < 4 + classical_len {
            return Err(LicenseError::InvalidKeyFormat(
                "Hybrid key truncated".to_string(),
            ));
        }

        let classical_pem =
            String::from_utf8(bytes[4..4 + classical_len].to_vec()).map_err(|e| {
                LicenseError::InvalidKeyFormat(format!("Invalid classical key encoding: {}", e))
            })?;

        let pq_pem = String::from_utf8(bytes[4 + classical_len..].to_vec()).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Invalid PQ key encoding: {}", e))
        })?;

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

        if sig.len() < 4 + classical_len {
            return Err(LicenseError::VerificationFailed(
                "Hybrid signature truncated".to_string(),
            ));
        }

        let classical_sig = sig[4..4 + classical_len].to_vec();
        let pq_sig = sig[4 + classical_len..].to_vec();

        Ok((classical_sig, pq_sig))
    }
}

impl SignatureAlgorithm for HybridRsaDilithiumSigner {
    fn algorithm_id(&self) -> &'static str {
        super::algorithm_ids::HYBRID_RSA_DILITHIUM3
    }

    fn sign(&self, data: &[u8], private_key_pem: &str) -> Result<Vec<u8>> {
        let (rsa_private, dilithium_private) = Self::parse_private_key(private_key_pem)?;

        // Sign with both algorithms
        let rsa_sig = self.rsa_signer.sign(data, &rsa_private)?;
        let dilithium_sig = self.dilithium_signer.sign(data, &dilithium_private)?;

        Ok(Self::encode_hybrid_signature(&rsa_sig, &dilithium_sig))
    }

    fn verify(&self, data: &[u8], signature: &[u8], public_key_pem: &str) -> Result<()> {
        let (rsa_public, dilithium_public) = Self::parse_public_key(public_key_pem)?;
        let (rsa_sig, dilithium_sig) = Self::decode_hybrid_signature(signature)?;

        // BOTH signatures must verify
        self.rsa_signer.verify(data, &rsa_sig, &rsa_public)?;
        self.dilithium_signer
            .verify(data, &dilithium_sig, &dilithium_public)?;

        Ok(())
    }

    fn generate_keypair(&self) -> Result<(String, String)> {
        // Generate both key pairs
        let (rsa_private, rsa_public) = self.rsa_signer.generate_keypair()?;
        let (dilithium_private, dilithium_public) = self.dilithium_signer.generate_keypair()?;

        // Encode hybrid keys
        let private_bytes = Self::encode_hybrid_key(&rsa_private, &dilithium_private);
        let public_bytes = Self::encode_hybrid_key(&rsa_public, &dilithium_public);

        let private_pem = encode(&Pem::new(
            HYBRID_RSA_DILITHIUM_PRIVATE_KEY_TAG,
            private_bytes,
        ));
        let public_pem = encode(&Pem::new(HYBRID_RSA_DILITHIUM_PUBLIC_KEY_TAG, public_bytes));

        Ok((private_pem, public_pem))
    }

    fn extract_public_key(&self, private_key_pem: &str) -> Result<String> {
        let (rsa_private, dilithium_private) = Self::parse_private_key(private_key_pem)?;

        let rsa_public = self.rsa_signer.extract_public_key(&rsa_private)?;
        let dilithium_public = self
            .dilithium_signer
            .extract_public_key(&dilithium_private)?;

        let public_bytes = Self::encode_hybrid_key(&rsa_public, &dilithium_public);
        let public_pem = encode(&Pem::new(HYBRID_RSA_DILITHIUM_PUBLIC_KEY_TAG, public_bytes));

        Ok(public_pem)
    }
}

/// Hybrid Ed25519 + Dilithium3 signer
///
/// Signs data with both Ed25519 and Dilithium3, requiring both signatures
/// to verify for the overall verification to succeed.
///
/// This combination is recommended for new deployments as it provides:
/// - Ed25519: Fast, secure classical signatures with small keys
/// - Dilithium3: Post-quantum security for future-proofing
pub struct HybridEd25519DilithiumSigner {
    ed25519_signer: Ed25519Signer,
    dilithium_signer: Dilithium3Signer,
}

impl Default for HybridEd25519DilithiumSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl HybridEd25519DilithiumSigner {
    /// Create a new hybrid Ed25519 + Dilithium3 signer
    pub fn new() -> Self {
        Self {
            ed25519_signer: Ed25519Signer::new(),
            dilithium_signer: Dilithium3Signer::new(),
        }
    }

    /// Parse a hybrid private key into its component keys
    fn parse_private_key(pem_str: &str) -> Result<(String, String)> {
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse hybrid private key PEM: {}", e))
        })?;

        if pem.tag() != HYBRID_ED25519_DILITHIUM_PRIVATE_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                HYBRID_ED25519_DILITHIUM_PRIVATE_KEY_TAG,
                pem.tag()
            )));
        }

        Self::decode_hybrid_key(pem.contents())
    }

    /// Parse a hybrid public key into its component keys
    fn parse_public_key(pem_str: &str) -> Result<(String, String)> {
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse hybrid public key PEM: {}", e))
        })?;

        if pem.tag() != HYBRID_ED25519_DILITHIUM_PUBLIC_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                HYBRID_ED25519_DILITHIUM_PUBLIC_KEY_TAG,
                pem.tag()
            )));
        }

        Self::decode_hybrid_key(pem.contents())
    }

    /// Decode a hybrid key from bytes into two PEM strings
    fn decode_hybrid_key(bytes: &[u8]) -> Result<(String, String)> {
        if bytes.len() < 4 {
            return Err(LicenseError::InvalidKeyFormat(
                "Hybrid key too short".to_string(),
            ));
        }

        let classical_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;

        if bytes.len() < 4 + classical_len {
            return Err(LicenseError::InvalidKeyFormat(
                "Hybrid key truncated".to_string(),
            ));
        }

        let classical_pem =
            String::from_utf8(bytes[4..4 + classical_len].to_vec()).map_err(|e| {
                LicenseError::InvalidKeyFormat(format!("Invalid classical key encoding: {}", e))
            })?;

        let pq_pem = String::from_utf8(bytes[4 + classical_len..].to_vec()).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Invalid PQ key encoding: {}", e))
        })?;

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

        if sig.len() < 4 + classical_len {
            return Err(LicenseError::VerificationFailed(
                "Hybrid signature truncated".to_string(),
            ));
        }

        let classical_sig = sig[4..4 + classical_len].to_vec();
        let pq_sig = sig[4 + classical_len..].to_vec();

        Ok((classical_sig, pq_sig))
    }
}

impl SignatureAlgorithm for HybridEd25519DilithiumSigner {
    fn algorithm_id(&self) -> &'static str {
        super::algorithm_ids::HYBRID_ED25519_DILITHIUM3
    }

    fn sign(&self, data: &[u8], private_key_pem: &str) -> Result<Vec<u8>> {
        let (ed25519_private, dilithium_private) = Self::parse_private_key(private_key_pem)?;

        // Sign with both algorithms
        let ed25519_sig = self.ed25519_signer.sign(data, &ed25519_private)?;
        let dilithium_sig = self.dilithium_signer.sign(data, &dilithium_private)?;

        Ok(Self::encode_hybrid_signature(&ed25519_sig, &dilithium_sig))
    }

    fn verify(&self, data: &[u8], signature: &[u8], public_key_pem: &str) -> Result<()> {
        let (ed25519_public, dilithium_public) = Self::parse_public_key(public_key_pem)?;
        let (ed25519_sig, dilithium_sig) = Self::decode_hybrid_signature(signature)?;

        // BOTH signatures must verify
        self.ed25519_signer
            .verify(data, &ed25519_sig, &ed25519_public)?;
        self.dilithium_signer
            .verify(data, &dilithium_sig, &dilithium_public)?;

        Ok(())
    }

    fn generate_keypair(&self) -> Result<(String, String)> {
        // Generate both key pairs
        let (ed25519_private, ed25519_public) = self.ed25519_signer.generate_keypair()?;
        let (dilithium_private, dilithium_public) = self.dilithium_signer.generate_keypair()?;

        // Encode hybrid keys
        let private_bytes = Self::encode_hybrid_key(&ed25519_private, &dilithium_private);
        let public_bytes = Self::encode_hybrid_key(&ed25519_public, &dilithium_public);

        let private_pem = encode(&Pem::new(
            HYBRID_ED25519_DILITHIUM_PRIVATE_KEY_TAG,
            private_bytes,
        ));
        let public_pem = encode(&Pem::new(
            HYBRID_ED25519_DILITHIUM_PUBLIC_KEY_TAG,
            public_bytes,
        ));

        Ok((private_pem, public_pem))
    }

    fn extract_public_key(&self, private_key_pem: &str) -> Result<String> {
        let (ed25519_private, dilithium_private) = Self::parse_private_key(private_key_pem)?;

        let ed25519_public = self.ed25519_signer.extract_public_key(&ed25519_private)?;
        let dilithium_public = self
            .dilithium_signer
            .extract_public_key(&dilithium_private)?;

        let public_bytes = Self::encode_hybrid_key(&ed25519_public, &dilithium_public);
        let public_pem = encode(&Pem::new(
            HYBRID_ED25519_DILITHIUM_PUBLIC_KEY_TAG,
            public_bytes,
        ));

        Ok(public_pem)
    }
}

/// Utility functions for working with hybrid signatures
pub mod utils {
    use super::*;

    /// Check if a signature is in hybrid format
    ///
    /// Hybrid signatures have a 4-byte length prefix that indicates the size
    /// of the classical signature component.
    pub fn is_hybrid_signature(signature: &[u8], expected_classical_size: usize) -> bool {
        if signature.len() < 4 {
            return false;
        }

        let classical_len =
            u32::from_le_bytes([signature[0], signature[1], signature[2], signature[3]]) as usize;

        // Check if the declared length is plausible
        classical_len == expected_classical_size && signature.len() > 4 + classical_len
    }

    /// Get the classical signature from a hybrid signature
    pub fn extract_classical_signature(signature: &[u8]) -> Result<Vec<u8>> {
        if signature.len() < 4 {
            return Err(LicenseError::VerificationFailed(
                "Signature too short".to_string(),
            ));
        }

        let classical_len =
            u32::from_le_bytes([signature[0], signature[1], signature[2], signature[3]]) as usize;

        if signature.len() < 4 + classical_len {
            return Err(LicenseError::VerificationFailed(
                "Signature truncated".to_string(),
            ));
        }

        Ok(signature[4..4 + classical_len].to_vec())
    }

    /// Get the PQ signature from a hybrid signature
    pub fn extract_pq_signature(signature: &[u8]) -> Result<Vec<u8>> {
        if signature.len() < 4 {
            return Err(LicenseError::VerificationFailed(
                "Signature too short".to_string(),
            ));
        }

        let classical_len =
            u32::from_le_bytes([signature[0], signature[1], signature[2], signature[3]]) as usize;

        if signature.len() < 4 + classical_len {
            return Err(LicenseError::VerificationFailed(
                "Signature truncated".to_string(),
            ));
        }

        Ok(signature[4 + classical_len..].to_vec())
    }

    /// Estimate the size of a hybrid signature given the component algorithm names
    pub fn estimate_signature_size(classical_algorithm: &str) -> usize {
        let classical_size = match classical_algorithm {
            "RSA-SHA256" => 256, // 2048-bit RSA
            "Ed25519" => 64,     // Ed25519 is always 64 bytes
            _ => 256,            // Default assumption
        };

        let dilithium_size = 3293; // Dilithium3 signature size

        4 + classical_size + dilithium_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== HybridRsaDilithiumSigner Tests ====================

    #[test]
    fn test_hybrid_rsa_dilithium_algorithm_id() {
        let signer = HybridRsaDilithiumSigner::new();
        assert_eq!(signer.algorithm_id(), "Hybrid-RSA-Dilithium3");
    }

    #[test]
    fn test_hybrid_rsa_dilithium_generate_keypair() {
        let signer = HybridRsaDilithiumSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        assert!(private_pem.contains(HYBRID_RSA_DILITHIUM_PRIVATE_KEY_TAG));
        assert!(public_pem.contains(HYBRID_RSA_DILITHIUM_PUBLIC_KEY_TAG));
    }

    #[test]
    fn test_hybrid_rsa_dilithium_sign_and_verify() {
        let signer = HybridRsaDilithiumSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, Hybrid World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        // Signature should contain both RSA (~256 bytes) and Dilithium (~3293 bytes)
        assert!(signature.len() > 3500);

        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_hybrid_rsa_dilithium_verify_wrong_data() {
        let signer = HybridRsaDilithiumSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let wrong_data = b"Goodbye, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(wrong_data, &signature, &public_pem).is_err());
    }

    #[test]
    fn test_hybrid_rsa_dilithium_verify_wrong_key() {
        let signer = HybridRsaDilithiumSigner::new();
        let (private_pem, _) = signer.generate_keypair().unwrap();
        let (_, other_public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(data, &signature, &other_public_pem).is_err());
    }

    #[test]
    fn test_hybrid_rsa_dilithium_extract_public_key() {
        let signer = HybridRsaDilithiumSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let extracted = signer.extract_public_key(&private_pem).unwrap();

        // Verify that the extracted public key works for verification
        let data = b"Test data";
        let signature = signer.sign(data, &private_pem).unwrap();
        assert!(signer.verify(data, &signature, &extracted).is_ok());

        assert_eq!(extracted, public_pem);
    }

    // ==================== HybridEd25519DilithiumSigner Tests ====================

    #[test]
    fn test_hybrid_ed25519_dilithium_algorithm_id() {
        let signer = HybridEd25519DilithiumSigner::new();
        assert_eq!(signer.algorithm_id(), "Hybrid-Ed25519-Dilithium3");
    }

    #[test]
    fn test_hybrid_ed25519_dilithium_generate_keypair() {
        let signer = HybridEd25519DilithiumSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        assert!(private_pem.contains(HYBRID_ED25519_DILITHIUM_PRIVATE_KEY_TAG));
        assert!(public_pem.contains(HYBRID_ED25519_DILITHIUM_PUBLIC_KEY_TAG));
    }

    #[test]
    fn test_hybrid_ed25519_dilithium_sign_and_verify() {
        let signer = HybridEd25519DilithiumSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, Hybrid World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        // Signature should contain both Ed25519 (64 bytes) and Dilithium (~3293 bytes)
        assert!(signature.len() > 3300);

        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_hybrid_ed25519_dilithium_verify_wrong_data() {
        let signer = HybridEd25519DilithiumSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let wrong_data = b"Goodbye, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(wrong_data, &signature, &public_pem).is_err());
    }

    #[test]
    fn test_hybrid_ed25519_dilithium_verify_wrong_key() {
        let signer = HybridEd25519DilithiumSigner::new();
        let (private_pem, _) = signer.generate_keypair().unwrap();
        let (_, other_public_pem) = signer.generate_keypair().unwrap();

        let data = b"Hello, World!";
        let signature = signer.sign(data, &private_pem).unwrap();

        assert!(signer.verify(data, &signature, &other_public_pem).is_err());
    }

    #[test]
    fn test_hybrid_ed25519_dilithium_extract_public_key() {
        let signer = HybridEd25519DilithiumSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let extracted = signer.extract_public_key(&private_pem).unwrap();

        // Verify that the extracted public key works for verification
        let data = b"Test data";
        let signature = signer.sign(data, &private_pem).unwrap();
        assert!(signer.verify(data, &signature, &extracted).is_ok());

        assert_eq!(extracted, public_pem);
    }

    // ==================== Utility Tests ====================

    #[test]
    fn test_extract_signature_components() {
        let signer = HybridEd25519DilithiumSigner::new();
        let (private_pem, _) = signer.generate_keypair().unwrap();

        let data = b"Test data";
        let signature = signer.sign(data, &private_pem).unwrap();

        // Extract components
        let classical = utils::extract_classical_signature(&signature).unwrap();
        let pq = utils::extract_pq_signature(&signature).unwrap();

        // Ed25519 signatures are always 64 bytes
        assert_eq!(classical.len(), 64);

        // Dilithium3 signatures are around 3293 bytes
        assert!(pq.len() > 3200);
    }

    #[test]
    fn test_is_hybrid_signature() {
        let signer = HybridEd25519DilithiumSigner::new();
        let (private_pem, _) = signer.generate_keypair().unwrap();

        let data = b"Test data";
        let signature = signer.sign(data, &private_pem).unwrap();

        // Should detect as hybrid with correct classical size
        assert!(utils::is_hybrid_signature(&signature, 64));

        // Should not detect as hybrid with wrong classical size
        assert!(!utils::is_hybrid_signature(&signature, 256));
    }

    #[test]
    fn test_estimate_signature_size() {
        let ed25519_hybrid_size = utils::estimate_signature_size("Ed25519");
        let rsa_hybrid_size = utils::estimate_signature_size("RSA-SHA256");

        // Ed25519 (64) + Dilithium3 (3293) + 4 byte header
        assert_eq!(ed25519_hybrid_size, 4 + 64 + 3293);

        // RSA-2048 (256) + Dilithium3 (3293) + 4 byte header
        assert_eq!(rsa_hybrid_size, 4 + 256 + 3293);
    }

    // ==================== Cross-verification Tests ====================

    #[test]
    fn test_hybrid_tampered_classical_signature() {
        let signer = HybridEd25519DilithiumSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Test data";
        let mut signature = signer.sign(data, &private_pem).unwrap();

        // Tamper with the classical signature (bytes 4-67)
        signature[10] ^= 0xFF;

        // Verification should fail
        assert!(signer.verify(data, &signature, &public_pem).is_err());
    }

    #[test]
    fn test_hybrid_tampered_pq_signature() {
        let signer = HybridEd25519DilithiumSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"Test data";
        let mut signature = signer.sign(data, &private_pem).unwrap();

        // Tamper with the PQ signature (after the classical part)
        let last_idx = signature.len() - 1;
        signature[last_idx] ^= 0xFF;

        // Verification should fail
        assert!(signer.verify(data, &signature, &public_pem).is_err());
    }

    #[test]
    fn test_hybrid_empty_data() {
        let signer = HybridEd25519DilithiumSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = b"";
        let signature = signer.sign(data, &private_pem).unwrap();
        assert!(signer.verify(data, &signature, &public_pem).is_ok());
    }

    #[test]
    fn test_hybrid_large_data() {
        let signer = HybridEd25519DilithiumSigner::new();
        let (private_pem, public_pem) = signer.generate_keypair().unwrap();

        let data = vec![0xABu8; 100_000];
        let signature = signer.sign(&data, &private_pem).unwrap();
        assert!(signer.verify(&data, &signature, &public_pem).is_ok());
    }
}
