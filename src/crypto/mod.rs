//! Pluggable cryptographic architecture using the strategy pattern.
//!
//! This module provides a flexible crypto system that allows switching between
//! different signature algorithms (RSA-SHA256, Ed25519, and post-quantum algorithms).
//!
//! # Classical Algorithms
//!
//! - **RSA-SHA256**: Traditional RSA signatures with SHA-256 hashing
//! - **Ed25519**: Fast, modern elliptic curve signatures
//!
//! # Post-Quantum Algorithms (feature: `post-quantum`)
//!
//! - **Dilithium3**: NIST-standardized lattice-based signatures (ML-DSA)
//! - **Kyber768**: NIST-standardized key encapsulation mechanism (ML-KEM)
//!
//! # Hybrid Algorithms (feature: `post-quantum`)
//!
//! - **Hybrid-RSA-Dilithium3**: RSA + Dilithium3 dual signatures
//! - **Hybrid-Ed25519-Dilithium3**: Ed25519 + Dilithium3 dual signatures
//!
//! Hybrid modes require BOTH signatures to verify, providing security even if
//! one algorithm is compromised (defense in depth).
//!
//! # Example
//!
//! ```rust,no_run
//! use licenz_core::crypto::{SignatureAlgorithm, CryptoRegistry};
//!
//! // Get an algorithm by ID
//! let algorithm = CryptoRegistry::get_signature_algorithm("RSA-SHA256").unwrap();
//! println!("Using algorithm: {}", algorithm.algorithm_id());
//!
//! // List all supported algorithms
//! for alg_id in CryptoRegistry::supported_signature_algorithms() {
//!     println!("Supported: {}", alg_id);
//! }
//! ```

pub mod ed25519;
pub mod rsa;

// Post-quantum cryptography modules (feature-gated)
#[cfg(feature = "post-quantum")]
pub mod dilithium;
#[cfg(feature = "post-quantum")]
pub mod hybrid;
#[cfg(feature = "post-quantum")]
pub mod kyber;

// Post-quantum tests
#[cfg(all(test, feature = "post-quantum"))]
mod pq_tests;

use crate::error::{LicenseError, Result};
use std::collections::HashMap;
use std::sync::LazyLock;

/// Algorithm identifiers for signature algorithms
pub mod algorithm_ids {
    /// RSA with SHA-256 (PKCS#1 v1.5)
    pub const RSA_SHA256: &str = "RSA-SHA256";
    /// Ed25519 signature scheme
    pub const ED25519: &str = "Ed25519";

    // Post-quantum algorithm identifiers (available when feature enabled)

    /// Dilithium3 (ML-DSA-65) post-quantum signature scheme
    #[cfg(feature = "post-quantum")]
    pub const DILITHIUM3: &str = "Dilithium3";

    /// Kyber768 (ML-KEM-768) post-quantum key encapsulation
    /// Note: This is a KEM, not a signature algorithm
    #[cfg(feature = "post-quantum")]
    pub const KYBER768: &str = "Kyber768";

    /// Hybrid RSA + Dilithium3 dual signature scheme
    #[cfg(feature = "post-quantum")]
    pub const HYBRID_RSA_DILITHIUM3: &str = "Hybrid-RSA-Dilithium3";

    /// Hybrid Ed25519 + Dilithium3 dual signature scheme
    #[cfg(feature = "post-quantum")]
    pub const HYBRID_ED25519_DILITHIUM3: &str = "Hybrid-Ed25519-Dilithium3";
}

/// Trait for signature algorithms (strategy pattern)
///
/// This trait defines the interface for cryptographic signature operations,
/// allowing different algorithms to be plugged in interchangeably.
pub trait SignatureAlgorithm: Send + Sync {
    /// Returns the unique identifier for this algorithm (e.g., "RSA-SHA256", "Ed25519")
    fn algorithm_id(&self) -> &'static str;

    /// Sign data with the private key
    ///
    /// # Arguments
    /// * `data` - The data to sign
    /// * `private_key_pem` - The private key in PEM format
    ///
    /// # Returns
    /// The signature as a byte vector
    fn sign(&self, data: &[u8], private_key_pem: &str) -> Result<Vec<u8>>;

    /// Verify a signature against data and public key
    ///
    /// # Arguments
    /// * `data` - The original data that was signed
    /// * `signature` - The signature to verify
    /// * `public_key_pem` - The public key in PEM format
    ///
    /// # Returns
    /// Ok(()) if the signature is valid, Err otherwise
    fn verify(&self, data: &[u8], signature: &[u8], public_key_pem: &str) -> Result<()>;

    /// Generate a new key pair
    ///
    /// # Returns
    /// A tuple of (private_key_pem, public_key_pem)
    fn generate_keypair(&self) -> Result<(String, String)>;

    /// Extract the public key from a private key
    ///
    /// # Arguments
    /// * `private_key_pem` - The private key in PEM format
    ///
    /// # Returns
    /// The public key in PEM format
    fn extract_public_key(&self, private_key_pem: &str) -> Result<String>;
}

/// Trait for symmetric encryption algorithms
///
/// This trait defines the interface for symmetric encryption operations,
/// used for encrypting license data at rest.
pub trait EncryptionAlgorithm: Send + Sync {
    /// Returns the unique identifier for this algorithm (e.g., "AES-256-GCM")
    fn algorithm_id(&self) -> &'static str;

    /// Encrypt data with the given key
    ///
    /// # Arguments
    /// * `data` - The plaintext data to encrypt
    /// * `key` - The encryption key
    ///
    /// # Returns
    /// The encrypted data (including nonce/IV if applicable)
    fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt data with the given key
    ///
    /// # Arguments
    /// * `data` - The encrypted data
    /// * `key` - The encryption key
    ///
    /// # Returns
    /// The decrypted plaintext
    fn decrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>>;

    /// Returns the required key size in bytes
    fn key_size(&self) -> usize;

    /// Returns the nonce/IV size in bytes
    fn nonce_size(&self) -> usize;
}

/// A boxed signature algorithm for dynamic dispatch
pub type BoxedSignatureAlgorithm = Box<dyn SignatureAlgorithm>;

/// A boxed encryption algorithm for dynamic dispatch
pub type BoxedEncryptionAlgorithm = Box<dyn EncryptionAlgorithm>;

/// Registry for cryptographic algorithms
///
/// Provides lookup functionality to get algorithms by their identifier.
/// This enables runtime selection of algorithms based on license metadata.
pub struct CryptoRegistry;

/// Static registry of signature algorithms
static SIGNATURE_ALGORITHMS: LazyLock<HashMap<&'static str, BoxedSignatureAlgorithm>> =
    LazyLock::new(|| {
        let mut map: HashMap<&'static str, BoxedSignatureAlgorithm> = HashMap::new();

        // Classical algorithms (always available)
        map.insert(algorithm_ids::RSA_SHA256, Box::new(rsa::RsaSigner::new()));
        map.insert(
            algorithm_ids::ED25519,
            Box::new(ed25519::Ed25519Signer::new()),
        );

        // Post-quantum algorithms (feature-gated)
        #[cfg(feature = "post-quantum")]
        {
            map.insert(
                algorithm_ids::DILITHIUM3,
                Box::new(dilithium::Dilithium3Signer::new()),
            );
            map.insert(
                algorithm_ids::HYBRID_RSA_DILITHIUM3,
                Box::new(hybrid::HybridRsaDilithiumSigner::new()),
            );
            map.insert(
                algorithm_ids::HYBRID_ED25519_DILITHIUM3,
                Box::new(hybrid::HybridEd25519DilithiumSigner::new()),
            );
        }

        map
    });

impl CryptoRegistry {
    /// Get a signature algorithm by its identifier
    ///
    /// # Arguments
    /// * `algorithm_id` - The algorithm identifier (e.g., "RSA-SHA256", "Ed25519")
    ///
    /// # Returns
    /// A reference to the signature algorithm, or an error if not found
    pub fn get_signature_algorithm(algorithm_id: &str) -> Result<&'static dyn SignatureAlgorithm> {
        SIGNATURE_ALGORITHMS
            .get(algorithm_id)
            .map(|boxed| boxed.as_ref())
            .ok_or_else(|| {
                LicenseError::InvalidKeyFormat(format!(
                    "Unknown signature algorithm: {}. Supported: {:?}",
                    algorithm_id,
                    Self::supported_signature_algorithms()
                ))
            })
    }

    /// Get a list of all supported signature algorithm IDs
    pub fn supported_signature_algorithms() -> Vec<&'static str> {
        SIGNATURE_ALGORITHMS.keys().copied().collect()
    }

    /// Check if a signature algorithm is supported
    pub fn is_signature_algorithm_supported(algorithm_id: &str) -> bool {
        SIGNATURE_ALGORITHMS.contains_key(algorithm_id)
    }

    /// Get the default signature algorithm (RSA-SHA256 for backward compatibility)
    pub fn default_signature_algorithm() -> &'static dyn SignatureAlgorithm {
        SIGNATURE_ALGORITHMS
            .get(algorithm_ids::RSA_SHA256)
            .map(|boxed| boxed.as_ref())
            .expect("RSA-SHA256 should always be available")
    }

    /// Check if post-quantum algorithms are available
    ///
    /// Returns true if the `post-quantum` feature is enabled at compile time.
    pub fn is_post_quantum_available() -> bool {
        #[cfg(feature = "post-quantum")]
        {
            true
        }
        #[cfg(not(feature = "post-quantum"))]
        {
            false
        }
    }

    /// Get a list of post-quantum signature algorithm IDs
    ///
    /// Returns an empty list if the `post-quantum` feature is not enabled.
    #[cfg(feature = "post-quantum")]
    pub fn post_quantum_signature_algorithms() -> Vec<&'static str> {
        vec![
            algorithm_ids::DILITHIUM3,
            algorithm_ids::HYBRID_RSA_DILITHIUM3,
            algorithm_ids::HYBRID_ED25519_DILITHIUM3,
        ]
    }

    /// Get a list of post-quantum signature algorithm IDs
    #[cfg(not(feature = "post-quantum"))]
    pub fn post_quantum_signature_algorithms() -> Vec<&'static str> {
        vec![]
    }

    /// Get a list of classical (non-PQ) signature algorithm IDs
    pub fn classical_signature_algorithms() -> Vec<&'static str> {
        vec![algorithm_ids::RSA_SHA256, algorithm_ids::ED25519]
    }

    /// Get a list of hybrid signature algorithm IDs
    ///
    /// Hybrid algorithms combine classical and post-quantum cryptography.
    #[cfg(feature = "post-quantum")]
    pub fn hybrid_signature_algorithms() -> Vec<&'static str> {
        vec![
            algorithm_ids::HYBRID_RSA_DILITHIUM3,
            algorithm_ids::HYBRID_ED25519_DILITHIUM3,
        ]
    }

    /// Get a list of hybrid signature algorithm IDs
    #[cfg(not(feature = "post-quantum"))]
    pub fn hybrid_signature_algorithms() -> Vec<&'static str> {
        vec![]
    }

    /// Get the recommended algorithm for maximum security
    ///
    /// Returns a hybrid algorithm if post-quantum is available,
    /// otherwise returns Ed25519.
    pub fn recommended_algorithm() -> &'static dyn SignatureAlgorithm {
        #[cfg(feature = "post-quantum")]
        {
            SIGNATURE_ALGORITHMS
                .get(algorithm_ids::HYBRID_ED25519_DILITHIUM3)
                .map(|boxed| boxed.as_ref())
                .expect("Hybrid-Ed25519-Dilithium3 should be available with post-quantum feature")
        }
        #[cfg(not(feature = "post-quantum"))]
        {
            SIGNATURE_ALGORITHMS
                .get(algorithm_ids::ED25519)
                .map(|boxed| boxed.as_ref())
                .expect("Ed25519 should always be available")
        }
    }
}

/// Key pair abstraction that works with any signature algorithm
#[derive(Debug, Clone)]
pub struct CryptoKeyPair {
    /// The private key in PEM format
    pub private_key_pem: String,
    /// The public key in PEM format
    pub public_key_pem: String,
    /// The algorithm used to generate this key pair
    pub algorithm_id: String,
}

impl CryptoKeyPair {
    /// Generate a new key pair using the specified algorithm
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
    pub fn from_pem(private_key_pem: String, public_key_pem: String, algorithm_id: &str) -> Self {
        Self {
            private_key_pem,
            public_key_pem,
            algorithm_id: algorithm_id.to_string(),
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_get_rsa() {
        let alg = CryptoRegistry::get_signature_algorithm(algorithm_ids::RSA_SHA256).unwrap();
        assert_eq!(alg.algorithm_id(), algorithm_ids::RSA_SHA256);
    }

    #[test]
    fn test_registry_get_ed25519() {
        let alg = CryptoRegistry::get_signature_algorithm(algorithm_ids::ED25519).unwrap();
        assert_eq!(alg.algorithm_id(), algorithm_ids::ED25519);
    }

    #[test]
    fn test_registry_unknown_algorithm() {
        let result = CryptoRegistry::get_signature_algorithm("UNKNOWN-ALG");
        assert!(result.is_err());
    }

    #[test]
    fn test_supported_algorithms() {
        let supported = CryptoRegistry::supported_signature_algorithms();
        assert!(supported.contains(&algorithm_ids::RSA_SHA256));
        assert!(supported.contains(&algorithm_ids::ED25519));
    }

    #[test]
    fn test_default_algorithm() {
        let alg = CryptoRegistry::default_signature_algorithm();
        assert_eq!(alg.algorithm_id(), algorithm_ids::RSA_SHA256);
    }

    #[test]
    fn test_crypto_keypair_rsa() {
        let keypair = CryptoKeyPair::generate(algorithm_ids::RSA_SHA256).unwrap();
        assert_eq!(keypair.algorithm_id, algorithm_ids::RSA_SHA256);
        assert!(keypair.private_key_pem.contains("PRIVATE KEY"));
        assert!(keypair.public_key_pem.contains("PUBLIC KEY"));

        // Test sign and verify
        let data = b"test message";
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
        let data = b"test message";
        let signature = keypair.sign(data).unwrap();
        assert!(keypair.verify(data, &signature).is_ok());
    }
}
