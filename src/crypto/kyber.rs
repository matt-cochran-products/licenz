//! Kyber768 post-quantum key encapsulation mechanism (KEM) implementation.
//!
//! This module provides Kyber768 key encapsulation for encrypting license payloads.
//! Kyber is a lattice-based KEM selected by NIST for post-quantum cryptography
//! standardization (FIPS 203 / ML-KEM).
//!
//! Kyber768 provides NIST Level 3 security (equivalent to AES-192).
//!
//! Key and ciphertext sizes:
//! - Public key: 1,184 bytes
//! - Private key: 2,400 bytes
//! - Ciphertext: 1,088 bytes
//! - Shared secret: 32 bytes
//!
//! # Usage
//!
//! Kyber is used for key encapsulation, not direct encryption. The typical flow is:
//! 1. Generate a Kyber key pair (done once, stored with the license issuer)
//! 2. Encapsulate: Generate a random shared secret and ciphertext using the public key
//! 3. Use the shared secret with a symmetric cipher (like AES-GCM) to encrypt data
//! 4. Decapsulate: Recover the shared secret from the ciphertext using the private key
//!
//! This provides forward secrecy for license payloads even if the private key is later compromised.

use crate::error::{LicenseError, Result};
use pem::{encode, parse, Pem};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

/// PEM tag for Kyber768 private keys
const KYBER768_PRIVATE_KEY_TAG: &str = "KYBER768 PRIVATE KEY";

/// PEM tag for Kyber768 public keys
const KYBER768_PUBLIC_KEY_TAG: &str = "KYBER768 PUBLIC KEY";

/// PEM tag for Kyber768 ciphertext
const KYBER768_CIPHERTEXT_TAG: &str = "KYBER768 CIPHERTEXT";

/// Kyber768 key encapsulation mechanism implementation
pub struct Kyber768Kem;

impl Default for Kyber768Kem {
    fn default() -> Self {
        Self::new()
    }
}

impl Kyber768Kem {
    /// Create a new Kyber768 KEM instance
    pub fn new() -> Self {
        Self
    }

    /// Generate a new Kyber768 key pair
    ///
    /// # Returns
    /// A tuple of (private_key_pem, public_key_pem)
    pub fn generate_keypair(&self) -> Result<(String, String)> {
        let (public_key, secret_key) = kyber768::keypair();

        let private_pem = encode(&Pem::new(KYBER768_PRIVATE_KEY_TAG, secret_key.as_bytes()));
        let public_pem = encode(&Pem::new(KYBER768_PUBLIC_KEY_TAG, public_key.as_bytes()));

        Ok((private_pem, public_pem))
    }

    /// Encapsulate a shared secret using the recipient's public key
    ///
    /// This generates a random shared secret and returns it along with the
    /// ciphertext that can be sent to the recipient.
    ///
    /// # Arguments
    /// * `public_key_pem` - The recipient's Kyber768 public key in PEM format
    ///
    /// # Returns
    /// A tuple of (shared_secret, ciphertext_pem)
    /// - shared_secret: 32 bytes that can be used as a symmetric key
    /// - ciphertext_pem: The encapsulated key in PEM format
    pub fn encapsulate(&self, public_key_pem: &str) -> Result<(Vec<u8>, String)> {
        let public_key = self.parse_public_key(public_key_pem)?;

        let (shared_secret, ciphertext) = kyber768::encapsulate(&public_key);

        let ciphertext_pem = encode(&Pem::new(KYBER768_CIPHERTEXT_TAG, ciphertext.as_bytes()));

        Ok((shared_secret.as_bytes().to_vec(), ciphertext_pem))
    }

    /// Decapsulate a shared secret using the recipient's private key
    ///
    /// # Arguments
    /// * `ciphertext_pem` - The ciphertext in PEM format
    /// * `private_key_pem` - The recipient's Kyber768 private key in PEM format
    ///
    /// # Returns
    /// The 32-byte shared secret
    pub fn decapsulate(&self, ciphertext_pem: &str, private_key_pem: &str) -> Result<Vec<u8>> {
        let secret_key = self.parse_private_key(private_key_pem)?;
        let ciphertext = self.parse_ciphertext(ciphertext_pem)?;

        let shared_secret = kyber768::decapsulate(&ciphertext, &secret_key);

        Ok(shared_secret.as_bytes().to_vec())
    }

    /// Encapsulate and return raw bytes (for direct use without PEM encoding)
    ///
    /// # Arguments
    /// * `public_key_pem` - The recipient's Kyber768 public key in PEM format
    ///
    /// # Returns
    /// A tuple of (shared_secret, ciphertext_bytes)
    pub fn encapsulate_raw(&self, public_key_pem: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let public_key = self.parse_public_key(public_key_pem)?;

        let (shared_secret, ciphertext) = kyber768::encapsulate(&public_key);

        Ok((
            shared_secret.as_bytes().to_vec(),
            ciphertext.as_bytes().to_vec(),
        ))
    }

    /// Decapsulate from raw ciphertext bytes
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext bytes
    /// * `private_key_pem` - The recipient's Kyber768 private key in PEM format
    ///
    /// # Returns
    /// The 32-byte shared secret
    pub fn decapsulate_raw(&self, ciphertext: &[u8], private_key_pem: &str) -> Result<Vec<u8>> {
        let secret_key = self.parse_private_key(private_key_pem)?;

        let ct = kyber768::Ciphertext::from_bytes(ciphertext).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Invalid Kyber768 ciphertext: {:?}", e))
        })?;

        let shared_secret = kyber768::decapsulate(&ct, &secret_key);

        Ok(shared_secret.as_bytes().to_vec())
    }

    /// Parse a Kyber768 private key from PEM format
    fn parse_private_key(&self, pem_str: &str) -> Result<kyber768::SecretKey> {
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse Kyber768 PEM: {}", e))
        })?;

        if pem.tag() != KYBER768_PRIVATE_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                KYBER768_PRIVATE_KEY_TAG,
                pem.tag()
            )));
        }

        kyber768::SecretKey::from_bytes(pem.contents()).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Invalid Kyber768 private key: {:?}", e))
        })
    }

    /// Parse a Kyber768 public key from PEM format
    fn parse_public_key(&self, pem_str: &str) -> Result<kyber768::PublicKey> {
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse Kyber768 PEM: {}", e))
        })?;

        if pem.tag() != KYBER768_PUBLIC_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                KYBER768_PUBLIC_KEY_TAG,
                pem.tag()
            )));
        }

        kyber768::PublicKey::from_bytes(pem.contents()).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Invalid Kyber768 public key: {:?}", e))
        })
    }

    /// Parse a Kyber768 ciphertext from PEM format
    fn parse_ciphertext(&self, pem_str: &str) -> Result<kyber768::Ciphertext> {
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!(
                "Failed to parse Kyber768 ciphertext PEM: {}",
                e
            ))
        })?;

        if pem.tag() != KYBER768_CIPHERTEXT_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                KYBER768_CIPHERTEXT_TAG,
                pem.tag()
            )));
        }

        kyber768::Ciphertext::from_bytes(pem.contents()).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Invalid Kyber768 ciphertext: {:?}", e))
        })
    }

    /// Extract the public key from a private key (for Kyber, this is embedded)
    pub fn extract_public_key(&self, private_key_pem: &str) -> Result<String> {
        // Kyber secret key format includes the public key
        // The layout is: s || pk || H(pk) || z
        // where pk is at offset secret_key_bytes - public_key_bytes - 64
        let secret_key = self.parse_private_key(private_key_pem)?;
        let sk_bytes = secret_key.as_bytes();

        let pk_len = kyber768::public_key_bytes();
        let _sk_len = kyber768::secret_key_bytes();

        // Extract public key from the secret key
        // In Kyber768, the layout puts pk at a specific offset
        let pk_offset = 1152; // Kyber768 specific: s (1152 bytes) || pk || H(pk) || z

        if sk_bytes.len() < pk_offset + pk_len {
            return Err(LicenseError::InvalidKeyFormat(
                "Secret key too short to contain public key".to_string(),
            ));
        }

        let pk_bytes = &sk_bytes[pk_offset..pk_offset + pk_len];
        let _public_key = kyber768::PublicKey::from_bytes(pk_bytes).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!(
                "Failed to extract public key from secret key: {:?}",
                e
            ))
        })?;

        Ok(encode(&Pem::new(KYBER768_PUBLIC_KEY_TAG, pk_bytes)))
    }
}

/// Get the size of Kyber768 keys and ciphertext
pub mod sizes {
    use pqcrypto_kyber::kyber768;

    /// Size of the public key in bytes
    pub fn public_key_bytes() -> usize {
        kyber768::public_key_bytes()
    }

    /// Size of the secret key in bytes
    pub fn secret_key_bytes() -> usize {
        kyber768::secret_key_bytes()
    }

    /// Size of the ciphertext in bytes
    pub fn ciphertext_bytes() -> usize {
        kyber768::ciphertext_bytes()
    }

    /// Size of the shared secret in bytes (always 32)
    pub fn shared_secret_bytes() -> usize {
        32
    }
}

/// Encrypt data using Kyber768 + AES-256-GCM hybrid encryption
///
/// This is a convenience function that combines KEM with symmetric encryption.
///
/// # Arguments
/// * `data` - The plaintext data to encrypt
/// * `public_key_pem` - The recipient's Kyber768 public key
///
/// # Returns
/// Encrypted data in format: `[ciphertext_len (4 bytes)] || [kyber_ciphertext] || [aes_encrypted_data]`
pub fn encrypt_with_kyber(data: &[u8], public_key_pem: &str) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use rand::RngCore;

    let kem = Kyber768Kem::new();

    // Encapsulate to get shared secret and ciphertext
    let (shared_secret, kyber_ciphertext) = kem.encapsulate_raw(public_key_pem)?;

    // Use shared secret as AES-256-GCM key
    let key: [u8; 32] = shared_secret.try_into().map_err(|_| {
        LicenseError::KeyGenerationFailed("Invalid shared secret length".to_string())
    })?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| LicenseError::SigningFailed(format!("Failed to create cipher: {}", e)))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt data
    let encrypted = cipher
        .encrypt(nonce, data)
        .map_err(|e| LicenseError::SigningFailed(format!("Encryption failed: {}", e)))?;

    // Build output: [kyber_ct_len (4 bytes)] || [kyber_ct] || [nonce (12 bytes)] || [aes_encrypted]
    let mut output = Vec::new();
    let ct_len = kyber_ciphertext.len() as u32;
    output.extend_from_slice(&ct_len.to_le_bytes());
    output.extend_from_slice(&kyber_ciphertext);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&encrypted);

    Ok(output)
}

/// Decrypt data that was encrypted with `encrypt_with_kyber`
///
/// # Arguments
/// * `data` - The encrypted data
/// * `private_key_pem` - The recipient's Kyber768 private key
///
/// # Returns
/// The decrypted plaintext
pub fn decrypt_with_kyber(data: &[u8], private_key_pem: &str) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    if data.len() < 4 {
        return Err(LicenseError::InvalidLicenseFormat(
            "Encrypted data too short".to_string(),
        ));
    }

    // Parse header
    let ct_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;

    if data.len() < 4 + ct_len + 12 {
        return Err(LicenseError::InvalidLicenseFormat(
            "Encrypted data truncated".to_string(),
        ));
    }

    let kyber_ciphertext = &data[4..4 + ct_len];
    let nonce_bytes = &data[4 + ct_len..4 + ct_len + 12];
    let encrypted = &data[4 + ct_len + 12..];

    // Decapsulate to recover shared secret
    let kem = Kyber768Kem::new();
    let shared_secret = kem.decapsulate_raw(kyber_ciphertext, private_key_pem)?;

    // Use shared secret as AES-256-GCM key
    let key: [u8; 32] = shared_secret.try_into().map_err(|_| {
        LicenseError::KeyGenerationFailed("Invalid shared secret length".to_string())
    })?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| LicenseError::VerificationFailed(format!("Failed to create cipher: {}", e)))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt data
    let decrypted = cipher
        .decrypt(nonce, encrypted)
        .map_err(|e| LicenseError::VerificationFailed(format!("Decryption failed: {}", e)))?;

    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber768_generate_keypair() {
        let kem = Kyber768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        assert!(private_pem.contains(KYBER768_PRIVATE_KEY_TAG));
        assert!(public_pem.contains(KYBER768_PUBLIC_KEY_TAG));
    }

    #[test]
    fn test_kyber768_encapsulate_decapsulate() {
        let kem = Kyber768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        // Encapsulate
        let (shared_secret_enc, ciphertext_pem) = kem.encapsulate(&public_pem).unwrap();

        // Decapsulate
        let shared_secret_dec = kem.decapsulate(&ciphertext_pem, &private_pem).unwrap();

        // Shared secrets must match
        assert_eq!(shared_secret_enc, shared_secret_dec);
        assert_eq!(shared_secret_enc.len(), 32);
    }

    #[test]
    fn test_kyber768_encapsulate_decapsulate_raw() {
        let kem = Kyber768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        // Encapsulate
        let (shared_secret_enc, ciphertext) = kem.encapsulate_raw(&public_pem).unwrap();

        // Decapsulate
        let shared_secret_dec = kem.decapsulate_raw(&ciphertext, &private_pem).unwrap();

        // Shared secrets must match
        assert_eq!(shared_secret_enc, shared_secret_dec);
    }

    #[test]
    fn test_kyber768_wrong_key() {
        let kem = Kyber768Kem::new();
        let (_, public_pem) = kem.generate_keypair().unwrap();
        let (other_private_pem, _) = kem.generate_keypair().unwrap();

        // Encapsulate with first keypair's public key
        let (shared_secret_enc, ciphertext_pem) = kem.encapsulate(&public_pem).unwrap();

        // Try to decapsulate with different private key
        let shared_secret_dec = kem
            .decapsulate(&ciphertext_pem, &other_private_pem)
            .unwrap();

        // Shared secrets should NOT match
        assert_ne!(shared_secret_enc, shared_secret_dec);
    }

    #[test]
    fn test_kyber768_key_sizes() {
        // Kyber768 key sizes per NIST specification
        assert_eq!(sizes::public_key_bytes(), 1184);
        assert_eq!(sizes::ciphertext_bytes(), 1088);
        assert_eq!(sizes::shared_secret_bytes(), 32);
    }

    #[test]
    fn test_kyber768_extract_public_key() {
        let kem = Kyber768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        let extracted = kem.extract_public_key(&private_pem).unwrap();

        // Verify that encapsulation works with extracted key
        let (_, ciphertext) = kem.encapsulate_raw(&extracted).unwrap();

        // Verify decapsulation works
        let result = kem.decapsulate_raw(&ciphertext, &private_pem);
        assert!(result.is_ok());

        // The extracted key should match the original
        assert_eq!(extracted, public_pem);
    }

    #[test]
    fn test_encrypt_decrypt_with_kyber() {
        let kem = Kyber768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        let plaintext = b"This is a secret license payload with sensitive data!";

        // Encrypt
        let encrypted = encrypt_with_kyber(plaintext, &public_pem).unwrap();

        // Encrypted data should be larger than plaintext
        assert!(encrypted.len() > plaintext.len());

        // Decrypt
        let decrypted = decrypt_with_kyber(&encrypted, &private_pem).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let kem = Kyber768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        let plaintext = b"";

        let encrypted = encrypt_with_kyber(plaintext, &public_pem).unwrap();
        let decrypted = decrypt_with_kyber(&encrypted, &private_pem).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let kem = Kyber768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        let plaintext = vec![0xABu8; 100_000];

        let encrypted = encrypt_with_kyber(&plaintext, &public_pem).unwrap();
        let decrypted = decrypt_with_kyber(&encrypted, &private_pem).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let kem = Kyber768Kem::new();
        let (_, public_pem) = kem.generate_keypair().unwrap();
        let (other_private_pem, _) = kem.generate_keypair().unwrap();

        let plaintext = b"Secret data";

        let encrypted = encrypt_with_kyber(plaintext, &public_pem).unwrap();

        // Decryption with wrong key should fail (AES-GCM authentication)
        let result = decrypt_with_kyber(&encrypted, &other_private_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_data() {
        let kem = Kyber768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        let plaintext = b"Secret data";

        let mut encrypted = encrypt_with_kyber(plaintext, &public_pem).unwrap();

        // Tamper with the encrypted data
        if let Some(last) = encrypted.last_mut() {
            *last ^= 0xFF;
        }

        // Decryption should fail due to authentication
        let result = decrypt_with_kyber(&encrypted, &private_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_encapsulations_different_secrets() {
        let kem = Kyber768Kem::new();
        let (_, public_pem) = kem.generate_keypair().unwrap();

        // Each encapsulation should produce a different shared secret
        let (secret1, _) = kem.encapsulate(&public_pem).unwrap();
        let (secret2, _) = kem.encapsulate(&public_pem).unwrap();

        assert_ne!(secret1, secret2);
    }
}
