//! ML-KEM-768 post-quantum key encapsulation mechanism (KEM) implementation.
//!
//! This module provides ML-KEM-768 key encapsulation for encrypting license payloads.
//! ML-KEM is a lattice-based KEM standardized by NIST as FIPS 203
//! (formerly known as CRYSTALS-Kyber).
//!
//! ML-KEM-768 provides NIST Level 3 security (equivalent to AES-192).
//!
//! Key and ciphertext sizes:
//! - Public key (encapsulation key): 1,184 bytes
//! - Private key (seed): 64 bytes
//! - Ciphertext: 1,088 bytes
//! - Shared secret: 32 bytes
//!
//! # Usage
//!
//! ML-KEM is used for key encapsulation, not direct encryption. The typical flow is:
//! 1. Generate a key pair (done once, stored with the license issuer)
//! 2. Encapsulate: Generate a random shared secret and ciphertext using the public key
//! 3. Use the shared secret with a symmetric cipher (like AES-GCM) to encrypt data
//! 4. Decapsulate: Recover the shared secret from the ciphertext using the private key

use crate::error::{LicenseError, Result};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{DecapsulationKey, EncapsulationKey, KeyExport, MlKem768};
use pem::{encode, parse, Pem};

/// PEM tag for ML-KEM-768 private keys
const ML_KEM_768_PRIVATE_KEY_TAG: &str = "ML-KEM-768 PRIVATE KEY";

/// PEM tag for ML-KEM-768 public keys
const ML_KEM_768_PUBLIC_KEY_TAG: &str = "ML-KEM-768 PUBLIC KEY";

/// PEM tag for ML-KEM-768 ciphertext
const ML_KEM_768_CIPHERTEXT_TAG: &str = "ML-KEM-768 CIPHERTEXT";

/// ML-KEM-768 key encapsulation mechanism implementation
pub struct MlKem768Kem;

impl Default for MlKem768Kem {
    fn default() -> Self {
        Self::new()
    }
}

impl MlKem768Kem {
    /// Create a new ML-KEM-768 KEM instance
    pub fn new() -> Self {
        Self
    }

    /// Generate a new ML-KEM-768 key pair
    ///
    /// # Returns
    /// A tuple of (private_key_pem, public_key_pem)
    pub fn generate_keypair(&self) -> Result<(String, String)> {
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
        let (dk, ek) = MlKem768::generate_keypair_from_rng(&mut rng);

        let private_pem = encode(&Pem::new(
            ML_KEM_768_PRIVATE_KEY_TAG,
            dk.to_bytes().as_slice().to_vec(),
        ));
        let public_pem = encode(&Pem::new(
            ML_KEM_768_PUBLIC_KEY_TAG,
            ek.to_bytes().as_slice().to_vec(),
        ));

        Ok((private_pem, public_pem))
    }

    /// Encapsulate a shared secret using the recipient's public key
    ///
    /// # Arguments
    /// * `public_key_pem` - The recipient's ML-KEM-768 public key in PEM format
    ///
    /// # Returns
    /// A tuple of (shared_secret, ciphertext_pem)
    pub fn encapsulate(&self, public_key_pem: &str) -> Result<(Vec<u8>, String)> {
        let ek = self.parse_public_key(public_key_pem)?;
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);

        let (ct, ss) = ek.encapsulate_with_rng(&mut rng);

        let ciphertext_pem = encode(&Pem::new(ML_KEM_768_CIPHERTEXT_TAG, ct.as_slice().to_vec()));

        Ok((ss.as_slice().to_vec(), ciphertext_pem))
    }

    /// Decapsulate a shared secret using the recipient's private key
    ///
    /// # Arguments
    /// * `ciphertext_pem` - The ciphertext in PEM format
    /// * `private_key_pem` - The recipient's ML-KEM-768 private key in PEM format
    ///
    /// # Returns
    /// The 32-byte shared secret
    pub fn decapsulate(&self, ciphertext_pem: &str, private_key_pem: &str) -> Result<Vec<u8>> {
        let dk = self.parse_private_key(private_key_pem)?;
        let ct = self.parse_ciphertext(ciphertext_pem)?;

        let ss = dk.decapsulate(&ct);

        Ok(ss.as_slice().to_vec())
    }

    /// Encapsulate and return raw bytes
    ///
    /// # Arguments
    /// * `public_key_pem` - The recipient's ML-KEM-768 public key in PEM format
    ///
    /// # Returns
    /// A tuple of (shared_secret, ciphertext_bytes)
    pub fn encapsulate_raw(&self, public_key_pem: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let ek = self.parse_public_key(public_key_pem)?;
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);

        let (ct, ss) = ek.encapsulate_with_rng(&mut rng);

        Ok((ss.as_slice().to_vec(), ct.as_slice().to_vec()))
    }

    /// Decapsulate from raw ciphertext bytes
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext bytes
    /// * `private_key_pem` - The recipient's ML-KEM-768 private key in PEM format
    ///
    /// # Returns
    /// The 32-byte shared secret
    pub fn decapsulate_raw(&self, ciphertext: &[u8], private_key_pem: &str) -> Result<Vec<u8>> {
        let dk = self.parse_private_key(private_key_pem)?;

        let ct: &ml_kem::Ciphertext<MlKem768> = ciphertext.try_into().map_err(|_| {
            LicenseError::InvalidKeyFormat(format!(
                "Invalid ML-KEM-768 ciphertext length: got {}",
                ciphertext.len()
            ))
        })?;

        let ss = dk.decapsulate(ct);

        Ok(ss.as_slice().to_vec())
    }

    /// Parse a private key from PEM format.
    ///
    /// The PEM contains the 64-byte seed from which the decapsulation key
    /// is deterministically derived.
    fn parse_private_key(&self, pem_str: &str) -> Result<DecapsulationKey<MlKem768>> {
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse ML-KEM-768 PEM: {}", e))
        })?;

        if pem.tag() != ML_KEM_768_PRIVATE_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                ML_KEM_768_PRIVATE_KEY_TAG,
                pem.tag()
            )));
        }

        let seed: &ml_kem::Seed = pem.contents().try_into().map_err(|_| {
            LicenseError::InvalidKeyFormat(format!(
                "Invalid ML-KEM-768 seed length: expected 64, got {}",
                pem.contents().len()
            ))
        })?;

        Ok(DecapsulationKey::<MlKem768>::from_seed(*seed))
    }

    /// Parse a public key from PEM format
    fn parse_public_key(&self, pem_str: &str) -> Result<EncapsulationKey<MlKem768>> {
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!("Failed to parse ML-KEM-768 PEM: {}", e))
        })?;

        if pem.tag() != ML_KEM_768_PUBLIC_KEY_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                ML_KEM_768_PUBLIC_KEY_TAG,
                pem.tag()
            )));
        }

        let ek_bytes: &ml_kem::Key<EncapsulationKey<MlKem768>> =
            pem.contents().try_into().map_err(|_| {
                LicenseError::InvalidKeyFormat(format!(
                    "Invalid ML-KEM-768 public key length: got {}",
                    pem.contents().len()
                ))
            })?;

        EncapsulationKey::<MlKem768>::new(ek_bytes).map_err(|_| {
            LicenseError::InvalidKeyFormat("Invalid ML-KEM-768 public key".to_string())
        })
    }

    /// Parse a ciphertext from PEM format
    fn parse_ciphertext(&self, pem_str: &str) -> Result<ml_kem::Ciphertext<MlKem768>> {
        let pem_str = pem_str.replace("\\n", "\n");

        let pem = parse(&pem_str).map_err(|e| {
            LicenseError::InvalidKeyFormat(format!(
                "Failed to parse ML-KEM-768 ciphertext PEM: {}",
                e
            ))
        })?;

        if pem.tag() != ML_KEM_768_CIPHERTEXT_TAG {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Expected PEM tag '{}', got '{}'",
                ML_KEM_768_CIPHERTEXT_TAG,
                pem.tag()
            )));
        }

        let ct: &ml_kem::Ciphertext<MlKem768> = pem.contents().try_into().map_err(|_| {
            LicenseError::InvalidKeyFormat(format!(
                "Invalid ML-KEM-768 ciphertext length: got {}",
                pem.contents().len()
            ))
        })?;

        Ok(*ct)
    }

    /// Extract the public key from a private key
    pub fn extract_public_key(&self, private_key_pem: &str) -> Result<String> {
        let dk = self.parse_private_key(private_key_pem)?;
        let ek = dk.encapsulation_key();

        Ok(encode(&Pem::new(
            ML_KEM_768_PUBLIC_KEY_TAG,
            ek.to_bytes().as_slice().to_vec(),
        )))
    }
}

/// Known sizes for ML-KEM-768 parameters
pub mod sizes {
    /// ML-KEM-768 public (encapsulation) key size in bytes
    pub const fn public_key_bytes() -> usize {
        1184
    }

    /// ML-KEM-768 ciphertext size in bytes
    pub const fn ciphertext_bytes() -> usize {
        1088
    }

    /// ML-KEM-768 shared secret size in bytes
    pub const fn shared_secret_bytes() -> usize {
        32
    }
}

/// Encrypt data using ML-KEM-768 + AES-256-GCM hybrid encryption
///
/// # Arguments
/// * `data` - The plaintext data to encrypt
/// * `public_key_pem` - The recipient's ML-KEM-768 public key
///
/// # Returns
/// Encrypted data in format: `[ciphertext_len (4 bytes)] || [kem_ciphertext] || [nonce (12 bytes)] || [aes_encrypted_data]`
pub fn encrypt_with_kem(data: &[u8], public_key_pem: &str) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use rand::RngCore;

    let kem = MlKem768Kem::new();

    // Encapsulate to get shared secret and ciphertext
    let (shared_secret, kem_ciphertext) = kem.encapsulate_raw(public_key_pem)?;

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

    // Build output: [kem_ct_len (4 bytes)] || [kem_ct] || [nonce (12 bytes)] || [aes_encrypted]
    let mut output = Vec::new();
    let ct_len = kem_ciphertext.len() as u32;
    output.extend_from_slice(&ct_len.to_le_bytes());
    output.extend_from_slice(&kem_ciphertext);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&encrypted);

    Ok(output)
}

/// Decrypt data that was encrypted with `encrypt_with_kem`
///
/// # Arguments
/// * `data` - The encrypted data
/// * `private_key_pem` - The recipient's ML-KEM-768 private key
///
/// # Returns
/// The decrypted plaintext
pub fn decrypt_with_kem(data: &[u8], private_key_pem: &str) -> Result<Vec<u8>> {
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

    // ML-KEM-768 ciphertext has a fixed length; reject before offset arithmetic.
    if ct_len != 1088 || data.len() - 4 < 1088 + 12 + 16 {
        return Err(LicenseError::InvalidLicenseFormat(
            "Encrypted data truncated".to_string(),
        ));
    }

    let kem_ciphertext = &data[4..4 + ct_len];
    let nonce_bytes = &data[4 + ct_len..4 + ct_len + 12];
    let encrypted = &data[4 + ct_len + 12..];

    // Decapsulate to recover shared secret
    let kem = MlKem768Kem::new();
    let shared_secret = kem.decapsulate_raw(kem_ciphertext, private_key_pem)?;

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
    fn security_kem_lengths_rejected_before_private_key_parse() {
        for length in [u32::MAX, u32::MAX - 15, 0, 1087, 1088, 1089] {
            let bytes = length.to_le_bytes();
            assert!(matches!(
                decrypt_with_kem(&bytes, "not a key"),
                Err(LicenseError::InvalidLicenseFormat(_))
            ));
        }
    }

    #[test]
    fn test_ml_kem_768_generate_keypair() {
        let kem = MlKem768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        assert!(private_pem.contains(ML_KEM_768_PRIVATE_KEY_TAG));
        assert!(public_pem.contains(ML_KEM_768_PUBLIC_KEY_TAG));
    }

    #[test]
    fn test_ml_kem_768_encapsulate_decapsulate() {
        let kem = MlKem768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        let (shared_secret_enc, ciphertext_pem) = kem.encapsulate(&public_pem).unwrap();
        let shared_secret_dec = kem.decapsulate(&ciphertext_pem, &private_pem).unwrap();

        assert_eq!(shared_secret_enc, shared_secret_dec);
        assert_eq!(shared_secret_enc.len(), 32);
    }

    #[test]
    fn test_ml_kem_768_encapsulate_decapsulate_raw() {
        let kem = MlKem768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        let (shared_secret_enc, ciphertext) = kem.encapsulate_raw(&public_pem).unwrap();
        let shared_secret_dec = kem.decapsulate_raw(&ciphertext, &private_pem).unwrap();

        assert_eq!(shared_secret_enc, shared_secret_dec);
    }

    #[test]
    fn test_ml_kem_768_wrong_key() {
        let kem = MlKem768Kem::new();
        let (_, public_pem) = kem.generate_keypair().unwrap();
        let (other_private_pem, _) = kem.generate_keypair().unwrap();

        let (shared_secret_enc, ciphertext_pem) = kem.encapsulate(&public_pem).unwrap();
        let shared_secret_dec = kem
            .decapsulate(&ciphertext_pem, &other_private_pem)
            .unwrap();

        // Shared secrets should NOT match with wrong key
        assert_ne!(shared_secret_enc, shared_secret_dec);
    }

    #[test]
    fn test_ml_kem_768_extract_public_key() {
        let kem = MlKem768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        let extracted = kem.extract_public_key(&private_pem).unwrap();

        // Verify that encapsulation works with extracted key
        let (_, ciphertext) = kem.encapsulate_raw(&extracted).unwrap();
        let result = kem.decapsulate_raw(&ciphertext, &private_pem);
        assert!(result.is_ok());

        assert_eq!(extracted, public_pem);
    }

    #[test]
    fn test_encrypt_decrypt_with_kem() {
        let kem = MlKem768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        let plaintext = b"This is a secret license payload with sensitive data!";

        let encrypted = encrypt_with_kem(plaintext, &public_pem).unwrap();
        assert!(encrypted.len() > plaintext.len());

        let decrypted = decrypt_with_kem(&encrypted, &private_pem).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let kem = MlKem768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        let plaintext = b"";
        let encrypted = encrypt_with_kem(plaintext, &public_pem).unwrap();
        let decrypted = decrypt_with_kem(&encrypted, &private_pem).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let kem = MlKem768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        let plaintext = vec![0xABu8; 100_000];
        let encrypted = encrypt_with_kem(&plaintext, &public_pem).unwrap();
        let decrypted = decrypt_with_kem(&encrypted, &private_pem).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let kem = MlKem768Kem::new();
        let (_, public_pem) = kem.generate_keypair().unwrap();
        let (other_private_pem, _) = kem.generate_keypair().unwrap();

        let plaintext = b"Secret data";
        let encrypted = encrypt_with_kem(plaintext, &public_pem).unwrap();

        let result = decrypt_with_kem(&encrypted, &other_private_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_data() {
        let kem = MlKem768Kem::new();
        let (private_pem, public_pem) = kem.generate_keypair().unwrap();

        let plaintext = b"Secret data";
        let mut encrypted = encrypt_with_kem(plaintext, &public_pem).unwrap();

        if let Some(last) = encrypted.last_mut() {
            *last ^= 0xFF;
        }

        let result = decrypt_with_kem(&encrypted, &private_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_encapsulations_different_secrets() {
        let kem = MlKem768Kem::new();
        let (_, public_pem) = kem.generate_keypair().unwrap();

        let (secret1, _) = kem.encapsulate(&public_pem).unwrap();
        let (secret2, _) = kem.encapsulate(&public_pem).unwrap();

        assert_ne!(secret1, secret2);
    }
}
