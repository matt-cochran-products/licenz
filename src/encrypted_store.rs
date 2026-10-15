//! Encrypted key storage for secure backups
//!
//! This module provides AES-256-GCM encryption for private key storage with
//! **Argon2id** key derivation. The on-disk format uses [`ENCRYPTED_STORE_VERSION`] **1**.

use crate::error::{LicenseError, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

/// Minimum passphrase length required for encryption
pub const MIN_PASSPHRASE_LENGTH: usize = 12;

/// On-disk encryption format version for [`EncryptedKeyStore`].
pub const ENCRYPTED_STORE_VERSION: u8 = 1;

/// Encrypted private key storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeyStore {
    /// Encrypted key data
    encrypted_data: Vec<u8>,
    /// Nonce used for encryption
    nonce: [u8; 12],
    /// Salt used for key derivation
    salt: [u8; 32],
    /// Version of the encryption format
    version: u8,
}

impl EncryptedKeyStore {
    /// Encrypt a private key PEM with a passphrase
    ///
    /// Uses Argon2id for key derivation and AES-256-GCM for encryption.
    pub fn encrypt(private_key_pem: &str, passphrase: &str) -> Result<Self> {
        // Validate passphrase strength
        if passphrase.len() < MIN_PASSPHRASE_LENGTH {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Passphrase must be at least {} characters",
                MIN_PASSPHRASE_LENGTH
            )));
        }

        // Generate random salt and nonce
        let salt: [u8; 32] = rand::random();
        let nonce: [u8; 12] = rand::random();

        let derived_key = derive_key(passphrase.as_bytes(), &salt)?;

        // Encrypt the private key
        let encrypted_data = encrypt_aes_gcm(private_key_pem.as_bytes(), &derived_key, &nonce)?;

        Ok(Self {
            encrypted_data,
            nonce,
            salt,
            version: ENCRYPTED_STORE_VERSION,
        })
    }

    /// Decrypt the private key using the passphrase
    pub fn decrypt(&self, passphrase: &str) -> Result<String> {
        if self.version != ENCRYPTED_STORE_VERSION {
            return Err(LicenseError::InvalidKeyFormat(format!(
                "Unsupported encrypted key store version: {} (expected {})",
                self.version, ENCRYPTED_STORE_VERSION
            )));
        }

        let derived_key = derive_key(passphrase.as_bytes(), &self.salt)?;

        // Decrypt
        let decrypted =
            decrypt_aes_gcm(&self.encrypted_data, &derived_key, &self.nonce).map_err(|_| {
                LicenseError::InvalidKeyFormat(
                    "Decryption failed - incorrect passphrase or corrupted data".into(),
                )
            })?;

        String::from_utf8(decrypted).map_err(|e| LicenseError::InvalidKeyFormat(e.to_string()))
    }

    /// Save the encrypted key store to a file
    pub fn save(&self, path: &Path) -> Result<()> {
        let data = bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| LicenseError::SerializationError(e.to_string()))?;

        crate::keys::write_private_file(path, &data)?;

        Ok(())
    }

    /// Load an encrypted key store from a file
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        let (store, _len) = bincode::serde::decode_from_slice(&data, bincode::config::standard())
            .map_err(|e| LicenseError::InvalidKeyFormat(e.to_string()))?;
        Ok(store)
    }

    /// Create an encrypted backup of a private key file
    pub fn backup_key_file(
        private_key_path: &Path,
        backup_path: &Path,
        passphrase: &str,
    ) -> Result<()> {
        let pem = std::fs::read_to_string(private_key_path)?;
        let store = Self::encrypt(&pem, passphrase)?;
        store.save(backup_path)?;
        Ok(())
    }

    /// Restore a private key from an encrypted backup
    pub fn restore_key_file(
        backup_path: &Path,
        private_key_path: &Path,
        passphrase: &str,
    ) -> Result<()> {
        let store = Self::load(backup_path)?;
        let pem = Zeroizing::new(store.decrypt(passphrase)?);

        crate::keys::write_private_file(private_key_path, pem.as_bytes())?;

        Ok(())
    }
}

/// Argon2id per OWASP-style parameters (~19 MiB, t=2, p=1).
fn derive_key(passphrase: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|e| LicenseError::KeyGenerationFailed(format!("Argon2 params: {}", e)))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, salt.as_slice(), key.as_mut())
        .map_err(|e| LicenseError::KeyGenerationFailed(format!("Argon2id: {}", e)))?;
    Ok(key)
}

/// Encrypt data with AES-256-GCM
fn encrypt_aes_gcm(
    plaintext: &[u8],
    key: &Zeroizing<[u8; 32]>,
    nonce: &[u8; 12],
) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| LicenseError::KeyGenerationFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| LicenseError::KeyGenerationFailed(e.to_string()))
}

/// Decrypt data with AES-256-GCM
fn decrypt_aes_gcm(
    ciphertext: &[u8],
    key: &Zeroizing<[u8; 32]>,
    nonce: &[u8; 12],
) -> std::result::Result<Vec<u8>, ()> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| ())?;
    let nonce = Nonce::from_slice(nonce);

    cipher.decrypt(nonce, ciphertext).map_err(|_| ())
}

/// Validate passphrase strength
pub fn validate_passphrase(passphrase: &str) -> std::result::Result<(), Vec<&'static str>> {
    let mut errors = Vec::new();

    if passphrase.len() < MIN_PASSPHRASE_LENGTH {
        errors.push("Passphrase must be at least 12 characters");
    }

    if !passphrase.chars().any(|c| c.is_uppercase()) {
        errors.push("Passphrase should contain at least one uppercase letter");
    }

    if !passphrase.chars().any(|c| c.is_lowercase()) {
        errors.push("Passphrase should contain at least one lowercase letter");
    }

    if !passphrase.chars().any(|c| c.is_numeric()) {
        errors.push("Passphrase should contain at least one number");
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn security_restore_replaces_public_inode_and_rejects_wrong_passphrase() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let backup = dir.path().join("backup");
        let restored = dir.path().join("restored");
        let alias = dir.path().join("alias");
        let password = "SecurePass123!";
        EncryptedKeyStore::encrypt("secret PEM", password)
            .unwrap()
            .save(&backup)
            .unwrap();
        std::fs::write(&restored, "old").unwrap();
        std::fs::hard_link(&restored, &alias).unwrap();
        assert!(EncryptedKeyStore::restore_key_file(&backup, &restored, "wrong").is_err());
        assert_eq!(std::fs::read_to_string(&restored).unwrap(), "old");
        EncryptedKeyStore::restore_key_file(&backup, &restored, password).unwrap();
        assert_eq!(std::fs::read_to_string(&restored).unwrap(), "secret PEM");
        assert_eq!(std::fs::read_to_string(&alias).unwrap(), "old");
        assert_eq!(
            std::fs::metadata(&restored).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    use tempfile::TempDir;

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let original = "-----BEGIN PRIVATE KEY-----\ntest key content\n-----END PRIVATE KEY-----";
        let passphrase = "SecurePass123!";

        let store = EncryptedKeyStore::encrypt(original, passphrase).unwrap();
        assert_eq!(store.version, ENCRYPTED_STORE_VERSION);
        let decrypted = store.decrypt(passphrase).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let original = "test key content";
        let passphrase = "SecurePass123!";

        let store = EncryptedKeyStore::encrypt(original, passphrase).unwrap();
        let result = store.decrypt("WrongPassword1!");

        assert!(result.is_err());
    }

    #[test]
    fn test_passphrase_too_short() {
        let result = EncryptedKeyStore::encrypt("key", "short");
        assert!(result.is_err());
    }

    #[test]
    fn test_file_round_trip() {
        let temp_dir = TempDir::new().unwrap();
        let backup_path = temp_dir.path().join("key.backup");

        let original = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----";
        let passphrase = "SecurePass123!";

        let store = EncryptedKeyStore::encrypt(original, passphrase).unwrap();
        store.save(&backup_path).unwrap();

        let loaded = EncryptedKeyStore::load(&backup_path).unwrap();
        let decrypted = loaded.decrypt(passphrase).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_validate_passphrase() {
        assert!(validate_passphrase("SecurePass123!").is_ok());
        assert!(validate_passphrase("short").is_err());
        assert!(validate_passphrase("alllowercase123").is_err());
    }
}
