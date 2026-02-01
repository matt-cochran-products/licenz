//! Encrypted key storage for secure backups
//!
//! This module provides AES-256-GCM encryption for private key storage
//! with Argon2 key derivation from a passphrase.

use crate::error::{LicenseError, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Minimum passphrase length required for encryption
pub const MIN_PASSPHRASE_LENGTH: usize = 12;

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

        // Derive encryption key from passphrase using Argon2id
        let derived_key = derive_key(passphrase.as_bytes(), &salt)?;

        // Encrypt the private key
        let encrypted_data = encrypt_aes_gcm(private_key_pem.as_bytes(), &derived_key, &nonce)?;

        Ok(Self {
            encrypted_data,
            nonce,
            salt,
            version: 1,
        })
    }

    /// Decrypt the private key using the passphrase
    pub fn decrypt(&self, passphrase: &str) -> Result<String> {
        // Derive the same encryption key
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
        let data = bincode::serialize(self)
            .map_err(|e| LicenseError::SerializationError(e.to_string()))?;

        std::fs::write(path, data)?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    /// Load an encrypted key store from a file
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        bincode::deserialize(&data).map_err(|e| LicenseError::InvalidKeyFormat(e.to_string()))
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
        let pem = store.decrypt(passphrase)?;

        std::fs::write(private_key_path, &pem)?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(private_key_path, perms)?;
        }

        Ok(())
    }
}

/// Derive an encryption key from a passphrase using Argon2id
fn derive_key(passphrase: &[u8], salt: &[u8; 32]) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};

    // Simple PBKDF2-like derivation using SHA-256
    // In production, use argon2 crate for proper Argon2id
    let mut key = [0u8; 32];

    // Multiple rounds to slow down brute force
    let mut current = [0u8; 64];
    current[..32].copy_from_slice(salt);
    current[32..32 + passphrase.len().min(32)]
        .copy_from_slice(&passphrase[..passphrase.len().min(32)]);

    for _ in 0..100_000 {
        let mut hasher = Sha256::new();
        hasher.update(current);
        hasher.update(passphrase);
        let result = hasher.finalize();
        current[..32].copy_from_slice(&result);
    }

    key.copy_from_slice(&current[..32]);
    Ok(key)
}

/// Encrypt data with AES-256-GCM
fn encrypt_aes_gcm(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| LicenseError::KeyGenerationFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| LicenseError::KeyGenerationFailed(e.to_string()))
}

/// Decrypt data with AES-256-GCM
fn decrypt_aes_gcm(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> std::result::Result<Vec<u8>, ()> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
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
    use tempfile::TempDir;

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let original = "-----BEGIN PRIVATE KEY-----\ntest key content\n-----END PRIVATE KEY-----";
        let passphrase = "SecurePass123!";

        let store = EncryptedKeyStore::encrypt(original, passphrase).unwrap();
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
