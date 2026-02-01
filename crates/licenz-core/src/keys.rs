//! RSA key management for license signing and verification

use crate::error::{LicenseError, Result};
use pem::{encode, Pem};
use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::path::Path;

/// Supported RSA key sizes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeySize {
    #[default]
    Bits2048,
    Bits3072,
    Bits4096,
}

impl KeySize {
    pub fn bits(&self) -> usize {
        match self {
            KeySize::Bits2048 => 2048,
            KeySize::Bits3072 => 3072,
            KeySize::Bits4096 => 4096,
        }
    }
}

/// RSA key pair for license signing
pub struct KeyPair {
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
}

impl KeyPair {
    /// Generate a new RSA key pair
    pub fn generate(size: KeySize) -> Result<Self> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, size.bits())
            .map_err(|e| LicenseError::KeyGenerationFailed(e.to_string()))?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Export the private key as PEM string
    pub fn export_private_pem(&self) -> Result<String> {
        let der = self
            .private_key
            .to_pkcs8_der()
            .map_err(|e| LicenseError::InvalidKeyFormat(e.to_string()))?;

        let pem = Pem::new("PRIVATE KEY", der.as_bytes());
        Ok(encode(&pem))
    }

    /// Export the public key as PEM string
    pub fn export_public_pem(&self) -> Result<String> {
        let der = self
            .public_key
            .to_public_key_der()
            .map_err(|e| LicenseError::InvalidKeyFormat(e.to_string()))?;

        let pem = Pem::new("PUBLIC KEY", der.as_bytes());
        Ok(encode(&pem))
    }

    /// Save the key pair to files
    pub fn save_to_files(&self, private_path: &Path, public_path: &Path) -> Result<()> {
        std::fs::write(private_path, self.export_private_pem()?)?;
        std::fs::write(public_path, self.export_public_pem()?)?;
        Ok(())
    }

    /// Load a key pair from files
    pub fn load_from_files(private_path: &Path, public_path: &Path) -> Result<Self> {
        let private_pem = std::fs::read_to_string(private_path)?;
        let public_pem = std::fs::read_to_string(public_path)?;

        let private_key = parse_private_key(&private_pem)?;
        let public_key = parse_public_key(&public_pem)?;

        Ok(Self {
            private_key,
            public_key,
        })
    }
}

/// Parse a private key from PEM format
pub fn parse_private_key(pem_str: &str) -> Result<RsaPrivateKey> {
    // Handle escaped newlines (from LDFLAGS injection)
    let pem_str = pem_str.replace("\\n", "\n");

    // Try PKCS#8 format first
    if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(&pem_str) {
        return Ok(key);
    }

    // Try PKCS#1 format
    if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(&pem_str) {
        return Ok(key);
    }

    Err(LicenseError::InvalidKeyFormat(
        "Could not parse private key (tried PKCS#8 and PKCS#1 formats)".into(),
    ))
}

/// Parse a public key from PEM format
pub fn parse_public_key(pem_str: &str) -> Result<RsaPublicKey> {
    // Handle escaped newlines (from LDFLAGS injection or env vars)
    let pem_str = pem_str.replace("\\n", "\n");

    // Try SPKI format first (most common)
    if let Ok(key) = RsaPublicKey::from_public_key_pem(&pem_str) {
        return Ok(key);
    }

    // Try PKCS#1 format
    if let Ok(key) = RsaPublicKey::from_pkcs1_pem(&pem_str) {
        return Ok(key);
    }

    Err(LicenseError::InvalidKeyFormat(
        "Could not parse public key (tried SPKI and PKCS#1 formats)".into(),
    ))
}

/// Extract the public key from a private key
pub fn extract_public_key(private_key: &RsaPrivateKey) -> RsaPublicKey {
    RsaPublicKey::from(private_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = KeyPair::generate(KeySize::Bits2048).unwrap();

        let private_pem = keypair.export_private_pem().unwrap();
        let public_pem = keypair.export_public_pem().unwrap();

        assert!(private_pem.contains("PRIVATE KEY"));
        assert!(public_pem.contains("PUBLIC KEY"));
    }

    #[test]
    fn test_key_round_trip() {
        let keypair = KeyPair::generate(KeySize::Bits2048).unwrap();

        let private_pem = keypair.export_private_pem().unwrap();
        let public_pem = keypair.export_public_pem().unwrap();

        let parsed_private = parse_private_key(&private_pem).unwrap();
        let parsed_public = parse_public_key(&public_pem).unwrap();

        assert_eq!(keypair.private_key, parsed_private);
        assert_eq!(keypair.public_key, parsed_public);
    }
}
