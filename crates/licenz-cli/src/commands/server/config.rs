//! Configuration management for CLI server commands
//!
//! Supports two credential storage modes:
//! 1. OS Keyring (secure, recommended) - when compiled with `keyring` feature
//! 2. File-based (fallback) - TOML file with restricted permissions

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Keyring service and username for credential storage
const KEYRING_SERVICE: &str = "licenz-cli";
const KEYRING_USERNAME: &str = "api_key";

#[derive(Debug, Serialize, Deserialize)]
pub struct Credentials {
    pub api_key: String,
    pub server_url: String,
}

/// Credential metadata stored in config file (without secret)
#[derive(Debug, Serialize, Deserialize)]
struct CredentialsMeta {
    pub server_url: String,
    /// Indicates API key is stored in keyring
    #[serde(default)]
    pub keyring_stored: bool,
}

fn get_config_dir() -> Result<PathBuf> {
    let proj_dirs = ProjectDirs::from("io", "licenz", "licenz")
        .context("Unable to determine config directory")?;
    let config_dir = proj_dirs.config_dir().to_path_buf();
    fs::create_dir_all(&config_dir)?;
    Ok(config_dir)
}

fn get_credentials_path() -> Result<PathBuf> {
    Ok(get_config_dir()?.join("credentials"))
}

// ============================================================================
// Keyring-based credential storage (when feature enabled)
// ============================================================================

#[cfg(feature = "keyring")]
mod keyring_storage {
    use super::*;

    /// Save API key to OS keyring
    pub fn save_to_keyring(api_key: &str) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USERNAME)
            .map_err(|e| anyhow::anyhow!("Failed to create keyring entry: {}", e))?;

        entry
            .set_password(api_key)
            .map_err(|e| anyhow::anyhow!("Failed to save to keyring: {}", e))?;

        Ok(())
    }

    /// Load API key from OS keyring
    pub fn load_from_keyring() -> Result<Option<String>> {
        let entry = match keyring::Entry::new(KEYRING_SERVICE, KEYRING_USERNAME) {
            Ok(e) => e,
            Err(_) => return Ok(None),
        };

        match entry.get_password() {
            Ok(password) => Ok(Some(password)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Failed to read from keyring: {}", e)),
        }
    }

    /// Delete API key from OS keyring
    pub fn delete_from_keyring() -> Result<()> {
        let entry = match keyring::Entry::new(KEYRING_SERVICE, KEYRING_USERNAME) {
            Ok(e) => e,
            Err(_) => return Ok(()), // No entry to delete
        };

        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // Already deleted
            Err(e) => Err(anyhow::anyhow!("Failed to delete from keyring: {}", e)),
        }
    }
}

/// Load credentials, preferring keyring if available
pub fn load_credentials() -> Result<Option<Credentials>> {
    let path = get_credentials_path()?;
    if !path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&path)?;

    // Try to parse as metadata first (keyring storage)
    if let Ok(meta) = toml::from_str::<CredentialsMeta>(&content) {
        if meta.keyring_stored {
            #[cfg(feature = "keyring")]
            {
                if let Some(api_key) = keyring_storage::load_from_keyring()? {
                    return Ok(Some(Credentials {
                        api_key,
                        server_url: meta.server_url,
                    }));
                }
                // Keyring entry missing, fall through to file-based
                tracing::warn!("Keyring entry not found, credentials may have been deleted");
                return Ok(None);
            }
            #[cfg(not(feature = "keyring"))]
            {
                return Err(anyhow::anyhow!(
                    "Credentials stored in keyring but keyring feature not enabled. \
                     Re-run login or rebuild with --features keyring"
                ));
            }
        }
    }

    // Fall back to legacy file-based storage
    let creds: Credentials = toml::from_str(&content)?;
    Ok(Some(creds))
}

/// Save credentials
///
/// With `keyring` feature: Stores API key in OS keyring, only metadata in file
/// Without `keyring` feature: Requires `allow_insecure` flag to store in plaintext file
pub fn save_credentials(creds: &Credentials, allow_insecure: bool) -> Result<()> {
    #[cfg(feature = "keyring")]
    {
        // Try keyring first
        match keyring_storage::save_to_keyring(&creds.api_key) {
            Ok(()) => {
                // Save metadata to file (without secret)
                let meta = CredentialsMeta {
                    server_url: creds.server_url.clone(),
                    keyring_stored: true,
                };
                let content = toml::to_string_pretty(&meta)?;
                let path = get_credentials_path()?;
                fs::write(&path, content)?;
                set_file_permissions(&path)?;
                tracing::info!("API key stored securely in OS keyring");
                return Ok(());
            }
            Err(e) => {
                if !allow_insecure {
                    return Err(anyhow::anyhow!(
                        "Failed to store in keyring: {}. \n\
                         Use --insecure-storage to store credentials in plaintext file (not recommended).",
                        e
                    ));
                }
                tracing::warn!(
                    "Keyring unavailable ({}), falling back to file storage",
                    e
                );
            }
        }
    }

    #[cfg(not(feature = "keyring"))]
    if !allow_insecure {
        return Err(anyhow::anyhow!(
            "Secure keyring storage not available (compile with --features keyring). \n\
             Use --insecure-storage to store credentials in plaintext file (not recommended)."
        ));
    }

    // File-based storage (insecure fallback)
    tracing::warn!("Storing API key in plaintext file - consider using keyring for secure storage");
    let path = get_credentials_path()?;
    let content = toml::to_string_pretty(creds)?;
    fs::write(&path, content)?;
    set_file_permissions(&path)?;

    Ok(())
}

/// Set restrictive file permissions
fn set_file_permissions(path: &PathBuf) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// Delete stored credentials from all storage locations
pub fn delete_credentials() -> Result<()> {
    // Delete from keyring if feature enabled
    #[cfg(feature = "keyring")]
    {
        let _ = keyring_storage::delete_from_keyring();
    }

    // Delete file
    let path = get_credentials_path()?;
    if path.exists() {
        fs::remove_file(&path)?;
    }

    Ok(())
}

/// Require credentials or return error with helpful message
pub fn require_credentials() -> Result<Credentials> {
    load_credentials()?.ok_or_else(|| {
        anyhow::anyhow!("Not logged in. Run 'licenz server login' first.")
    })
}
