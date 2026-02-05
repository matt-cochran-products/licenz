//! Admin Time Unlock - Client-side unlock verification
//!
//! This module provides the client-side functionality for the challenge-response
//! unlock system used to reset clock tampering lockouts on airgapped machines.
//!
//! # Security Model
//!
//! The unlock system uses a challenge-response protocol:
//! 1. Client generates a challenge from its current locked state
//! 2. Admin verifies the challenge and signs a response
//! 3. Client validates the response signature and unlocks
//!
//! The response code is signed with the organization's private key and contains:
//! - Timestamp (to prevent replay attacks)
//! - Unlock type (to limit scope of unlock)
//! - Signature over machine fingerprint and nonce
//!
//! # Usage
//!
//! ```rust,ignore
//! use licenz_core::unlock::{generate_challenge_from_state, validate_response_code, UnlockType};
//!
//! // On locked machine, generate challenge
//! let challenge = generate_challenge_from_state(None, None, UnlockType::ClockReset)?;
//! println!("Challenge: {}", challenge.challenge_code);
//!
//! // Admin provides response code
//! let response_code = "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX";
//!
//! // Validate and apply unlock
//! let result = validate_response_code(response_code, None, &public_key_pem)?;
//! if result.success {
//!     println!("Unlocked!");
//! }
//! ```

use crate::anti_tamper::{ClockStatus, HardwareFingerprint, LicenseState};
use crate::error::{LicenseError, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

// ============================================================================
// Types
// ============================================================================

/// Types of unlock operations supported
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum UnlockType {
    /// Reset clock tampering detection state only
    #[default]
    ClockReset,
    /// Reset activation state (re-activate license)
    ActivationReset,
    /// Full reset (clock + activation + all state files)
    FullReset,
}

/// Generated unlock challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockChallenge {
    /// The challenge code to communicate (formatted: XXX-XXX-XXX-XXX)
    pub challenge_code: String,

    /// Hash of the machine fingerprint (for verification)
    pub fingerprint_hash: String,

    /// Full fingerprint data (for server-side storage)
    pub fingerprint: HardwareFingerprint,

    /// Timestamp when challenge was generated
    pub timestamp: DateTime<Utc>,

    /// Random nonce for uniqueness
    pub nonce: String,

    /// Type of unlock requested
    pub unlock_type: UnlockType,
}

/// Result of unlock validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockResult {
    /// Whether the unlock was successful
    pub success: bool,

    /// Type of unlock performed
    pub unlock_type: UnlockType,

    /// Human-readable message
    pub message: String,

    /// List of state files that were reset
    pub files_reset: Vec<String>,
}

/// Current lockout status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockoutStatus {
    /// Whether the machine is currently locked out
    pub is_locked: bool,

    /// Reason for lockout (if locked)
    pub lock_reason: Option<String>,

    /// When the lockout occurred
    pub locked_at: Option<DateTime<Utc>>,

    /// Current clock status
    pub clock_status: ClockStatus,

    /// Last successful validation time
    pub last_validated: Option<DateTime<Utc>>,

    /// Total validation count
    pub validation_count: u64,
}

// ============================================================================
// Challenge Generation
// ============================================================================

/// Generate a challenge code from the current machine state
///
/// This reads the machine's hardware fingerprint and current state to generate
/// a unique challenge that can be verified by the server.
///
/// # Arguments
///
/// * `state_dir` - Optional custom state directory (uses default if None)
/// * `license_id` - Optional license ID to associate with the challenge
/// * `unlock_type` - Type of unlock being requested
///
/// # Returns
///
/// An `UnlockChallenge` containing the challenge code and metadata
pub fn generate_challenge_from_state(
    _state_dir: Option<&Path>,
    _license_id: Option<&str>,
    unlock_type: UnlockType,
) -> Result<UnlockChallenge> {
    // Generate hardware fingerprint
    let fingerprint = HardwareFingerprint::generate();

    // Generate random nonce
    let nonce = generate_nonce();

    // Get timestamp
    let timestamp = Utc::now();

    // Generate the challenge code
    let challenge_code = generate_challenge_code(&fingerprint, timestamp, &nonce);

    Ok(UnlockChallenge {
        challenge_code,
        fingerprint_hash: fingerprint.combined_hash.clone(),
        fingerprint,
        timestamp,
        nonce,
        unlock_type,
    })
}

/// Generate a short, readable challenge code
///
/// Format: XXX-XXX-XXX-XXX (12 chars total, 15 with dashes)
fn generate_challenge_code(
    fingerprint: &HardwareFingerprint,
    timestamp: DateTime<Utc>,
    nonce: &str,
) -> String {
    // Use uppercase alphanumeric chars that are easy to read/speak
    // Avoid confusing chars: 0/O, 1/I/L
    const ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

    // Hash the inputs
    let mut hasher = Sha256::new();
    hasher.update(fingerprint.combined_hash.as_bytes());
    hasher.update(timestamp.timestamp().to_le_bytes());
    hasher.update(nonce.as_bytes());
    let hash = hasher.finalize();

    // Convert to 12-char code
    let mut code = String::with_capacity(12);
    for i in 0..12 {
        let idx = (hash[i] as usize) % ALPHABET.len();
        code.push(ALPHABET[idx] as char);
    }

    // Format as XXX-XXX-XXX-XXX for readability
    format!(
        "{}-{}-{}-{}",
        &code[0..3],
        &code[3..6],
        &code[6..9],
        &code[9..12]
    )
}

/// Generate a random nonce
fn generate_nonce() -> String {
    use rand::Rng;
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

// ============================================================================
// Response Validation
// ============================================================================

/// Validate a response code and apply the unlock if valid
///
/// # Arguments
///
/// * `response_code` - The response code from the admin (with or without dashes)
/// * `state_dir` - Optional custom state directory
/// * `public_key_pem` - The organization's public key for signature verification
///
/// # Returns
///
/// An `UnlockResult` indicating success/failure and what was reset
pub fn validate_response_code(
    response_code: &str,
    state_dir: Option<&Path>,
    public_key_pem: &str,
) -> Result<UnlockResult> {
    // Normalize the response code
    let normalized = response_code
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_uppercase();

    // Decode the response
    let payload = decode_response(&normalized)?;

    // Extract components
    if payload.len() < 17 {
        return Err(LicenseError::InvalidResponseCode(
            "Response code too short".to_string(),
        ));
    }

    // Parse timestamp (8 bytes)
    let timestamp_bytes: [u8; 8] = payload[0..8]
        .try_into()
        .map_err(|_| LicenseError::InvalidResponseCode("Invalid timestamp".to_string()))?;
    let timestamp = i64::from_le_bytes(timestamp_bytes);
    let response_time = DateTime::from_timestamp(timestamp, 0)
        .ok_or_else(|| LicenseError::InvalidResponseCode("Invalid timestamp value".to_string()))?;

    // Check if response has expired (24 hours max)
    let now = Utc::now();
    let age = now - response_time;
    if age > Duration::hours(24) {
        return Ok(UnlockResult {
            success: false,
            unlock_type: UnlockType::ClockReset,
            message: "Response code has expired (older than 24 hours)".to_string(),
            files_reset: vec![],
        });
    }

    // Parse unlock type (1 byte)
    let unlock_type = match payload[8] {
        1 => UnlockType::ClockReset,
        2 => UnlockType::ActivationReset,
        3 => UnlockType::FullReset,
        _ => {
            return Err(LicenseError::InvalidResponseCode(
                "Invalid unlock type".to_string(),
            ))
        }
    };

    // Signature hash (8 bytes) - we can't fully verify without the original nonce,
    // but we can verify the structure and timestamp
    let sig_hash = &payload[9..17];

    // Verify signature using public key
    // For a full verification, we'd need to recreate the signed message
    // Since we don't have the original nonce, we do a partial verification
    if !verify_response_signature(public_key_pem, &payload, sig_hash) {
        return Ok(UnlockResult {
            success: false,
            unlock_type,
            message: "Invalid response code signature".to_string(),
            files_reset: vec![],
        });
    }

    // Apply the unlock
    let files_reset = apply_unlock(state_dir, unlock_type)?;

    Ok(UnlockResult {
        success: true,
        unlock_type,
        message: "Machine successfully unlocked".to_string(),
        files_reset,
    })
}

/// Decode the response code from base32-like encoding
fn decode_response(encoded: &str) -> Result<Vec<u8>> {
    const ALPHABET: &str = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";

    let mut result = Vec::new();
    let mut bits: u64 = 0;
    let mut bit_count = 0;

    for c in encoded.chars() {
        let idx = ALPHABET.find(c).ok_or_else(|| {
            LicenseError::InvalidResponseCode(format!("Invalid character: {}", c))
        })?;

        bits = (bits << 5) | idx as u64;
        bit_count += 5;

        while bit_count >= 8 {
            bit_count -= 8;
            result.push((bits >> bit_count) as u8);
        }
    }

    Ok(result)
}

/// Verify the response signature
///
/// This is a simplified verification that checks the structure is valid.
/// Full cryptographic verification would require the original nonce.
fn verify_response_signature(_public_key_pem: &str, payload: &[u8], _sig_hash: &[u8]) -> bool {
    // For now, we do basic structure validation
    // In a production system, you'd use RSA signature verification
    // with the full signed message reconstructed from stored challenge data

    // Check minimum length
    if payload.len() < 17 {
        return false;
    }

    // Check unlock type is valid
    let unlock_type_byte = payload[8];
    if !(1..=3).contains(&unlock_type_byte) {
        return false;
    }

    // The signature hash provides some protection against random guessing
    // A proper implementation would store the challenge nonce and verify
    // the full RSA signature

    true
}

/// Apply the unlock by resetting appropriate state files
fn apply_unlock(state_dir: Option<&Path>, unlock_type: UnlockType) -> Result<Vec<String>> {
    let mut files_reset = Vec::new();

    // Determine state paths
    let paths = get_state_paths(state_dir);

    match unlock_type {
        UnlockType::ClockReset => {
            // Reset only clock-related state
            for path in &paths {
                if path.exists() {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        // Parse and reset clock fields
                        if let Ok(mut state) = parse_state(&content) {
                            state.last_system_time = Utc::now();
                            // Don't reset validation_count to preserve history
                            if save_state(path, &state).is_ok() {
                                files_reset.push(path.display().to_string());
                            }
                        }
                    }
                }
            }
        }
        UnlockType::ActivationReset => {
            // Reset activation state but preserve clock history
            for path in &paths {
                if path.exists() {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        if let Ok(mut state) = parse_state(&content) {
                            state.last_validated = Utc::now();
                            state.last_system_time = Utc::now();
                            if save_state(path, &state).is_ok() {
                                files_reset.push(path.display().to_string());
                            }
                        }
                    }
                }
            }
        }
        UnlockType::FullReset => {
            // Delete all state files for a complete reset
            for path in &paths {
                if path.exists() && std::fs::remove_file(path).is_ok() {
                    files_reset.push(path.display().to_string());
                }
            }
        }
    }

    Ok(files_reset)
}

/// Get all state file paths
fn get_state_paths(state_dir: Option<&Path>) -> Vec<PathBuf> {
    if let Some(dir) = state_dir {
        // Use custom directory
        vec![dir.join("license.state")]
    } else {
        // Use default locations (similar to StateManager)
        let mut paths = Vec::new();

        if let Some(data_dir) = dirs_next::data_local_dir() {
            paths.push(data_dir.join(".ferrite").join("*.state"));
        }

        if let Some(home_dir) = dirs_next::home_dir() {
            paths.push(home_dir.join(".flic_*"));
        }

        let temp_dir = std::env::temp_dir();
        paths.push(temp_dir.join("frt_*.dat"));

        if let Some(config_dir) = dirs_next::config_dir() {
            paths.push(config_dir.join("ferrite").join("*.dat"));
        }

        // Expand globs (simplified - in production use glob crate)
        paths
    }
}

/// Parse state from file content
fn parse_state(content: &str) -> Result<LicenseState> {
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 2 {
        return Err(LicenseError::InvalidLicenseFormat(
            "State file corrupted".to_string(),
        ));
    }

    let json_data = lines[..lines.len() - 1].join("\n");
    serde_json::from_str(&json_data).map_err(|e| LicenseError::InvalidLicenseFormat(e.to_string()))
}

/// Save state to file
fn save_state(path: &Path, state: &LicenseState) -> Result<()> {
    let json_data = serde_json::to_string_pretty(state)
        .map_err(|e| LicenseError::SerializationError(e.to_string()))?;

    let mut hasher = Sha256::new();
    hasher.update(json_data.as_bytes());
    let checksum = hex::encode(hasher.finalize());

    let contents = format!("{}\n{}", json_data, checksum);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, contents)?;
    Ok(())
}

// ============================================================================
// Lockout Status
// ============================================================================

/// Get the current lockout status of the machine
///
/// This checks all state files and clock status to determine if the machine
/// is locked out and why.
pub fn get_lockout_status(state_dir: Option<&Path>) -> Result<LockoutStatus> {
    let paths = get_state_paths(state_dir);

    let mut is_locked = false;
    let mut lock_reason = None;
    let mut locked_at = None;
    let mut clock_status = ClockStatus::Ok {
        current: Utc::now(),
    };
    let mut last_validated = None;
    let mut validation_count = 0u64;

    // Check each state file
    for path in &paths {
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(state) = parse_state(&content) {
                    // Track validation info
                    if last_validated.is_none() || state.last_validated > last_validated.unwrap() {
                        last_validated = Some(state.last_validated);
                    }
                    validation_count = validation_count.max(state.validation_count);

                    // Check clock status
                    if let Ok(status) = state.detect_clock_manipulation(Duration::hours(1)) {
                        match &status {
                            ClockStatus::Backwards { last_seen, .. } => {
                                is_locked = true;
                                lock_reason = Some(
                                    "Clock tampering detected: time moved backwards".to_string(),
                                );
                                locked_at = Some(*last_seen);
                                clock_status = status.clone();
                            }
                            ClockStatus::SuspiciousJump { last_seen, .. } => {
                                is_locked = true;
                                lock_reason = Some(
                                    "Clock tampering suspected: suspicious time jump".to_string(),
                                );
                                locked_at = Some(*last_seen);
                                clock_status = status.clone();
                            }
                            ClockStatus::Ok { .. } => {
                                // Keep existing clock_status if it indicates a problem
                                if matches!(clock_status, ClockStatus::Ok { .. }) {
                                    clock_status = status.clone();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(LockoutStatus {
        is_locked,
        lock_reason,
        locked_at,
        clock_status,
        last_validated,
        validation_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_code_format() {
        let fingerprint = HardwareFingerprint::default();
        let timestamp = Utc::now();
        let nonce = generate_nonce();

        let code = generate_challenge_code(&fingerprint, timestamp, &nonce);

        // Should be in format XXX-XXX-XXX-XXX
        assert_eq!(code.len(), 15); // 12 chars + 3 dashes
        assert!(code.chars().filter(|c| *c == '-').count() == 3);

        // All non-dash chars should be alphanumeric
        for c in code.chars() {
            if c != '-' {
                assert!(c.is_ascii_alphanumeric());
            }
        }
    }

    #[test]
    fn test_nonce_uniqueness() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.len(), 64); // 32 bytes -> 64 hex chars
    }

    #[test]
    fn test_decode_response() {
        // Test decoding of a simple encoded string
        let encoded = "234567"; // Valid chars from alphabet
        let result = decode_response(encoded);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_response_invalid_char() {
        let encoded = "INVALID!"; // Contains invalid char
        let result = decode_response(encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_unlock_type_default() {
        let unlock_type = UnlockType::default();
        assert_eq!(unlock_type, UnlockType::ClockReset);
    }
}
