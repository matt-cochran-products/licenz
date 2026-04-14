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
//! let state_key = [0u8; 32]; // same key used for LicenseState HMAC
//! let challenge = generate_challenge_from_state(None, None, UnlockType::ClockReset, &state_key)?;
//! println!("Challenge: {}", challenge.challenge_code);
//!
//! // Admin signs the challenge and sends back raw response bytes
//! let response_bytes: &[u8] = &[/* timestamp(8) || unlock_type(1) || signature */];
//! let result = validate_response_code(
//!     response_bytes, None, "LIC-ID", &state_key, &public_key_pem, "Ed25519",
//! )?;
//! if result.success {
//!     println!("Unlocked!");
//! }
//! ```

use crate::anti_tamper::{ClockStatus, HardwareFingerprint, LicenseState};
use crate::crypto::CryptoRegistry;
use crate::error::{LicenseError, Result};
use crate::state_manager::StateManager;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
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

/// A pending challenge stored on disk for later verification.
///
/// This binds the nonce and metadata generated during challenge creation
/// so that the response can be verified against the original challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingChallenge {
    /// Random nonce generated during challenge
    nonce: String,
    /// When the challenge was generated
    timestamp: DateTime<Utc>,
    /// Type of unlock requested
    unlock_type: UnlockType,
    /// SHA-256 hash of the hardware fingerprint
    fingerprint_hash: String,
}

type HmacSha256 = Hmac<Sha256>;

impl PendingChallenge {
    /// Save pending challenge to disk with HMAC integrity protection
    fn save(&self, state_dir: &Path, state_integrity_key: &[u8; 32]) -> Result<()> {
        let json = serde_json::to_vec(self)
            .map_err(|e| LicenseError::SerializationError(e.to_string()))?;

        let mut mac = HmacSha256::new_from_slice(state_integrity_key)
            .map_err(|e| LicenseError::SigningFailed(format!("HMAC init: {}", e)))?;
        mac.update(&json);
        let tag = mac.finalize().into_bytes();

        // Format: [tag (32 bytes)] || [json]
        let mut data = Vec::with_capacity(32 + json.len());
        data.extend_from_slice(&tag);
        data.extend_from_slice(&json);

        let path = Self::challenge_path(state_dir);
        std::fs::create_dir_all(state_dir)?;
        std::fs::write(&path, &data)?;

        Ok(())
    }

    /// Load and verify a pending challenge from disk (one-time read)
    fn load_and_delete(state_dir: &Path, state_integrity_key: &[u8; 32]) -> Result<Self> {
        let path = Self::challenge_path(state_dir);

        let data = std::fs::read(&path).map_err(|_| {
            LicenseError::InvalidResponseCode(
                "No pending challenge found. Generate a challenge first.".to_string(),
            )
        })?;

        // Delete immediately to prevent replay
        let _ = std::fs::remove_file(&path);

        if data.len() < 33 {
            return Err(LicenseError::InvalidResponseCode(
                "Corrupted challenge file".to_string(),
            ));
        }

        let (tag_bytes, json) = data.split_at(32);

        // Verify HMAC
        let mut mac = HmacSha256::new_from_slice(state_integrity_key)
            .map_err(|e| LicenseError::VerificationFailed(format!("HMAC init: {}", e)))?;
        mac.update(json);
        mac.verify_slice(tag_bytes).map_err(|_| {
            LicenseError::VerificationFailed("Challenge file integrity check failed".to_string())
        })?;

        serde_json::from_slice(json)
            .map_err(|e| LicenseError::InvalidResponseCode(format!("Corrupt challenge: {}", e)))
    }

    fn challenge_path(state_dir: &Path) -> PathBuf {
        state_dir.join("pending.challenge")
    }
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
    state_dir: Option<&Path>,
    _license_id: Option<&str>,
    unlock_type: UnlockType,
    state_integrity_key: &[u8; 32],
) -> Result<UnlockChallenge> {
    // Generate hardware fingerprint
    let fingerprint = HardwareFingerprint::generate();

    // Generate random nonce
    let nonce = generate_nonce();

    // Get timestamp
    let timestamp = Utc::now();

    // Generate the challenge code
    let challenge_code = generate_challenge_code(&fingerprint, timestamp, &nonce);

    // Persist the pending challenge for later verification
    let pending = PendingChallenge {
        nonce: nonce.clone(),
        timestamp,
        unlock_type,
        fingerprint_hash: fingerprint.combined_hash.clone(),
    };

    let dir = state_dir.unwrap_or_else(|| Path::new("."));
    pending.save(dir, state_integrity_key)?;

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
/// The response is raw bytes: `[timestamp(8)] || [unlock_type(1)] || [signature(variable)]`.
/// The admin signs `SHA256(nonce || timestamp_bytes || unlock_type_byte || fingerprint_hash)`
/// using the organization's private key. The pending challenge (saved during
/// `generate_challenge_from_state`) supplies the nonce and fingerprint_hash for
/// reconstruction.
///
/// # Arguments
///
/// * `response_bytes` - The raw response bytes from the admin
/// * `state_dir` - Optional custom state directory (must match the one used for challenge)
/// * `license_id` - The license ID
/// * `state_integrity_key` - The state HMAC key (same key used for LicenseState)
/// * `public_key_pem` - The organization's public key for signature verification
/// * `algorithm_id` - The signature algorithm used (e.g., "RSA-SHA256", "Ed25519")
///
/// # Returns
///
/// An `UnlockResult` indicating success/failure and what was reset
pub fn validate_response_code(
    response_bytes: &[u8],
    state_dir: Option<&Path>,
    license_id: &str,
    state_integrity_key: &[u8; 32],
    public_key_pem: &str,
    algorithm_id: &str,
) -> Result<UnlockResult> {
    // Minimum: 8 (timestamp) + 1 (unlock_type) + 1 (signature)
    if response_bytes.len() < 10 {
        return Err(LicenseError::InvalidResponseCode(
            "Response too short".to_string(),
        ));
    }

    // Parse timestamp (8 bytes LE)
    let timestamp_bytes: [u8; 8] = response_bytes[0..8]
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
    let unlock_type = match response_bytes[8] {
        1 => UnlockType::ClockReset,
        2 => UnlockType::ActivationReset,
        3 => UnlockType::FullReset,
        _ => {
            return Err(LicenseError::InvalidResponseCode(
                "Invalid unlock type".to_string(),
            ))
        }
    };

    // Remaining bytes are the signature
    let signature = &response_bytes[9..];

    // Load the pending challenge (deletes it to prevent replay)
    let dir = state_dir.unwrap_or_else(|| Path::new("."));
    let pending = PendingChallenge::load_and_delete(dir, state_integrity_key)?;

    // Check challenge hasn't expired (challenge itself has a 24-hour window)
    let challenge_age = now - pending.timestamp;
    if challenge_age > Duration::hours(24) {
        return Ok(UnlockResult {
            success: false,
            unlock_type,
            message: "Challenge has expired (older than 24 hours). Generate a new one.".to_string(),
            files_reset: vec![],
        });
    }

    // Reconstruct the signed message: SHA256(nonce || timestamp || unlock_type || fingerprint_hash)
    let unlock_type_byte = response_bytes[8];
    let mut hasher = Sha256::new();
    hasher.update(pending.nonce.as_bytes());
    hasher.update(timestamp_bytes);
    hasher.update([unlock_type_byte]);
    hasher.update(pending.fingerprint_hash.as_bytes());
    let message = hasher.finalize();

    // Verify the signature using the specified algorithm
    let algorithm = CryptoRegistry::get_signature_algorithm(algorithm_id)?;
    algorithm
        .verify(&message, signature, public_key_pem)
        .map_err(|_| {
            LicenseError::InvalidResponseCode("Invalid signature on response code".to_string())
        })?;

    // Apply the unlock
    let files_reset = apply_unlock(state_dir, unlock_type, license_id, state_integrity_key)?;

    Ok(UnlockResult {
        success: true,
        unlock_type,
        message: "Machine successfully unlocked".to_string(),
        files_reset,
    })
}

/// Apply the unlock by resetting appropriate state files
fn apply_unlock(
    state_dir: Option<&Path>,
    unlock_type: UnlockType,
    license_id: &str,
    state_integrity_key: &[u8; 32],
) -> Result<Vec<String>> {
    let mut files_reset = Vec::new();

    let paths = unlock_state_paths(state_dir, license_id, state_integrity_key);

    match unlock_type {
        UnlockType::ClockReset => {
            for path in &paths {
                if path.exists() {
                    if let Ok(Some(mut state)) =
                        LicenseState::load(path, license_id, state_integrity_key)
                    {
                        state.last_system_time = Utc::now();
                        if state.save(path, state_integrity_key).is_ok() {
                            files_reset.push(path.display().to_string());
                        }
                    }
                }
            }
        }
        UnlockType::ActivationReset => {
            for path in &paths {
                if path.exists() {
                    if let Ok(Some(mut state)) =
                        LicenseState::load(path, license_id, state_integrity_key)
                    {
                        state.last_validated = Utc::now();
                        state.last_system_time = Utc::now();
                        if state.save(path, state_integrity_key).is_ok() {
                            files_reset.push(path.display().to_string());
                        }
                    }
                }
            }
        }
        UnlockType::FullReset => {
            for path in &paths {
                if path.exists() && std::fs::remove_file(path).is_ok() {
                    files_reset.push(path.display().to_string());
                }
            }
        }
    }

    Ok(files_reset)
}

fn unlock_state_paths(
    state_dir: Option<&Path>,
    license_id: &str,
    state_integrity_key: &[u8; 32],
) -> Vec<PathBuf> {
    if let Some(dir) = state_dir {
        vec![dir.join("license.state")]
    } else {
        StateManager::new(license_id, *state_integrity_key)
            .paths()
            .to_vec()
    }
}

// ============================================================================
// Lockout Status
// ============================================================================

/// Get the current lockout status of the machine
///
/// This checks all state files and clock status to determine if the machine
/// is locked out and why.
pub fn get_lockout_status(
    state_dir: Option<&Path>,
    license_id: &str,
    state_integrity_key: &[u8; 32],
) -> Result<LockoutStatus> {
    let paths = unlock_state_paths(state_dir, license_id, state_integrity_key);

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
            if let Ok(Some(state)) = LicenseState::load(path, license_id, state_integrity_key) {
                if last_validated.is_none() || state.last_validated > last_validated.unwrap() {
                    last_validated = Some(state.last_validated);
                }
                validation_count = validation_count.max(state.validation_count);

                if let Ok(status) = state.detect_clock_manipulation(Duration::hours(1)) {
                    match &status {
                        ClockStatus::Backwards { last_seen, .. } => {
                            is_locked = true;
                            lock_reason =
                                Some("Clock tampering detected: time moved backwards".to_string());
                            locked_at = Some(*last_seen);
                            clock_status = status.clone();
                        }
                        ClockStatus::SuspiciousJump { last_seen, .. } => {
                            is_locked = true;
                            lock_reason =
                                Some("Clock tampering suspected: suspicious time jump".to_string());
                            locked_at = Some(*last_seen);
                            clock_status = status.clone();
                        }
                        ClockStatus::Ok { .. } => {
                            if matches!(clock_status, ClockStatus::Ok { .. }) {
                                clock_status = status.clone();
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
    fn test_unlock_type_default() {
        let unlock_type = UnlockType::default();
        assert_eq!(unlock_type, UnlockType::ClockReset);
    }

    #[test]
    fn test_pending_challenge_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0xABu8; 32];

        let pending = PendingChallenge {
            nonce: "test-nonce-123".to_string(),
            timestamp: Utc::now(),
            unlock_type: UnlockType::ClockReset,
            fingerprint_hash: "abc123".to_string(),
        };

        pending.save(dir.path(), &key).unwrap();

        let loaded = PendingChallenge::load_and_delete(dir.path(), &key).unwrap();
        assert_eq!(loaded.nonce, pending.nonce);
        assert_eq!(loaded.fingerprint_hash, pending.fingerprint_hash);
        assert_eq!(loaded.unlock_type, pending.unlock_type);

        // Second load should fail (file deleted)
        assert!(PendingChallenge::load_and_delete(dir.path(), &key).is_err());
    }

    #[test]
    fn test_pending_challenge_wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let key1 = [0xABu8; 32];
        let key2 = [0xCDu8; 32];

        let pending = PendingChallenge {
            nonce: "test-nonce".to_string(),
            timestamp: Utc::now(),
            unlock_type: UnlockType::FullReset,
            fingerprint_hash: "xyz".to_string(),
        };

        pending.save(dir.path(), &key1).unwrap();

        // Loading with wrong key should fail HMAC verification
        assert!(PendingChallenge::load_and_delete(dir.path(), &key2).is_err());
    }

    #[test]
    fn test_validate_response_with_real_signature() {
        use crate::crypto::algorithm_ids;
        use crate::keys::CryptoKeyPair;

        let dir = tempfile::tempdir().unwrap();
        let state_key = [0x42u8; 32];

        // Generate a challenge (saves pending challenge to disk)
        let challenge = generate_challenge_from_state(
            Some(dir.path()),
            Some("TEST-LIC"),
            UnlockType::ClockReset,
            &state_key,
        )
        .unwrap();

        // Admin side: sign the response
        let keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();

        let timestamp = Utc::now();
        let timestamp_bytes = timestamp.timestamp().to_le_bytes();
        let unlock_type_byte: u8 = 1; // ClockReset

        // Reconstruct the message the same way validate_response_code does
        let mut hasher = Sha256::new();
        hasher.update(challenge.nonce.as_bytes());
        hasher.update(timestamp_bytes);
        hasher.update([unlock_type_byte]);
        hasher.update(challenge.fingerprint_hash.as_bytes());
        let message = hasher.finalize();

        let algorithm = CryptoRegistry::get_signature_algorithm(algorithm_ids::ED25519).unwrap();
        let signature = algorithm.sign(&message, keypair.private_key_pem()).unwrap();

        // Build response bytes: [timestamp(8)] || [unlock_type(1)] || [signature]
        let mut response = Vec::new();
        response.extend_from_slice(&timestamp_bytes);
        response.push(unlock_type_byte);
        response.extend_from_slice(&signature);

        // Validate
        let result = validate_response_code(
            &response,
            Some(dir.path()),
            "TEST-LIC",
            &state_key,
            &keypair.public_key_pem,
            algorithm_ids::ED25519,
        )
        .unwrap();

        assert!(result.success, "Expected success, got: {}", result.message);
        assert_eq!(result.unlock_type, UnlockType::ClockReset);
    }

    #[test]
    fn test_validate_response_wrong_signature_fails() {
        use crate::crypto::algorithm_ids;
        use crate::keys::CryptoKeyPair;

        let dir = tempfile::tempdir().unwrap();
        let state_key = [0x42u8; 32];

        let _challenge = generate_challenge_from_state(
            Some(dir.path()),
            Some("TEST-LIC"),
            UnlockType::ClockReset,
            &state_key,
        )
        .unwrap();

        // Sign with one key, verify with another
        let _signing_keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();
        let wrong_keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();

        let timestamp_bytes = Utc::now().timestamp().to_le_bytes();

        // Build a response with garbage signature
        let mut response = Vec::new();
        response.extend_from_slice(&timestamp_bytes);
        response.push(1); // ClockReset
        response.extend_from_slice(&[0u8; 64]); // Fake Ed25519 signature

        let result = validate_response_code(
            &response,
            Some(dir.path()),
            "TEST-LIC",
            &state_key,
            &wrong_keypair.public_key_pem,
            algorithm_ids::ED25519,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_response_no_pending_challenge_fails() {
        use crate::crypto::algorithm_ids;
        use crate::keys::CryptoKeyPair;

        let dir = tempfile::tempdir().unwrap();
        let state_key = [0x42u8; 32];
        let keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();

        // No challenge was generated; try to validate directly
        let mut response = Vec::new();
        response.extend_from_slice(&Utc::now().timestamp().to_le_bytes());
        response.push(1);
        response.extend_from_slice(&[0u8; 64]);

        let result = validate_response_code(
            &response,
            Some(dir.path()),
            "TEST-LIC",
            &state_key,
            &keypair.public_key_pem,
            algorithm_ids::ED25519,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_response_replay_fails() {
        use crate::crypto::algorithm_ids;
        use crate::keys::CryptoKeyPair;

        let dir = tempfile::tempdir().unwrap();
        let state_key = [0x42u8; 32];

        let challenge = generate_challenge_from_state(
            Some(dir.path()),
            Some("TEST-LIC"),
            UnlockType::ClockReset,
            &state_key,
        )
        .unwrap();

        let keypair = CryptoKeyPair::generate(algorithm_ids::ED25519).unwrap();

        let timestamp = Utc::now();
        let timestamp_bytes = timestamp.timestamp().to_le_bytes();

        let mut hasher = Sha256::new();
        hasher.update(challenge.nonce.as_bytes());
        hasher.update(timestamp_bytes);
        hasher.update([1u8]);
        hasher.update(challenge.fingerprint_hash.as_bytes());
        let message = hasher.finalize();

        let algorithm = CryptoRegistry::get_signature_algorithm(algorithm_ids::ED25519).unwrap();
        let signature = algorithm.sign(&message, keypair.private_key_pem()).unwrap();

        let mut response = Vec::new();
        response.extend_from_slice(&timestamp_bytes);
        response.push(1);
        response.extend_from_slice(&signature);

        // First validation succeeds
        let result = validate_response_code(
            &response,
            Some(dir.path()),
            "TEST-LIC",
            &state_key,
            &keypair.public_key_pem,
            algorithm_ids::ED25519,
        )
        .unwrap();
        assert!(result.success);

        // Replay attempt fails (challenge was deleted)
        let result2 = validate_response_code(
            &response,
            Some(dir.path()),
            "TEST-LIC",
            &state_key,
            &keypair.public_key_pem,
            algorithm_ids::ED25519,
        );
        assert!(result2.is_err());
    }
}
