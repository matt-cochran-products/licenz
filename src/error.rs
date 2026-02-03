//! Error types for the license system

use thiserror::Error;

/// Errors that can occur during license operations
#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("License signing failed: {0}")]
    SigningFailed(String),

    #[error("License verification failed: {0}")]
    VerificationFailed(String),

    #[error("License has expired (expired on {0})")]
    LicenseExpired(String),

    #[error("Hardware binding mismatch: {field} - expected one of {expected:?}, got {actual}")]
    HardwareBindingMismatch {
        field: String,
        expected: Vec<String>,
        actual: String,
    },

    #[error("Invalid license format: {0}")]
    InvalidLicenseFormat(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("License not yet valid (valid from {0})")]
    NotYetValid(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    // Anti-tamper errors
    #[error("Clock manipulation detected: system time moved backwards by {drift_hours} hours")]
    ClockManipulationDetected { drift_hours: i64 },

    #[error("Clock drift too large: {drift_hours} hours difference from expected")]
    ClockDriftTooLarge { drift_hours: i64 },

    #[error("License state file has been tampered with")]
    StateFileTampered,

    #[error("License state file is for a different license")]
    StateLicenseMismatch,

    #[error("Activation denied: {0}")]
    ActivationDenied(String),

    #[error("Activation limit reached: {current} of {max} activations used")]
    ActivationLimitReached { max: u32, current: u32 },

    #[error("Hardware fingerprint mismatch: only {percentage:.1}% match (minimum 70% required)")]
    HardwareFingerprintMismatch { percentage: f32 },

    #[error("Insecure key permissions on {path}: mode {mode}. {suggestion}")]
    InsecureKeyPermissions {
        path: std::path::PathBuf,
        mode: String,
        suggestion: String,
    },

    #[error("Validation error: {0}")]
    Validation(String),
}

/// Result type alias for license operations
pub type Result<T> = std::result::Result<T, LicenseError>;
