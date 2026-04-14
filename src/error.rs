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

    #[error("Hardware binding mismatch: {field}")]
    HardwareBindingMismatch { field: String },

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

    // Sneakernet (offline activation) errors
    #[error("Invalid activation request: {0}")]
    InvalidActivationRequest(String),

    #[error("Invalid activation response: {0}")]
    InvalidActivationResponse(String),

    #[error("Activation request checksum mismatch - data may be corrupted")]
    ActivationRequestCorrupted,

    #[error("Activation response signature mismatch - data may be corrupted")]
    ActivationResponseCorrupted,

    #[error(
        "Activation request/response version mismatch: request v{request}, response v{response}"
    )]
    ActivationVersionMismatch { request: u8, response: u8 },

    #[error("Activation response does not match request ID")]
    ActivationRequestMismatch,

    #[error("Activation response has expired")]
    ActivationResponseExpired,

    // Admin unlock errors
    #[error("Invalid unlock response code: {0}")]
    InvalidResponseCode(String),

    #[error("Unlock response has expired")]
    UnlockResponseExpired,

    #[error("Machine is locked: {0}")]
    MachineLocked(String),
}

/// Result type alias for license operations
pub type Result<T> = std::result::Result<T, LicenseError>;
