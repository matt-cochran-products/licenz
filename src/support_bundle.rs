//! Support Bundle Generation
//!
//! This module provides functionality to generate diagnostic support bundles
//! for troubleshooting license-related issues, particularly useful in air-gapped
//! environments where direct support access isn't possible.
//!
//! # Overview
//!
//! A support bundle collects system and license state information that helps
//! diagnose licensing problems without exposing sensitive data. The bundle can
//! be optionally encrypted using a hardware-derived key for secure transmission.
//!
//! # Security
//!
//! - All sensitive data is sanitized or hashed before inclusion
//! - MAC addresses, disk IDs, and hostnames are shown as partial/hashed values
//! - License keys and signatures are never included in plain text
//! - Optional encryption provides additional protection during transmission

use crate::anti_tamper::{ClockStatus, HardwareFingerprint, LicenseState};
use crate::container::RuntimeEnvironment;
use crate::error::{LicenseError, Result};
use crate::hardware::{detect_hardware, HardwareInfo};
use crate::state_manager::StateManager;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::path::Path;

/// Support bundle format version
pub const BUNDLE_VERSION: u8 = 1;

/// Magic bytes for encrypted bundle format
pub const ENCRYPTED_BUNDLE_MAGIC: &[u8; 4] = b"LSBX";

/// A diagnostic support bundle containing system and license state information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundle {
    /// Bundle format version
    pub version: u8,

    /// When this bundle was generated
    pub generated_at: DateTime<Utc>,

    /// Hardware fingerprint information (sanitized)
    pub hardware: HardwareSummary,

    /// System clock state
    pub clock_state: ClockState,

    /// License status summary
    pub license_status: Option<LicenseStatusSummary>,

    /// Recent verification events/errors
    pub verification_log: Vec<VerificationEvent>,

    /// Environment information
    pub environment: EnvironmentInfo,

    /// State file observations
    pub state_files: StateFileSummary,

    /// Bundle metadata
    pub metadata: HashMap<String, String>,
}

/// Sanitized hardware information summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSummary {
    /// Partial MAC addresses (first 3 octets shown, rest masked)
    pub mac_addresses_partial: Vec<String>,

    /// Number of detected MAC addresses
    pub mac_count: usize,

    /// Partial hostname (first 4 chars + hash suffix)
    pub hostname_partial: Option<String>,

    /// Number of detected disk IDs
    pub disk_count: usize,

    /// Partial disk identifiers (hashed)
    pub disk_ids_hashed: Vec<String>,

    /// Machine ID present (yes/no, not actual value)
    pub has_machine_id: bool,

    /// Combined fingerprint hash (for matching purposes)
    pub fingerprint_hash: String,
}

/// System clock state information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockState {
    /// Current system time
    pub current_time: DateTime<Utc>,

    /// Last recorded validation time (from state)
    pub last_validation_time: Option<DateTime<Utc>>,

    /// Time drift detected (if any)
    pub drift_seconds: Option<i64>,

    /// Clock status assessment
    pub status: ClockStatusSummary,

    /// System timezone (from environment)
    pub timezone: Option<String>,
}

/// Summary of clock status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClockStatusSummary {
    /// Clock appears normal
    Normal,
    /// Clock drifted backward (potential manipulation)
    DriftedBackward { seconds: i64 },
    /// Clock jumped forward significantly
    JumpedForward { seconds: i64 },
    /// No previous state available for comparison
    NoPreviousState,
    /// Unable to determine clock status
    Unknown { reason: String },
}

/// License status summary (no sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseStatusSummary {
    /// License ID hash (not the actual ID)
    pub id_hash: String,

    /// Product ID (non-sensitive)
    pub product_id: String,

    /// Whether the license is currently valid
    pub is_valid: bool,

    /// Days until expiration (negative if expired)
    pub days_remaining: i64,

    /// Expiration date
    pub expires_at: DateTime<Utc>,

    /// Issue date
    pub issued_at: DateTime<Utc>,

    /// Whether hardware binding is configured
    pub has_hardware_binding: bool,

    /// Hardware binding match status
    pub hardware_match: Option<HardwareMatchStatus>,

    /// Number of features enabled
    pub feature_count: usize,

    /// Validation count from state
    pub validation_count: Option<u64>,

    /// Signature algorithm used
    pub algorithm: String,
}

/// Hardware binding match status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareMatchStatus {
    /// Match percentage (0-100)
    pub percentage: f32,

    /// Factors that matched
    pub matched_factors: Vec<String>,

    /// Factors that did not match
    pub unmatched_factors: Vec<String>,
}

/// A verification event/error for the log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationEvent {
    /// When this event occurred
    pub timestamp: DateTime<Utc>,

    /// Event type
    pub event_type: VerificationEventType,

    /// Event message
    pub message: String,

    /// Additional context
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub context: HashMap<String, String>,
}

/// Types of verification events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationEventType {
    /// Successful verification
    Success,
    /// Signature verification failed
    SignatureFailure,
    /// License expired
    Expired,
    /// License not yet valid
    NotYetValid,
    /// Hardware binding mismatch
    HardwareMismatch,
    /// Clock manipulation detected
    ClockManipulation,
    /// State file issue
    StateFileIssue,
    /// General error
    Error,
}

/// Environment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    /// Operating system name
    pub os_name: String,

    /// Operating system version
    pub os_version: String,

    /// CPU architecture
    pub architecture: String,

    /// Runtime environment detection
    pub runtime: RuntimeEnvironmentSummary,

    /// Is this a containerized environment?
    pub is_containerized: bool,

    /// Is this a virtualized environment?
    pub is_virtualized: bool,

    /// Detected cloud provider (if any)
    pub cloud_provider: Option<String>,

    /// Licenz library version
    pub licenz_version: String,
}

/// Runtime environment summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuntimeEnvironmentSummary {
    /// Native/bare metal
    Native,
    /// Docker container
    Docker,
    /// Kubernetes pod
    Kubernetes,
    /// AWS EC2 instance
    AwsEc2,
    /// Google Compute Engine
    GcpCompute,
    /// Azure VM
    AzureVm,
    /// Generic cloud/virtual
    GenericCloud,
    /// Unknown
    Unknown,
}

/// State file summary
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateFileSummary {
    /// Number of state file locations checked
    pub locations_checked: usize,

    /// Number of valid state files found
    pub valid_files: usize,

    /// Number of corrupted/missing files
    pub corrupted_or_missing: usize,

    /// State file locations (paths only, not contents)
    pub locations: Vec<StateFileLocation>,
}

/// State file location info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateFileLocation {
    /// Path (may be sanitized)
    pub path: String,

    /// Status of this location
    pub status: StateFileLocationStatus,
}

/// Status of a state file location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateFileLocationStatus {
    /// Valid state file exists
    Valid,
    /// File is missing
    Missing,
    /// File exists but is corrupted
    Corrupted,
    /// File appears tampered with
    Tampered,
    /// Unable to read/access
    Inaccessible { reason: String },
}

impl SupportBundle {
    /// Generate a new support bundle with basic system information
    pub fn generate() -> Self {
        let now = Utc::now();

        Self {
            version: BUNDLE_VERSION,
            generated_at: now,
            hardware: HardwareSummary::collect(),
            clock_state: ClockState::collect(None),
            license_status: None,
            verification_log: Vec::new(),
            environment: EnvironmentInfo::collect(),
            state_files: StateFileSummary::default(),
            metadata: HashMap::new(),
        }
    }

    /// Generate a support bundle with license information (`state_integrity_key` for [`LicenseState`] files).
    pub fn generate_with_license(license_id: &str, state_integrity_key: &[u8; 32]) -> Self {
        let now = Utc::now();
        let state_manager = StateManager::new(license_id, *state_integrity_key);

        // Load state if available
        let state = state_manager.load(license_id).ok().flatten();

        Self {
            version: BUNDLE_VERSION,
            generated_at: now,
            hardware: HardwareSummary::collect(),
            clock_state: ClockState::collect(state.as_ref()),
            license_status: None, // Will be filled in by caller with license data
            verification_log: Vec::new(),
            environment: EnvironmentInfo::collect(),
            state_files: StateFileSummary::collect(license_id, state_integrity_key),
            metadata: HashMap::new(),
        }
    }

    /// Add a verification event to the log
    pub fn add_event(&mut self, event: VerificationEvent) {
        self.verification_log.push(event);
    }

    /// Add metadata to the bundle
    pub fn add_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Set license status summary
    pub fn set_license_status(&mut self, status: LicenseStatusSummary) {
        self.license_status = Some(status);
    }

    /// Serialize the bundle to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| LicenseError::SerializationError(e.to_string()))
    }

    /// Serialize the bundle to compact JSON
    pub fn to_json_compact(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| LicenseError::SerializationError(e.to_string()))
    }

    /// Parse a bundle from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| LicenseError::InvalidLicenseFormat(format!("Invalid bundle JSON: {}", e)))
    }

    /// Encrypt the bundle using a hardware-derived key
    pub fn encrypt(&self) -> Result<Vec<u8>> {
        let json = self.to_json_compact()?;
        encrypt_bundle(json.as_bytes())
    }

    /// Decrypt an encrypted bundle
    pub fn decrypt(encrypted: &[u8]) -> Result<Self> {
        let decrypted = decrypt_bundle(encrypted)?;
        let json = String::from_utf8(decrypted)
            .map_err(|e| LicenseError::InvalidLicenseFormat(format!("Invalid UTF-8: {}", e)))?;
        Self::from_json(&json)
    }

    /// Save the bundle to a file (JSON format)
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Save the bundle as encrypted binary
    pub fn save_encrypted(&self, path: &Path) -> Result<()> {
        let encrypted = self.encrypt()?;
        std::fs::write(path, encrypted)?;
        Ok(())
    }

    /// Load a bundle from a file (auto-detects format)
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;

        // Check for encrypted format
        if data.len() > 4 && &data[..4] == ENCRYPTED_BUNDLE_MAGIC {
            Self::decrypt(&data)
        } else {
            let json = String::from_utf8(data)
                .map_err(|e| LicenseError::InvalidLicenseFormat(format!("Invalid UTF-8: {}", e)))?;
            Self::from_json(&json)
        }
    }
}

impl HardwareSummary {
    /// Collect sanitized hardware information
    pub fn collect() -> Self {
        let hw = detect_hardware();
        let fingerprint = HardwareFingerprint::from_hardware_info(&hw);

        Self {
            mac_addresses_partial: hw
                .mac_addresses
                .iter()
                .map(|mac| sanitize_mac_address(mac))
                .collect(),
            mac_count: hw.mac_addresses.len(),
            hostname_partial: hw.hostname.as_ref().map(|h| sanitize_hostname(h)),
            disk_count: hw.disk_ids.len(),
            disk_ids_hashed: hw.disk_ids.iter().map(|d| hash_identifier(d)).collect(),
            has_machine_id: hw.machine_id.is_some(),
            fingerprint_hash: fingerprint.combined_hash,
        }
    }

    /// Create from existing HardwareInfo
    pub fn from_hardware_info(hw: &HardwareInfo) -> Self {
        let fingerprint = HardwareFingerprint::from_hardware_info(hw);

        Self {
            mac_addresses_partial: hw
                .mac_addresses
                .iter()
                .map(|mac| sanitize_mac_address(mac))
                .collect(),
            mac_count: hw.mac_addresses.len(),
            hostname_partial: hw.hostname.as_ref().map(|h| sanitize_hostname(h)),
            disk_count: hw.disk_ids.len(),
            disk_ids_hashed: hw.disk_ids.iter().map(|d| hash_identifier(d)).collect(),
            has_machine_id: hw.machine_id.is_some(),
            fingerprint_hash: fingerprint.combined_hash,
        }
    }
}

impl ClockState {
    /// Collect clock state information
    pub fn collect(state: Option<&LicenseState>) -> Self {
        let now = Utc::now();

        let (last_validation_time, drift_seconds, status) = match state {
            Some(s) => {
                let drift = (now - s.last_system_time).num_seconds();

                let status = match s.detect_clock_manipulation(Duration::hours(1)) {
                    Ok(ClockStatus::Ok { .. }) => ClockStatusSummary::Normal,
                    Ok(ClockStatus::Backwards { drift, .. }) => {
                        ClockStatusSummary::DriftedBackward {
                            seconds: drift.num_seconds(),
                        }
                    }
                    Ok(ClockStatus::SuspiciousJump { jump, .. }) => {
                        ClockStatusSummary::JumpedForward {
                            seconds: jump.num_seconds(),
                        }
                    }
                    Err(e) => ClockStatusSummary::Unknown {
                        reason: e.to_string(),
                    },
                };

                (Some(s.last_system_time), Some(drift), status)
            }
            None => (None, None, ClockStatusSummary::NoPreviousState),
        };

        Self {
            current_time: now,
            last_validation_time,
            drift_seconds,
            status,
            timezone: env::var("TZ").ok(),
        }
    }
}

impl EnvironmentInfo {
    /// Collect environment information
    pub fn collect() -> Self {
        let runtime_env = RuntimeEnvironment::detect();

        let runtime = match runtime_env {
            RuntimeEnvironment::Standalone => RuntimeEnvironmentSummary::Native,
            RuntimeEnvironment::Docker => RuntimeEnvironmentSummary::Docker,
            RuntimeEnvironment::Kubernetes => RuntimeEnvironmentSummary::Kubernetes,
            RuntimeEnvironment::AwsEc2 => RuntimeEnvironmentSummary::AwsEc2,
            RuntimeEnvironment::GcpCompute => RuntimeEnvironmentSummary::GcpCompute,
            RuntimeEnvironment::AzureVm => RuntimeEnvironmentSummary::AzureVm,
            RuntimeEnvironment::GenericCloud => RuntimeEnvironmentSummary::GenericCloud,
        };

        let is_containerized = matches!(
            runtime_env,
            RuntimeEnvironment::Docker | RuntimeEnvironment::Kubernetes
        );

        let is_virtualized = matches!(
            runtime_env,
            RuntimeEnvironment::AwsEc2
                | RuntimeEnvironment::GcpCompute
                | RuntimeEnvironment::AzureVm
                | RuntimeEnvironment::GenericCloud
        );

        let cloud_provider = match runtime_env {
            RuntimeEnvironment::AwsEc2 => Some("AWS".to_string()),
            RuntimeEnvironment::GcpCompute => Some("GCP".to_string()),
            RuntimeEnvironment::AzureVm => Some("Azure".to_string()),
            _ => None,
        };

        Self {
            os_name: env::consts::OS.to_string(),
            os_version: get_os_version(),
            architecture: env::consts::ARCH.to_string(),
            runtime,
            is_containerized,
            is_virtualized,
            cloud_provider,
            licenz_version: crate::VERSION.to_string(),
        }
    }
}

impl StateFileSummary {
    /// Collect state file information for a license
    pub fn collect(license_id: &str, state_integrity_key: &[u8; 32]) -> Self {
        let state_manager = StateManager::new(license_id, *state_integrity_key);
        let paths = state_manager.paths();

        let mut valid_count = 0;
        let mut invalid_count = 0;
        let mut locations = Vec::new();

        for path in paths {
            let path_str = sanitize_path(&path.display().to_string());

            if !path.exists() {
                invalid_count += 1;
                locations.push(StateFileLocation {
                    path: path_str,
                    status: StateFileLocationStatus::Missing,
                });
            } else {
                match LicenseState::load(path, license_id, state_integrity_key) {
                    Ok(Some(_)) => {
                        valid_count += 1;
                        locations.push(StateFileLocation {
                            path: path_str,
                            status: StateFileLocationStatus::Valid,
                        });
                    }
                    Ok(None) => {
                        invalid_count += 1;
                        locations.push(StateFileLocation {
                            path: path_str,
                            status: StateFileLocationStatus::Missing,
                        });
                    }
                    Err(LicenseError::StateFileTampered) => {
                        invalid_count += 1;
                        locations.push(StateFileLocation {
                            path: path_str,
                            status: StateFileLocationStatus::Tampered,
                        });
                    }
                    Err(e) => {
                        invalid_count += 1;
                        locations.push(StateFileLocation {
                            path: path_str,
                            status: StateFileLocationStatus::Inaccessible {
                                reason: e.to_string(),
                            },
                        });
                    }
                }
            }
        }

        Self {
            locations_checked: paths.len(),
            valid_files: valid_count,
            corrupted_or_missing: invalid_count,
            locations,
        }
    }
}

impl VerificationEvent {
    /// Create a new verification event
    pub fn new(event_type: VerificationEventType, message: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type,
            message: message.into(),
            context: HashMap::new(),
        }
    }

    /// Add context to the event
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }
}

// =============================================================================
// Sanitization Functions
// =============================================================================

/// Sanitize a MAC address (show first 3 octets, mask the rest)
fn sanitize_mac_address(mac: &str) -> String {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() >= 3 {
        format!(
            "{}:{}:{}:XX:XX:XX",
            parts[0].to_uppercase(),
            parts[1].to_uppercase(),
            parts[2].to_uppercase()
        )
    } else {
        // Different separator or format
        let hash = hash_identifier(mac);
        format!("MAC-{}", &hash[..8])
    }
}

/// Sanitize a hostname (show first chars + hash)
fn sanitize_hostname(hostname: &str) -> String {
    let visible_chars = hostname.chars().take(4).collect::<String>();
    let hash = hash_identifier(hostname);
    format!("{}...{}", visible_chars, &hash[..6])
}

/// Hash an identifier for safe storage
fn hash_identifier(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

/// Sanitize a file path (replace user-specific parts)
fn sanitize_path(path: &str) -> String {
    // Replace common user directory patterns
    let path = if let Some(home) = dirs_next::home_dir() {
        path.replace(&home.display().to_string(), "~")
    } else {
        path.to_string()
    };

    // Also handle Windows-style paths

    path.replace("C:\\Users\\", "~\\")
        .replace("/home/", "~/")
        .replace("/Users/", "~/")
}

/// Get OS version information
fn get_os_version() -> String {
    // Try to get from environment or system
    #[cfg(target_os = "linux")]
    {
        if let Ok(contents) = std::fs::read_to_string("/etc/os-release") {
            for line in contents.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    return line
                        .trim_start_matches("PRETTY_NAME=")
                        .trim_matches('"')
                        .to_string();
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
        {
            return String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("cmd")
            .args(["/C", "ver"])
            .output()
        {
            return String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }

    "unknown".to_string()
}

// =============================================================================
// Encryption Functions
// =============================================================================

/// Encrypt bundle data using hardware-derived key
fn encrypt_bundle(data: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    // Generate encryption key from hardware fingerprint
    let fingerprint = HardwareFingerprint::generate();
    let key = derive_bundle_key(&fingerprint.combined_hash);

    // Generate random nonce
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| LicenseError::KeyGenerationFailed(e.to_string()))?;

    let encrypted = cipher
        .encrypt(nonce, data)
        .map_err(|e| LicenseError::KeyGenerationFailed(format!("Encryption failed: {}", e)))?;

    // Build output: MAGIC + VERSION + NONCE + ENCRYPTED_DATA
    let mut output = Vec::with_capacity(4 + 1 + 12 + encrypted.len());
    output.extend_from_slice(ENCRYPTED_BUNDLE_MAGIC);
    output.push(BUNDLE_VERSION);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&encrypted);

    Ok(output)
}

/// Decrypt bundle data using hardware-derived key
fn decrypt_bundle(data: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    // Check minimum length and magic
    if data.len() < 17 {
        return Err(LicenseError::InvalidLicenseFormat(
            "Encrypted bundle too short".into(),
        ));
    }

    if &data[..4] != ENCRYPTED_BUNDLE_MAGIC {
        return Err(LicenseError::InvalidLicenseFormat(
            "Invalid encrypted bundle format".into(),
        ));
    }

    let version = data[4];
    if version != BUNDLE_VERSION {
        return Err(LicenseError::InvalidLicenseFormat(format!(
            "Unsupported bundle version: {}",
            version
        )));
    }

    let nonce_bytes: [u8; 12] = data[5..17]
        .try_into()
        .map_err(|_| LicenseError::InvalidLicenseFormat("Invalid nonce".into()))?;

    let encrypted = &data[17..];

    // Derive key from hardware fingerprint
    let fingerprint = HardwareFingerprint::generate();
    let key = derive_bundle_key(&fingerprint.combined_hash);

    // Decrypt
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| LicenseError::KeyGenerationFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher.decrypt(nonce, encrypted).map_err(|_| {
        LicenseError::InvalidLicenseFormat(
            "Decryption failed - bundle may be from a different machine".into(),
        )
    })
}

/// Derive encryption key from fingerprint hash
fn derive_bundle_key(fingerprint_hash: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"licenz-support-bundle-v1:");
    hasher.update(fingerprint_hash.as_bytes());

    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// =============================================================================
// Builder Pattern
// =============================================================================

/// Builder for creating support bundles
pub struct SupportBundleBuilder {
    bundle: SupportBundle,
}

impl SupportBundleBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            bundle: SupportBundle::generate(),
        }
    }

    /// Create a builder with license context
    pub fn with_license_id(license_id: &str, state_integrity_key: &[u8; 32]) -> Self {
        Self {
            bundle: SupportBundle::generate_with_license(license_id, state_integrity_key),
        }
    }

    /// Set license status
    pub fn license_status(mut self, status: LicenseStatusSummary) -> Self {
        self.bundle.license_status = Some(status);
        self
    }

    /// Add a verification event
    pub fn event(mut self, event: VerificationEvent) -> Self {
        self.bundle.verification_log.push(event);
        self
    }

    /// Add metadata
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.bundle.metadata.insert(key.into(), value.into());
        self
    }

    /// Build the final bundle
    pub fn build(self) -> SupportBundle {
        self.bundle
    }
}

impl Default for SupportBundleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_basic_bundle() {
        let bundle = SupportBundle::generate();

        assert_eq!(bundle.version, BUNDLE_VERSION);
        // mac_count is usize, so always >= 0 - just verify it exists
        let _ = bundle.hardware.mac_count;
        assert!(!bundle.environment.licenz_version.is_empty());
    }

    #[test]
    fn test_sanitize_mac_address() {
        let mac = "AA:BB:CC:DD:EE:FF";
        let sanitized = sanitize_mac_address(mac);
        assert_eq!(sanitized, "AA:BB:CC:XX:XX:XX");
        assert!(!sanitized.contains("DD"));
        assert!(!sanitized.contains("EE"));
        assert!(!sanitized.contains("FF"));
    }

    #[test]
    fn test_sanitize_hostname() {
        let hostname = "my-production-server";
        let sanitized = sanitize_hostname(hostname);
        assert!(sanitized.starts_with("my-p"));
        assert!(sanitized.contains("..."));
    }

    #[test]
    fn test_bundle_json_round_trip() {
        let bundle = SupportBundle::generate();
        let json = bundle.to_json().unwrap();
        let parsed = SupportBundle::from_json(&json).unwrap();

        assert_eq!(bundle.version, parsed.version);
        assert_eq!(
            bundle.hardware.fingerprint_hash,
            parsed.hardware.fingerprint_hash
        );
    }

    #[test]
    fn test_bundle_encryption_round_trip() {
        let bundle = SupportBundle::generate();
        let encrypted = bundle.encrypt().unwrap();

        assert!(encrypted.starts_with(ENCRYPTED_BUNDLE_MAGIC));

        let decrypted = SupportBundle::decrypt(&encrypted).unwrap();
        assert_eq!(bundle.version, decrypted.version);
    }

    #[test]
    fn test_verification_event() {
        let event = VerificationEvent::new(VerificationEventType::Success, "License validated")
            .with_context("license_id", "LIC-001");

        assert!(matches!(event.event_type, VerificationEventType::Success));
        assert_eq!(
            event.context.get("license_id"),
            Some(&"LIC-001".to_string())
        );
    }

    #[test]
    fn test_builder_pattern() {
        let bundle = SupportBundleBuilder::new()
            .metadata("support_ticket", "TICKET-12345")
            .event(VerificationEvent::new(
                VerificationEventType::Error,
                "Test error",
            ))
            .build();

        assert_eq!(
            bundle.metadata.get("support_ticket"),
            Some(&"TICKET-12345".to_string())
        );
        assert_eq!(bundle.verification_log.len(), 1);
    }
}
