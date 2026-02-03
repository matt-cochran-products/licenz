//! Anti-tamper and clock manipulation detection
//!
//! This module provides countermeasures against common license bypass techniques.

use crate::error::{LicenseError, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Persistent state for detecting clock manipulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseState {
    /// Last successful validation timestamp
    pub last_validated: DateTime<Utc>,

    /// Last observed system time
    pub last_system_time: DateTime<Utc>,

    /// Monotonic counter (always increases)
    pub validation_count: u64,

    /// Hash of license ID being tracked
    pub license_id_hash: String,

    /// State file integrity checksum
    #[serde(skip)]
    checksum: Option<String>,
}

impl LicenseState {
    /// Create new state for a license
    pub fn new(license_id: &str) -> Self {
        let now = Utc::now();
        Self {
            last_validated: now,
            last_system_time: now,
            validation_count: 1,
            license_id_hash: hash_string(license_id),
            checksum: None,
        }
    }

    /// Load state from file with integrity check
    pub fn load(path: &Path, license_id: &str) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }

        let contents = std::fs::read_to_string(path)?;

        // Split content and checksum
        let lines: Vec<&str> = contents.lines().collect();
        if lines.len() < 2 {
            // Corrupted file, treat as missing
            return Ok(None);
        }

        let json_data = lines[..lines.len() - 1].join("\n");
        let stored_checksum = lines.last().unwrap_or(&"");

        // Verify checksum
        let computed_checksum = hash_string(&json_data);
        if &computed_checksum != stored_checksum {
            return Err(LicenseError::StateFileTampered);
        }

        let mut state: Self = serde_json::from_str(&json_data)
            .map_err(|e| LicenseError::InvalidLicenseFormat(e.to_string()))?;

        // Verify this state is for the same license
        if state.license_id_hash != hash_string(license_id) {
            return Err(LicenseError::StateLicenseMismatch);
        }

        state.checksum = Some(computed_checksum);
        Ok(Some(state))
    }

    /// Save state to file with integrity checksum
    pub fn save(&self, path: &Path) -> Result<()> {
        let json_data = serde_json::to_string_pretty(self)
            .map_err(|e| LicenseError::SerializationError(e.to_string()))?;

        let checksum = hash_string(&json_data);
        let contents = format!("{}\n{}", json_data, checksum);

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Check for clock manipulation
    pub fn detect_clock_manipulation(&self, tolerance: Duration) -> Result<ClockStatus> {
        let now = Utc::now();

        // Check if clock went backwards significantly
        if now < self.last_system_time {
            let drift = self.last_system_time - now;

            if drift > tolerance {
                return Ok(ClockStatus::Backwards {
                    drift,
                    last_seen: self.last_system_time,
                    current: now,
                });
            }
        }

        // Check for suspicious forward jump (could indicate tampering then reset)
        let time_since_last = now - self.last_system_time;
        if time_since_last > Duration::days(365) {
            return Ok(ClockStatus::SuspiciousJump {
                jump: time_since_last,
                last_seen: self.last_system_time,
                current: now,
            });
        }

        Ok(ClockStatus::Ok { current: now })
    }

    /// Update state after successful validation
    pub fn record_validation(&mut self) {
        let now = Utc::now();
        self.last_validated = now;
        self.last_system_time = now;
        self.validation_count += 1;
    }
}

/// Result of clock manipulation check
#[derive(Debug, Clone)]
pub enum ClockStatus {
    /// Clock is within acceptable range
    Ok { current: DateTime<Utc> },

    /// Clock moved backwards (possible manipulation)
    Backwards {
        drift: Duration,
        last_seen: DateTime<Utc>,
        current: DateTime<Utc>,
    },

    /// Clock jumped forward suspiciously far
    SuspiciousJump {
        jump: Duration,
        last_seen: DateTime<Utc>,
        current: DateTime<Utc>,
    },
}

impl ClockStatus {
    pub fn is_ok(&self) -> bool {
        matches!(self, ClockStatus::Ok { .. })
    }
}

/// Multi-factor hardware fingerprint for stronger binding
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HardwareFingerprint {
    /// Hashed MAC addresses
    pub mac_hashes: Vec<String>,

    /// Hashed disk serial numbers
    pub disk_hashes: Vec<String>,

    /// Hashed hostname
    pub hostname_hash: Option<String>,

    /// Hashed machine GUID (OS-level)
    pub machine_guid_hash: Option<String>,

    /// Combined fingerprint hash
    pub combined_hash: String,
}

impl HardwareFingerprint {
    /// Generate fingerprint from current hardware
    #[cfg(feature = "hardware-binding")]
    pub fn generate() -> Self {
        use crate::hardware::detect_hardware;

        let hw = detect_hardware();

        let mac_hashes: Vec<String> = hw.mac_addresses.iter().map(|m| hash_string(m)).collect();

        let disk_hashes: Vec<String> = hw.disk_ids.iter().map(|d| hash_string(d)).collect();

        let hostname_hash = hw.hostname.as_ref().map(|h| hash_string(h));
        let machine_guid_hash = hw.machine_id.as_ref().map(|m| hash_string(m));

        // Create combined hash
        let mut combined = String::new();
        for hash in &mac_hashes {
            combined.push_str(hash);
        }
        for hash in &disk_hashes {
            combined.push_str(hash);
        }
        if let Some(ref h) = hostname_hash {
            combined.push_str(h);
        }
        if let Some(ref m) = machine_guid_hash {
            combined.push_str(m);
        }

        let combined_hash = hash_string(&combined);

        Self {
            mac_hashes,
            disk_hashes,
            hostname_hash,
            machine_guid_hash,
            combined_hash,
        }
    }

    #[cfg(not(feature = "hardware-binding"))]
    pub fn generate() -> Self {
        Self::default()
    }

    /// Calculate match score against a binding
    pub fn match_score(&self, other: &HardwareFingerprint) -> MatchResult {
        let mut score = 0u32;
        let mut max_score = 0u32;

        // MAC addresses (weight: 2)
        max_score += 2;
        if self.mac_hashes.iter().any(|h| other.mac_hashes.contains(h)) {
            score += 2;
        }

        // Disk serials (weight: 3) - harder to spoof
        max_score += 3;
        if self
            .disk_hashes
            .iter()
            .any(|h| other.disk_hashes.contains(h))
        {
            score += 3;
        }

        // Hostname (weight: 1) - easy to change
        if self.hostname_hash.is_some() || other.hostname_hash.is_some() {
            max_score += 1;
            if self.hostname_hash == other.hostname_hash {
                score += 1;
            }
        }

        // Machine GUID (weight: 4) - OS-level, hardest to spoof
        if self.machine_guid_hash.is_some() || other.machine_guid_hash.is_some() {
            max_score += 4;
            if self.machine_guid_hash == other.machine_guid_hash {
                score += 4;
            }
        }

        let percentage = if max_score > 0 {
            (score as f32 / max_score as f32) * 100.0
        } else {
            100.0
        };

        MatchResult {
            score,
            max_score,
            percentage,
        }
    }
}

/// Result of hardware fingerprint matching
///
/// Note: This struct provides attestation data only. The policy layer
/// (e.g., `licenz-policy` crate) decides whether the match percentage
/// is sufficient based on configurable thresholds.
#[derive(Debug, Clone)]
pub struct MatchResult {
    pub score: u32,
    pub max_score: u32,
    pub percentage: f32,
}

impl MatchResult {
    /// Check if the match meets a given threshold (0.0 - 100.0)
    ///
    /// This is a convenience method. Policy enforcement should use
    /// the `percentage` field directly with configurable thresholds.
    pub fn meets_threshold(&self, threshold_percent: f32) -> bool {
        self.percentage >= threshold_percent
    }
}

/// Hash a string with SHA-256 and return hex
fn hash_string(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

// Add these error variants
impl LicenseError {
    pub const STATE_FILE_TAMPERED: &'static str = "License state file has been tampered with";
    pub const STATE_LICENSE_MISMATCH: &'static str =
        "License state file is for a different license";
}

// Extend the error enum
#[derive(Debug)]
pub struct StateFileTampered;

#[derive(Debug)]
pub struct StateLicenseMismatch;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_status_ok() {
        let state = LicenseState::new("test-license");
        let status = state.detect_clock_manipulation(Duration::hours(1)).unwrap();
        assert!(status.is_ok());
    }

    #[test]
    fn test_fingerprint_match() {
        let fp1 = HardwareFingerprint {
            mac_hashes: vec![hash_string("AA:BB:CC:DD:EE:FF")],
            disk_hashes: vec![hash_string("DISK123")],
            hostname_hash: Some(hash_string("myhost")),
            machine_guid_hash: Some(hash_string("guid123")),
            combined_hash: String::new(),
        };

        let fp2 = HardwareFingerprint {
            mac_hashes: vec![hash_string("AA:BB:CC:DD:EE:FF")],
            disk_hashes: vec![hash_string("DISK123")],
            hostname_hash: Some(hash_string("myhost")),
            machine_guid_hash: Some(hash_string("guid123")),
            combined_hash: String::new(),
        };

        let result = fp1.match_score(&fp2);
        assert_eq!(result.percentage, 100.0);
        assert!(result.meets_threshold(70.0)); // Policy decision made by caller
    }

    #[test]
    fn test_partial_fingerprint_match() {
        let fp1 = HardwareFingerprint {
            mac_hashes: vec![hash_string("AA:BB:CC:DD:EE:FF")],
            disk_hashes: vec![hash_string("DISK123")],
            hostname_hash: Some(hash_string("myhost")),
            machine_guid_hash: Some(hash_string("guid123")),
            combined_hash: String::new(),
        };

        // Different hostname and GUID, same MAC and disk
        let fp2 = HardwareFingerprint {
            mac_hashes: vec![hash_string("AA:BB:CC:DD:EE:FF")],
            disk_hashes: vec![hash_string("DISK123")],
            hostname_hash: Some(hash_string("otherhost")),
            machine_guid_hash: Some(hash_string("otherguid")),
            combined_hash: String::new(),
        };

        let result = fp1.match_score(&fp2);
        // MAC (2) + Disk (3) = 5 out of 10 = 50%
        // Whether this passes depends on the policy threshold chosen by caller
        assert!(!result.meets_threshold(70.0)); // Would fail default 70% threshold
        assert!(result.meets_threshold(50.0));  // Would pass permissive 50% threshold
    }
}
