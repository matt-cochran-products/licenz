//! Security Witness Pattern
//!
//! This module provides the Security Witness functionality - pure attestation
//! of license state without any policy enforcement. The witness observes and
//! reports; it does not decide or enforce.
//!
//! # Philosophy
//!
//! The Security Witness Pattern separates concerns:
//! - **Attestation** (this module): Observe, measure, report facts
//! - **Enforcement** (licenz-policy): Decide, enforce, act on attestations
//!
//! By keeping attestation in open-source core, users can audit exactly
//! what is being measured. By keeping enforcement in a separate layer,
//! applications can customize their response to attestations.

use crate::anti_tamper::{ClockStatus, HardwareFingerprint, LicenseState};
use crate::container::RuntimeEnvironment;
use crate::hardware::{default_hardware_environment, HardwareEnvironment};
use crate::verifier::LicenseVerifier;
use crate::{LicenseError, Result, SignedLicense, StateManager};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// Security attestation result from the witness
///
/// This struct contains observations about the license and system state.
/// It does NOT make policy decisions - that's for the enforcement layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAttestation {
    // ============================================
    // Core validation results
    // ============================================
    /// Was the signature cryptographically valid?
    pub signature_valid: bool,

    /// Signature verification details (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_error: Option<String>,

    /// Expiration observation
    pub expiration: ExpirationAttestation,

    /// Hardware binding observation
    pub hardware: HardwareAttestation,

    // ============================================
    // State observations
    // ============================================
    /// Clock/time observations
    pub clock: ClockAttestation,

    /// State file observations
    pub state_files: StateFileAttestation,

    /// Environment observations
    pub environment: EnvironmentAttestation,

    // ============================================
    // Anomalies detected
    // ============================================
    /// List of anomalies observed (neutral - no judgment on severity)
    pub anomalies: Vec<SecurityAnomaly>,

    // ============================================
    // Metadata
    // ============================================
    /// When this attestation was created
    pub attested_at: DateTime<Utc>,

    /// Overall validity (signature AND expiration AND hardware all pass)
    /// Note: This is a factual observation, not a policy decision
    pub is_valid: bool,
}

/// Expiration attestation - factual observation about time validity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpirationAttestation {
    /// Is the current time within the valid window?
    pub is_within_window: bool,

    /// Valid from timestamp
    pub valid_from: DateTime<Utc>,

    /// Valid until timestamp
    pub valid_until: DateTime<Utc>,

    /// Days until expiration (negative if expired)
    pub days_remaining: i64,

    /// If not valid, why?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue: Option<ExpirationIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExpirationIssue {
    NotYetValid { starts_in_days: i64 },
    Expired { expired_days_ago: i64 },
}

/// Hardware attestation - factual observation about hardware match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareAttestation {
    /// Was hardware binding checked?
    pub was_checked: bool,

    /// Match percentage (0.0 - 100.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_percentage: Option<f32>,

    /// Which factors matched
    pub matched_factors: Vec<String>,

    /// Which factors did not match
    pub unmatched_factors: Vec<String>,

    /// Current hardware fingerprint (for debugging)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_fingerprint: Option<HardwareFingerprint>,
}

/// Clock attestation - factual observation about system time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockAttestation {
    /// Current system time at attestation
    pub current_time: DateTime<Utc>,

    /// Last known system time (from state)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_time: Option<DateTime<Utc>>,

    /// Drift from last seen time (positive = forward, negative = backward)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drift_seconds: Option<i64>,

    /// Clock status observation
    pub status: ClockStatusAttestation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClockStatusAttestation {
    /// Clock appears normal
    Normal,
    /// Clock moved backward
    DriftedBackward { seconds: i64 },
    /// Clock jumped forward significantly
    JumpedForward { seconds: i64 },
    /// No previous state to compare
    NoPreviousState,
    /// Error checking clock
    CheckFailed { reason: String },
}

/// State file attestation - factual observation about state files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateFileAttestation {
    /// Number of state file locations checked
    pub locations_checked: usize,

    /// Number of valid state files found
    pub valid_files_found: usize,

    /// Number of corrupted/tampered files found
    pub corrupted_files_found: usize,

    /// Number of missing files
    pub missing_files: usize,

    /// State file observations
    pub observations: Vec<StateFileObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateFileObservation {
    pub location: String,
    pub status: StateFileStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateFileStatus {
    Valid,
    Missing,
    Corrupted,
    Tampered,
    ReadError { reason: String },
}

/// Environment attestation - factual observation about runtime environment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentAttestation {
    /// Detected runtime environment
    pub runtime: RuntimeEnvironment,

    /// Is this a containerized environment?
    pub is_containerized: bool,

    /// Is this a virtualized environment?
    pub is_virtualized: bool,

    /// Cloud provider (if detected)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_provider: Option<String>,
}

/// Security anomaly - an observation that something unusual was detected
///
/// Note: These are neutral observations. Whether an anomaly is "bad" or
/// requires action is a POLICY decision, not an attestation decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityAnomaly {
    /// Clock moved backward
    ClockMovedBackward {
        drift_seconds: i64,
        last_seen: DateTime<Utc>,
        current: DateTime<Utc>,
    },

    /// Clock jumped forward significantly
    ClockJumpedForward {
        jump_seconds: i64,
        last_seen: DateTime<Utc>,
        current: DateTime<Utc>,
    },

    /// State file was missing
    StateFileMissing { location: String },

    /// State file was corrupted
    StateFileCorrupted { location: String },

    /// State file appeared tampered (checksum mismatch)
    StateFileTampered { location: String },

    /// State files inconsistent (different validation counts)
    StateFilesInconsistent {
        highest_count: u64,
        lowest_count: u64,
    },

    /// Hardware fingerprint partially changed
    HardwareFingerprintChanged {
        changed_factors: Vec<String>,
        unchanged_factors: Vec<String>,
    },

    /// Running in a virtual machine
    VirtualMachineDetected { hypervisor: Option<String> },

    /// Running in a container
    ContainerDetected { runtime: String },

    /// Debugger or instrumentation detected
    DebuggerDetected { method: String },

    /// License file was modified (caught by signature)
    LicenseModified,

    /// Custom anomaly for extensibility
    Custom { code: String, description: String },
}

/// Configuration for the security witness
#[derive(Clone)]
pub struct WitnessConfig {
    /// Check hardware binding
    pub check_hardware: bool,

    /// Check clock consistency (requires [`Self::state_integrity_key`] when true)
    pub check_clock: bool,

    /// Check state files (requires [`Self::state_integrity_key`] when true)
    pub check_state_files: bool,

    /// Detect virtualization
    pub detect_virtualization: bool,

    /// Detect containers
    pub detect_containers: bool,

    /// Tolerance for clock drift detection
    pub clock_tolerance: Duration,

    /// HMAC key for [`LicenseState`] at rest; required when `check_clock` or `check_state_files` is true.
    pub state_integrity_key: Option<[u8; 32]>,

    /// Source of [`crate::hardware::HardwareInfo`] for binding attestation (default: OS probe).
    pub hardware_environment: Arc<dyn HardwareEnvironment>,
}

impl std::fmt::Debug for WitnessConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessConfig")
            .field("check_hardware", &self.check_hardware)
            .field("check_clock", &self.check_clock)
            .field("check_state_files", &self.check_state_files)
            .field("detect_virtualization", &self.detect_virtualization)
            .field("detect_containers", &self.detect_containers)
            .field("clock_tolerance", &self.clock_tolerance)
            .field(
                "state_integrity_key",
                &self.state_integrity_key.as_ref().map(|_| "<redacted>"),
            )
            .field("hardware_environment", &"<dyn HardwareEnvironment>")
            .finish()
    }
}

impl Default for WitnessConfig {
    fn default() -> Self {
        Self {
            check_hardware: true,
            check_clock: false,
            check_state_files: false,
            detect_virtualization: true,
            detect_containers: true,
            clock_tolerance: Duration::hours(1),
            state_integrity_key: None,
            hardware_environment: default_hardware_environment(),
        }
    }
}

/// The Security Witness - performs attestation without enforcement
pub struct SecurityWitness {
    verifier: LicenseVerifier,
}

impl SecurityWitness {
    /// Create a new security witness from a public key PEM string
    pub fn new(public_key_pem: &str) -> Result<Self> {
        let verifier = LicenseVerifier::from_pem(public_key_pem)?;
        Ok(Self { verifier })
    }

    /// Create from a PEM file path
    pub fn from_pem_file(path: &Path) -> Result<Self> {
        let verifier = LicenseVerifier::from_pem_file(path)?;
        Ok(Self { verifier })
    }

    /// Perform comprehensive attestation of a license
    pub fn attest(
        &self,
        license_path: impl AsRef<Path>,
        config: &WitnessConfig,
    ) -> Result<SecurityAttestation> {
        let license = self.verifier.load_license(license_path.as_ref())?;
        self.attest_license(&license, config)
    }

    /// Attest an already-loaded license
    pub fn attest_license(
        &self,
        license: &SignedLicense,
        config: &WitnessConfig,
    ) -> Result<SecurityAttestation> {
        if (config.check_state_files || config.check_clock) && config.state_integrity_key.is_none()
        {
            return Err(LicenseError::Validation(
                "WitnessConfig: check_clock and check_state_files require state_integrity_key"
                    .into(),
            ));
        }

        let mut anomalies = Vec::new();
        let now = Utc::now();

        // 1. Verify signature
        let (signature_valid, signature_error) = match self.verifier.verify_signature(license) {
            Ok(_) => (true, None),
            Err(e) => {
                anomalies.push(SecurityAnomaly::LicenseModified);
                (false, Some(e.to_string()))
            }
        };

        // 2. Check expiration
        let expiration = self.attest_expiration(license, now);

        // 3. Check hardware
        let hardware = if config.check_hardware {
            self.attest_hardware(license, config, &mut anomalies)
        } else {
            HardwareAttestation {
                was_checked: false,
                match_percentage: None,
                matched_factors: Vec::new(),
                unmatched_factors: Vec::new(),
                current_fingerprint: None,
            }
        };

        // 4. Check clock
        let clock = if config.check_clock {
            self.attest_clock(&license.data.id, config, &mut anomalies)
        } else {
            ClockAttestation {
                current_time: now,
                last_seen_time: None,
                drift_seconds: None,
                status: ClockStatusAttestation::NoPreviousState,
            }
        };

        // 5. Check state files
        let state_files = if config.check_state_files {
            self.attest_state_files(&license.data.id, config, &mut anomalies)
        } else {
            StateFileAttestation {
                locations_checked: 0,
                valid_files_found: 0,
                corrupted_files_found: 0,
                missing_files: 0,
                observations: Vec::new(),
            }
        };

        // 6. Check environment
        let environment = self.attest_environment(config, &mut anomalies);

        // Calculate overall validity (factual, not policy)
        let is_valid = signature_valid
            && expiration.is_within_window
            && (!hardware.was_checked
                || hardware
                    .matched_factors
                    .len()
                    .saturating_add(hardware.unmatched_factors.len())
                    == 0
                || !hardware.matched_factors.is_empty());

        Ok(SecurityAttestation {
            signature_valid,
            signature_error,
            expiration,
            hardware,
            clock,
            state_files,
            environment,
            anomalies,
            attested_at: now,
            is_valid,
        })
    }

    fn attest_expiration(
        &self,
        license: &SignedLicense,
        now: DateTime<Utc>,
    ) -> ExpirationAttestation {
        let days_remaining = license.data.days_remaining();
        let is_within_window = now >= license.data.valid_from && now <= license.data.valid_until;

        let issue = if now < license.data.valid_from {
            Some(ExpirationIssue::NotYetValid {
                starts_in_days: (license.data.valid_from - now).num_days(),
            })
        } else if now > license.data.valid_until {
            Some(ExpirationIssue::Expired {
                expired_days_ago: (now - license.data.valid_until).num_days(),
            })
        } else {
            None
        };

        ExpirationAttestation {
            is_within_window,
            valid_from: license.data.valid_from,
            valid_until: license.data.valid_until,
            days_remaining,
            issue,
        }
    }

    fn attest_hardware(
        &self,
        license: &SignedLicense,
        config: &WitnessConfig,
        anomalies: &mut Vec<SecurityAnomaly>,
    ) -> HardwareAttestation {
        let current_hw = config.hardware_environment.snapshot();
        let binding = &license.data.hardware_binding;

        let mut matched_factors = Vec::new();
        let mut unmatched_factors = Vec::new();

        // Check MAC addresses
        if !binding.mac_addresses.is_empty() {
            let current_macs: Vec<String> = current_hw
                .mac_addresses
                .iter()
                .map(|m| m.to_uppercase())
                .collect();

            let has_match = binding
                .mac_addresses
                .iter()
                .any(|bound| current_macs.contains(&bound.to_uppercase()));

            if has_match {
                matched_factors.push("mac_address".to_string());
            } else {
                unmatched_factors.push("mac_address".to_string());
            }
        }

        // Check hostnames
        if !binding.hostnames.is_empty() {
            if let Some(ref hostname) = current_hw.hostname {
                let has_match = binding
                    .hostnames
                    .iter()
                    .any(|bound| bound.eq_ignore_ascii_case(hostname));

                if has_match {
                    matched_factors.push("hostname".to_string());
                } else {
                    unmatched_factors.push("hostname".to_string());
                }
            } else {
                unmatched_factors.push("hostname".to_string());
            }
        }

        // Check disk IDs
        if !binding.disk_ids.is_empty() {
            let has_match = binding
                .disk_ids
                .iter()
                .any(|bound| current_hw.disk_ids.contains(bound));

            if has_match {
                matched_factors.push("disk_id".to_string());
            } else {
                unmatched_factors.push("disk_id".to_string());
            }
        }

        // Check machine ID (custom binding)
        if let Some(expected_ids) = binding.custom.get("machine_id") {
            if let Some(ref current_id) = current_hw.machine_id {
                if expected_ids.contains(current_id) {
                    matched_factors.push("machine_id".to_string());
                } else {
                    unmatched_factors.push("machine_id".to_string());
                }
            } else {
                unmatched_factors.push("machine_id".to_string());
            }
        }

        // Record anomaly if hardware changed
        if !unmatched_factors.is_empty() && !matched_factors.is_empty() {
            anomalies.push(SecurityAnomaly::HardwareFingerprintChanged {
                changed_factors: unmatched_factors.clone(),
                unchanged_factors: matched_factors.clone(),
            });
        }

        // Calculate match percentage
        let total_factors = matched_factors.len() + unmatched_factors.len();
        let match_percentage = if total_factors > 0 {
            Some((matched_factors.len() as f32 / total_factors as f32) * 100.0)
        } else {
            None
        };

        HardwareAttestation {
            was_checked: true,
            match_percentage,
            matched_factors,
            unmatched_factors,
            current_fingerprint: Some(HardwareFingerprint::generate_with(
                config.hardware_environment.as_ref(),
            )),
        }
    }

    fn attest_clock(
        &self,
        license_id: &str,
        config: &WitnessConfig,
        anomalies: &mut Vec<SecurityAnomaly>,
    ) -> ClockAttestation {
        let now = Utc::now();
        let key = config
            .state_integrity_key
            .expect("validated at attest_license");
        let state_manager = StateManager::new(license_id, key);

        match state_manager.load(license_id) {
            Ok(Some(state)) => {
                let drift_seconds = (now - state.last_system_time).num_seconds();

                let status = match state.detect_clock_manipulation(config.clock_tolerance) {
                    Ok(ClockStatus::Ok { .. }) => ClockStatusAttestation::Normal,
                    Ok(ClockStatus::Backwards {
                        drift,
                        last_seen,
                        current,
                    }) => {
                        anomalies.push(SecurityAnomaly::ClockMovedBackward {
                            drift_seconds: drift.num_seconds(),
                            last_seen,
                            current,
                        });
                        ClockStatusAttestation::DriftedBackward {
                            seconds: drift.num_seconds(),
                        }
                    }
                    Ok(ClockStatus::SuspiciousJump {
                        jump,
                        last_seen,
                        current,
                    }) => {
                        anomalies.push(SecurityAnomaly::ClockJumpedForward {
                            jump_seconds: jump.num_seconds(),
                            last_seen,
                            current,
                        });
                        ClockStatusAttestation::JumpedForward {
                            seconds: jump.num_seconds(),
                        }
                    }
                    Err(e) => ClockStatusAttestation::CheckFailed {
                        reason: e.to_string(),
                    },
                };

                ClockAttestation {
                    current_time: now,
                    last_seen_time: Some(state.last_system_time),
                    drift_seconds: Some(drift_seconds),
                    status,
                }
            }
            Ok(None) => ClockAttestation {
                current_time: now,
                last_seen_time: None,
                drift_seconds: None,
                status: ClockStatusAttestation::NoPreviousState,
            },
            Err(e) => ClockAttestation {
                current_time: now,
                last_seen_time: None,
                drift_seconds: None,
                status: ClockStatusAttestation::CheckFailed {
                    reason: e.to_string(),
                },
            },
        }
    }

    fn attest_state_files(
        &self,
        license_id: &str,
        config: &WitnessConfig,
        anomalies: &mut Vec<SecurityAnomaly>,
    ) -> StateFileAttestation {
        let key = config
            .state_integrity_key
            .expect("validated at attest_license");
        let state_manager = StateManager::new(license_id, key);
        let paths = state_manager.paths();

        let mut observations = Vec::new();
        let mut valid_count = 0;
        let mut corrupted_count = 0;
        let mut missing_count = 0;

        for path in paths {
            let location = path.display().to_string();

            if !path.exists() {
                missing_count += 1;
                anomalies.push(SecurityAnomaly::StateFileMissing {
                    location: location.clone(),
                });
                observations.push(StateFileObservation {
                    location,
                    status: StateFileStatus::Missing,
                });
            } else {
                match LicenseState::load(path, license_id, &key) {
                    Ok(Some(_)) => {
                        valid_count += 1;
                        observations.push(StateFileObservation {
                            location,
                            status: StateFileStatus::Valid,
                        });
                    }
                    Ok(None) => {
                        missing_count += 1;
                        observations.push(StateFileObservation {
                            location,
                            status: StateFileStatus::Missing,
                        });
                    }
                    Err(LicenseError::StateFileTampered) => {
                        corrupted_count += 1;
                        anomalies.push(SecurityAnomaly::StateFileTampered {
                            location: location.clone(),
                        });
                        observations.push(StateFileObservation {
                            location,
                            status: StateFileStatus::Tampered,
                        });
                    }
                    Err(e) => {
                        corrupted_count += 1;
                        anomalies.push(SecurityAnomaly::StateFileCorrupted {
                            location: location.clone(),
                        });
                        observations.push(StateFileObservation {
                            location,
                            status: StateFileStatus::ReadError {
                                reason: e.to_string(),
                            },
                        });
                    }
                }
            }
        }

        StateFileAttestation {
            locations_checked: paths.len(),
            valid_files_found: valid_count,
            corrupted_files_found: corrupted_count,
            missing_files: missing_count,
            observations,
        }
    }

    fn attest_environment(
        &self,
        config: &WitnessConfig,
        anomalies: &mut Vec<SecurityAnomaly>,
    ) -> EnvironmentAttestation {
        let runtime = RuntimeEnvironment::detect();

        let is_containerized = matches!(
            runtime,
            RuntimeEnvironment::Docker | RuntimeEnvironment::Kubernetes
        );

        let is_virtualized = matches!(
            runtime,
            RuntimeEnvironment::AwsEc2
                | RuntimeEnvironment::GcpCompute
                | RuntimeEnvironment::AzureVm
                | RuntimeEnvironment::GenericCloud
        );

        let cloud_provider = match runtime {
            RuntimeEnvironment::AwsEc2 => Some("AWS".to_string()),
            RuntimeEnvironment::GcpCompute => Some("GCP".to_string()),
            RuntimeEnvironment::AzureVm => Some("Azure".to_string()),
            _ => None,
        };

        // Record anomalies for detection
        if config.detect_containers && is_containerized {
            anomalies.push(SecurityAnomaly::ContainerDetected {
                runtime: format!("{:?}", runtime),
            });
        }

        if config.detect_virtualization && is_virtualized {
            anomalies.push(SecurityAnomaly::VirtualMachineDetected {
                hypervisor: cloud_provider.clone(),
            });
        }

        EnvironmentAttestation {
            runtime,
            is_containerized,
            is_virtualized,
            cloud_provider,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyPair, KeySize, LicenseData, LicenseGenerator};

    fn create_test_license() -> (String, SignedLicense) {
        let keypair = KeyPair::generate(KeySize::Bits2048).unwrap();
        let generator = LicenseGenerator::new(keypair.private_key().clone());

        let data = LicenseData::builder()
            .id("TEST-001")
            .serial("SN-12345")
            .customer_id("Test Customer")
            .product_id("TestApp")
            .valid_days(365)
            .feature("basic")
            .build()
            .unwrap();

        let signed = generator.generate(data).unwrap();
        let public_key = keypair.export_public_pem().unwrap();

        (public_key, signed)
    }

    #[test]
    fn test_witness_attestation() {
        let (public_key, license) = create_test_license();

        let witness = SecurityWitness::new(&public_key).unwrap();
        let attestation = witness
            .attest_license(&license, &WitnessConfig::default())
            .unwrap();

        assert!(attestation.signature_valid);
        assert!(attestation.expiration.is_within_window);
        assert!(attestation.is_valid);
    }

    #[test]
    fn test_attestation_is_informational() {
        let (public_key, license) = create_test_license();

        let witness = SecurityWitness::new(&public_key).unwrap();
        let attestation = witness
            .attest_license(&license, &WitnessConfig::default())
            .unwrap();

        // Attestation provides facts, not decisions
        // The match_percentage is a measurement, not a pass/fail
        // The anomalies list observations, not judgments
        assert!(attestation.signature_valid); // Fact: signature matches
                                              // Days remaining might be 364 or 365 depending on exact timing
        assert!(
            attestation.expiration.days_remaining >= 364
                && attestation.expiration.days_remaining <= 365
        );
    }
}
