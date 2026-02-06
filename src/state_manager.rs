//! Multi-location state management for tamper resistance
//!
//! This module stores license state in multiple locations to detect
//! deletion attacks on clock manipulation detection.
//!
//! # Security Witness Pattern
//!
//! This module provides **attestation** about state file integrity.
//! It detects and reports issues but does not automatically repair them.
//! A policy layer should decide how to respond.

use crate::anti_tamper::LicenseState;
use crate::error::{LicenseError, Result};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Observations about state file storage locations.
///
/// This provides attestation data for policy layers to make decisions about
/// whether to repair, fail, or warn about state file issues.
#[derive(Debug, Clone, Default)]
pub struct StateObservations {
    /// Locations with valid state files
    pub valid_locations: Vec<PathBuf>,
    /// Locations where state files are missing
    pub missing_locations: Vec<PathBuf>,
    /// Locations with corrupted/tampered state files
    pub corrupted_locations: Vec<PathBuf>,
    /// Locations with read errors (permissions, etc.)
    pub error_locations: Vec<PathBuf>,
}

impl StateObservations {
    /// Check if there's any inconsistency in state files
    pub fn has_inconsistency(&self) -> bool {
        !self.missing_locations.is_empty() || !self.corrupted_locations.is_empty()
    }

    /// Check if any valid state exists
    pub fn has_valid_state(&self) -> bool {
        !self.valid_locations.is_empty()
    }

    /// Total number of locations checked
    pub fn total_locations(&self) -> usize {
        self.valid_locations.len()
            + self.missing_locations.len()
            + self.corrupted_locations.len()
            + self.error_locations.len()
    }
}

/// Manages license state across multiple storage locations
pub struct StateManager {
    /// Primary storage paths (filesystem)
    paths: Vec<PathBuf>,
}

impl StateManager {
    /// Create a new state manager for a license
    pub fn new(license_id: &str) -> Self {
        let license_hash = sha256_short(license_id);

        let mut paths = Vec::new();

        // Primary: Application data directory
        if let Some(data_dir) = dirs_next::data_local_dir() {
            paths.push(
                data_dir
                    .join(".licenz")
                    .join(format!("{}.state", &license_hash)),
            );
        }

        // Secondary: Hidden file in home directory
        if let Some(home_dir) = dirs_next::home_dir() {
            paths.push(home_dir.join(format!(".lz_{}", &license_hash[..12])));
        }

        // Tertiary: Temp directory with obfuscated name
        let temp_dir = std::env::temp_dir();
        paths.push(temp_dir.join(format!("lzs_{}.dat", &license_hash[..16])));

        // Quaternary: Config directory
        if let Some(config_dir) = dirs_next::config_dir() {
            paths.push(
                config_dir
                    .join("licenz")
                    .join(format!("{}.dat", &license_hash[..8])),
            );
        }

        Self { paths }
    }

    /// Create with custom paths (for testing)
    pub fn with_paths(_license_id: &str, paths: Vec<PathBuf>) -> Self {
        Self { paths }
    }

    /// Load the most recent valid state from any location.
    ///
    /// Returns the state along with observations about the storage locations.
    /// This is pure attestation - no automatic repairs are performed.
    /// Use `repair()` explicitly if policy dictates recovery should be attempted.
    pub fn load(&self, license_id: &str) -> Result<Option<LicenseState>> {
        let (state, _observations) = self.load_with_observations(license_id)?;
        Ok(state)
    }

    /// Load state with detailed observations about each storage location.
    ///
    /// This provides full attestation data for policy layers to make decisions.
    pub fn load_with_observations(
        &self,
        license_id: &str,
    ) -> Result<(Option<LicenseState>, StateObservations)> {
        let mut best_state: Option<LicenseState> = None;
        let mut observations = StateObservations::default();

        for path in &self.paths {
            match LicenseState::load(path, license_id) {
                Ok(Some(state)) => {
                    observations.valid_locations.push(path.clone());

                    // Keep the state with highest validation count
                    match &best_state {
                        None => best_state = Some(state),
                        Some(existing) if state.validation_count > existing.validation_count => {
                            best_state = Some(state);
                        }
                        _ => {}
                    }
                }
                Ok(None) => {
                    observations.missing_locations.push(path.clone());
                }
                Err(LicenseError::StateFileTampered) => {
                    observations.corrupted_locations.push(path.clone());
                    tracing::debug!("Corrupted state file detected at {:?}", path);
                }
                Err(_) => {
                    observations.error_locations.push(path.clone());
                }
            }
        }

        // Log observations (but don't auto-repair - that's a policy decision)
        if !observations.corrupted_locations.is_empty() {
            tracing::debug!(
                "Found {} corrupted state files",
                observations.corrupted_locations.len()
            );
        }

        if observations.has_inconsistency() {
            tracing::debug!(
                "State file inconsistency: {} valid, {} missing, {} corrupted of {} total",
                observations.valid_locations.len(),
                observations.missing_locations.len(),
                observations.corrupted_locations.len(),
                self.paths.len()
            );
        }

        Ok((best_state, observations))
    }

    /// Repair missing and corrupted state files from the best available state.
    ///
    /// This is a policy action - call it explicitly when policy dictates recovery.
    /// Returns the number of files successfully repaired.
    pub fn repair(&self, state: &LicenseState) -> usize {
        let mut repaired = 0;

        for path in &self.paths {
            let needs_repair = !path.exists() || {
                // Check if corrupted
                match std::fs::read_to_string(path) {
                    Ok(contents) => {
                        let lines: Vec<&str> = contents.lines().collect();
                        if lines.len() < 2 {
                            true
                        } else {
                            let json_data = lines[..lines.len() - 1].join("\n");
                            let stored_checksum = lines.last().unwrap_or(&"");
                            let computed = sha256_short(&json_data);
                            &computed != stored_checksum
                        }
                    }
                    Err(_) => true,
                }
            };

            if needs_repair {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if state.save(path).is_ok() {
                    repaired += 1;
                    tracing::info!("Repaired state file {:?}", path);
                }
            }
        }

        repaired
    }

    /// Save state to all locations
    pub fn save(&self, state: &LicenseState) -> Result<()> {
        let mut success_count = 0;
        let mut errors = Vec::new();

        for path in &self.paths {
            // Create parent directory if needed
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            match state.save(path) {
                Ok(_) => success_count += 1,
                Err(e) => errors.push((path.clone(), e)),
            }
        }

        // At least one location must succeed
        if success_count == 0 {
            return Err(LicenseError::StateFileTampered); // Reusing error for "save failed"
        }

        // Log any failures
        for (path, error) in errors {
            tracing::warn!("Failed to save state to {:?}: {}", path, error);
        }

        Ok(())
    }

    /// Delete all state files (for testing or license revocation)
    pub fn clear(&self) -> Result<()> {
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }

    /// Get the paths being used
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }
}

/// Generate a short SHA-256 hash of a string
fn sha256_short(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..16]) // First 16 bytes = 32 hex chars
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_state_manager_round_trip() {
        let temp_dir = TempDir::new().unwrap();
        let paths = vec![
            temp_dir.path().join("state1.dat"),
            temp_dir.path().join("state2.dat"),
        ];

        let manager = StateManager::with_paths("test-license", paths);

        // Initially no state
        let loaded = manager.load("test-license").unwrap();
        assert!(loaded.is_none());

        // Create and save state
        let state = LicenseState::new("test-license");
        manager.save(&state).unwrap();

        // Load should find it
        let loaded = manager.load("test-license").unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().validation_count, 1);
    }

    #[test]
    fn test_state_manager_detects_missing() {
        let temp_dir = TempDir::new().unwrap();
        let paths = vec![
            temp_dir.path().join("state1.dat"),
            temp_dir.path().join("state2.dat"),
            temp_dir.path().join("state3.dat"),
        ];

        let manager = StateManager::with_paths("test-license", paths.clone());

        // Save state to all locations
        let mut state = LicenseState::new("test-license");
        state.validation_count = 5;
        manager.save(&state).unwrap();

        // Verify all files exist
        for path in &paths {
            assert!(path.exists(), "File should exist: {:?}", path);
        }

        // Delete one file (simulating tampering)
        std::fs::remove_file(&paths[1]).unwrap();
        assert!(!paths[1].exists());

        // Load should detect the missing file but NOT auto-repair
        let (loaded, observations) = manager.load_with_observations("test-license").unwrap();
        assert!(loaded.is_some());
        assert!(observations.has_inconsistency());
        assert_eq!(observations.missing_locations.len(), 1);
        assert_eq!(observations.valid_locations.len(), 2);

        // File should still be missing (no auto-repair)
        assert!(!paths[1].exists());

        // Now explicitly repair (policy decision)
        let repaired = manager.repair(&state);
        assert!(repaired >= 1); // At least the missing file should be repaired

        // All files should now exist
        for path in &paths {
            assert!(path.exists(), "File should be restored: {:?}", path);
        }
    }

    #[test]
    fn test_state_manager_uses_newest() {
        let temp_dir = TempDir::new().unwrap();
        let paths = vec![
            temp_dir.path().join("state1.dat"),
            temp_dir.path().join("state2.dat"),
        ];

        // Manually create states with different counts
        let mut state1 = LicenseState::new("test-license");
        state1.validation_count = 10;
        state1.save(&paths[0]).unwrap();

        let mut state2 = LicenseState::new("test-license");
        state2.validation_count = 20;
        state2.save(&paths[1]).unwrap();

        // Manager should load the one with higher count
        let manager = StateManager::with_paths("test-license", paths);
        let loaded = manager.load("test-license").unwrap().unwrap();

        assert_eq!(loaded.validation_count, 20);
    }
}
