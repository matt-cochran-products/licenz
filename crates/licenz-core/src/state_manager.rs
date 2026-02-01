//! Multi-location state management for tamper resistance
//!
//! This module stores license state in multiple locations to prevent
//! simple deletion attacks on clock manipulation detection.

use crate::anti_tamper::LicenseState;
use crate::error::{LicenseError, Result};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Manages license state across multiple storage locations
pub struct StateManager {
    /// Primary storage paths (filesystem)
    paths: Vec<PathBuf>,
    /// License ID hash for file naming
    #[allow(dead_code)]
    license_hash: String,
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
                    .join(".ferrite")
                    .join(format!("{}.state", &license_hash)),
            );
        }

        // Secondary: Hidden file in home directory
        if let Some(home_dir) = dirs_next::home_dir() {
            paths.push(home_dir.join(format!(".flic_{}", &license_hash[..12])));
        }

        // Tertiary: Temp directory with obfuscated name
        let temp_dir = std::env::temp_dir();
        paths.push(temp_dir.join(format!("frt_{}.dat", &license_hash[..16])));

        // Quaternary: Config directory
        if let Some(config_dir) = dirs_next::config_dir() {
            paths.push(
                config_dir
                    .join("ferrite")
                    .join(format!("{}.dat", &license_hash[..8])),
            );
        }

        Self {
            paths,
            license_hash,
        }
    }

    /// Create with custom paths (for testing)
    pub fn with_paths(license_id: &str, paths: Vec<PathBuf>) -> Self {
        Self {
            paths,
            license_hash: sha256_short(license_id),
        }
    }

    /// Load the most recent valid state from any location
    pub fn load(&self, license_id: &str) -> Result<Option<LicenseState>> {
        let mut best_state: Option<LicenseState> = None;
        let mut found_locations = Vec::new();
        let mut corrupted_locations = Vec::new();

        for path in &self.paths {
            match LicenseState::load(path, license_id) {
                Ok(Some(state)) => {
                    found_locations.push(path.clone());

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
                    // File doesn't exist - not an error
                }
                Err(LicenseError::StateFileTampered) => {
                    corrupted_locations.push(path.clone());
                    tracing::warn!("Corrupted state file detected at {:?}", path);
                }
                Err(_) => {
                    // Other errors (permissions, etc.) - skip silently
                }
            }
        }

        // DETECTION: If some files exist but not all, possible tampering
        let existing_count = found_locations.len() + corrupted_locations.len();
        if existing_count > 0 && existing_count < self.paths.len() {
            tracing::warn!(
                "State file inconsistency: {} of {} locations have data. Possible tampering.",
                existing_count,
                self.paths.len()
            );

            // Restore missing files from best state
            if let Some(ref state) = best_state {
                self.repair_missing(state);
            }
        }

        // DETECTION: If we found corrupted files, repair them
        if !corrupted_locations.is_empty() {
            tracing::warn!(
                "Found {} corrupted state files. Attempting repair.",
                corrupted_locations.len()
            );

            if let Some(ref state) = best_state {
                for path in &corrupted_locations {
                    if let Err(e) = state.save(path) {
                        tracing::error!("Failed to repair state file {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok(best_state)
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

    /// Repair missing state files
    fn repair_missing(&self, state: &LicenseState) {
        for path in &self.paths {
            if !path.exists() {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = state.save(path) {
                    tracing::warn!("Failed to restore state file {:?}: {}", path, e);
                } else {
                    tracing::info!("Restored missing state file {:?}", path);
                }
            }
        }
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
    fn test_state_manager_repairs_missing() {
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

        // Load should detect and repair
        let loaded = manager.load("test-license").unwrap();
        assert!(loaded.is_some());

        // All files should now exist again
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
