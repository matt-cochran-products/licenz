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
#[derive(Debug, Clone, Default)]
pub struct StateObservations {
    pub valid_locations: Vec<PathBuf>,
    pub missing_locations: Vec<PathBuf>,
    pub corrupted_locations: Vec<PathBuf>,
    pub error_locations: Vec<PathBuf>,
}

impl StateObservations {
    pub fn has_inconsistency(&self) -> bool {
        !self.missing_locations.is_empty() || !self.corrupted_locations.is_empty()
    }

    pub fn has_valid_state(&self) -> bool {
        !self.valid_locations.is_empty()
    }

    pub fn total_locations(&self) -> usize {
        self.valid_locations.len()
            + self.missing_locations.len()
            + self.corrupted_locations.len()
            + self.error_locations.len()
    }
}

/// Manages license state across multiple storage locations
pub struct StateManager {
    paths: Vec<PathBuf>,
    state_integrity_key: [u8; 32],
}

impl StateManager {
    /// Create a new state manager for a license (`state_integrity_key` must match save/load).
    pub fn new(license_id: &str, state_integrity_key: [u8; 32]) -> Self {
        let license_hash = sha256_short(license_id);

        let mut paths = Vec::new();

        if let Some(data_dir) = dirs_next::data_local_dir() {
            paths.push(
                data_dir
                    .join(".licenz")
                    .join(format!("{}.state", &license_hash)),
            );
        }

        if let Some(home_dir) = dirs_next::home_dir() {
            paths.push(home_dir.join(format!(".lz_{}", &license_hash[..12])));
        }

        let temp_dir = std::env::temp_dir();
        paths.push(temp_dir.join(format!("lzs_{}.dat", &license_hash[..16])));

        if let Some(config_dir) = dirs_next::config_dir() {
            paths.push(
                config_dir
                    .join("licenz")
                    .join(format!("{}.dat", &license_hash[..8])),
            );
        }

        Self {
            paths,
            state_integrity_key,
        }
    }

    /// Create with custom paths (for testing)
    pub fn with_paths(
        _license_id: &str,
        paths: Vec<PathBuf>,
        state_integrity_key: [u8; 32],
    ) -> Self {
        Self {
            paths,
            state_integrity_key,
        }
    }

    pub fn load(&self, license_id: &str) -> Result<Option<LicenseState>> {
        let (state, _observations) = self.load_with_observations(license_id)?;
        Ok(state)
    }

    pub fn load_with_observations(
        &self,
        license_id: &str,
    ) -> Result<(Option<LicenseState>, StateObservations)> {
        let mut best_state: Option<LicenseState> = None;
        let mut observations = StateObservations::default();
        let key = &self.state_integrity_key;

        for path in &self.paths {
            match LicenseState::load(path, license_id, key) {
                Ok(Some(state)) => {
                    observations.valid_locations.push(path.clone());

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

    /// Repair missing or unreadable state files using the canonical `state`.
    /// `license_id` must match the id used when the state was created.
    pub fn repair(&self, state: &LicenseState, license_id: &str) -> usize {
        let mut repaired = 0;
        let key = &self.state_integrity_key;

        for path in &self.paths {
            let needs_repair =
                !path.exists() || !matches!(LicenseState::load(path, license_id, key), Ok(Some(_)));

            if needs_repair {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if state.save(path, key).is_ok() {
                    repaired += 1;
                    tracing::info!("Repaired state file {:?}", path);
                }
            }
        }

        repaired
    }

    pub fn save(&self, state: &LicenseState) -> Result<()> {
        let mut success_count = 0;
        let mut errors = Vec::new();
        let key = &self.state_integrity_key;

        for path in &self.paths {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            match state.save(path, key) {
                Ok(_) => success_count += 1,
                Err(e) => errors.push((path.clone(), e)),
            }
        }

        if success_count == 0 {
            return Err(LicenseError::StateFileTampered);
        }

        for (path, error) in errors {
            tracing::warn!("Failed to save state to {:?}: {}", path, error);
        }

        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }

    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }
}

fn sha256_short(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const TEST_KEY: [u8; 32] = [42u8; 32];

    #[test]
    fn test_state_manager_round_trip() {
        let temp_dir = TempDir::new().unwrap();
        let paths = vec![
            temp_dir.path().join("state1.dat"),
            temp_dir.path().join("state2.dat"),
        ];

        let manager = StateManager::with_paths("test-license", paths, TEST_KEY);

        let loaded = manager.load("test-license").unwrap();
        assert!(loaded.is_none());

        let state = LicenseState::new("test-license");
        manager.save(&state).unwrap();

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

        let manager = StateManager::with_paths("test-license", paths.clone(), TEST_KEY);

        let mut state = LicenseState::new("test-license");
        state.validation_count = 5;
        manager.save(&state).unwrap();

        for path in &paths {
            assert!(path.exists(), "File should exist: {:?}", path);
        }

        std::fs::remove_file(&paths[1]).unwrap();
        assert!(!paths[1].exists());

        let (loaded, observations) = manager.load_with_observations("test-license").unwrap();
        assert!(loaded.is_some());
        assert!(observations.has_inconsistency());
        assert_eq!(observations.missing_locations.len(), 1);
        assert_eq!(observations.valid_locations.len(), 2);

        assert!(!paths[1].exists());

        let repaired = manager.repair(&state, "test-license");
        assert!(repaired >= 1);

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

        let mut state1 = LicenseState::new("test-license");
        state1.validation_count = 10;
        state1.save(&paths[0], &TEST_KEY).unwrap();

        let mut state2 = LicenseState::new("test-license");
        state2.validation_count = 20;
        state2.save(&paths[1], &TEST_KEY).unwrap();

        let manager = StateManager::with_paths("test-license", paths, TEST_KEY);
        let loaded = manager.load("test-license").unwrap().unwrap();

        assert_eq!(loaded.validation_count, 20);
    }
}
