//! Online license validation
//!
//! This module provides functionality for checking license status against a server.
//! It's useful for:
//! - Revocation checking
//! - License sync reporting
//! - Server-side validation
//!
//! This module is only available when the `online-check` feature is enabled.
//!
//! # Example
//!
//! ```rust,ignore
//! use licenz_core::{online_check, SignedLicense};
//!
//! let license: SignedLicense = // ... load license
//! let result = online_check::check_revocation(
//!     &license,
//!     "https://your-server.com",
//!     "lk_your_api_key",
//! )?;
//!
//! match result.status {
//!     RevocationStatus::Active => println!("License is active"),
//!     RevocationStatus::Revoked => println!("License has been revoked!"),
//!     RevocationStatus::Expired => println!("License has expired"),
//!     RevocationStatus::Unknown => println!("Could not determine status"),
//! }
//! ```

use crate::{LicenseError, Result, SignedLicense};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// License revocation status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    /// License is active and valid
    Active,
    /// License has been revoked
    Revoked,
    /// License has expired
    Expired,
    /// License was not found on server
    NotFound,
    /// Could not determine status (server unreachable, etc.)
    Unknown,
}

/// Result of a revocation check
#[derive(Debug, Clone)]
pub struct RevocationCheckResult {
    /// The license serial that was checked
    pub serial: String,
    /// The revocation status
    pub status: RevocationStatus,
    /// When the license was revoked (if applicable)
    pub revoked_at: Option<DateTime<Utc>>,
    /// Server timestamp when the check was performed
    pub checked_at: DateTime<Utc>,
}

/// Sync report to send to the server
#[derive(Debug, Clone, Serialize)]
pub struct SyncReport {
    /// License serial number
    pub license_serial: String,
    /// Hardware fingerprint (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_fingerprint: Option<String>,
    /// Application version (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    /// Features currently being used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features_used: Option<Vec<String>>,
    /// Number of seats currently in use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seats_in_use: Option<i32>,
}

/// Response from sync endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct SyncResponse {
    /// Status: "ok", "revoked", "expired", "not_found"
    pub status: String,
    /// Optional message from server
    pub message: Option<String>,
    /// Server timestamp
    pub server_time: DateTime<Utc>,
}

/// Request for batch revocation check
#[derive(Debug, Serialize)]
struct CheckRevocationRequest {
    serials: Vec<String>,
}

/// Response from batch revocation check
#[derive(Debug, Deserialize)]
struct CheckRevocationResponse {
    results: Vec<RevocationResult>,
    checked_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct RevocationResult {
    serial: String,
    status: String,
    revoked_at: Option<DateTime<Utc>>,
}

/// Configuration for online checks
#[derive(Debug, Clone)]
pub struct OnlineCheckConfig {
    /// Server URL
    pub server_url: String,
    /// API key for authentication
    pub api_key: String,
    /// Request timeout
    pub timeout: Duration,
}

impl Default for OnlineCheckConfig {
    fn default() -> Self {
        Self {
            server_url: "https://api.licenz.io".to_string(),
            api_key: String::new(),
            timeout: Duration::from_secs(10),
        }
    }
}

impl OnlineCheckConfig {
    /// Create a new config with server URL and API key
    pub fn new(server_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            api_key: api_key.into(),
            ..Default::default()
        }
    }

    /// Set the request timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Check if a license has been revoked
///
/// This makes an HTTP request to the server to check the license status.
/// If the server is unreachable, returns `RevocationStatus::Unknown`.
///
/// # Arguments
///
/// * `license` - The signed license to check
/// * `config` - Configuration for the online check
///
/// # Returns
///
/// Returns the revocation check result, or an error if the request fails.
pub fn check_revocation(
    license: &SignedLicense,
    config: &OnlineCheckConfig,
) -> Result<RevocationCheckResult> {
    check_revocation_by_serial(&license.data.serial, config)
}

/// Check revocation status by serial number
pub fn check_revocation_by_serial(
    serial: &str,
    config: &OnlineCheckConfig,
) -> Result<RevocationCheckResult> {
    let results = check_revocation_batch(&[serial.to_string()], config)?;
    results
        .into_iter()
        .next()
        .ok_or_else(|| LicenseError::Validation("No result returned from server".to_string()))
}

/// Batch check multiple licenses for revocation
pub fn check_revocation_batch(
    serials: &[String],
    config: &OnlineCheckConfig,
) -> Result<Vec<RevocationCheckResult>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(config.timeout)
        .build()
        .map_err(|e| LicenseError::Validation(format!("Failed to create HTTP client: {}", e)))?;

    let url = format!(
        "{}/api/v1/licenses/check-revocation",
        config.server_url.trim_end_matches('/')
    );

    let request = CheckRevocationRequest {
        serials: serials.to_vec(),
    };

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .json(&request)
        .send();

    match response {
        Ok(resp) => {
            if !resp.status().is_success() {
                // Server returned an error, but we can still return Unknown status
                let now = Utc::now();
                return Ok(serials
                    .iter()
                    .map(|s| RevocationCheckResult {
                        serial: s.clone(),
                        status: RevocationStatus::Unknown,
                        revoked_at: None,
                        checked_at: now,
                    })
                    .collect());
            }

            let body: CheckRevocationResponse = resp.json().map_err(|e| {
                LicenseError::Validation(format!("Failed to parse response: {}", e))
            })?;

            Ok(body
                .results
                .into_iter()
                .map(|r| RevocationCheckResult {
                    serial: r.serial,
                    status: parse_status(&r.status),
                    revoked_at: r.revoked_at,
                    checked_at: body.checked_at,
                })
                .collect())
        }
        Err(_) => {
            // Network error - return Unknown status for all
            let now = Utc::now();
            Ok(serials
                .iter()
                .map(|s| RevocationCheckResult {
                    serial: s.clone(),
                    status: RevocationStatus::Unknown,
                    revoked_at: None,
                    checked_at: now,
                })
                .collect())
        }
    }
}

/// Report license usage to the server (sync)
///
/// This is a fire-and-forget operation - errors are logged but don't
/// prevent the application from running.
pub fn sync_report(report: &SyncReport, config: &OnlineCheckConfig) -> Result<SyncResponse> {
    let client = reqwest::blocking::Client::builder()
        .timeout(config.timeout)
        .build()
        .map_err(|e| LicenseError::Validation(format!("Failed to create HTTP client: {}", e)))?;

    let url = format!(
        "{}/api/v1/licenses/sync",
        config.server_url.trim_end_matches('/')
    );

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .json(report)
        .send()
        .map_err(|e| LicenseError::Validation(format!("Sync request failed: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        return Err(LicenseError::Validation(format!(
            "Sync failed with status {}: {}",
            status, body
        )));
    }

    response
        .json()
        .map_err(|e| LicenseError::Validation(format!("Failed to parse sync response: {}", e)))
}

fn parse_status(status: &str) -> RevocationStatus {
    match status.to_lowercase().as_str() {
        "active" => RevocationStatus::Active,
        "revoked" => RevocationStatus::Revoked,
        "expired" => RevocationStatus::Expired,
        "not_found" => RevocationStatus::NotFound,
        _ => RevocationStatus::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_status() {
        assert_eq!(parse_status("active"), RevocationStatus::Active);
        assert_eq!(parse_status("ACTIVE"), RevocationStatus::Active);
        assert_eq!(parse_status("revoked"), RevocationStatus::Revoked);
        assert_eq!(parse_status("expired"), RevocationStatus::Expired);
        assert_eq!(parse_status("not_found"), RevocationStatus::NotFound);
        assert_eq!(parse_status("unknown"), RevocationStatus::Unknown);
        assert_eq!(parse_status("something_else"), RevocationStatus::Unknown);
    }

    #[test]
    fn test_config_builder() {
        let config = OnlineCheckConfig::new("https://example.com", "test_key")
            .with_timeout(Duration::from_secs(30));

        assert_eq!(config.server_url, "https://example.com");
        assert_eq!(config.api_key, "test_key");
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_sync_report_serialization() {
        let report = SyncReport {
            license_serial: "LIC-TEST-123".to_string(),
            hardware_fingerprint: Some("abc123".to_string()),
            app_version: Some("1.0.0".to_string()),
            features_used: Some(vec!["premium".to_string()]),
            seats_in_use: Some(5),
        };

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("LIC-TEST-123"));
        assert!(json.contains("abc123"));
    }
}
