//! Online license validation
//!
//! Configure via [`OnlineCheckConfig`]. **HTTPS** is required for `server_url`.
//! Responses from revocation and sync endpoints must be JSON `{"jws":"<compact-jws>"}`
//! with a verified payload (see `SECURITY.md`). Configure exactly one of
//! [`OnlineCheckConfig::jwks_url`] or [`OnlineCheckConfig::jws_verifying_key_pem`].

mod jws;

use crate::{LicenseError, Result, SignedLicense};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::Read;
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
    /// Status string in a **verified** JWS payload was not recognized (not transport failure).
    Unknown,
}

/// Result of a revocation check
#[derive(Debug, Clone)]
pub struct RevocationCheckResult {
    pub serial: String,
    pub status: RevocationStatus,
    pub revoked_at: Option<DateTime<Utc>>,
    pub checked_at: DateTime<Utc>,
}

/// Sync report to send to the server
#[derive(Debug, Clone, Serialize)]
pub struct SyncReport {
    pub license_serial: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features_used: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seats_in_use: Option<i32>,
}

/// Response from sync endpoint (JWS claims after verification)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SyncResponse {
    pub status: String,
    pub message: Option<String>,
    pub server_time: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct CheckRevocationRequest {
    serials: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct CheckRevocationResponse {
    results: Vec<RevocationResult>,
    checked_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct RevocationResult {
    serial: String,
    status: String,
    revoked_at: Option<DateTime<Utc>>,
}

/// Configuration for online checks
#[derive(Debug, Clone)]
pub struct OnlineCheckConfig {
    pub server_url: String,
    pub api_key: String,
    pub timeout: Duration,
    pub max_response_bytes: usize,
    pub max_serials_per_request: usize,
    /// HTTPS URL returning a JWKS document (use this **or** `jws_verifying_key_pem`, not both).
    pub jwks_url: Option<String>,
    /// PEM-encoded RSA or Ed25519 public key (use this **or** `jwks_url`, not both).
    pub jws_verifying_key_pem: Option<String>,
    /// Expected JWT `aud` claim. When set, the JWS `aud` must match this value.
    pub expected_audience: Option<String>,
}

impl Default for OnlineCheckConfig {
    fn default() -> Self {
        Self {
            server_url: "https://api.licenz.io".to_string(),
            api_key: String::new(),
            timeout: Duration::from_secs(10),
            max_response_bytes: 512 * 1024,
            max_serials_per_request: 500,
            jwks_url: None,
            jws_verifying_key_pem: None,
            expected_audience: None,
        }
    }
}

impl OnlineCheckConfig {
    pub fn new(server_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            api_key: api_key.into(),
            ..Default::default()
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_response_bytes(mut self, max: usize) -> Self {
        self.max_response_bytes = max;
        self
    }

    pub fn with_max_serials_per_request(mut self, max: usize) -> Self {
        self.max_serials_per_request = max;
        self
    }

    pub fn with_jwks_url(mut self, url: impl Into<String>) -> Self {
        self.jwks_url = Some(url.into());
        self
    }

    pub fn with_jws_verifying_key_pem(mut self, pem: impl Into<String>) -> Self {
        self.jws_verifying_key_pem = Some(pem.into());
        self
    }
}

fn validate_config(config: &OnlineCheckConfig) -> Result<()> {
    let url_lower = config.server_url.to_ascii_lowercase();
    if !url_lower.starts_with("https://") {
        return Err(LicenseError::Validation(
            "HTTPS is required for online checks (server_url must start with https://)".into(),
        ));
    }
    if config.api_key.is_empty() {
        return Err(LicenseError::Validation(
            "API key must not be empty for online checks".into(),
        ));
    }
    let has_jwks = config
        .jwks_url
        .as_ref()
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let has_pem = config
        .jws_verifying_key_pem
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    match (has_jwks, has_pem) {
        (true, false) | (false, true) => Ok(()),
        (false, false) => Err(LicenseError::Validation(
            "Exactly one of jwks_url or jws_verifying_key_pem must be set for JWS verification"
                .into(),
        )),
        (true, true) => Err(LicenseError::Validation(
            "Set only one of jwks_url or jws_verifying_key_pem, not both".into(),
        )),
    }
}

fn build_client(config: &OnlineCheckConfig) -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(config.timeout)
        .build()
        .map_err(|e| LicenseError::Validation(format!("Failed to create HTTP client: {}", e)))
}

fn read_body_limited(response: &mut reqwest::blocking::Response, limit: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut reader = response.take((limit as u64).saturating_add(1));
    reader
        .read_to_end(&mut buf)
        .map_err(|e| LicenseError::Validation(format!("Failed to read response body: {}", e)))?;
    if buf.len() > limit {
        return Err(LicenseError::Validation(format!(
            "Response body exceeds maximum of {} bytes",
            limit
        )));
    }
    Ok(buf)
}

fn truncate_body_for_error(body: &str, max: usize) -> String {
    if body.len() <= max {
        return body.to_string();
    }
    format!("{}… (truncated, {} bytes total)", &body[..max], body.len())
}

pub fn check_revocation(
    license: &SignedLicense,
    config: &OnlineCheckConfig,
) -> Result<RevocationCheckResult> {
    check_revocation_by_serial(&license.data.serial, config)
}

pub fn check_revocation_by_serial(
    serial: &str,
    config: &OnlineCheckConfig,
) -> Result<RevocationCheckResult> {
    let results = check_revocation_batch(&[serial.to_string()], config)?;
    results
        .into_iter()
        .next()
        .ok_or_else(|| LicenseError::Validation("No result returned from server".into()))
}

pub fn check_revocation_batch(
    serials: &[String],
    config: &OnlineCheckConfig,
) -> Result<Vec<RevocationCheckResult>> {
    validate_config(config)?;
    if serials.is_empty() {
        return Ok(Vec::new());
    }
    if serials.len() > config.max_serials_per_request {
        return Err(LicenseError::Validation(format!(
            "Too many serials: {} exceeds max_serials_per_request ({})",
            serials.len(),
            config.max_serials_per_request
        )));
    }

    let client = build_client(config)?;

    let url = format!(
        "{}/api/v1/licenses/check-revocation",
        config.server_url.trim_end_matches('/')
    );

    let request = CheckRevocationRequest {
        serials: serials.to_vec(),
    };

    let mut resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .json(&request)
        .send()
        .map_err(|e| LicenseError::Validation(format!("Revocation request failed: {}", e)))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body_raw = resp.text().unwrap_or_default();
        let snippet = truncate_body_for_error(&body_raw, 256);
        return Err(LicenseError::Validation(format!(
            "Revocation check failed with HTTP {}; truncated body preview: {:?}",
            status, snippet
        )));
    }

    let raw = read_body_limited(&mut resp, config.max_response_bytes)?;
    let parsed = parse_revocation_body(&raw, config, &client)?;
    let checked_at = parsed.checked_at;
    Ok(parsed
        .results
        .into_iter()
        .map(|r| RevocationCheckResult {
            serial: r.serial,
            status: parse_status(&r.status),
            revoked_at: r.revoked_at,
            checked_at,
        })
        .collect())
}

fn parse_revocation_body(
    body: &[u8],
    config: &OnlineCheckConfig,
    client: &reqwest::blocking::Client,
) -> Result<CheckRevocationResponse> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| LicenseError::Validation(format!("Failed to parse revocation JSON: {}", e)))?;
    let jws = v.get("jws").and_then(|x| x.as_str()).ok_or_else(|| {
        LicenseError::Validation("Revocation response missing top-level \"jws\" field".into())
    })?;
    jws::verify_revocation_jws(jws, config, client, config.timeout)
}

pub fn sync_report(report: &SyncReport, config: &OnlineCheckConfig) -> Result<SyncResponse> {
    validate_config(config)?;
    let client = build_client(config)?;

    let url = format!(
        "{}/api/v1/licenses/sync",
        config.server_url.trim_end_matches('/')
    );

    let mut response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .json(report)
        .send()
        .map_err(|e| LicenseError::Validation(format!("Sync request failed: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body_raw = response.text().unwrap_or_default();
        let snippet = truncate_body_for_error(&body_raw, 256);
        return Err(LicenseError::Validation(format!(
            "Sync failed with HTTP {}; response body omitted from error (truncated preview: {:?})",
            status, snippet
        )));
    }

    let body = read_body_limited(&mut response, config.max_response_bytes)?;
    let v: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        LicenseError::Validation(format!("Failed to parse sync response JSON: {}", e))
    })?;
    let jws = v.get("jws").and_then(|x| x.as_str()).ok_or_else(|| {
        LicenseError::Validation("Sync response missing top-level \"jws\" field".into())
    })?;
    jws::verify_sync_jws(jws, config, &client, config.timeout)
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

    const TEST_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkPkblXN/KFhH
XuQgG6aMufVKA2cFFnTXka7s7ZWRfqJBXAJcpZMeKUFb7c4CdFIcfoiZFuVs8Un
k/6TmEYLOxOt17oZUKF8KCB8kWFuLLN24mTS7kbYB2gPpII5JadOxlAHfS6V0V2
MbuXg9qIfVu1Z1t456oiBOy2dPk2jAo1Pkr6N5wQrY1RG6VBX9J2T6dF9bR1QqQ
IDAQAB
-----END PUBLIC KEY-----"#;

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
            .with_jws_verifying_key_pem(TEST_PEM)
            .with_timeout(Duration::from_secs(30));

        assert_eq!(config.server_url, "https://example.com");
        assert_eq!(config.api_key, "test_key");
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_validate_rejects_http() {
        let config =
            OnlineCheckConfig::new("http://example.com", "k").with_jws_verifying_key_pem(TEST_PEM);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_rejects_empty_key() {
        let config =
            OnlineCheckConfig::new("https://example.com", "").with_jws_verifying_key_pem(TEST_PEM);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_requires_exactly_one_jws_source() {
        let mut c = OnlineCheckConfig::new("https://a.com", "k");
        assert!(validate_config(&c).is_err());

        c.jws_verifying_key_pem = Some(TEST_PEM.into());
        assert!(validate_config(&c).is_ok());

        c.jwks_url = Some("https://a.com/jwks".into());
        assert!(validate_config(&c).is_err());
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
