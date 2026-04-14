//! Activation response file format
//!
//! The `.resp` file contains the signed license and metadata from the
//! licensing server, ready to be installed on the air-gapped machine.

use crate::error::{LicenseError, Result};
use crate::license::SignedLicense;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

use super::{
    detect_format, SneakernetFormat, MAX_SNEAKERNET_JSON_PAYLOAD, RESPONSE_MAGIC,
    RESPONSE_TEXT_PREFIX, RESPONSE_TEXT_SUFFIX, RESPONSE_VERSION,
};

/// An activation response from the licensing server
///
/// This struct contains the signed license ready for installation,
/// along with metadata linking it to the original request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationResponse {
    /// The request ID this response is for (links to ActivationRequest)
    pub request_id: Uuid,

    /// The signed license blob
    pub license: SignedLicense,

    /// When the license expires
    pub expires_at: DateTime<Utc>,

    /// Server timestamp when the response was generated
    pub server_timestamp: DateTime<Utc>,

    /// Response format version
    pub version: u8,

    /// Optional message from the server (e.g., "Thank you for your purchase!")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Integrity digest (SHA-256 hex of canonical fields) for accidental corruption detection; not a keyed MAC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_digest: Option<String>,
}

impl ActivationResponse {
    /// Create a new activation response
    pub fn new(request_id: Uuid, license: SignedLicense, expires_at: DateTime<Utc>) -> Self {
        let mut response = Self {
            request_id,
            license,
            expires_at,
            server_timestamp: Utc::now(),
            version: RESPONSE_VERSION,
            message: None,
            integrity_digest: None,
        };

        // Compute and set integrity digest
        response.integrity_digest = Some(response.compute_integrity_digest());

        response
    }

    /// Create a new activation response with a custom message
    pub fn with_message(
        request_id: Uuid,
        license: SignedLicense,
        expires_at: DateTime<Utc>,
        message: impl Into<String>,
    ) -> Self {
        let mut response = Self {
            request_id,
            license,
            expires_at,
            server_timestamp: Utc::now(),
            version: RESPONSE_VERSION,
            message: Some(message.into()),
            integrity_digest: None,
        };

        // Compute and set integrity digest
        response.integrity_digest = Some(response.compute_integrity_digest());

        response
    }

    /// Create a builder for more complex response construction
    pub fn builder(request_id: Uuid, license: SignedLicense) -> ActivationResponseBuilder {
        ActivationResponseBuilder::new(request_id, license)
    }

    /// Load an activation response from a file (auto-detects format)
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }

    /// Parse an activation response from bytes (auto-detects format)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        match detect_format(data) {
            Some(SneakernetFormat::Binary) => Self::from_binary(data),
            Some(SneakernetFormat::Text) => {
                let text = std::str::from_utf8(data)
                    .map_err(|e| LicenseError::InvalidLicenseFormat(e.to_string()))?;
                Self::from_base64(text)
            }
            None => Err(LicenseError::InvalidLicenseFormat(
                "Unknown activation response format".to_string(),
            )),
        }
    }

    /// Parse from binary format
    pub fn from_binary(data: &[u8]) -> Result<Self> {
        if data.len() < 9 {
            return Err(LicenseError::InvalidLicenseFormat(
                "Activation response too short".to_string(),
            ));
        }

        // Verify magic header
        if &data[0..4] != RESPONSE_MAGIC {
            return Err(LicenseError::InvalidLicenseFormat(
                "Invalid activation response magic header".to_string(),
            ));
        }

        // Check version
        let version = data[4];
        if version > RESPONSE_VERSION {
            return Err(LicenseError::InvalidLicenseFormat(format!(
                "Unsupported activation response version: {} (max supported: {})",
                version, RESPONSE_VERSION
            )));
        }

        // Read payload length
        let len = u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;

        if len > MAX_SNEAKERNET_JSON_PAYLOAD {
            return Err(LicenseError::InvalidLicenseFormat(format!(
                "Activation response payload exceeds maximum of {} bytes",
                MAX_SNEAKERNET_JSON_PAYLOAD
            )));
        }

        if data.len() < 9 + len {
            return Err(LicenseError::InvalidLicenseFormat(
                "Activation response data truncated".to_string(),
            ));
        }

        // Deserialize the response
        let response: Self = serde_json::from_slice(&data[9..9 + len])
            .map_err(|e| LicenseError::InvalidLicenseFormat(e.to_string()))?;

        // Verify integrity digest if present
        if let Some(ref stored_digest) = response.integrity_digest {
            let computed = response.compute_integrity_digest();
            if &computed != stored_digest {
                return Err(LicenseError::InvalidLicenseFormat(
                    "Activation response integrity digest mismatch - data may be corrupted"
                        .to_string(),
                ));
            }
        }

        Ok(response)
    }

    /// Parse from base64 text format
    pub fn from_base64(text: &str) -> Result<Self> {
        let trimmed = text.trim();

        // Strip prefix/suffix if present
        let base64_content = if trimmed.starts_with(RESPONSE_TEXT_PREFIX) {
            trimmed
                .strip_prefix(RESPONSE_TEXT_PREFIX)
                .and_then(|s| s.strip_suffix(RESPONSE_TEXT_SUFFIX))
                .map(|s| s.trim())
                .ok_or_else(|| {
                    LicenseError::InvalidLicenseFormat(
                        "Malformed activation response text format".to_string(),
                    )
                })?
        } else {
            trimmed
        };

        // Remove any whitespace/newlines from base64 content
        let clean_base64: String = base64_content
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        // Decode base64
        let binary = BASE64
            .decode(&clean_base64)
            .map_err(|e| LicenseError::InvalidLicenseFormat(format!("Invalid base64: {}", e)))?;

        // Parse as binary
        Self::from_binary(&binary)
    }

    /// Export to binary format
    pub fn to_binary(&self) -> Result<Vec<u8>> {
        let mut output = Vec::new();

        // Write magic header
        output.write_all(RESPONSE_MAGIC)?;

        // Write version
        output.write_all(&[RESPONSE_VERSION])?;

        // Serialize the response
        let encoded = serde_json::to_vec(self)
            .map_err(|e| LicenseError::SerializationError(e.to_string()))?;

        // Write length as u32 little-endian
        let len = encoded.len() as u32;
        output.write_all(&len.to_le_bytes())?;

        // Write the encoded response
        output.write_all(&encoded)?;

        Ok(output)
    }

    /// Export to base64 text format (suitable for email/copy-paste)
    pub fn to_base64(&self) -> Result<String> {
        let binary = self.to_binary()?;
        let base64_content = BASE64.encode(&binary);

        // Format with line wrapping (64 chars per line)
        let wrapped: Vec<&str> = base64_content
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect();

        Ok(format!(
            "{}\n{}\n{}",
            RESPONSE_TEXT_PREFIX,
            wrapped.join("\n"),
            RESPONSE_TEXT_SUFFIX
        ))
    }

    /// Save to a binary file
    pub fn save_binary(&self, path: &Path) -> Result<()> {
        let binary = self.to_binary()?;
        std::fs::write(path, binary)?;
        Ok(())
    }

    /// Save to a text file (base64 format)
    pub fn save_text(&self, path: &Path) -> Result<()> {
        let text = self.to_base64()?;
        std::fs::write(path, text)?;
        Ok(())
    }

    /// Extract the signed license from this response
    ///
    /// This is the license that should be saved and used for validation.
    pub fn extract_license(&self) -> SignedLicense {
        self.license.clone()
    }

    /// Check if this response matches a specific request
    pub fn matches_request(&self, request_id: Uuid) -> bool {
        self.request_id == request_id
    }

    /// Integrity digest (SHA-256 hex of canonical fields; not a keyed MAC).
    fn compute_integrity_digest(&self) -> String {
        let mut hasher = Sha256::new();

        // Hash the key fields
        hasher.update(self.request_id.as_bytes());
        hasher.update(self.license.data.id.as_bytes());
        hasher.update(self.license.signature.as_bytes());
        hasher.update(self.expires_at.to_rfc3339().as_bytes());
        hasher.update(self.server_timestamp.to_rfc3339().as_bytes());
        hasher.update([self.version]);

        if let Some(ref msg) = self.message {
            hasher.update(msg.as_bytes());
        }

        hex::encode(hasher.finalize())
    }

    /// Verify the response's integrity
    pub fn verify_integrity(&self) -> bool {
        match &self.integrity_digest {
            Some(stored) => &self.compute_integrity_digest() == stored,
            None => true, // No digest to verify
        }
    }

    /// Check if the response has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Get days until expiration
    pub fn days_until_expiry(&self) -> i64 {
        (self.expires_at - Utc::now()).num_days()
    }
}

/// Builder for creating activation responses
pub struct ActivationResponseBuilder {
    request_id: Uuid,
    license: SignedLicense,
    expires_at: Option<DateTime<Utc>>,
    message: Option<String>,
}

impl ActivationResponseBuilder {
    /// Create a new builder
    pub fn new(request_id: Uuid, license: SignedLicense) -> Self {
        Self {
            request_id,
            license,
            expires_at: None,
            message: None,
        }
    }

    /// Set the expiration date
    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set expiration to a number of days from now
    pub fn expires_in_days(mut self, days: i64) -> Self {
        self.expires_at = Some(Utc::now() + chrono::Duration::days(days));
        self
    }

    /// Set a message for the response
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Build the activation response
    pub fn build(self) -> ActivationResponse {
        let expires_at = self.expires_at.unwrap_or(self.license.data.valid_until);

        let mut response = ActivationResponse {
            request_id: self.request_id,
            license: self.license,
            expires_at,
            server_timestamp: Utc::now(),
            version: RESPONSE_VERSION,
            message: self.message,
            integrity_digest: None,
        };

        // Compute and set integrity digest
        response.integrity_digest = Some(response.compute_integrity_digest());

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::LicenseData;

    fn create_test_license() -> SignedLicense {
        SignedLicense {
            data: LicenseData::builder()
                .id("TEST-LIC-001")
                .serial("SN-TEST-001")
                .customer_id("TEST-CUST")
                .product_id("TEST-PROD")
                .valid_days(365)
                .feature("basic")
                .build()
                .unwrap(),
            signature: "dGVzdC1zaWduYXR1cmU=".to_string(),
            algorithm: "RSA-SHA256".to_string(),
        }
    }

    #[test]
    fn test_response_creation() {
        let request_id = Uuid::new_v4();
        let license = create_test_license();
        let expires_at = Utc::now() + chrono::Duration::days(365);

        let response = ActivationResponse::new(request_id, license.clone(), expires_at);

        assert_eq!(response.request_id, request_id);
        assert_eq!(response.license.data.id, "TEST-LIC-001");
        assert!(response.integrity_digest.is_some());
    }

    #[test]
    fn test_response_with_message() {
        let request_id = Uuid::new_v4();
        let license = create_test_license();
        let expires_at = Utc::now() + chrono::Duration::days(365);

        let response = ActivationResponse::with_message(
            request_id,
            license,
            expires_at,
            "Thank you for your purchase!",
        );

        assert_eq!(
            response.message,
            Some("Thank you for your purchase!".to_string())
        );
    }

    #[test]
    fn test_response_builder() {
        let request_id = Uuid::new_v4();
        let license = create_test_license();

        let response = ActivationResponse::builder(request_id, license)
            .expires_in_days(30)
            .message("Enjoy your trial!")
            .build();

        assert_eq!(response.message, Some("Enjoy your trial!".to_string()));
        assert!(response.days_until_expiry() <= 30);
        assert!(response.days_until_expiry() >= 29); // Allow for test timing
    }

    #[test]
    fn test_binary_serialization_roundtrip() {
        let request_id = Uuid::new_v4();
        let license = create_test_license();
        let expires_at = Utc::now() + chrono::Duration::days(365);

        let response = ActivationResponse::new(request_id, license, expires_at);

        let binary = response.to_binary().unwrap();

        // Verify magic header
        assert_eq!(&binary[0..4], RESPONSE_MAGIC);
        assert_eq!(binary[4], RESPONSE_VERSION);

        // Parse back
        let parsed = ActivationResponse::from_binary(&binary).unwrap();

        assert_eq!(parsed.request_id, response.request_id);
        assert_eq!(parsed.license.data.id, response.license.data.id);
        assert_eq!(parsed.integrity_digest, response.integrity_digest);
    }

    #[test]
    fn test_base64_serialization_roundtrip() {
        let request_id = Uuid::new_v4();
        let license = create_test_license();
        let expires_at = Utc::now() + chrono::Duration::days(365);

        let response =
            ActivationResponse::with_message(request_id, license, expires_at, "Welcome aboard!");

        let text = response.to_base64().unwrap();

        // Verify format
        assert!(text.starts_with(RESPONSE_TEXT_PREFIX));
        assert!(text.ends_with(RESPONSE_TEXT_SUFFIX));

        // Parse back
        let parsed = ActivationResponse::from_base64(&text).unwrap();

        assert_eq!(parsed.request_id, response.request_id);
        assert_eq!(parsed.license.data.id, response.license.data.id);
        assert_eq!(parsed.message, Some("Welcome aboard!".to_string()));
    }

    #[test]
    fn test_auto_detect_format() {
        let request_id = Uuid::new_v4();
        let license = create_test_license();
        let expires_at = Utc::now() + chrono::Duration::days(365);

        let response = ActivationResponse::new(request_id, license, expires_at);

        // Test binary
        let binary = response.to_binary().unwrap();
        let parsed_binary = ActivationResponse::from_bytes(&binary).unwrap();
        assert_eq!(parsed_binary.request_id, request_id);

        // Test text
        let text = response.to_base64().unwrap();
        let parsed_text = ActivationResponse::from_bytes(text.as_bytes()).unwrap();
        assert_eq!(parsed_text.request_id, request_id);
    }

    #[test]
    fn test_integrity_verification() {
        let request_id = Uuid::new_v4();
        let license = create_test_license();
        let expires_at = Utc::now() + chrono::Duration::days(365);

        let response = ActivationResponse::new(request_id, license, expires_at);

        assert!(response.verify_integrity());
    }

    #[test]
    fn test_matches_request() {
        let request_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let license = create_test_license();
        let expires_at = Utc::now() + chrono::Duration::days(365);

        let response = ActivationResponse::new(request_id, license, expires_at);

        assert!(response.matches_request(request_id));
        assert!(!response.matches_request(other_id));
    }

    #[test]
    fn test_extract_license() {
        let request_id = Uuid::new_v4();
        let license = create_test_license();
        let expires_at = Utc::now() + chrono::Duration::days(365);

        let response = ActivationResponse::new(request_id, license.clone(), expires_at);
        let extracted = response.extract_license();

        assert_eq!(extracted.data.id, license.data.id);
        assert_eq!(extracted.signature, license.signature);
    }

    #[test]
    fn test_invalid_magic_header() {
        let mut bad_data = vec![b'B', b'A', b'D', b'!'];
        bad_data.extend_from_slice(&[1, 0, 0, 0, 0]);

        let result = ActivationResponse::from_binary(&bad_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_data() {
        let request_id = Uuid::new_v4();
        let license = create_test_license();
        let expires_at = Utc::now() + chrono::Duration::days(365);

        let response = ActivationResponse::new(request_id, license, expires_at);
        let binary = response.to_binary().unwrap();

        // Truncate the data
        let truncated = &binary[0..20];

        let result = ActivationResponse::from_binary(truncated);
        assert!(result.is_err());
    }

    #[test]
    fn test_expiry_check() {
        let request_id = Uuid::new_v4();
        let license = create_test_license();

        // Create an expired response
        let expired_at = Utc::now() - chrono::Duration::days(1);
        let expired_response = ActivationResponse::new(request_id, license.clone(), expired_at);
        assert!(expired_response.is_expired());

        // Create a valid response
        let valid_until = Utc::now() + chrono::Duration::days(30);
        let valid_response = ActivationResponse::new(request_id, license, valid_until);
        assert!(!valid_response.is_expired());
        assert!(valid_response.days_until_expiry() > 0);
    }
}
