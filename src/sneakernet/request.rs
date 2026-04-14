//! Activation request file format
//!
//! The `.req` file contains all information needed for the licensing server
//! to generate a license for an air-gapped machine.

use crate::anti_tamper::HardwareFingerprint;
use crate::error::{LicenseError, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

use super::{
    detect_format, SneakernetFormat, MAX_SNEAKERNET_JSON_PAYLOAD, REQUEST_MAGIC,
    REQUEST_TEXT_PREFIX, REQUEST_TEXT_SUFFIX, REQUEST_VERSION,
};

/// An activation request generated on an air-gapped machine
///
/// This struct contains all the information a licensing server needs
/// to generate a license that will work on the requesting machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationRequest {
    /// Unique identifier for this request (UUID v4)
    pub request_id: Uuid,

    /// Hardware fingerprint of the requesting machine
    pub fingerprint: HardwareFingerprint,

    /// Product identifier (which product is being activated)
    pub product_id: String,

    /// Requested features (optional - server may grant subset)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_features: Vec<String>,

    /// When this request was created
    pub timestamp: DateTime<Utc>,

    /// Request format version (for future compatibility)
    pub version: u8,

    /// Additional metadata (customer info, notes, etc.)
    ///
    /// Uses `BTreeMap` for deterministic iteration order, which is critical for
    /// consistent checksum computation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,

    /// Checksum of the request data (for integrity verification)
    /// This is computed from the serialized request content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
}

impl ActivationRequest {
    /// Create a new activation request builder
    pub fn builder() -> ActivationRequestBuilder {
        ActivationRequestBuilder::new()
    }

    /// Load an activation request from a file (auto-detects format)
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }

    /// Parse an activation request from bytes (auto-detects format)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        match detect_format(data) {
            Some(SneakernetFormat::Binary) => Self::from_binary(data),
            Some(SneakernetFormat::Text) => {
                let text = std::str::from_utf8(data)
                    .map_err(|e| LicenseError::InvalidLicenseFormat(e.to_string()))?;
                Self::from_base64(text)
            }
            None => Err(LicenseError::InvalidLicenseFormat(
                "Unknown activation request format".to_string(),
            )),
        }
    }

    /// Parse from binary format
    pub fn from_binary(data: &[u8]) -> Result<Self> {
        if data.len() < 9 {
            return Err(LicenseError::InvalidLicenseFormat(
                "Activation request too short".to_string(),
            ));
        }

        // Verify magic header
        if &data[0..4] != REQUEST_MAGIC {
            return Err(LicenseError::InvalidLicenseFormat(
                "Invalid activation request magic header".to_string(),
            ));
        }

        // Check version
        let version = data[4];
        if version > REQUEST_VERSION {
            return Err(LicenseError::InvalidLicenseFormat(format!(
                "Unsupported activation request version: {} (max supported: {})",
                version, REQUEST_VERSION
            )));
        }

        // Read payload length
        let len = u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;

        if len > MAX_SNEAKERNET_JSON_PAYLOAD {
            return Err(LicenseError::InvalidLicenseFormat(format!(
                "Activation request payload exceeds maximum of {} bytes",
                MAX_SNEAKERNET_JSON_PAYLOAD
            )));
        }

        if data.len() < 9 + len {
            return Err(LicenseError::InvalidLicenseFormat(
                "Activation request data truncated".to_string(),
            ));
        }

        // Deserialize the request
        let request: Self = serde_json::from_slice(&data[9..9 + len])
            .map_err(|e| LicenseError::InvalidLicenseFormat(e.to_string()))?;

        // Verify checksum if present
        if let Some(ref stored_checksum) = request.checksum {
            let computed = request.compute_checksum();
            if &computed != stored_checksum {
                return Err(LicenseError::InvalidLicenseFormat(
                    "Activation request checksum mismatch - data may be corrupted".to_string(),
                ));
            }
        }

        Ok(request)
    }

    /// Parse from base64 text format
    pub fn from_base64(text: &str) -> Result<Self> {
        let trimmed = text.trim();

        // Strip prefix/suffix if present
        let base64_content = if trimmed.starts_with(REQUEST_TEXT_PREFIX) {
            trimmed
                .strip_prefix(REQUEST_TEXT_PREFIX)
                .and_then(|s| s.strip_suffix(REQUEST_TEXT_SUFFIX))
                .map(|s| s.trim())
                .ok_or_else(|| {
                    LicenseError::InvalidLicenseFormat(
                        "Malformed activation request text format".to_string(),
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
        output.write_all(REQUEST_MAGIC)?;

        // Write version
        output.write_all(&[REQUEST_VERSION])?;

        // Serialize the request
        let encoded = serde_json::to_vec(self)
            .map_err(|e| LicenseError::SerializationError(e.to_string()))?;

        // Write length as u32 little-endian
        let len = encoded.len() as u32;
        output.write_all(&len.to_le_bytes())?;

        // Write the encoded request
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
            REQUEST_TEXT_PREFIX,
            wrapped.join("\n"),
            REQUEST_TEXT_SUFFIX
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

    /// Compute checksum of request content (excluding the checksum field itself)
    fn compute_checksum(&self) -> String {
        let mut hasher = Sha256::new();

        // Hash the key fields
        hasher.update(self.request_id.as_bytes());
        hasher.update(self.product_id.as_bytes());
        hasher.update(self.fingerprint.combined_hash.as_bytes());
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update([self.version]);

        for feature in &self.requested_features {
            hasher.update(feature.as_bytes());
        }

        for (key, value) in &self.metadata {
            hasher.update(key.as_bytes());
            hasher.update(value.as_bytes());
        }

        hex::encode(hasher.finalize())
    }

    /// Verify the request's integrity
    pub fn verify_integrity(&self) -> bool {
        match &self.checksum {
            Some(stored) => &self.compute_checksum() == stored,
            None => true, // No checksum to verify
        }
    }
}

/// Builder for creating activation requests
#[derive(Default)]
pub struct ActivationRequestBuilder {
    fingerprint: Option<HardwareFingerprint>,
    product_id: Option<String>,
    requested_features: Vec<String>,
    metadata: BTreeMap<String, String>,
}

impl ActivationRequestBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the hardware fingerprint
    pub fn fingerprint(mut self, fingerprint: HardwareFingerprint) -> Self {
        self.fingerprint = Some(fingerprint);
        self
    }

    /// Set the hardware fingerprint from the current machine
    pub fn fingerprint_current(mut self) -> Self {
        self.fingerprint = Some(HardwareFingerprint::generate());
        self
    }

    /// Set the product ID
    pub fn product_id(mut self, product_id: impl Into<String>) -> Self {
        self.product_id = Some(product_id.into());
        self
    }

    /// Add a requested feature
    pub fn feature(mut self, feature: impl Into<String>) -> Self {
        self.requested_features.push(feature.into());
        self
    }

    /// Add multiple requested features
    pub fn features(mut self, features: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.requested_features
            .extend(features.into_iter().map(|f| f.into()));
        self
    }

    /// Add metadata
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Add customer name metadata
    pub fn customer_name(self, name: impl Into<String>) -> Self {
        self.metadata("customer_name", name)
    }

    /// Add customer email metadata
    pub fn customer_email(self, email: impl Into<String>) -> Self {
        self.metadata("customer_email", email)
    }

    /// Add order/purchase reference metadata
    pub fn order_reference(self, reference: impl Into<String>) -> Self {
        self.metadata("order_reference", reference)
    }

    /// Build the activation request
    pub fn build(self) -> Result<ActivationRequest> {
        let fingerprint = self.fingerprint.unwrap_or_default();
        let product_id = self
            .product_id
            .ok_or_else(|| LicenseError::MissingField("product_id".into()))?;

        let mut request = ActivationRequest {
            request_id: Uuid::new_v4(),
            fingerprint,
            product_id,
            requested_features: self.requested_features,
            timestamp: Utc::now(),
            version: REQUEST_VERSION,
            metadata: self.metadata,
            checksum: None,
        };

        // Compute and set checksum
        request.checksum = Some(request.compute_checksum());

        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_fingerprint() -> HardwareFingerprint {
        HardwareFingerprint {
            mac_hashes: vec!["abc123".to_string()],
            disk_hashes: vec!["def456".to_string()],
            hostname_hash: Some("host789".to_string()),
            machine_guid_hash: Some("guid012".to_string()),
            combined_hash: "combined345".to_string(),
        }
    }

    #[test]
    fn test_request_builder() {
        let request = ActivationRequest::builder()
            .product_id("TEST-PRODUCT")
            .fingerprint(create_test_fingerprint())
            .feature("basic")
            .feature("premium")
            .customer_name("John Doe")
            .customer_email("john@example.com")
            .build()
            .unwrap();

        assert_eq!(request.product_id, "TEST-PRODUCT");
        assert_eq!(request.requested_features.len(), 2);
        assert!(request.requested_features.contains(&"basic".to_string()));
        assert!(request.requested_features.contains(&"premium".to_string()));
        assert_eq!(
            request.metadata.get("customer_name"),
            Some(&"John Doe".to_string())
        );
        assert!(request.checksum.is_some());
    }

    #[test]
    fn test_request_builder_missing_product_id() {
        let result = ActivationRequest::builder()
            .fingerprint(create_test_fingerprint())
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_binary_serialization_roundtrip() {
        let request = ActivationRequest::builder()
            .product_id("MY-APP")
            .fingerprint(create_test_fingerprint())
            .feature("pro")
            .build()
            .unwrap();

        let binary = request.to_binary().unwrap();

        // Verify magic header
        assert_eq!(&binary[0..4], REQUEST_MAGIC);
        assert_eq!(binary[4], REQUEST_VERSION);

        // Parse back
        let parsed = ActivationRequest::from_binary(&binary).unwrap();

        assert_eq!(parsed.request_id, request.request_id);
        assert_eq!(parsed.product_id, request.product_id);
        assert_eq!(parsed.requested_features, request.requested_features);
        assert_eq!(parsed.checksum, request.checksum);
    }

    #[test]
    fn test_base64_serialization_roundtrip() {
        let request = ActivationRequest::builder()
            .product_id("MY-APP")
            .fingerprint(create_test_fingerprint())
            .feature("enterprise")
            .customer_name("Acme Corp")
            .build()
            .unwrap();

        let text = request.to_base64().unwrap();

        // Verify format
        assert!(text.starts_with(REQUEST_TEXT_PREFIX));
        assert!(text.ends_with(REQUEST_TEXT_SUFFIX));

        // Parse back
        let parsed = ActivationRequest::from_base64(&text).unwrap();

        assert_eq!(parsed.request_id, request.request_id);
        assert_eq!(parsed.product_id, request.product_id);
        assert_eq!(parsed.requested_features, request.requested_features);
        assert_eq!(
            parsed.metadata.get("customer_name"),
            Some(&"Acme Corp".to_string())
        );
    }

    #[test]
    fn test_auto_detect_format() {
        let request = ActivationRequest::builder()
            .product_id("AUTO-DETECT")
            .fingerprint(create_test_fingerprint())
            .build()
            .unwrap();

        // Test binary
        let binary = request.to_binary().unwrap();
        let parsed_binary = ActivationRequest::from_bytes(&binary).unwrap();
        assert_eq!(parsed_binary.product_id, "AUTO-DETECT");

        // Test text
        let text = request.to_base64().unwrap();
        let parsed_text = ActivationRequest::from_bytes(text.as_bytes()).unwrap();
        assert_eq!(parsed_text.product_id, "AUTO-DETECT");
    }

    #[test]
    fn test_integrity_verification() {
        let request = ActivationRequest::builder()
            .product_id("INTEGRITY-TEST")
            .fingerprint(create_test_fingerprint())
            .build()
            .unwrap();

        assert!(request.verify_integrity());
    }

    #[test]
    fn test_invalid_magic_header() {
        let mut bad_data = vec![b'B', b'A', b'D', b'!'];
        bad_data.extend_from_slice(&[1, 0, 0, 0, 0]);

        let result = ActivationRequest::from_binary(&bad_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_data() {
        let request = ActivationRequest::builder()
            .product_id("TRUNCATE-TEST")
            .fingerprint(create_test_fingerprint())
            .build()
            .unwrap();

        let binary = request.to_binary().unwrap();

        // Truncate the data
        let truncated = &binary[0..20];

        let result = ActivationRequest::from_binary(truncated);
        assert!(result.is_err());
    }
}
