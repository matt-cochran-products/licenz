//! License data structures and types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Hardware binding information for a license
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct HardwareBinding {
    /// Allowed MAC addresses (any match is valid)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mac_addresses: Vec<String>,

    /// Allowed disk/drive IDs (any match is valid)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disk_ids: Vec<String>,

    /// Allowed hostnames (any match is valid)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,

    /// Custom hardware identifiers (key-value pairs)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub custom: HashMap<String, Vec<String>>,
}

impl HardwareBinding {
    /// Create a new empty hardware binding
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a MAC address to the allowed list
    pub fn with_mac_address(mut self, mac: impl Into<String>) -> Self {
        self.mac_addresses.push(mac.into().to_uppercase());
        self
    }

    /// Add multiple MAC addresses
    pub fn with_mac_addresses(mut self, macs: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.mac_addresses.extend(macs.into_iter().map(|m| m.into().to_uppercase()));
        self
    }

    /// Add a disk ID to the allowed list
    pub fn with_disk_id(mut self, disk_id: impl Into<String>) -> Self {
        self.disk_ids.push(disk_id.into());
        self
    }

    /// Add a hostname to the allowed list
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostnames.push(hostname.into().to_lowercase());
        self
    }

    /// Add a custom hardware identifier
    pub fn with_custom(mut self, key: impl Into<String>, values: Vec<String>) -> Self {
        self.custom.insert(key.into(), values);
        self
    }

    /// Check if any hardware binding is set
    pub fn is_empty(&self) -> bool {
        self.mac_addresses.is_empty()
            && self.disk_ids.is_empty()
            && self.hostnames.is_empty()
            && self.custom.is_empty()
    }
}

/// The core license data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseData {
    /// Unique license identifier
    pub id: String,

    /// Serial number for tracking
    pub serial: String,

    /// Customer/organization identifier
    pub customer_id: String,

    /// Product identifier
    pub product_id: String,

    /// License version
    #[serde(default = "default_version")]
    pub version: u32,

    /// When the license becomes valid
    pub valid_from: DateTime<Utc>,

    /// When the license expires
    pub valid_until: DateTime<Utc>,

    /// List of enabled features
    #[serde(default)]
    pub features: Vec<String>,

    /// Hardware binding restrictions
    #[serde(default)]
    pub hardware_binding: HardwareBinding,

    /// Maximum number of seats/users (0 = unlimited)
    #[serde(default)]
    pub max_seats: u32,

    /// Additional metadata
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,

    /// License issue timestamp
    pub issued_at: DateTime<Utc>,
}

fn default_version() -> u32 {
    1
}

impl LicenseData {
    /// Create a new license data builder
    pub fn builder() -> LicenseDataBuilder {
        LicenseDataBuilder::new()
    }

    /// Check if a feature is enabled
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f.eq_ignore_ascii_case(feature))
    }

    /// Get remaining days until expiration
    pub fn days_remaining(&self) -> i64 {
        let now = Utc::now();
        (self.valid_until - now).num_days()
    }

    /// Check if the license is currently in its valid time window
    pub fn is_time_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.valid_from && now <= self.valid_until
    }
}

/// Builder for creating license data
#[derive(Default)]
pub struct LicenseDataBuilder {
    id: Option<String>,
    serial: Option<String>,
    customer_id: Option<String>,
    product_id: Option<String>,
    version: u32,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
    features: Vec<String>,
    hardware_binding: HardwareBinding,
    max_seats: u32,
    metadata: HashMap<String, String>,
}

impl LicenseDataBuilder {
    pub fn new() -> Self {
        Self {
            version: 1,
            ..Default::default()
        }
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn serial(mut self, serial: impl Into<String>) -> Self {
        self.serial = Some(serial.into());
        self
    }

    pub fn customer_id(mut self, customer_id: impl Into<String>) -> Self {
        self.customer_id = Some(customer_id.into());
        self
    }

    pub fn product_id(mut self, product_id: impl Into<String>) -> Self {
        self.product_id = Some(product_id.into());
        self
    }

    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    pub fn valid_from(mut self, valid_from: DateTime<Utc>) -> Self {
        self.valid_from = Some(valid_from);
        self
    }

    pub fn valid_until(mut self, valid_until: DateTime<Utc>) -> Self {
        self.valid_until = Some(valid_until);
        self
    }

    pub fn valid_days(mut self, days: i64) -> Self {
        let now = Utc::now();
        self.valid_from = Some(now);
        self.valid_until = Some(now + chrono::Duration::days(days));
        self
    }

    pub fn feature(mut self, feature: impl Into<String>) -> Self {
        self.features.push(feature.into());
        self
    }

    pub fn features(mut self, features: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.features.extend(features.into_iter().map(|f| f.into()));
        self
    }

    pub fn hardware_binding(mut self, binding: HardwareBinding) -> Self {
        self.hardware_binding = binding;
        self
    }

    pub fn max_seats(mut self, max_seats: u32) -> Self {
        self.max_seats = max_seats;
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Build the license data
    pub fn build(self) -> crate::Result<LicenseData> {
        use crate::error::LicenseError;

        let now = Utc::now();

        Ok(LicenseData {
            id: self.id.ok_or_else(|| LicenseError::MissingField("id".into()))?,
            serial: self.serial.ok_or_else(|| LicenseError::MissingField("serial".into()))?,
            customer_id: self.customer_id.ok_or_else(|| LicenseError::MissingField("customer_id".into()))?,
            product_id: self.product_id.ok_or_else(|| LicenseError::MissingField("product_id".into()))?,
            version: self.version,
            valid_from: self.valid_from.unwrap_or(now),
            valid_until: self.valid_until.unwrap_or(now + chrono::Duration::days(365)),
            features: self.features,
            hardware_binding: self.hardware_binding,
            max_seats: self.max_seats,
            metadata: self.metadata,
            issued_at: now,
        })
    }
}

/// A signed license containing the data and cryptographic signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLicense {
    /// The license data
    pub data: LicenseData,

    /// Digital signature (base64 encoded)
    pub signature: String,

    /// Signature algorithm used
    pub algorithm: String,
}

/// License file format marker
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseFormat {
    /// Binary format (v2+)
    Binary,
    /// JSON format (v1 legacy)
    Json,
}

/// Binary license file header
pub const BINARY_MAGIC: &[u8; 4] = b"FLIC";
pub const BINARY_VERSION: u8 = 1;
