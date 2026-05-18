//! Hardware detection for license binding
//!
//! This module provides functionality to detect hardware identifiers
//! for binding licenses to specific machines.
//!
//! ## Pluggable environment
//!
//! Use [`HardwareEnvironment`] to supply [`HardwareInfo`] for verification and attestation.
//! The default implementation calls [`detect_hardware`]. Integrators can provide a custom
//! implementation (for example TPM-derived material in the license `HardwareBinding` `custom` map) without
//! modifying this crate.

use crate::license::HardwareBinding;
use std::sync::Arc;

/// Supplies a snapshot of the current machine for license binding checks.
///
/// Implement this type in your application or a companion crate if the default
/// OS-visible probe ([`detect_hardware`]) is not sufficient.
pub trait HardwareEnvironment: Send + Sync {
    /// Current hardware identifiers as seen by the licensing layer.
    fn snapshot(&self) -> HardwareInfo;
}

/// Default probe: MAC addresses, disk IDs, hostname, machine ID via [`detect_hardware`].
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultHardwareEnvironment;

impl HardwareEnvironment for DefaultHardwareEnvironment {
    fn snapshot(&self) -> HardwareInfo {
        detect_hardware()
    }
}

/// Fixed snapshot (tests, diagnostics, or air-gapped override).
#[derive(Debug, Clone)]
pub struct FixedHardwareEnvironment(pub HardwareInfo);

impl HardwareEnvironment for FixedHardwareEnvironment {
    fn snapshot(&self) -> HardwareInfo {
        self.0.clone()
    }
}

/// Shared default implementation used by [`LicenseVerifier`](crate::verifier::LicenseVerifier) and [`WitnessConfig`](crate::witness::WitnessConfig).
pub fn default_hardware_environment() -> Arc<dyn HardwareEnvironment> {
    Arc::new(DefaultHardwareEnvironment)
}

/// Detected hardware information from the current machine
#[derive(Debug, Clone, Default)]
pub struct HardwareInfo {
    /// All detected MAC addresses
    pub mac_addresses: Vec<String>,

    /// Detected disk/volume serial numbers
    pub disk_ids: Vec<String>,

    /// System hostname
    pub hostname: Option<String>,

    /// Machine UUID (if available)
    pub machine_id: Option<String>,

    /// Custom hardware identifiers provided by the application
    ///
    /// Integrators can populate this map with arbitrary key-value pairs
    /// (e.g., TPM PCR measurements, dongle serial numbers) that will be
    /// matched against the corresponding keys in [`HardwareBinding::custom`].
    pub custom: std::collections::BTreeMap<String, String>,
}

impl HardwareInfo {
    /// Convert to a HardwareBinding (for creating hardware-bound licenses)
    pub fn to_binding(&self) -> HardwareBinding {
        let mut binding = HardwareBinding::new();

        if !self.mac_addresses.is_empty() {
            binding.mac_addresses = self.mac_addresses.clone();
        }

        if !self.disk_ids.is_empty() {
            binding.disk_ids = self.disk_ids.clone();
        }

        if let Some(ref hostname) = self.hostname {
            binding.hostnames.push(hostname.clone());
        }

        if let Some(ref machine_id) = self.machine_id {
            binding
                .custom
                .insert("machine_id".to_string(), vec![machine_id.clone()]);
        }

        for (key, value) in &self.custom {
            binding
                .custom
                .insert(key.clone(), vec![value.clone()]);
        }

        binding
    }
}

/// Detect hardware information from the current machine
///
/// When the `hardware-detect` feature is disabled, this returns empty/None for all fields.
pub fn detect_hardware() -> HardwareInfo {
    #[cfg(feature = "hardware-detect")]
    {
        HardwareInfo {
            mac_addresses: detect_mac_addresses(),
            hostname: detect_hostname(),
            disk_ids: detect_disk_ids(),
            machine_id: detect_machine_id(),
            custom: std::collections::BTreeMap::new(),
        }
    }
    #[cfg(not(feature = "hardware-detect"))]
    {
        HardwareInfo {
            mac_addresses: vec![],
            hostname: None,
            disk_ids: vec![],
            machine_id: None,
            custom: std::collections::BTreeMap::new(),
        }
    }
}

#[cfg(feature = "hardware-detect")]
/// Detect all MAC addresses on the system
fn detect_mac_addresses() -> Vec<String> {
    let mut macs = Vec::new();

    // Try to get MAC addresses using mac_address crate
    if let Ok(Some(mac)) = mac_address::get_mac_address() {
        macs.push(mac.to_string().to_uppercase());
    }

    // Also try to get all interfaces
    if let Ok(Some(mac)) = mac_address::mac_address_by_name("eth0") {
        let mac_str = mac.to_string().to_uppercase();
        if !macs.contains(&mac_str) {
            macs.push(mac_str);
        }
    }

    // Use sysinfo for additional network info
    use sysinfo::Networks;
    let networks = Networks::new_with_refreshed_list();

    for (interface_name, _data) in networks.iter() {
        // Try to get MAC for each interface
        if let Ok(Some(mac)) = mac_address::mac_address_by_name(interface_name) {
            let mac_str = mac.to_string().to_uppercase();
            if !macs.contains(&mac_str) && !mac_str.starts_with("00:00:00") {
                macs.push(mac_str);
            }
        }
    }

    macs
}

#[cfg(feature = "hardware-detect")]
/// Detect the system hostname
fn detect_hostname() -> Option<String> {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .map(|s| s.to_lowercase())
}

#[cfg(feature = "hardware-detect")]
/// Detect disk serial numbers
fn detect_disk_ids() -> Vec<String> {
    let mut disk_ids = Vec::new();

    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();

    for disk in disks.iter() {
        // Get the disk name/mount point as an identifier
        let name = disk.name().to_string_lossy().to_string();
        if !name.is_empty() && !disk_ids.contains(&name) {
            disk_ids.push(name);
        }
    }

    // On Linux, try to read disk serial from /sys
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/block") {
            for entry in entries.flatten() {
                let path = entry.path().join("device/serial");
                if let Ok(serial) = std::fs::read_to_string(&path) {
                    let serial = serial.trim().to_string();
                    if !serial.is_empty() && !disk_ids.contains(&serial) {
                        disk_ids.push(serial);
                    }
                }
            }
        }
    }

    disk_ids
}

#[cfg(feature = "hardware-detect")]
/// Detect machine ID (platform-specific)
fn detect_machine_id() -> Option<String> {
    // Linux: /etc/machine-id
    #[cfg(target_os = "linux")]
    {
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            return Some(id.trim().to_string());
        }
        if let Ok(id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
            return Some(id.trim().to_string());
        }
    }

    // macOS: Use IOPlatformSerialNumber
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("IOPlatformUUID") {
                    if let Some(start) = line.find('"') {
                        if let Some(end) = line.rfind('"') {
                            if start < end {
                                return Some(line[start + 1..end].to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Windows: Use wmic or registry
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("wmic")
            .args(["csproduct", "get", "UUID"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let uuid = line.trim();
                if !uuid.is_empty() && uuid != "UUID" {
                    return Some(uuid.to_string());
                }
            }
        }
    }

    None
}

/// Check if the current hardware matches the binding
pub fn verify_hardware_binding(
    binding: &HardwareBinding,
    current: &HardwareInfo,
) -> Result<(), HardwareBindingError> {
    // If no binding is set, always pass
    if binding.is_empty() {
        return Ok(());
    }

    // Check MAC addresses (any match is valid)
    if !binding.mac_addresses.is_empty() {
        let current_macs: Vec<String> = current
            .mac_addresses
            .iter()
            .map(|m| m.to_uppercase())
            .collect();

        let has_match = binding
            .mac_addresses
            .iter()
            .any(|bound| current_macs.contains(&bound.to_uppercase()));

        if !has_match {
            return Err(HardwareBindingError::MacAddressMismatch {
                expected: binding.mac_addresses.clone(),
                found: current.mac_addresses.clone(),
            });
        }
    }

    // Check hostnames (any match is valid)
    if !binding.hostnames.is_empty() {
        if let Some(ref current_hostname) = current.hostname {
            let has_match = binding
                .hostnames
                .iter()
                .any(|bound| bound.eq_ignore_ascii_case(current_hostname));

            if !has_match {
                return Err(HardwareBindingError::HostnameMismatch {
                    expected: binding.hostnames.clone(),
                    found: current_hostname.clone(),
                });
            }
        } else {
            return Err(HardwareBindingError::HostnameMismatch {
                expected: binding.hostnames.clone(),
                found: "<unknown>".to_string(),
            });
        }
    }

    // Check disk IDs (any match is valid)
    if !binding.disk_ids.is_empty() {
        let has_match = binding
            .disk_ids
            .iter()
            .any(|bound| current.disk_ids.contains(bound));

        if !has_match {
            return Err(HardwareBindingError::DiskIdMismatch {
                expected: binding.disk_ids.clone(),
                found: current.disk_ids.clone(),
            });
        }
    }

    // Check custom bindings
    for (key, expected_values) in &binding.custom {
        let current_value = if key == "machine_id" {
            current.machine_id.as_deref()
        } else {
            current.custom.get(key.as_str()).map(|s| s.as_str())
        };

        match current_value {
            Some(val) => {
                if !expected_values.iter().any(|e| e == val) {
                    return Err(HardwareBindingError::CustomMismatch {
                        key: key.clone(),
                        expected: expected_values.clone(),
                        found: val.to_string(),
                    });
                }
            }
            None => {
                return Err(HardwareBindingError::CustomMismatch {
                    key: key.clone(),
                    expected: expected_values.clone(),
                    found: "<not detected>".to_string(),
                });
            }
        }
    }

    Ok(())
}

/// Hardware binding verification errors
#[derive(Debug, Clone)]
pub enum HardwareBindingError {
    MacAddressMismatch {
        expected: Vec<String>,
        found: Vec<String>,
    },
    HostnameMismatch {
        expected: Vec<String>,
        found: String,
    },
    DiskIdMismatch {
        expected: Vec<String>,
        found: Vec<String>,
    },
    CustomMismatch {
        key: String,
        expected: Vec<String>,
        found: String,
    },
}

impl std::fmt::Display for HardwareBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MacAddressMismatch { expected, found } => {
                write!(
                    f,
                    "MAC address mismatch: expected one of {:?}, found {:?}",
                    expected, found
                )
            }
            Self::HostnameMismatch { expected, found } => {
                write!(
                    f,
                    "Hostname mismatch: expected one of {:?}, found {}",
                    expected, found
                )
            }
            Self::DiskIdMismatch { expected, found } => {
                write!(
                    f,
                    "Disk ID mismatch: expected one of {:?}, found {:?}",
                    expected, found
                )
            }
            Self::CustomMismatch {
                key,
                expected,
                found,
            } => {
                write!(
                    f,
                    "Custom binding '{}' mismatch: expected one of {:?}, found {}",
                    key, expected, found
                )
            }
        }
    }
}

impl std::error::Error for HardwareBindingError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_binding_always_passes() {
        let binding = HardwareBinding::new();
        let hardware = HardwareInfo::default();

        assert!(verify_hardware_binding(&binding, &hardware).is_ok());
    }

    #[test]
    fn test_mac_address_binding() {
        let binding = HardwareBinding::new().with_mac_address("AA:BB:CC:DD:EE:FF");

        let mut hardware = HardwareInfo {
            mac_addresses: vec!["AA:BB:CC:DD:EE:FF".to_string()],
            ..Default::default()
        };

        assert!(verify_hardware_binding(&binding, &hardware).is_ok());

        hardware.mac_addresses = vec!["11:22:33:44:55:66".to_string()];
        assert!(verify_hardware_binding(&binding, &hardware).is_err());
    }

    #[test]
    fn test_hostname_binding() {
        let binding = HardwareBinding::new().with_hostname("my-server");

        let mut hardware = HardwareInfo {
            hostname: Some("my-server".to_string()),
            ..Default::default()
        };

        assert!(verify_hardware_binding(&binding, &hardware).is_ok());

        hardware.hostname = Some("other-server".to_string());
        assert!(verify_hardware_binding(&binding, &hardware).is_err());
    }

    // ========================================================================
    // Fix #4: Custom binding keys must be checked (not silently ignored)
    // ========================================================================

    #[test]
    fn custom_key_matching_value_passes() {
        let binding =
            HardwareBinding::new().with_custom("tpm_pcr7", vec!["abc123".to_string()]);
        let mut hw = HardwareInfo::default();
        hw.custom
            .insert("tpm_pcr7".to_string(), "abc123".to_string());
        assert!(verify_hardware_binding(&binding, &hw).is_ok());
    }

    #[test]
    fn custom_key_mismatching_value_fails() {
        let binding =
            HardwareBinding::new().with_custom("tpm_pcr7", vec!["abc123".to_string()]);
        let mut hw = HardwareInfo::default();
        hw.custom
            .insert("tpm_pcr7".to_string(), "wrong".to_string());
        assert!(verify_hardware_binding(&binding, &hw).is_err());
    }

    #[test]
    fn custom_key_absent_from_hardware_fails() {
        let binding =
            HardwareBinding::new().with_custom("dongle_serial", vec!["D001".to_string()]);
        let hw = HardwareInfo::default();
        assert!(verify_hardware_binding(&binding, &hw).is_err());
    }

    #[test]
    fn custom_key_absent_returns_custom_mismatch_error() {
        let binding =
            HardwareBinding::new().with_custom("dongle_serial", vec!["D001".to_string()]);
        let hw = HardwareInfo::default();
        let err = verify_hardware_binding(&binding, &hw).unwrap_err();
        match err {
            HardwareBindingError::CustomMismatch { key, found, .. } => {
                assert_eq!(key, "dongle_serial");
                assert_eq!(found, "<not detected>");
            }
            other => panic!("expected CustomMismatch, got: {}", other),
        }
    }

    #[test]
    fn custom_key_any_of_multiple_values_passes() {
        let binding = HardwareBinding::new()
            .with_custom("region", vec!["us-east".to_string(), "eu-west".to_string()]);
        let mut hw = HardwareInfo::default();
        hw.custom
            .insert("region".to_string(), "eu-west".to_string());
        assert!(verify_hardware_binding(&binding, &hw).is_ok());
    }

    #[test]
    fn multiple_custom_keys_all_must_match() {
        let binding = HardwareBinding::new()
            .with_custom("tpm_pcr7", vec!["abc".to_string()])
            .with_custom("dongle", vec!["D1".to_string()]);
        let mut hw = HardwareInfo::default();
        hw.custom
            .insert("tpm_pcr7".to_string(), "abc".to_string());
        // dongle missing → should fail
        assert!(verify_hardware_binding(&binding, &hw).is_err());
    }

    #[test]
    fn multiple_custom_keys_all_present_passes() {
        let binding = HardwareBinding::new()
            .with_custom("tpm_pcr7", vec!["abc".to_string()])
            .with_custom("dongle", vec!["D1".to_string()]);
        let mut hw = HardwareInfo::default();
        hw.custom
            .insert("tpm_pcr7".to_string(), "abc".to_string());
        hw.custom
            .insert("dongle".to_string(), "D1".to_string());
        assert!(verify_hardware_binding(&binding, &hw).is_ok());
    }

    // ========================================================================
    // Fix #5: Missing machine_id must fail (not silently pass)
    // ========================================================================

    #[test]
    fn machine_id_binding_passes_when_present_and_matching() {
        let binding = HardwareBinding::new()
            .with_custom("machine_id", vec!["mid-123".to_string()]);
        let hw = HardwareInfo {
            machine_id: Some("mid-123".to_string()),
            ..Default::default()
        };
        assert!(verify_hardware_binding(&binding, &hw).is_ok());
    }

    #[test]
    fn machine_id_binding_fails_when_present_but_wrong() {
        let binding = HardwareBinding::new()
            .with_custom("machine_id", vec!["mid-123".to_string()]);
        let hw = HardwareInfo {
            machine_id: Some("mid-wrong".to_string()),
            ..Default::default()
        };
        assert!(verify_hardware_binding(&binding, &hw).is_err());
    }

    #[test]
    fn machine_id_binding_fails_when_absent() {
        let binding = HardwareBinding::new()
            .with_custom("machine_id", vec!["mid-123".to_string()]);
        let hw = HardwareInfo {
            machine_id: None,
            ..Default::default()
        };
        assert!(verify_hardware_binding(&binding, &hw).is_err());
    }

    #[test]
    fn machine_id_absent_returns_not_detected_in_error() {
        let binding = HardwareBinding::new()
            .with_custom("machine_id", vec!["mid-123".to_string()]);
        let hw = HardwareInfo {
            machine_id: None,
            ..Default::default()
        };
        let err = verify_hardware_binding(&binding, &hw).unwrap_err();
        match err {
            HardwareBindingError::CustomMismatch { key, found, .. } => {
                assert_eq!(key, "machine_id");
                assert_eq!(found, "<not detected>");
            }
            other => panic!("expected CustomMismatch, got: {}", other),
        }
    }

    // ========================================================================
    // HardwareInfo.custom field integration
    // ========================================================================

    #[test]
    fn hardware_info_custom_field_defaults_to_empty() {
        let hw = HardwareInfo::default();
        assert!(hw.custom.is_empty());
    }

    #[test]
    fn to_binding_includes_custom_fields() {
        let mut hw = HardwareInfo::default();
        hw.custom
            .insert("sensor_id".to_string(), "S42".to_string());
        let binding = hw.to_binding();
        assert_eq!(
            binding.custom.get("sensor_id").unwrap(),
            &vec!["S42".to_string()]
        );
    }

    // ========================================================================
    // Existing behavior preserved: disk_id binding
    // ========================================================================

    #[test]
    fn disk_id_binding_passes_when_matching() {
        let binding = HardwareBinding::new().with_disk_id("DISK-001");
        let hw = HardwareInfo {
            disk_ids: vec!["DISK-001".to_string()],
            ..Default::default()
        };
        assert!(verify_hardware_binding(&binding, &hw).is_ok());
    }

    #[test]
    fn disk_id_binding_fails_when_no_match() {
        let binding = HardwareBinding::new().with_disk_id("DISK-001");
        let hw = HardwareInfo {
            disk_ids: vec!["DISK-999".to_string()],
            ..Default::default()
        };
        assert!(verify_hardware_binding(&binding, &hw).is_err());
    }

    #[test]
    fn hostname_binding_is_case_insensitive() {
        let binding = HardwareBinding::new().with_hostname("My-Server");
        let hw = HardwareInfo {
            hostname: Some("MY-SERVER".to_string()),
            ..Default::default()
        };
        assert!(verify_hardware_binding(&binding, &hw).is_ok());
    }

    #[test]
    fn hostname_binding_fails_when_hostname_is_none() {
        let binding = HardwareBinding::new().with_hostname("my-server");
        let hw = HardwareInfo {
            hostname: None,
            ..Default::default()
        };
        assert!(verify_hardware_binding(&binding, &hw).is_err());
    }

    #[test]
    fn mac_address_binding_is_case_insensitive() {
        let binding = HardwareBinding::new().with_mac_address("aa:bb:cc:dd:ee:ff");
        let hw = HardwareInfo {
            mac_addresses: vec!["AA:BB:CC:DD:EE:FF".to_string()],
            ..Default::default()
        };
        assert!(verify_hardware_binding(&binding, &hw).is_ok());
    }
}
