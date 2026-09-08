//! Sneakernet (offline) license activation support
//!
//! This module provides file formats for offline "sneakernet" license activation,
//! where users can:
//!
//! 1. Generate a `.req` file on an air-gapped machine
//! 2. Transfer it to an internet-connected machine
//! 3. Get a `.resp` file from the licensing server
//! 4. Transfer the `.resp` back and install the license
//!
//! ## File Formats
//!
//! Both `.req` and `.resp` files support two formats:
//!
//! - **Binary format**: Compact, efficient for file transfer
//! - **Base64 text format**: Human-readable, suitable for email/copy-paste
//!
//! ## Security
//!
//! - Request/response records include an **integrity digest** (SHA-256 of canonical fields) to catch accidental corruption; it is not a keyed MAC.
//! - Responses embed the **cryptographically signed license** (`SignedLicense`); always verify that signature.
//! - Binary payloads enforce [`MAX_SNEAKERNET_JSON_PAYLOAD`] before JSON decode (DoS bound).
//! - Both formats include version fields for future evolution.
//!
//! ## Example Usage
//!
//! ### Client-side (air-gapped machine)
//!
//! ```rust,ignore
//! use licenz_core::sneakernet::{ActivationRequest, ActivationRequestBuilder};
//! use licenz_core::anti_tamper::HardwareFingerprint;
//!
//! // Generate activation request
//! let request = ActivationRequestBuilder::new()
//!     .product_id("MY-APP")
//!     .fingerprint(HardwareFingerprint::generate())
//!     .feature("pro")
//!     .feature("enterprise")
//!     .build()
//!     .unwrap();
//!
//! // Save as binary .req file
//! request.save_binary("activation.req".as_ref()).unwrap();
//!
//! // Or get as base64 text for email
//! let text = request.to_base64().unwrap();
//! ```
//!
//! ### Server-side (licensing server)
//!
//! ```rust,ignore
//! use licenz_core::sneakernet::{ActivationRequest, ActivationResponse};
//!
//! // Load the request
//! let request = ActivationRequest::load("activation.req".as_ref()).unwrap();
//!
//! // Validate and create license...
//! // let signed_license = create_license_for_request(&request);
//!
//! // Create response
//! let response = ActivationResponse::new(
//!     request.request_id,
//!     signed_license,
//!     chrono::Utc::now() + chrono::Duration::days(365),
//! );
//!
//! // Save as .resp file
//! response.save_binary("activation.resp".as_ref()).unwrap();
//! ```
//!
//! ### Client-side (installing the license)
//!
//! ```rust,ignore
//! use licenz_core::sneakernet::ActivationResponse;
//!
//! // Load response
//! let response = ActivationResponse::load("activation.resp".as_ref()).unwrap();
//!
//! // Extract and save the license
//! let license = response.extract_license().unwrap();
//! // Save license to appropriate location...
//! ```

mod request;
mod response;

pub use request::{ActivationRequest, ActivationRequestBuilder};
pub use response::ActivationResponse;

/// Magic header for activation request files (.req)
pub const REQUEST_MAGIC: &[u8; 4] = b"LREQ";

/// Magic header for activation response files (.resp)
pub const RESPONSE_MAGIC: &[u8; 4] = b"LRSP";

/// Current format version for request files
pub const REQUEST_VERSION: u8 = 1;

/// Current format version for response files
pub const RESPONSE_VERSION: u8 = 1;

/// Maximum JSON payload size (bytes) inside binary `.req` / `.resp` wrappers.
pub const MAX_SNEAKERNET_JSON_PAYLOAD: usize = 2 * 1024 * 1024;

/// Maximum complete binary frame (nine-byte header plus JSON).
pub const MAX_SNEAKERNET_BINARY_SIZE: usize = 9 + MAX_SNEAKERNET_JSON_PAYLOAD;
/// Maximum normalized Base64 size, including padding.
pub const MAX_SNEAKERNET_BASE64_SIZE: usize = MAX_SNEAKERNET_BINARY_SIZE.div_ceil(3) * 4;
/// Maximum text/file input: Base64 plus enough space for CRLF wrapping and markers.
/// Excess whitespace and trailing content count toward this limit.
pub const MAX_SNEAKERNET_INPUT_SIZE: usize =
    MAX_SNEAKERNET_BASE64_SIZE + MAX_SNEAKERNET_BASE64_SIZE.div_ceil(64) * 2 + 256;

fn check_input_size(size: usize, maximum: usize) -> crate::error::Result<()> {
    if size > maximum {
        return Err(crate::error::LicenseError::InvalidLicenseFormat(format!(
            "Activation input exceeds maximum of {maximum} bytes"
        )));
    }
    Ok(())
}

fn read_bounded(path: &std::path::Path) -> crate::error::Result<Vec<u8>> {
    use std::io::Read;
    // Bound the read itself: metadata checks alone race file growth and miss streams.
    let file = std::fs::File::open(path)?;
    check_input_size(
        file.metadata()?.len().try_into().unwrap_or(usize::MAX),
        MAX_SNEAKERNET_INPUT_SIZE,
    )?;
    let mut data = Vec::new();
    file.take((MAX_SNEAKERNET_INPUT_SIZE + 1) as u64)
        .read_to_end(&mut data)?;
    check_input_size(data.len(), MAX_SNEAKERNET_INPUT_SIZE)?;
    Ok(data)
}

fn decode_base64_bounded(content: &str) -> crate::error::Result<Vec<u8>> {
    use base64::Engine;
    check_input_size(content.len(), MAX_SNEAKERNET_INPUT_SIZE)?;
    // Count before collecting; both normalized and decoded allocations have fixed bounds.
    let count = content.chars().filter(|c| !c.is_whitespace()).count();
    check_input_size(count, MAX_SNEAKERNET_BASE64_SIZE)?;
    let clean: String = content.chars().filter(|c| !c.is_whitespace()).collect();
    let mut binary =
        vec![0; base64::decoded_len_estimate(clean.len()).min(MAX_SNEAKERNET_BINARY_SIZE)];
    let decoded_len = base64::engine::general_purpose::STANDARD
        .decode_slice(clean, &mut binary)
        .map_err(|e| {
            crate::error::LicenseError::InvalidLicenseFormat(format!(
                "Invalid or oversized base64: {e}"
            ))
        })?;
    binary.truncate(decoded_len);
    Ok(binary)
}

/// Base64 prefix for text-format request files
pub const REQUEST_TEXT_PREFIX: &str = "-----BEGIN LICENZ ACTIVATION REQUEST-----";
/// Base64 suffix for text-format request files
pub const REQUEST_TEXT_SUFFIX: &str = "-----END LICENZ ACTIVATION REQUEST-----";

/// Base64 prefix for text-format response files
pub const RESPONSE_TEXT_PREFIX: &str = "-----BEGIN LICENZ ACTIVATION RESPONSE-----";
/// Base64 suffix for text-format response files
pub const RESPONSE_TEXT_SUFFIX: &str = "-----END LICENZ ACTIVATION RESPONSE-----";

/// File format type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SneakernetFormat {
    /// Binary format (compact, for file transfer)
    Binary,
    /// Base64 text format (for email/copy-paste)
    Text,
}

/// Detect the format of a sneakernet file
pub fn detect_format(data: &[u8]) -> Option<SneakernetFormat> {
    if data.len() >= 4 && (&data[0..4] == REQUEST_MAGIC || &data[0..4] == RESPONSE_MAGIC) {
        return Some(SneakernetFormat::Binary);
    }

    // Check for text format
    if let Ok(text) = std::str::from_utf8(data) {
        let trimmed = text.trim();
        if trimmed.starts_with(REQUEST_TEXT_PREFIX) || trimmed.starts_with(RESPONSE_TEXT_PREFIX) {
            return Some(SneakernetFormat::Text);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_binary_format() {
        let mut data = Vec::new();
        data.extend_from_slice(REQUEST_MAGIC);
        data.push(REQUEST_VERSION);

        assert_eq!(detect_format(&data), Some(SneakernetFormat::Binary));
    }

    #[test]
    fn test_detect_text_format() {
        let text = format!(
            "{}\nSW1hZ2luZSBhIGxvbmcgYmFzZTY0IHN0cmluZyBoZXJl\n{}",
            REQUEST_TEXT_PREFIX, REQUEST_TEXT_SUFFIX
        );

        assert_eq!(detect_format(text.as_bytes()), Some(SneakernetFormat::Text));
    }

    #[test]
    fn test_detect_unknown_format() {
        let data = b"random garbage data";
        assert_eq!(detect_format(data), None);
    }
}
