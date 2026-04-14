//! JWS verification for signed online API responses.

use super::{CheckRevocationResponse, LicenseError, OnlineCheckConfig, Result, SyncResponse};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use std::time::Duration;

pub(super) fn verify_revocation_jws(
    compact_jws: &str,
    config: &OnlineCheckConfig,
    http: &reqwest::blocking::Client,
    timeout: Duration,
) -> Result<CheckRevocationResponse> {
    let header = decode_header(compact_jws)
        .map_err(|e| LicenseError::Validation(format!("Invalid JWS header: {}", e)))?;

    let validation = build_validation(config);

    let key = resolve_decoding_key(&header, config, http, timeout)?;
    let data = decode::<CheckRevocationResponse>(compact_jws, &key, &validation)
        .map_err(|e| LicenseError::Validation(format!("JWS verification failed: {}", e)))?;

    Ok(data.claims)
}

pub(super) fn verify_sync_jws(
    compact_jws: &str,
    config: &OnlineCheckConfig,
    http: &reqwest::blocking::Client,
    timeout: Duration,
) -> Result<SyncResponse> {
    let header = decode_header(compact_jws)
        .map_err(|e| LicenseError::Validation(format!("Invalid JWS header: {}", e)))?;

    let validation = build_validation(config);

    let key = resolve_decoding_key(&header, config, http, timeout)?;
    let data = decode::<SyncResponse>(compact_jws, &key, &validation)
        .map_err(|e| LicenseError::Validation(format!("JWS verification failed: {}", e)))?;

    Ok(data.claims)
}

/// Build JWT validation with security-critical defaults:
/// - `exp` is always validated (prevents indefinitely-valid JWS responses)
/// - `aud` is validated when `expected_audience` is configured
fn build_validation(config: &OnlineCheckConfig) -> Validation {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.algorithms = vec![Algorithm::RS256, Algorithm::PS256, Algorithm::EdDSA];

    if let Some(ref aud) = config.expected_audience {
        validation.set_audience(&[aud]);
    } else {
        validation.validate_aud = false;
    }

    validation
}

fn resolve_decoding_key(
    header: &jsonwebtoken::Header,
    config: &OnlineCheckConfig,
    http: &reqwest::blocking::Client,
    timeout: Duration,
) -> Result<DecodingKey> {
    if let Some(ref pem) = config.jws_verifying_key_pem {
        return decoding_key_from_pem(pem.trim());
    }

    let jwks_url = config
        .jwks_url
        .as_ref()
        .ok_or_else(|| LicenseError::Validation("JWKS URL not configured".into()))?;

    let kid = header.kid.as_ref().ok_or_else(|| {
        LicenseError::Validation("JWS header missing kid (required when using JWKS)".into())
    })?;

    let jwks: JwkSet = http
        .get(jwks_url)
        .timeout(timeout)
        .send()
        .map_err(|e| LicenseError::Validation(format!("JWKS request failed: {}", e)))?
        .error_for_status()
        .map_err(|e| LicenseError::Validation(format!("JWKS HTTP error: {}", e)))?
        .json()
        .map_err(|e| LicenseError::Validation(format!("Invalid JWKS JSON: {}", e)))?;

    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(kid.as_str()))
        .ok_or_else(|| LicenseError::Validation(format!("No JWK for kid={}", kid)))?;

    DecodingKey::from_jwk(jwk)
        .map_err(|e| LicenseError::Validation(format!("Unsupported JWK / key material: {}", e)))
}

fn decoding_key_from_pem(pem: &str) -> Result<DecodingKey> {
    DecodingKey::from_rsa_pem(pem.as_bytes())
        .or_else(|_| DecodingKey::from_ed_pem(pem.as_bytes()))
        .map_err(|e| LicenseError::Validation(format!("Invalid PEM public key: {}", e)))
}
