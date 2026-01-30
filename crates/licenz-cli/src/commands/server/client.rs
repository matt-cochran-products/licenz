//! Client wrapper for the generated Licenz API client
//!
//! This module provides helpers to create authenticated clients from stored credentials.
//! Implements HTTPS-only enforcement and TLS 1.2+ minimum.

use anyhow::{Context, Result};
use futures::StreamExt;
use url::Url;

use super::config::Credentials;

// Re-export the generated client types for use in other modules
pub use licenz_api_client::types;
pub use licenz_api_client::Client;
pub use licenz_api_client::ResponseValue;

/// Validate server URL for security requirements.
///
/// Enforces:
/// - HTTPS-only (no HTTP)
/// - Valid URL format
///
/// This is a Poka-Yoke: prevents accidental insecure connections.
pub fn validate_server_url(url: &str) -> Result<Url> {
    let parsed = Url::parse(url).context("Invalid server URL format")?;

    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" => {
            // Allow localhost for development
            if let Some(host) = parsed.host_str() {
                if host == "localhost" || host == "127.0.0.1" || host == "::1" {
                    tracing::warn!(
                        "Using insecure HTTP connection to localhost. \
                         This is only acceptable for local development."
                    );
                    return Ok(parsed);
                }
            }
            Err(anyhow::anyhow!(
                "HTTPS required for security. Got: {}\n\
                 Hint: Use https:// URL (e.g., https://api.licenz.io)",
                url
            ))
        }
        scheme => Err(anyhow::anyhow!(
            "Invalid URL scheme '{}'. Only HTTPS is supported.",
            scheme
        )),
    }
}

/// Create an authenticated API client from credentials.
///
/// Security features:
/// - HTTPS-only (enforced by validate_server_url)
/// - TLS 1.2+ minimum (via rustls)
/// - 30-second timeout
pub fn create_client(creds: &Credentials) -> Result<Client> {
    // Validate URL security before creating client
    validate_server_url(&creds.server_url)?;

    let reqwest_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        // Use rustls for TLS (configured via Cargo features)
        // rustls enforces TLS 1.2+ by default
        .use_rustls_tls()
        // Disable HTTP/2 to avoid potential ALPN issues with some servers
        .http1_only()
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", creds.api_key)
                    .parse()
                    .context("Invalid API key format")?,
            );
            // Add Accept header for JSON responses
            headers.insert(
                reqwest::header::ACCEPT,
                "application/json".parse().unwrap(),
            );
            headers
        })
        .build()
        .context("Failed to create HTTP client")?;

    Ok(Client::new_with_client(&creds.server_url, reqwest_client))
}

/// Run an async operation in a blocking context
///
/// The generated client is async, but the CLI needs synchronous execution.
/// This helper creates a tokio runtime and blocks on the provided future.
pub fn block_on<F, T, E>(future: F) -> Result<T>
where
    F: std::future::Future<Output = Result<ResponseValue<T>, licenz_api_client::Error<E>>>,
    E: std::fmt::Debug,
{
    let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
    rt.block_on(future)
        .map(|rv| rv.into_inner())
        .map_err(|e| anyhow::anyhow!("API error: {:?}", e))
}

/// Download a license file and return the bytes
///
/// This is a special case because download_license returns a ByteStream
/// that needs to be consumed asynchronously.
pub fn download_license_bytes(client: &Client, license_id: &str) -> Result<Vec<u8>> {
    let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
    rt.block_on(async {
        let response = client
            .download_license(license_id)
            .await
            .map_err(|e| anyhow::anyhow!("API error: {:?}", e))?;

        // Get the ByteStream and collect all bytes
        let stream = response.into_inner();
        let mut inner_stream = stream.into_inner();

        // Collect all chunks from the stream
        let mut bytes = Vec::new();
        while let Some(chunk_result) = inner_stream.next().await {
            let chunk = chunk_result.map_err(|e| anyhow::anyhow!("Failed to read chunk: {}", e))?;
            bytes.extend_from_slice(&chunk);
        }

        Ok(bytes)
    })
}
