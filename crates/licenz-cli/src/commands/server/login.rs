//! Login, logout, and status commands

use anyhow::Result;
use colored::Colorize;
use dialoguer::{Input, Password};

use super::client::{block_on, create_client, validate_server_url};
use super::config::{delete_credentials, load_credentials, save_credentials, Credentials};

const DEFAULT_SERVER_URL: &str = "https://api.licenz.io";

/// Run the login flow
///
/// # Arguments
/// * `server` - Optional server URL (defaults to https://api.licenz.io)
/// * `api_key` - Optional API key (prompts if not provided)
/// * `insecure_storage` - If true, allows storing credentials in plaintext file
pub fn run_login(
    server: Option<String>,
    api_key: Option<String>,
    insecure_storage: bool,
) -> Result<()> {
    println!("{}", "Licenz Server Login".bold().cyan());
    println!();

    // Get server URL
    let server_url = if let Some(s) = server {
        s
    } else {
        Input::new()
            .with_prompt("Server URL")
            .default(DEFAULT_SERVER_URL.to_string())
            .interact_text()?
    };

    // Validate server URL security (HTTPS required)
    validate_server_url(&server_url)?;

    // Get API key
    let api_key = if let Some(k) = api_key {
        k
    } else {
        Password::new()
            .with_prompt("API Key")
            .interact()?
    };

    // Validate the API key by making a test request
    let credentials = Credentials {
        api_key: api_key.clone(),
        server_url: server_url.clone(),
    };

    print!("Verifying credentials... ");

    let client = create_client(&credentials)?;
    match block_on(client.list_organizations()) {
        Ok(response) => {
            println!("{}", "OK".green());
            println!();

            // Save credentials (with security check)
            save_credentials(&credentials, insecure_storage)?;

            println!("{} Logged in successfully!", "✓".green());

            // Show storage location info
            #[cfg(feature = "keyring")]
            {
                if !insecure_storage {
                    println!("  API key stored securely in OS keyring");
                } else {
                    println!(
                        "  {} API key stored in plaintext file (--insecure-storage used)",
                        "⚠".yellow()
                    );
                }
            }
            #[cfg(not(feature = "keyring"))]
            {
                println!(
                    "  {} API key stored in plaintext file",
                    "⚠".yellow()
                );
                println!("  Consider rebuilding with --features keyring for secure storage");
            }

            println!();

            if !response.organizations.is_empty() {
                println!("Organizations:");
                for org in &response.organizations {
                    println!("  {} ({})", org.name.bold(), org.slug.dimmed());
                }
            }

            Ok(())
        }
        Err(e) => {
            println!("{}", "FAILED".red());
            anyhow::bail!("Authentication failed: {}", e);
        }
    }
}

pub fn run_logout() -> Result<()> {
    if load_credentials()?.is_some() {
        delete_credentials()?;
        println!("{} Logged out successfully", "✓".green());
    } else {
        println!("Not currently logged in");
    }
    Ok(())
}

pub fn run_status() -> Result<()> {
    match load_credentials()? {
        Some(creds) => {
            println!("{}", "Authentication Status".bold().cyan());
            println!();
            println!("  {} Logged in", "●".green());
            println!("  Server: {}", creds.server_url);
            println!("  API Key: {}...", &creds.api_key[..12.min(creds.api_key.len())]);
            println!();

            // Try to fetch org info
            let client = create_client(&creds)?;
            match block_on(client.list_organizations()) {
                Ok(response) => {
                    if !response.organizations.is_empty() {
                        println!("Organizations:");
                        for org in &response.organizations {
                            println!("  - {} ({})", org.name.bold(), org.slug.dimmed());
                        }
                    }
                }
                Err(e) => {
                    println!("  {} Could not fetch organization info: {}", "⚠".yellow(), e);
                }
            }
        }
        None => {
            println!("{}", "Authentication Status".bold().cyan());
            println!();
            println!("  {} Not logged in", "●".dimmed());
            println!();
            println!("Run 'licenz server login' to authenticate");
        }
    }
    Ok(())
}
