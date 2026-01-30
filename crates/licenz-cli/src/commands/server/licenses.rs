//! License-related server commands

use anyhow::Result;
use colored::Colorize;
use std::fs;
use std::path::Path;

use super::client::{block_on, create_client, download_license_bytes, types};
use super::config::require_credentials;

pub fn run_list(product: Option<&str>, _status: Option<&str>, json: bool) -> Result<()> {
    let creds = require_credentials()?;
    let client = create_client(&creds)?;

    // Call with optional filters (customer_id, limit, page, product_id)
    let response = block_on(client.list_licenses(
        None,           // customer_id
        Some(50),       // limit
        Some(1),        // page
        product,        // product_id
    ))?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response.data)?);
        return Ok(());
    }

    if response.data.is_empty() {
        println!("No licenses found");
        return Ok(());
    }

    println!("{}", "Licenses".bold().cyan());
    println!();

    for license in &response.data {
        let status_str = license.status.to_string();
        let status_colored = match license.status {
            types::LicenseResponseStatus::Active => status_str.green(),
            types::LicenseResponseStatus::Revoked => status_str.red(),
            types::LicenseResponseStatus::Expired => status_str.yellow(),
            types::LicenseResponseStatus::Suspended => status_str.yellow(),
        };

        println!(
            "  {} {} [{}]",
            "●".green(),
            license.serial.bold(),
            status_colored
        );
        println!("    Product ID: {}", license.product_id);
        if let Some(ref email) = license.customer_email {
            println!("    Customer: {}", email);
        }
        println!("    Valid until: {}", license.valid_until);
        if !license.features.is_empty() {
            println!("    Features: {}", license.features.join(", "));
        }
        if let Some(days) = license.days_remaining {
            println!("    Days remaining: {}", days);
        }
        println!("    ID: {}", license.id.dimmed());
        println!();
    }

    println!(
        "Total: {} licenses (page {} of {})",
        response.pagination.total,
        response.pagination.page,
        response.pagination.total_pages
    );
    Ok(())
}

pub fn run_create(
    product: &str,
    customer: Option<&str>,
    email: Option<&str>,
    features: Option<Vec<String>>,
    days: Option<i32>,
    max_seats: Option<i32>,
    json: bool,
) -> Result<()> {
    let creds = require_credentials()?;
    let client = create_client(&creds)?;

    // Build the request body
    let body = types::CreateLicenseRequest {
        product_id: product.to_string(),
        customer_id: customer.unwrap_or("cli-customer").to_string(),
        customer_email: email.map(|e| e.to_string()),
        features: features.unwrap_or_default(),
        valid_days: days.map(|d| d as i64).unwrap_or(365),
        max_seats: max_seats.map(|s| s as i64).unwrap_or(1),
        hardware_binding: None,
        metadata: Default::default(),
    };

    let response = block_on(client.create_license(&body))?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    let status_str = response.status.to_string();
    println!("{} License created!", "✓".green());
    println!();
    println!("  Serial:       {}", response.serial.bold());
    println!("  Product ID:   {}", response.product_id);
    println!("  Status:       {}", status_str.green());
    if let Some(ref email) = response.customer_email {
        println!("  Customer:     {}", email);
    }
    println!("  Valid until:  {}", response.valid_until);
    if !response.features.is_empty() {
        println!("  Features:     {}", response.features.join(", "));
    }
    if let Some(seats) = response.max_seats {
        println!("  Max seats:    {}", seats);
    }
    println!("  License ID:   {}", response.id.dimmed());
    println!();
    println!(
        "Download with: licenz server license download {}",
        response.id
    );

    Ok(())
}

pub fn run_download(id: &str, output: &Path) -> Result<()> {
    let creds = require_credentials()?;
    let client = create_client(&creds)?;

    let bytes = download_license_bytes(&client, id)?;

    fs::write(output, &bytes)?;

    println!("{} License downloaded to {}", "✓".green(), output.display());
    println!("  Size: {} bytes", bytes.len());

    Ok(())
}

pub fn run_revoke(id: &str) -> Result<()> {
    let creds = require_credentials()?;
    let client = create_client(&creds)?;

    block_on(client.revoke_license(id))?;

    println!("{} License revoked successfully", "✓".green());

    Ok(())
}

pub fn run_verify(license_path: &Path, _product: Option<&str>) -> Result<()> {
    let creds = require_credentials()?;
    let client = create_client(&creds)?;

    // Read and encode the license file
    let license_bytes = fs::read(license_path)?;
    let license_data = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &license_bytes,
    );

    let body = types::VerifyLicenseRequest {
        license_data,
        hardware: None,
        skip_hardware_check: false,
    };

    let response = block_on(client.verify_license(&body))?;

    if response.valid {
        println!("{} License is valid!", "✓".green());
        println!();
        println!("  Signature valid:   {}", if response.signature_valid { "yes".green() } else { "no".red() });
        println!("  Expiration valid:  {}", if response.expiration_valid { "yes".green() } else { "no".red() });
        println!("  Hardware valid:    {}", if response.hardware_valid { "yes".green() } else { "no".red() });

        if let Some(days) = response.days_remaining {
            println!("  Days remaining:    {}", days);
        }

        if let Some(ref license) = response.license {
            println!();
            println!("  Serial:     {}", license.serial.bold());
            println!("  Product:    {}", license.product_id);
            if let Some(ref customer) = license.customer_email {
                println!("  Customer:   {}", customer);
            }
            if !license.features.is_empty() {
                println!("  Features:   {}", license.features.join(", "));
            }
            println!("  Valid from: {}", license.valid_from);
            println!("  Valid until: {}", license.valid_until);
        }
    } else {
        println!("{} License is invalid!", "✗".red());

        if let Some(ref error) = response.error {
            println!();
            println!("Error: {}", error);
        }
    }

    Ok(())
}
