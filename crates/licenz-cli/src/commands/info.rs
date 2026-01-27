use anyhow::{Context, Result};
use chrono::Utc;
use colored::Colorize;
use licenz_core::{detect_license_format, LicenseFormat, LicenseVerifier};
use serde_json::json;
use std::path::Path;

pub fn run(license_path: &Path, key_path: &Path, json_output: bool) -> Result<()> {
    // Load verifier
    let verifier = LicenseVerifier::from_pem_file(key_path)
        .with_context(|| format!("Failed to load public key from {:?}", key_path))?;

    // Load license
    let license = verifier.load_license(license_path)
        .with_context(|| format!("Failed to load license from {:?}", license_path))?;

    // Verify signature
    let signature_valid = verifier.verify_signature(&license).is_ok();

    // Check expiration
    let now = Utc::now();
    let expired = now > license.data.valid_until;
    let not_yet_valid = now < license.data.valid_from;
    let days_remaining = license.data.days_remaining();

    // Detect format
    let license_bytes = std::fs::read(license_path)?;
    let format = detect_license_format(&license_bytes);

    if json_output {
        let output = json!({
            "license": {
                "id": license.data.id,
                "serial": license.data.serial,
                "customer_id": license.data.customer_id,
                "product_id": license.data.product_id,
                "version": license.data.version,
                "valid_from": license.data.valid_from.to_rfc3339(),
                "valid_until": license.data.valid_until.to_rfc3339(),
                "issued_at": license.data.issued_at.to_rfc3339(),
                "features": license.data.features,
                "max_seats": license.data.max_seats,
                "hardware_binding": {
                    "mac_addresses": license.data.hardware_binding.mac_addresses,
                    "hostnames": license.data.hardware_binding.hostnames,
                    "disk_ids": license.data.hardware_binding.disk_ids,
                },
                "metadata": license.data.metadata,
            },
            "validation": {
                "signature_valid": signature_valid,
                "expired": expired,
                "not_yet_valid": not_yet_valid,
                "days_remaining": days_remaining,
            },
            "format": match format {
                LicenseFormat::Binary => "binary",
                LicenseFormat::Json => "json",
            },
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", "License Information".bold().cyan());
        println!("{}", "═".repeat(50));
        println!();

        // Basic info
        println!("  {} {}", "License ID:".dimmed(), license.data.id.cyan());
        println!("  {} {}", "Serial:    ".dimmed(), license.data.serial);
        println!("  {} {}", "Customer:  ".dimmed(), license.data.customer_id);
        println!("  {} {}", "Product:   ".dimmed(), license.data.product_id);
        println!("  {} {}", "Version:   ".dimmed(), license.data.version);
        println!();

        // Validity
        println!("{}", "Validity".bold());
        println!(
            "  {} {}",
            "Valid from: ".dimmed(),
            license.data.valid_from.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!(
            "  {} {}",
            "Valid until:".dimmed(),
            license.data.valid_until.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!(
            "  {} {}",
            "Issued at:  ".dimmed(),
            license.data.issued_at.format("%Y-%m-%d %H:%M:%S UTC")
        );

        // Status
        if expired {
            println!("  {} {}", "Status:".dimmed(), "EXPIRED".red().bold());
        } else if not_yet_valid {
            println!("  {} {}", "Status:".dimmed(), "NOT YET VALID".yellow().bold());
        } else {
            println!(
                "  {} {} ({} days remaining)",
                "Status:".dimmed(),
                "VALID".green().bold(),
                days_remaining
            );
        }
        println!();

        // Features
        println!("{}", "Features".bold());
        if license.data.features.is_empty() {
            println!("  {}", "(none)".dimmed());
        } else {
            for feature in &license.data.features {
                println!("  • {}", feature.green());
            }
        }
        println!();

        // Hardware binding
        println!("{}", "Hardware Binding".bold());
        if license.data.hardware_binding.is_empty() {
            println!("  {}", "(no hardware binding)".dimmed());
        } else {
            if !license.data.hardware_binding.mac_addresses.is_empty() {
                println!(
                    "  {} {}",
                    "MAC Addresses:".dimmed(),
                    license.data.hardware_binding.mac_addresses.join(", ")
                );
            }
            if !license.data.hardware_binding.hostnames.is_empty() {
                println!(
                    "  {} {}",
                    "Hostnames:    ".dimmed(),
                    license.data.hardware_binding.hostnames.join(", ")
                );
            }
            if !license.data.hardware_binding.disk_ids.is_empty() {
                println!(
                    "  {} {}",
                    "Disk IDs:     ".dimmed(),
                    license.data.hardware_binding.disk_ids.join(", ")
                );
            }
        }
        println!();

        // Seats
        if license.data.max_seats > 0 {
            println!("{}", "Licensing".bold());
            println!("  {} {}", "Max seats:".dimmed(), license.data.max_seats);
            println!();
        }

        // Verification status
        println!("{}", "Verification".bold());
        println!(
            "  {} {}",
            "Signature:".dimmed(),
            if signature_valid {
                "✓ Valid".green()
            } else {
                "✗ Invalid".red()
            }
        );
        println!(
            "  {} {}",
            "Format:   ".dimmed(),
            match format {
                LicenseFormat::Binary => "Binary (v2)",
                LicenseFormat::Json => "JSON (legacy)",
            }
        );
        println!();

        // Metadata
        if !license.data.metadata.is_empty() {
            println!("{}", "Metadata".bold());
            for (key, value) in &license.data.metadata {
                println!("  {} {}", format!("{}:", key).dimmed(), value);
            }
        }
    }

    Ok(())
}
