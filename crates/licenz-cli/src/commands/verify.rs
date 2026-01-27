use anyhow::{Context, Result};
use colored::Colorize;
use licenz_core::{HardwareInfo, LicenseVerifier};
use std::path::Path;

pub fn run(license_path: &Path, key_path: &Path, skip_hardware: bool) -> Result<()> {
    // Load verifier
    let mut verifier = LicenseVerifier::from_pem_file(key_path)
        .with_context(|| format!("Failed to load public key from {:?}", key_path))?;

    // If skipping hardware, provide empty hardware info
    if skip_hardware {
        verifier = verifier.with_hardware_info(HardwareInfo::default());
    }

    // Load license
    let license = verifier
        .load_license(license_path)
        .with_context(|| format!("Failed to load license from {:?}", license_path))?;

    // Perform detailed validation
    let result = verifier.validate_detailed(&license);

    println!();
    println!("{}", "License Verification Results".bold().cyan());
    println!("{}", "═".repeat(50));
    println!();

    // Signature check
    print!("  {} Signature verification... ", "•".dimmed());
    if result.signature_valid {
        println!("{}", "✓ PASS".green().bold());
    } else {
        println!("{}", "✗ FAIL".red().bold());
    }

    // Expiration check
    print!("  {} Expiration check... ", "•".dimmed());
    if result.expiration_valid {
        println!(
            "{} ({} days remaining)",
            "✓ PASS".green().bold(),
            result.days_remaining
        );
    } else {
        println!("{}", "✗ FAIL".red().bold());
    }

    // Hardware check
    if !skip_hardware {
        print!("  {} Hardware binding... ", "•".dimmed());
        if result.hardware_valid {
            println!("{}", "✓ PASS".green().bold());
        } else {
            println!("{}", "✗ FAIL".red().bold());
        }
    } else {
        println!("  {} Hardware binding... {}", "•".dimmed(), "SKIPPED".yellow());
    }

    println!();

    // Final result
    if result.is_valid {
        println!("{}", "═".repeat(50));
        println!(
            "  {} {}",
            "Result:".bold(),
            "LICENSE VALID ✓".green().bold()
        );
        println!("{}", "═".repeat(50));

        // Show license details
        println!();
        println!("  {} {}", "License ID:".dimmed(), license.data.id.cyan());
        println!("  {} {}", "Customer:  ".dimmed(), license.data.customer_id);
        println!("  {} {}", "Product:   ".dimmed(), license.data.product_id);
        println!(
            "  {} {}",
            "Features:  ".dimmed(),
            license.data.features.join(", ").green()
        );
        println!();

        Ok(())
    } else {
        println!("{}", "═".repeat(50));
        println!(
            "  {} {}",
            "Result:".bold(),
            "LICENSE INVALID ✗".red().bold()
        );
        println!("{}", "═".repeat(50));

        if let Some(error) = &result.error {
            println!();
            println!("  {} {}", "Error:".red(), error);
            println!();
        }

        // Return error to set exit code
        anyhow::bail!("License validation failed")
    }
}
