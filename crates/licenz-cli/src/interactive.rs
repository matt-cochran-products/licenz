use anyhow::{Context, Result};
use colored::Colorize;
use dialoguer::{Confirm, Input, MultiSelect};
use licenz_core::{detect_hardware, HardwareBinding, LicenseData, LicenseGenerator};
use std::path::Path;
use uuid::Uuid;

pub fn run_interactive_generate(key_path: &Path, output_path: &Path, json_format: bool) -> Result<()> {
    println!();
    println!("{}", "Interactive License Generator".bold().cyan());
    println!("{}", "═".repeat(50));
    println!();

    // License ID
    let default_id = format!("LIC-{}", &Uuid::new_v4().to_string()[..8].to_uppercase());
    let id: String = Input::new()
        .with_prompt("License ID")
        .default(default_id)
        .interact_text()?;

    // Serial
    let default_serial = format!("SN-{}", &Uuid::new_v4().to_string()[..12].to_uppercase());
    let serial: String = Input::new()
        .with_prompt("Serial Number")
        .default(default_serial)
        .interact_text()?;

    // Customer ID
    let customer: String = Input::new()
        .with_prompt("Customer ID")
        .interact_text()?;

    // Product ID
    let product: String = Input::new()
        .with_prompt("Product ID")
        .interact_text()?;

    // Validity days
    let days: i64 = Input::new()
        .with_prompt("Validity (days)")
        .default(365i64)
        .interact_text()?;

    // Features
    let features_input: String = Input::new()
        .with_prompt("Features (comma-separated)")
        .default("basic".to_string())
        .interact_text()?;

    let features: Vec<String> = features_input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Max seats
    let max_seats: u32 = Input::new()
        .with_prompt("Max seats (0 = unlimited)")
        .default(0u32)
        .interact_text()?;

    // Hardware binding
    let use_hardware = Confirm::new()
        .with_prompt("Add hardware binding?")
        .default(false)
        .interact()?;

    let hardware_binding = if use_hardware {
        let auto_detect = Confirm::new()
            .with_prompt("Auto-detect current hardware?")
            .default(true)
            .interact()?;

        if auto_detect {
            let hw = detect_hardware();
            println!();
            println!("{}", "Detected hardware:".cyan());

            let mut binding = HardwareBinding::new();

            // Select MAC addresses
            if !hw.mac_addresses.is_empty() {
                let selected = MultiSelect::new()
                    .with_prompt("Select MAC addresses to bind")
                    .items(&hw.mac_addresses)
                    .interact()?;

                for idx in selected {
                    binding = binding.with_mac_address(&hw.mac_addresses[idx]);
                }
            }

            // Select hostname
            if let Some(ref hostname) = hw.hostname {
                if Confirm::new()
                    .with_prompt(format!("Bind to hostname '{}'?", hostname))
                    .default(false)
                    .interact()?
                {
                    binding = binding.with_hostname(hostname);
                }
            }

            binding
        } else {
            let mut binding = HardwareBinding::new();

            // Manual MAC addresses
            let macs: String = Input::new()
                .with_prompt("MAC addresses (comma-separated, or empty)")
                .default(String::new())
                .interact_text()?;

            for mac in macs.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                binding = binding.with_mac_address(mac);
            }

            // Manual hostnames
            let hostnames: String = Input::new()
                .with_prompt("Hostnames (comma-separated, or empty)")
                .default(String::new())
                .interact_text()?;

            for host in hostnames.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                binding = binding.with_hostname(host);
            }

            binding
        }
    } else {
        HardwareBinding::new()
    };

    println!();
    println!("{}", "Generating license...".dimmed());

    // Load generator
    let generator = LicenseGenerator::from_pem_file(key_path)
        .with_context(|| format!("Failed to load private key from {:?}", key_path))?;

    // Build license
    let license_data = LicenseData::builder()
        .id(&id)
        .serial(&serial)
        .customer_id(&customer)
        .product_id(&product)
        .valid_days(days)
        .features(features.clone())
        .hardware_binding(hardware_binding)
        .max_seats(max_seats)
        .build()
        .with_context(|| "Failed to build license data")?;

    // Generate and save
    let signed_license = generator
        .generate(license_data)
        .with_context(|| "Failed to sign license")?;

    if json_format {
        generator.save_json(&signed_license, output_path)?;
    } else {
        generator.save_binary(&signed_license, output_path)?;
    }

    println!();
    println!("{}", "✓ License generated successfully!".green().bold());
    println!();
    println!("  {} {}", "License ID:".dimmed(), id.cyan());
    println!("  {} {}", "Serial:    ".dimmed(), serial);
    println!("  {} {}", "Customer:  ".dimmed(), customer);
    println!("  {} {}", "Product:   ".dimmed(), product);
    println!("  {} {} days", "Valid for: ".dimmed(), days);
    println!("  {} {}", "Features:  ".dimmed(), features.join(", "));
    println!();
    println!("  {} {}", "Output:".dimmed(), output_path.display().to_string().green());
    println!();

    Ok(())
}
