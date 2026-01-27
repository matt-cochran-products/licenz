use anyhow::{Context, Result, bail};
use colored::Colorize;
use licenz_core::{
    detect_hardware, HardwareBinding, LicenseData, LicenseGenerator,
};
use std::path::PathBuf;
use uuid::Uuid;

pub struct GenerateArgs {
    pub id: Option<String>,
    pub customer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    pub days: i64,
    pub features: Option<Vec<String>>,
    pub macs: Option<Vec<String>>,
    pub diskids: Option<Vec<String>>,
    pub hostnames: Option<Vec<String>>,
    pub key: PathBuf,
    pub output: PathBuf,
    pub json: bool,
    pub auto_hardware: bool,
    pub max_seats: u32,
}

pub fn run(args: GenerateArgs) -> Result<()> {
    // Validate required fields
    let id = args.id.unwrap_or_else(|| format!("LIC-{}", Uuid::new_v4().to_string()[..8].to_uppercase()));
    let customer = args.customer.ok_or_else(|| anyhow::anyhow!("Customer ID is required (use --customer)"))?;
    let product = args.product.ok_or_else(|| anyhow::anyhow!("Product ID is required (use --product)"))?;
    let serial = args.serial.unwrap_or_else(|| format!("SN-{}", Uuid::new_v4().to_string()[..12].to_uppercase()));

    // Load private key
    let generator = LicenseGenerator::from_pem_file(&args.key)
        .with_context(|| format!("Failed to load private key from {:?}", args.key))?;

    // Build hardware binding
    let mut hardware_binding = HardwareBinding::new();

    if args.auto_hardware {
        let hw = detect_hardware();
        hardware_binding = hw.to_binding();
        println!("{}", "Auto-detected hardware:".cyan());
        if !hardware_binding.mac_addresses.is_empty() {
            println!("  MAC addresses: {}", hardware_binding.mac_addresses.join(", "));
        }
        if !hardware_binding.hostnames.is_empty() {
            println!("  Hostnames: {}", hardware_binding.hostnames.join(", "));
        }
        if !hardware_binding.disk_ids.is_empty() {
            println!("  Disk IDs: {}", hardware_binding.disk_ids.join(", "));
        }
        println!();
    } else {
        if let Some(macs) = args.macs {
            for mac in macs {
                hardware_binding = hardware_binding.with_mac_address(mac);
            }
        }
        if let Some(diskids) = args.diskids {
            for disk in diskids {
                hardware_binding = hardware_binding.with_disk_id(disk);
            }
        }
        if let Some(hostnames) = args.hostnames {
            for host in hostnames {
                hardware_binding = hardware_binding.with_hostname(host);
            }
        }
    }

    // Build license data
    let mut builder = LicenseData::builder()
        .id(&id)
        .serial(&serial)
        .customer_id(&customer)
        .product_id(&product)
        .valid_days(args.days)
        .hardware_binding(hardware_binding)
        .max_seats(args.max_seats);

    if let Some(features) = args.features {
        builder = builder.features(features);
    } else {
        builder = builder.feature("basic");
    }

    let license_data = builder.build()
        .with_context(|| "Failed to build license data")?;

    // Generate signed license
    let signed_license = generator.generate(license_data)
        .with_context(|| "Failed to sign license")?;

    // Save license
    if args.json {
        generator.save_json(&signed_license, &args.output)
            .with_context(|| format!("Failed to save license to {:?}", args.output))?;
    } else {
        generator.save_binary(&signed_license, &args.output)
            .with_context(|| format!("Failed to save license to {:?}", args.output))?;
    }

    println!("{}", "✓ License generated successfully!".green().bold());
    println!();
    println!("  {} {}", "License ID:".dimmed(), id.cyan());
    println!("  {} {}", "Serial:    ".dimmed(), serial);
    println!("  {} {}", "Customer:  ".dimmed(), customer);
    println!("  {} {}", "Product:   ".dimmed(), product);
    println!("  {} {} days", "Valid for: ".dimmed(), args.days);
    println!("  {} {}", "Features:  ".dimmed(), signed_license.data.features.join(", "));
    println!("  {} {}", "Format:    ".dimmed(), if args.json { "JSON" } else { "Binary" });
    println!();
    println!("  {} {}", "Output:".dimmed(), args.output.display().to_string().green());

    Ok(())
}
