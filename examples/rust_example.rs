//! Example: Using Licenz as a Rust library
//!
//! Add to your Cargo.toml:
//! ```toml
//! [dependencies]
//! licenz-core = { path = "../crates/licenz-core" }
//! ```

use licenz_core::{
    detect_hardware, HardwareBinding, KeyPair, KeySize, LicenseData, LicenseGenerator,
    LicenseVerifier,
};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Licenz Rust Library Example ===\n");

    // ================================================================
    // STEP 1: Generate RSA Key Pair (do this once, store securely)
    // ================================================================
    println!("1. Generating RSA-2048 key pair...");
    let keypair = KeyPair::generate(KeySize::Bits2048)?;

    // Save keys to files
    std::fs::create_dir_all("keys")?;
    keypair.save_to_files(Path::new("keys/private.pem"), Path::new("keys/public.pem"))?;
    println!("   ✓ Keys saved to keys/private.pem and keys/public.pem\n");

    // ================================================================
    // STEP 2: Create License Generator (Server-Side)
    // ================================================================
    println!("2. Creating license generator...");
    let generator = LicenseGenerator::new(keypair.private_key.clone());
    println!("   ✓ Generator ready\n");

    // ================================================================
    // STEP 3: Build License Data
    // ================================================================
    println!("3. Building license data...");

    // Detect current hardware for binding
    let hardware = detect_hardware();
    println!("   Detected hardware:");
    println!("     MAC addresses: {:?}", hardware.mac_addresses);
    println!("     Hostname: {:?}", hardware.hostname);
    println!("     Disk IDs: {:?}", hardware.disk_ids);

    // Create hardware binding (optional)
    let binding = HardwareBinding::new()
        .with_mac_addresses(hardware.mac_addresses.clone())
        .with_hostname(hardware.hostname.clone().unwrap_or_default());

    // Build the license
    let license_data = LicenseData::builder()
        .id("LIC-RUST-001")
        .serial("SN-RUST-12345")
        .customer_id("Rust Developer Inc")
        .product_id("MyRustApp")
        .valid_days(365)
        .feature("basic")
        .feature("premium")
        .feature("enterprise")
        .hardware_binding(binding)
        .max_seats(10)
        .metadata("environment", "production")
        .metadata("tier", "gold")
        .build()?;

    println!("   ✓ License data built\n");

    // ================================================================
    // STEP 4: Generate and Sign License
    // ================================================================
    println!("4. Signing license...");
    let signed_license = generator.generate(license_data)?;
    println!("   ✓ License signed with RSA-SHA256\n");

    // Save to binary file
    generator.save_binary(&signed_license, Path::new("license.lic"))?;
    println!("   ✓ Saved to license.lic (binary format)\n");

    // Also save JSON for debugging
    generator.save_json(&signed_license, Path::new("license.json"))?;
    println!("   ✓ Saved to license.json (debug format)\n");

    // ================================================================
    // STEP 5: Verify License (Client-Side)
    // ================================================================
    println!("5. Verifying license...");

    // Create verifier with public key
    let verifier = LicenseVerifier::new(keypair.public_key);

    // Load and validate
    let loaded_license = verifier.load_license(Path::new("license.lic"))?;

    // Perform detailed validation
    let result = verifier.validate_detailed(&loaded_license);

    println!("   Signature valid:   {}", if result.signature_valid { "✓" } else { "✗" });
    println!("   Expiration valid:  {}", if result.expiration_valid { "✓" } else { "✗" });
    println!("   Hardware valid:    {}", if result.hardware_valid { "✓" } else { "✗" });
    println!("   Days remaining:    {}", result.days_remaining);
    println!("   Overall valid:     {}\n", if result.is_valid { "✓ YES" } else { "✗ NO" });

    // ================================================================
    // STEP 6: Use License Data
    // ================================================================
    println!("6. License details:");
    println!("   ID:        {}", loaded_license.data.id);
    println!("   Serial:    {}", loaded_license.data.serial);
    println!("   Customer:  {}", loaded_license.data.customer_id);
    println!("   Product:   {}", loaded_license.data.product_id);
    println!("   Features:  {:?}", loaded_license.data.features);
    println!("   Max seats: {}", loaded_license.data.max_seats);
    println!("   Expires:   {}", loaded_license.data.valid_until);
    println!();

    // Check specific features
    if loaded_license.data.has_feature("premium") {
        println!("   🎉 Premium features enabled!");
    }
    if loaded_license.data.has_feature("enterprise") {
        println!("   🏢 Enterprise features enabled!");
    }

    println!("\n=== Example Complete ===");
    Ok(())
}
