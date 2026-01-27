use anyhow::{Context, Result, bail};
use colored::Colorize;
use licenz_core::{KeyPair, KeySize};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;
use std::time::Duration;

pub fn run(size: u16, dir: &Path, force: bool) -> Result<()> {
    // Validate key size
    let key_size = match size {
        2048 => KeySize::Bits2048,
        3072 => KeySize::Bits3072,
        4096 => KeySize::Bits4096,
        _ => bail!("Invalid key size: {}. Valid sizes are: 2048, 3072, 4096", size),
    };

    // Check if keys already exist
    let private_path = dir.join("private.pem");
    let public_path = dir.join("public.pem");

    if !force && (private_path.exists() || public_path.exists()) {
        bail!(
            "Key files already exist in {:?}. Use --force to overwrite.",
            dir
        );
    }

    // Create output directory
    std::fs::create_dir_all(dir)
        .with_context(|| format!("Failed to create directory: {:?}", dir))?;

    // Show progress
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_message(format!("Generating {}-bit RSA key pair...", size));

    // Generate key pair
    let keypair = KeyPair::generate(key_size)
        .with_context(|| "Failed to generate key pair")?;

    // Save keys
    keypair
        .save_to_files(&private_path, &public_path)
        .with_context(|| "Failed to save key files")?;

    pb.finish_and_clear();

    println!("{}", "✓ Key pair generated successfully!".green().bold());
    println!();
    println!("  {} {}", "Private key:".dimmed(), private_path.display());
    println!("  {} {}", "Public key: ".dimmed(), public_path.display());
    println!();
    println!(
        "{}",
        "⚠ Keep the private key secure and never distribute it!".yellow()
    );
    println!(
        "{}",
        "  The public key can be embedded in client applications.".dimmed()
    );

    Ok(())
}
