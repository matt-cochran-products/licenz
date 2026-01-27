//! Licenz CLI
//!
//! A command-line tool for license generation, verification, and key management.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

mod commands;
mod interactive;
mod output;

use commands::{generate, info, keygen, verify};

/// Licenz - Powerful offline software license management
#[derive(Parser)]
#[command(name = "licenz")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate RSA key pairs for license signing
    Keygen {
        /// RSA key size (2048, 3072, or 4096)
        #[arg(short, long, default_value = "2048")]
        size: u16,

        /// Output directory for key files
        #[arg(short, long, default_value = "keys")]
        dir: PathBuf,

        /// Force overwrite existing keys
        #[arg(short, long)]
        force: bool,
    },

    /// Generate a new license
    #[command(alias = "gen")]
    Generate {
        /// License ID
        #[arg(short, long)]
        id: Option<String>,

        /// Customer ID
        #[arg(short, long)]
        customer: Option<String>,

        /// Product ID
        #[arg(short, long)]
        product: Option<String>,

        /// Serial number
        #[arg(short, long)]
        serial: Option<String>,

        /// Validity period in days
        #[arg(short, long, default_value = "365")]
        days: i64,

        /// Comma-separated list of features
        #[arg(short = 'F', long, value_delimiter = ',')]
        features: Option<Vec<String>>,

        /// Comma-separated list of MAC addresses for hardware binding
        #[arg(long, value_delimiter = ',')]
        macs: Option<Vec<String>>,

        /// Comma-separated list of disk IDs for hardware binding
        #[arg(long, value_delimiter = ',')]
        diskids: Option<Vec<String>>,

        /// Comma-separated list of hostnames for hardware binding
        #[arg(long, value_delimiter = ',')]
        hostnames: Option<Vec<String>>,

        /// Path to private key file
        #[arg(short, long, default_value = "keys/private.pem")]
        key: PathBuf,

        /// Output license file path
        #[arg(short, long, default_value = "license.lic")]
        output: PathBuf,

        /// Use JSON format instead of binary
        #[arg(long)]
        json: bool,

        /// Auto-detect current hardware for binding
        #[arg(long)]
        auto_hardware: bool,

        /// Interactive mode
        #[arg(short = 'I', long)]
        interactive: bool,

        /// Maximum number of seats (0 = unlimited)
        #[arg(long, default_value = "0")]
        max_seats: u32,
    },

    /// Display license information
    Info {
        /// Path to license file
        #[arg(short, long, default_value = "license.lic")]
        license: PathBuf,

        /// Path to public key file
        #[arg(short, long, default_value = "keys/public.pem")]
        key: PathBuf,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Verify a license
    Verify {
        /// Path to license file
        #[arg(short, long, default_value = "license.lic")]
        license: PathBuf,

        /// Path to public key file
        #[arg(short, long, default_value = "keys/public.pem")]
        key: PathBuf,

        /// Skip hardware binding check
        #[arg(long)]
        skip_hardware: bool,
    },

    /// Display detected hardware information
    Hardware,

    /// Show version information
    Version,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("licenz=debug")
            .init();
    }

    match cli.command {
        Commands::Keygen { size, dir, force } => {
            keygen::run(size, &dir, force)?;
        }

        Commands::Generate {
            id,
            customer,
            product,
            serial,
            days,
            features,
            macs,
            diskids,
            hostnames,
            key,
            output,
            json,
            auto_hardware,
            interactive,
            max_seats,
        } => {
            if interactive {
                interactive::run_interactive_generate(&key, &output, json)?;
            } else {
                generate::run(generate::GenerateArgs {
                    id,
                    customer,
                    product,
                    serial,
                    days,
                    features,
                    macs,
                    diskids,
                    hostnames,
                    key,
                    output,
                    json,
                    auto_hardware,
                    max_seats,
                })?;
            }
        }

        Commands::Info { license, key, json } => {
            info::run(&license, &key, json)?;
        }

        Commands::Verify {
            license,
            key,
            skip_hardware,
        } => {
            verify::run(&license, &key, skip_hardware)?;
        }

        Commands::Hardware => {
            commands::hardware::run()?;
        }

        Commands::Version => {
            println!(
                "{} v{}",
                "Licenz".bold().cyan(),
                licenz_core::VERSION
            );
            println!("A powerful offline software license management system");
        }
    }

    Ok(())
}
