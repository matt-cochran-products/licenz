//! Server commands for interacting with the Licenz SaaS API
//!
//! These commands require the `server` feature to be enabled.

mod client;
mod config;
mod licenses;
mod login;
mod products;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum ServerCommands {
    /// Login to the Licenz SaaS
    Login {
        /// Server URL (default: https://api.licenz.io)
        /// Must be HTTPS (HTTP only allowed for localhost)
        #[arg(long)]
        server: Option<String>,

        /// API key (if not provided, will prompt)
        #[arg(long)]
        api_key: Option<String>,

        /// Store credentials in plaintext file instead of OS keyring (not recommended)
        /// Use this only if keyring is unavailable on your system
        #[arg(long)]
        insecure_storage: bool,
    },

    /// Logout and remove stored credentials
    Logout,

    /// Show current authentication status
    Status,

    /// List products
    Products {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Product subcommands
    #[command(subcommand)]
    Product(ProductCommands),

    /// License subcommands
    #[command(subcommand)]
    License(LicenseCommands),
}

#[derive(Subcommand)]
pub enum ProductCommands {
    /// Show product details
    Show {
        /// Product ID
        id: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Get product's public key
    PublicKey {
        /// Product ID
        id: String,

        /// Output file (prints to stdout if not specified)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum LicenseCommands {
    /// List licenses
    List {
        /// Filter by product ID
        #[arg(long)]
        product: Option<String>,

        /// Filter by status (active, revoked, expired)
        #[arg(long)]
        status: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Create a new license
    Create {
        /// Product ID
        #[arg(long)]
        product: String,

        /// Customer ID
        #[arg(long)]
        customer: Option<String>,

        /// Customer email
        #[arg(long)]
        email: Option<String>,

        /// Comma-separated features
        #[arg(long, value_delimiter = ',')]
        features: Option<Vec<String>>,

        /// Validity in days
        #[arg(long)]
        days: Option<i32>,

        /// Maximum seats
        #[arg(long)]
        max_seats: Option<i32>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Download a license file
    Download {
        /// License ID
        id: String,

        /// Output file path
        #[arg(short, long, default_value = "license.lic")]
        output: std::path::PathBuf,
    },

    /// Revoke a license
    Revoke {
        /// License ID
        id: String,
    },

    /// Verify a license against the server
    Verify {
        /// Path to license file
        #[arg(short, long)]
        license: std::path::PathBuf,

        /// Product ID (optional, uses product from license if not specified)
        #[arg(long)]
        product: Option<String>,
    },
}

pub fn run(cmd: ServerCommands) -> anyhow::Result<()> {
    match cmd {
        ServerCommands::Login {
            server,
            api_key,
            insecure_storage,
        } => login::run_login(server, api_key, insecure_storage),
        ServerCommands::Logout => login::run_logout(),
        ServerCommands::Status => login::run_status(),
        ServerCommands::Products { json } => products::run_list(json),
        ServerCommands::Product(cmd) => match cmd {
            ProductCommands::Show { id, json } => products::run_show(&id, json),
            ProductCommands::PublicKey { id, output } => {
                products::run_public_key(&id, output.as_deref())
            }
        },
        ServerCommands::License(cmd) => match cmd {
            LicenseCommands::List {
                product,
                status,
                json,
            } => licenses::run_list(product.as_deref(), status.as_deref(), json),
            LicenseCommands::Create {
                product,
                customer,
                email,
                features,
                days,
                max_seats,
                json,
            } => licenses::run_create(
                &product,
                customer.as_deref(),
                email.as_deref(),
                features,
                days,
                max_seats,
                json,
            ),
            LicenseCommands::Download { id, output } => licenses::run_download(&id, &output),
            LicenseCommands::Revoke { id } => licenses::run_revoke(&id),
            LicenseCommands::Verify { license, product } => {
                licenses::run_verify(&license, product.as_deref())
            }
        },
    }
}
