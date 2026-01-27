# Deploying Licenz Server on Fly.io

## Overview

This guide walks through deploying a license server on Fly.io that:
1. Receives webhooks from your payment provider (Stripe, Paddle, etc.)
2. Generates licenses with appropriate feature tiers
3. Serves licenses to customers
4. Provides a verification endpoint for your app

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              YOUR SETUP                                      │
└─────────────────────────────────────────────────────────────────────────────┘

    Customer                    Payment Provider              Fly.io
    ────────                    ────────────────              ──────
        │                             │                          │
        │  1. Purchases "Pro"         │                          │
        │────────────────────────────▶│                          │
        │                             │                          │
        │                             │  2. Webhook: payment     │
        │                             │     succeeded            │
        │                             │─────────────────────────▶│
        │                             │                          │
        │                             │                          │ 3. Match price
        │                             │                          │    to tier,
        │                             │                          │    generate
        │                             │                          │    license
        │                             │                          │
        │  4. Email with license.lic  │                          │
        │◀───────────────────────────────────────────────────────│
        │                             │                          │
        │                                                        │
        │  5. Download license, put in app directory             │
        │                                                        │
        ▼                                                        │
    ┌────────┐                                                   │
    │Your App│  (Optional) 6. Verify online                      │
    │        │──────────────────────────────────────────────────▶│
    │        │◀──────────────────────────────────────────────────│
    │        │                                                   │
    │        │  7. Offline verification (normal mode)            │
    │        │     - Check signature with embedded public key    │
    │        │     - Check expiry                                │
    │        │     - Check features                              │
    └────────┘
```

## Step 1: Project Structure

```
my-license-server/
├── Cargo.toml
├── src/
│   └── main.rs
├── config/
│   └── product.toml       # Tier definitions
├── Dockerfile
├── fly.toml
└── .env.example
```

## Step 2: Server Code

### Cargo.toml

```toml
[package]
name = "my-license-server"
version = "0.1.0"
edition = "2021"

[dependencies]
licenz-core = { path = "../licenz/crates/licenz-core" }
# Or from git:
# licenz-core = { git = "https://github.com/yourorg/licenz" }

axum = "0.7"
tokio = { version = "1", features = ["full"] }
tower-http = { version = "0.5", features = ["cors", "trace"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4"] }
base64 = "0.21"
hmac = "0.12"
sha2 = "0.10"
hex = "0.4"
lettre = { version = "0.11", features = ["tokio1-native-tls"] }  # For sending emails
```

### src/main.rs

```rust
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use licenz_core::{KeyPair, KeySize, LicenseData, LicenseGenerator, LicenseVerifier};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, sync::Arc};
use tracing::{error, info, warn};

// ============================================================================
// CONFIGURATION
// ============================================================================

/// Product configuration - defines your tiers
#[derive(Debug, Clone, Deserialize)]
struct ProductConfig {
    product_id: String,
    tiers: Vec<TierConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct TierConfig {
    name: String,
    features: Vec<String>,
    max_seats: u32,
    validity_days: u32,
    /// Price IDs from your payment provider that map to this tier
    price_ids: Vec<String>,
}

impl ProductConfig {
    fn find_tier_by_price(&self, price_id: &str) -> Option<&TierConfig> {
        self.tiers.iter().find(|t| {
            t.price_ids.iter().any(|p| {
                // Support wildcards: "price_pro_*" matches "price_pro_monthly"
                if p.contains('*') {
                    let pattern = p.replace('*', "");
                    price_id.contains(&pattern)
                } else {
                    p == price_id
                }
            })
        })
    }

    fn find_tier_by_name(&self, name: &str) -> Option<&TierConfig> {
        self.tiers.iter().find(|t| t.name.eq_ignore_ascii_case(name))
    }
}

// ============================================================================
// APPLICATION STATE
// ============================================================================

struct AppState {
    config: ProductConfig,
    generator: LicenseGenerator,
    verifier: LicenseVerifier,
    public_key_pem: String,
    webhook_secrets: HashMap<String, String>, // provider -> secret
    smtp_config: Option<SmtpConfig>,
    // In production, use a real database (Postgres, SQLite, etc.)
    processed_events: std::sync::Mutex<std::collections::HashSet<String>>,
}

#[derive(Clone)]
struct SmtpConfig {
    host: String,
    username: String,
    password: String,
    from_email: String,
}

// ============================================================================
// WEBHOOK HANDLERS
// ============================================================================

/// Generic webhook payload (provider-specific parsing below)
#[derive(Debug, Deserialize)]
struct WebhookPayload {
    #[serde(flatten)]
    data: serde_json::Value,
}

/// Stripe webhook handler
async fn handle_stripe_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // Verify signature
    let signature = headers
        .get("Stripe-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let secret = match state.webhook_secrets.get("stripe") {
        Some(s) => s,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "Stripe not configured"),
    };

    if let Err(e) = verify_stripe_signature(&body, signature, secret) {
        warn!("Invalid Stripe signature: {}", e);
        return (StatusCode::UNAUTHORIZED, "Invalid signature");
    }

    // Parse event
    let event: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse Stripe webhook: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid JSON");
        }
    };

    let event_id = event["id"].as_str().unwrap_or("");
    let event_type = event["type"].as_str().unwrap_or("");

    // Idempotency check
    {
        let mut processed = state.processed_events.lock().unwrap();
        if processed.contains(event_id) {
            info!("Event {} already processed", event_id);
            return (StatusCode::OK, "Already processed");
        }
        processed.insert(event_id.to_string());
    }

    // Handle relevant events
    match event_type {
        "checkout.session.completed" | "invoice.paid" => {
            let data = &event["data"]["object"];
            
            // Extract customer email
            let email = data["customer_email"]
                .as_str()
                .or_else(|| data["customer_details"]["email"].as_str())
                .unwrap_or("");

            // Extract price ID
            let price_id = extract_stripe_price_id(&event);

            if email.is_empty() || price_id.is_empty() {
                warn!("Missing email or price_id in event {}", event_id);
                return (StatusCode::OK, "Missing data, skipped");
            }

            // Find tier
            let tier = match state.config.find_tier_by_price(&price_id) {
                Some(t) => t,
                None => {
                    warn!("Unknown price_id: {}", price_id);
                    return (StatusCode::OK, "Unknown price, skipped");
                }
            };

            // Generate license
            match generate_and_send_license(&state, email, tier, event_id).await {
                Ok(_) => {
                    info!("License generated for {} (tier: {})", email, tier.name);
                    (StatusCode::OK, "License generated")
                }
                Err(e) => {
                    error!("Failed to generate license: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Generation failed")
                }
            }
        }
        "customer.subscription.deleted" => {
            // Optionally track revocations
            info!("Subscription deleted: {}", event_id);
            (StatusCode::OK, "Noted")
        }
        _ => {
            // Ignore other events
            (StatusCode::OK, "Event type not handled")
        }
    }
}

/// Paddle webhook handler (similar structure)
async fn handle_paddle_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // Verify Paddle signature (different format than Stripe)
    let signature = headers
        .get("Paddle-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let secret = match state.webhook_secrets.get("paddle") {
        Some(s) => s,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "Paddle not configured"),
    };

    // Paddle signature verification would go here
    // (Similar pattern to Stripe but different algorithm)

    let event: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse Paddle webhook: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid JSON");
        }
    };

    let event_type = event["event_type"].as_str().unwrap_or("");

    match event_type {
        "subscription.created" | "subscription.activated" => {
            let data = &event["data"];
            let email = data["customer"]["email"].as_str().unwrap_or("");
            let price_id = data["items"][0]["price"]["id"].as_str().unwrap_or("");

            // Same flow as Stripe...
            if let Some(tier) = state.config.find_tier_by_price(price_id) {
                let event_id = event["event_id"].as_str().unwrap_or("");
                match generate_and_send_license(&state, email, tier, event_id).await {
                    Ok(_) => (StatusCode::OK, "License generated"),
                    Err(e) => {
                        error!("Failed: {}", e);
                        (StatusCode::INTERNAL_SERVER_ERROR, "Failed")
                    }
                }
            } else {
                (StatusCode::OK, "Unknown price")
            }
        }
        _ => (StatusCode::OK, "Ignored"),
    }
}

// ============================================================================
// LICENSE GENERATION
// ============================================================================

async fn generate_and_send_license(
    state: &AppState,
    email: &str,
    tier: &TierConfig,
    event_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Build license data
    let license_data = LicenseData::builder()
        .id(&format!("LIC-{}", &uuid::Uuid::new_v4().to_string()[..8]))
        .serial(&format!("SN-{}", uuid::Uuid::new_v4()))
        .customer_id(email)
        .product_id(&state.config.product_id)
        .valid_days(tier.validity_days as i64)
        .features(tier.features.clone())
        .metadata("tier", &tier.name)
        .metadata("event_id", event_id)
        .metadata("max_seats", &tier.max_seats.to_string())
        .build()?;

    // Generate signed license
    let signed = state.generator.generate(license_data)?;
    let license_binary = state.generator.export_binary(&signed)?;
    let license_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &license_binary,
    );

    // Send via email
    if let Some(ref smtp) = state.smtp_config {
        send_license_email(smtp, email, &tier.name, &license_binary).await?;
    }

    info!(
        "Generated license: id={}, tier={}, customer={}, expires={}",
        signed.data.id, tier.name, email, signed.data.valid_until
    );

    Ok(())
}

async fn send_license_email(
    smtp: &SmtpConfig,
    to_email: &str,
    tier_name: &str,
    license_data: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use lettre::{
        message::{header::ContentType, Attachment, MultiPart, SinglePart},
        transport::smtp::authentication::Credentials,
        AsyncSmtpTransport, AsyncTransport, Message,
    };

    let attachment = Attachment::new("license.lic".to_string())
        .body(license_data.to_vec(), ContentType::APPLICATION_OCTET_STREAM);

    let email = Message::builder()
        .from(smtp.from_email.parse()?)
        .to(to_email.parse()?)
        .subject(format!("Your {} License", tier_name))
        .multipart(
            MultiPart::mixed()
                .singlepart(SinglePart::plain(format!(
                    "Thank you for your purchase!\n\n\
                     Your {} license is attached.\n\n\
                     To activate:\n\
                     1. Download the attached license.lic file\n\
                     2. Place it in your application's directory\n\
                     3. Restart the application\n\n\
                     If you have any questions, please contact support.",
                    tier_name
                )))
                .singlepart(attachment),
        )?;

    let creds = Credentials::new(smtp.username.clone(), smtp.password.clone());

    let mailer = AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(&smtp.host)?
        .credentials(creds)
        .build();

    mailer.send(email).await?;

    Ok(())
}

// ============================================================================
// API ENDPOINTS
// ============================================================================

/// Manual license generation (admin only - protect this endpoint!)
#[derive(Debug, Deserialize)]
struct ManualGenerateRequest {
    email: String,
    tier: String,
    #[serde(default)]
    admin_key: String,
}

#[derive(Debug, Serialize)]
struct GenerateResponse {
    license_id: String,
    tier: String,
    valid_until: String,
    license_base64: String,
}

async fn manual_generate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ManualGenerateRequest>,
) -> impl IntoResponse {
    // Simple admin key check (use proper auth in production!)
    let admin_key = env::var("ADMIN_KEY").unwrap_or_default();
    if req.admin_key != admin_key || admin_key.is_empty() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Unauthorized"})));
    }

    let tier = match state.config.find_tier_by_name(&req.tier) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Unknown tier"})),
            )
        }
    };

    let license_data = LicenseData::builder()
        .id(&format!("LIC-{}", &uuid::Uuid::new_v4().to_string()[..8]))
        .serial(&format!("SN-{}", uuid::Uuid::new_v4()))
        .customer_id(&req.email)
        .product_id(&state.config.product_id)
        .valid_days(tier.validity_days as i64)
        .features(tier.features.clone())
        .metadata("tier", &tier.name)
        .metadata("manual", "true")
        .build()
        .unwrap();

    let signed = state.generator.generate(license_data).unwrap();
    let license_binary = state.generator.export_binary(&signed).unwrap();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "license_id": signed.data.id,
            "tier": tier.name,
            "valid_until": signed.data.valid_until.to_rfc3339(),
            "license_base64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &license_binary
            ),
        })),
    )
}

/// Verify a license (optional online check)
#[derive(Debug, Deserialize)]
struct VerifyRequest {
    license_base64: String,
}

async fn verify_license(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> impl IntoResponse {
    let license_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.license_base64,
    ) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"valid": false, "error": "Invalid base64"})),
            )
        }
    };

    match state.verifier.load_and_validate_bytes(&license_bytes) {
        Ok(license) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "valid": true,
                "license_id": license.data.id,
                "customer": license.data.customer_id,
                "tier": license.data.metadata.get("tier"),
                "features": license.data.features,
                "valid_until": license.data.valid_until.to_rfc3339(),
                "days_remaining": license.data.days_remaining(),
            })),
        ),
        Err(e) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "valid": false,
                "error": e.to_string(),
            })),
        ),
    }
}

/// Get public key (for embedding in apps)
async fn get_public_key(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("Content-Type", "application/x-pem-file")],
        state.public_key_pem.clone(),
    )
}

/// Health check
async fn health() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

// ============================================================================
// HELPERS
// ============================================================================

fn verify_stripe_signature(payload: &str, signature: &str, secret: &str) -> Result<(), String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Parse signature header: t=timestamp,v1=signature
    let mut timestamp = None;
    let mut sig_v1 = None;

    for part in signature.split(',') {
        let mut kv = part.splitn(2, '=');
        match (kv.next(), kv.next()) {
            (Some("t"), Some(t)) => timestamp = Some(t),
            (Some("v1"), Some(s)) => sig_v1 = Some(s),
            _ => {}
        }
    }

    let timestamp = timestamp.ok_or("Missing timestamp")?;
    let expected_sig = sig_v1.ok_or("Missing v1 signature")?;

    // Check timestamp (5 minute tolerance)
    let ts: i64 = timestamp.parse().map_err(|_| "Invalid timestamp")?;
    let now = chrono::Utc::now().timestamp();
    if (now - ts).abs() > 300 {
        return Err("Timestamp too old".into());
    }

    // Compute signature
    let signed_payload = format!("{}.{}", timestamp, payload);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| "Invalid secret")?;
    mac.update(signed_payload.as_bytes());
    let computed = hex::encode(mac.finalize().into_bytes());

    // Constant-time comparison
    if computed.len() != expected_sig.len() {
        return Err("Signature mismatch".into());
    }
    let matches = computed
        .bytes()
        .zip(expected_sig.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));

    if matches != 0 {
        return Err("Signature mismatch".into());
    }

    Ok(())
}

fn extract_stripe_price_id(event: &serde_json::Value) -> String {
    // Try different locations where Stripe puts price IDs
    let data = &event["data"]["object"];

    // checkout.session.completed
    if let Some(price) = data["line_items"]["data"][0]["price"]["id"].as_str() {
        return price.to_string();
    }

    // invoice.paid
    if let Some(price) = data["lines"]["data"][0]["price"]["id"].as_str() {
        return price.to_string();
    }

    // subscription in metadata
    if let Some(price) = data["metadata"]["price_id"].as_str() {
        return price.to_string();
    }

    String::new()
}

// ============================================================================
// MAIN
// ============================================================================

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("my_license_server=info".parse().unwrap()),
        )
        .init();

    // Load configuration
    let config: ProductConfig = {
        let config_str = std::fs::read_to_string("config/product.toml")
            .expect("Failed to read config/product.toml");
        toml::from_str(&config_str).expect("Invalid config format")
    };

    info!("Loaded product config: {} tiers", config.tiers.len());

    // Load or generate keys
    let (private_key_pem, public_key_pem) = load_or_generate_keys();

    let keypair = KeyPair::from_pem(&private_key_pem, &public_key_pem)
        .expect("Invalid key pair");

    let generator = LicenseGenerator::new(keypair.private_key.clone());
    let verifier = LicenseVerifier::new(keypair.public_key);

    // Load webhook secrets from environment
    let mut webhook_secrets = HashMap::new();
    if let Ok(secret) = env::var("STRIPE_WEBHOOK_SECRET") {
        webhook_secrets.insert("stripe".to_string(), secret);
        info!("Stripe webhook configured");
    }
    if let Ok(secret) = env::var("PADDLE_WEBHOOK_SECRET") {
        webhook_secrets.insert("paddle".to_string(), secret);
        info!("Paddle webhook configured");
    }

    // SMTP configuration (optional)
    let smtp_config = match (
        env::var("SMTP_HOST"),
        env::var("SMTP_USERNAME"),
        env::var("SMTP_PASSWORD"),
        env::var("SMTP_FROM"),
    ) {
        (Ok(host), Ok(username), Ok(password), Ok(from_email)) => {
            info!("SMTP configured");
            Some(SmtpConfig {
                host,
                username,
                password,
                from_email,
            })
        }
        _ => {
            warn!("SMTP not configured - licenses will not be emailed");
            None
        }
    };

    let state = Arc::new(AppState {
        config,
        generator,
        verifier,
        public_key_pem,
        webhook_secrets,
        smtp_config,
        processed_events: std::sync::Mutex::new(std::collections::HashSet::new()),
    });

    // Build router
    let app = Router::new()
        // Health check
        .route("/health", get(health))
        // Webhook endpoints
        .route("/webhooks/stripe", post(handle_stripe_webhook))
        .route("/webhooks/paddle", post(handle_paddle_webhook))
        // API endpoints
        .route("/api/v1/licenses/generate", post(manual_generate))
        .route("/api/v1/licenses/verify", post(verify_license))
        .route("/api/v1/public-key", get(get_public_key))
        .with_state(state);

    // Get port from environment (Fly.io sets this)
    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .unwrap();

    let addr = format!("0.0.0.0:{}", port);
    info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn load_or_generate_keys() -> (String, String) {
    // Try environment variables first (recommended for Fly.io)
    if let (Ok(private), Ok(public)) = (
        env::var("LICENZ_PRIVATE_KEY"),
        env::var("LICENZ_PUBLIC_KEY"),
    ) {
        info!("Loaded keys from environment");
        return (private, public);
    }

    // Try files
    if let (Ok(private), Ok(public)) = (
        std::fs::read_to_string("keys/private.pem"),
        std::fs::read_to_string("keys/public.pem"),
    ) {
        info!("Loaded keys from files");
        return (private, public);
    }

    // Generate new keys (development only!)
    warn!("Generating new key pair - DO NOT USE IN PRODUCTION without saving keys!");
    let keypair = KeyPair::generate(KeySize::Bits2048).expect("Failed to generate keys");
    let private = keypair.export_private_pem().unwrap();
    let public = keypair.export_public_pem().unwrap();

    // Save for next time
    std::fs::create_dir_all("keys").ok();
    std::fs::write("keys/private.pem", &private).ok();
    std::fs::write("keys/public.pem", &public).ok();

    (private, public)
}
```

### config/product.toml

```toml
# Product Configuration
product_id = "my-awesome-app"

# Define your tiers
[[tiers]]
name = "free"
features = ["basic"]
max_seats = 1
validity_days = 36500  # ~100 years

# Free tier doesn't have price IDs (manual generation only)
price_ids = []

[[tiers]]
name = "starter"
features = ["basic", "export"]
max_seats = 1
validity_days = 35  # Slightly more than monthly

# Stripe price IDs
price_ids = [
    "price_starter_monthly",
    "price_starter_yearly",
    # Wildcards work too:
    "*starter*",
]

[[tiers]]
name = "pro"
features = ["basic", "export", "premium", "api_access", "priority_support"]
max_seats = 5
validity_days = 35

price_ids = [
    "price_pro_monthly",
    "price_pro_yearly",
    "*professional*",
    "*pro*",
]

[[tiers]]
name = "enterprise"
features = ["basic", "export", "premium", "api_access", "priority_support", "sso", "audit_log", "custom_branding", "dedicated_support"]
max_seats = 0  # Unlimited
validity_days = 35

price_ids = [
    "price_enterprise_monthly",
    "price_enterprise_yearly",
    "*enterprise*",
    "*business*",
]
```

## Step 3: Dockerfile

```dockerfile
# Build stage
FROM rust:1.75-slim-bookworm as builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source
COPY src ./src
COPY config ./config

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/my-license-server /app/
COPY --from=builder /app/config /app/config

# Create keys directory
RUN mkdir -p /app/keys

EXPOSE 8080

CMD ["/app/my-license-server"]
```

## Step 4: fly.toml

```toml
app = "my-license-server"
primary_region = "iad"  # Choose your region

[build]

[env]
  RUST_LOG = "info,my_license_server=debug"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true
  min_machines_running = 1

[[http_service.checks]]
  interval = "30s"
  timeout = "5s"
  grace_period = "10s"
  method = "GET"
  path = "/health"
```

## Step 5: Deploy to Fly.io

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Login
fly auth login

# Create app
fly apps create my-license-server

# Generate keys locally (do this ONCE and save them!)
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Set secrets (NEVER commit these!)
fly secrets set LICENZ_PRIVATE_KEY="$(cat private.pem)"
fly secrets set LICENZ_PUBLIC_KEY="$(cat public.pem)"
fly secrets set STRIPE_WEBHOOK_SECRET="whsec_your_stripe_secret"
fly secrets set ADMIN_KEY="your-secure-admin-key"

# Optional: SMTP for email delivery
fly secrets set SMTP_HOST="smtp.sendgrid.net"
fly secrets set SMTP_USERNAME="apikey"
fly secrets set SMTP_PASSWORD="your-sendgrid-api-key"
fly secrets set SMTP_FROM="licenses@yourcompany.com"

# Deploy
fly deploy

# Check logs
fly logs
```

## Step 6: Configure Stripe Webhook

1. Go to Stripe Dashboard → Developers → Webhooks
2. Add endpoint: `https://my-license-server.fly.dev/webhooks/stripe`
3. Select events:
   - `checkout.session.completed`
   - `invoice.paid`
   - `customer.subscription.deleted`
4. Copy the signing secret to Fly.io secrets

---

## Client-Side: Your Rust Application

Now the important part - how to use licenses in your app:

### Cargo.toml (your app)

```toml
[dependencies]
licenz-core = { git = "https://github.com/yourorg/licenz" }
```

### src/license.rs

```rust
use licenz_core::{require_license, ValidatedLicense, LicenseVerifier, LicenseError};
use std::path::Path;
use std::sync::OnceLock;

// Embed your public key at compile time
// Get this from: curl https://my-license-server.fly.dev/api/v1/public-key > public.pem
const PUBLIC_KEY: &str = include_str!("../public.pem");

// Global license state
static LICENSE: OnceLock<Option<ValidatedLicense>> = OnceLock::new();

/// Initialize license on app startup
pub fn init_license() -> Result<&'static ValidatedLicense, LicenseError> {
    let license = LICENSE.get_or_init(|| {
        // Look for license in standard locations
        let paths = [
            "license.lic",
            "~/.config/myapp/license.lic",
            "/etc/myapp/license.lic",
        ];

        for path in paths {
            let expanded = shellexpand::tilde(path);
            if Path::new(expanded.as_ref()).exists() {
                match require_license(expanded.as_ref(), PUBLIC_KEY) {
                    Ok(lic) => return Some(lic),
                    Err(e) => {
                        eprintln!("Invalid license at {}: {}", path, e);
                    }
                }
            }
        }

        None
    });

    license.as_ref().ok_or_else(|| {
        LicenseError::VerificationFailed("No valid license found".into())
    })
}

/// Get the current license (panics if not initialized)
pub fn get_license() -> &'static ValidatedLicense {
    LICENSE.get()
        .expect("License not initialized - call init_license() first")
        .as_ref()
        .expect("No valid license")
}

/// Check if a feature is available
pub fn has_feature(feature: &str) -> bool {
    LICENSE.get()
        .and_then(|l| l.as_ref())
        .map(|l| l.has_feature(feature))
        .unwrap_or(false)
}

/// Get the current tier name
pub fn current_tier() -> Option<&'static str> {
    LICENSE.get()
        .and_then(|l| l.as_ref())
        .and_then(|l| l.metadata.get("tier"))
        .map(|s| s.as_str())
}

/// Macro for feature gating
#[macro_export]
macro_rules! require_feature {
    ($feature:expr) => {
        if !$crate::license::has_feature($feature) {
            return Err($crate::Error::FeatureNotLicensed($feature.to_string()));
        }
    };
}

#[macro_export]
macro_rules! feature_gate {
    ($feature:expr, $enabled:block) => {
        if $crate::license::has_feature($feature) {
            $enabled
        }
    };
    ($feature:expr, $enabled:block else $disabled:block) => {
        if $crate::license::has_feature($feature) {
            $enabled
        } else {
            $disabled
        }
    };
}
```

### src/main.rs (your app)

```rust
mod license;

use license::{init_license, has_feature, current_tier};

fn main() {
    // Initialize license at startup
    match init_license() {
        Ok(lic) => {
            println!("✓ Licensed to: {}", lic.customer_id);
            println!("  Tier: {}", current_tier().unwrap_or("unknown"));
            println!("  Features: {:?}", lic.features);
            println!("  Valid until: {}", lic.valid_until);
            println!("  Days remaining: {}", lic.days_remaining());
        }
        Err(e) => {
            eprintln!("⚠ Running in free mode: {}", e);
            eprintln!("  Purchase a license at https://yoursite.com/pricing");
        }
    }

    // Your app logic with feature gates
    run_app();
}

fn run_app() {
    // Basic feature - always available
    do_basic_stuff();

    // Export feature - requires starter+
    feature_gate!("export", {
        println!("Export feature enabled!");
        do_export();
    } else {
        println!("Export requires Starter plan. Upgrade at https://yoursite.com/pricing");
    });

    // Premium feature - requires pro+
    if has_feature("premium") {
        do_premium_stuff();
    }

    // API access - requires pro+
    feature_gate!("api_access", {
        start_api_server();
    });

    // SSO - requires enterprise
    feature_gate!("sso", {
        configure_sso();
    });
}

fn do_basic_stuff() {
    println!("Doing basic stuff...");
}

fn do_export() {
    println!("Exporting data...");
}

fn do_premium_stuff() {
    println!("Premium features active!");
}

fn start_api_server() {
    println!("Starting API server...");
}

fn configure_sso() {
    println!("Configuring SSO...");
}
```

### Feature Matrix

| Feature | Free | Starter | Pro | Enterprise |
|---------|------|---------|-----|------------|
| `basic` | ✓ | ✓ | ✓ | ✓ |
| `export` | | ✓ | ✓ | ✓ |
| `premium` | | | ✓ | ✓ |
| `api_access` | | | ✓ | ✓ |
| `priority_support` | | | ✓ | ✓ |
| `sso` | | | | ✓ |
| `audit_log` | | | | ✓ |
| `custom_branding` | | | | ✓ |

---

## Complete Flow

1. **Customer** visits your pricing page, clicks "Buy Pro"
2. **Stripe** processes payment, sends webhook to `https://my-license-server.fly.dev/webhooks/stripe`
3. **Your server** matches `price_pro_monthly` → `pro` tier → generates license with `["basic", "export", "premium", "api_access", "priority_support"]`
4. **Server** emails `license.lic` to customer
5. **Customer** downloads license, puts in app directory
6. **Your app** loads license, verifies signature with embedded public key
7. **Your app** checks `has_feature("premium")` → returns `true` → premium features unlocked

All offline. No phone-home required. Works air-gapped.
