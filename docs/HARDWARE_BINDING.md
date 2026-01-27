# Hardware Binding Implementation

## How Hardware Binding Works

The license contains a **hardware fingerprint** that must match the machine running your app. If someone copies the license file to another machine, the fingerprint won't match and the license is rejected.

## Client Side: Collecting Hardware Info

### In Your Rust App

```rust
use licenz_core::{detect_hardware, HardwareInfo};
use sha2::{Sha256, Digest};

/// Generate a hardware fingerprint for this machine
pub fn get_hardware_fingerprint() -> String {
    let hw: HardwareInfo = detect_hardware();
    
    // Combine multiple factors for stronger binding
    let mut data = String::new();
    
    // MAC addresses (can have multiple)
    for mac in &hw.mac_addresses {
        data.push_str(mac);
    }
    
    // Disk serial numbers
    for disk in &hw.disk_ids {
        data.push_str(disk);
    }
    
    // Hostname
    if let Some(ref hostname) = hw.hostname {
        data.push_str(hostname);
    }
    
    // Machine ID (OS-level, most reliable)
    if let Some(ref machine_id) = hw.machine_id {
        data.push_str(machine_id);
    }
    
    // Hash it for privacy (don't send raw hardware IDs)
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let hash = hasher.finalize();
    
    // Return first 32 chars of hex hash
    hex::encode(&hash[..16])
}

/// Show "Buy License" button that includes fingerprint
pub fn open_purchase_url(base_url: &str) {
    let fingerprint = get_hardware_fingerprint();
    let url = format!("{}?fp={}", base_url, fingerprint);
    
    // Open in default browser
    if let Err(e) = open::that(&url) {
        println!("Please visit: {}", url);
    }
}
```

### CLI Helper Command

Your app can have a command to show the fingerprint:

```rust
// In your CLI app
fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.get(1).map(|s| s.as_str()) == Some("--hardware-id") {
        let fp = get_hardware_fingerprint();
        println!("Hardware Fingerprint: {}", fp);
        println!();
        println!("Use this when purchasing a license at:");
        println!("  https://yoursite.com/buy?fp={}", fp);
        return;
    }
    
    // Normal app startup...
}
```

```bash
$ myapp --hardware-id
Hardware Fingerprint: a1b2c3d4e5f67890a1b2c3d4e5f67890

Use this when purchasing a license at:
  https://yoursite.com/buy?fp=a1b2c3d4e5f67890a1b2c3d4e5f67890
```

---

## Server Side: Binding During Generation

### Updated Webhook Handler

```rust
async fn handle_stripe_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // ... signature verification ...
    
    let event: serde_json::Value = serde_json::from_str(&body)?;
    let data = &event["data"]["object"];
    
    // Extract customer info
    let email = data["customer_email"].as_str().unwrap_or("");
    let price_id = extract_stripe_price_id(&event);
    
    // IMPORTANT: Get hardware fingerprint from metadata
    let hardware_fingerprint = data["metadata"]["hardware_fingerprint"]
        .as_str()
        .or_else(|| data["metadata"]["fp"].as_str())
        .map(String::from);
    
    let tier = state.config.find_tier_by_price(&price_id)?;
    
    // Generate license WITH hardware binding
    generate_license_with_binding(
        &state,
        email,
        tier,
        hardware_fingerprint.as_deref(), // Option<&str>
    ).await
}

async fn generate_license_with_binding(
    state: &AppState,
    email: &str,
    tier: &TierConfig,
    hardware_fingerprint: Option<&str>,
) -> Result<SignedLicense, Error> {
    
    let mut builder = LicenseData::builder()
        .id(&format!("LIC-{}", uuid::Uuid::new_v4()))
        .serial(&format!("SN-{}", uuid::Uuid::new_v4()))
        .customer_id(email)
        .product_id(&state.config.product_id)
        .valid_days(tier.validity_days as i64)
        .features(tier.features.clone())
        .metadata("tier", &tier.name);
    
    // Add hardware binding if provided
    if let Some(fp) = hardware_fingerprint {
        builder = builder.hardware_binding(
            HardwareBinding::new()
                // The fingerprint is a hash, store it as machine_id
                .with_machine_id(fp)
        );
        builder = builder.metadata("hardware_bound", "true");
    } else {
        builder = builder.metadata("hardware_bound", "false");
    }
    
    let license_data = builder.build()?;
    let signed = state.generator.generate(license_data)?;
    
    Ok(signed)
}
```

### Stripe Checkout: Pass Fingerprint in Metadata

When creating a Stripe checkout session, include the fingerprint:

```javascript
// Your website's checkout handler
app.post('/create-checkout', async (req, res) => {
  const { priceId, fingerprint } = req.body;
  
  const session = await stripe.checkout.sessions.create({
    mode: 'subscription', // or 'payment'
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: 'https://yoursite.com/success',
    cancel_url: 'https://yoursite.com/pricing',
    
    // IMPORTANT: Include fingerprint in metadata
    metadata: {
      hardware_fingerprint: fingerprint,
    },
    
    // Also pass to subscription for renewals
    subscription_data: {
      metadata: {
        hardware_fingerprint: fingerprint,
      },
    },
  });
  
  res.json({ url: session.url });
});
```

Or with a simple buy link:

```
https://buy.stripe.com/xxx?client_reference_id=FINGERPRINT_HERE
```

---

## Client Side: Verifying Hardware Match

### Updated License Verification

```rust
use licenz_core::{LicenseVerifier, LicenseError, detect_hardware};

const PUBLIC_KEY: &str = include_str!("../public.pem");

pub fn verify_license(license_path: &str) -> Result<ValidatedLicense, LicenseError> {
    let verifier = LicenseVerifier::from_pem(PUBLIC_KEY)?;
    
    // Load license
    let license = verifier.load_license(license_path)?;
    
    // Verify signature and expiry
    verifier.validate(&license)?;
    
    // Check hardware binding (if present)
    if license.data.hardware_binding.is_some() {
        verify_hardware_binding(&license)?;
    }
    
    Ok(ValidatedLicense::new(license))
}

fn verify_hardware_binding(license: &SignedLicense) -> Result<(), LicenseError> {
    let binding = license.data.hardware_binding.as_ref().unwrap();
    let current_hw = detect_hardware();
    let current_fp = get_hardware_fingerprint();
    
    // Check machine ID (our hashed fingerprint)
    if !binding.machine_ids.is_empty() {
        let matches = binding.machine_ids.iter().any(|id| id == &current_fp);
        if !matches {
            return Err(LicenseError::HardwareBindingMismatch {
                field: "machine_id".into(),
                expected: binding.machine_ids.clone(),
                actual: current_fp,
            });
        }
    }
    
    // Optional: Also check individual hardware components
    // (More lenient - allows some hardware changes)
    if !binding.mac_addresses.is_empty() {
        let matches = binding.mac_addresses.iter()
            .any(|mac| current_hw.mac_addresses.contains(mac));
        if !matches {
            return Err(LicenseError::HardwareBindingMismatch {
                field: "mac_address".into(),
                expected: binding.mac_addresses.clone(),
                actual: current_hw.mac_addresses.join(", "),
            });
        }
    }
    
    Ok(())
}
```

---

## Alternative: Activation Flow

If you don't want to collect hardware info at checkout:

### 1. Generate "Activation Code" Instead of License

```rust
// Server: On payment, generate activation code (not full license)
async fn handle_payment(email: &str, tier: &str) -> String {
    let activation_code = format!(
        "ACT-{}-{}-{}",
        tier.to_uppercase(),
        &uuid::Uuid::new_v4().to_string()[..8],
        &uuid::Uuid::new_v4().to_string()[..4],
    );
    // Example: ACT-PRO-a1b2c3d4-e5f6
    
    // Store in database: activation_code -> (email, tier, used: false)
    db.store_activation(activation_code.clone(), email, tier);
    
    activation_code
}
```

### 2. Activation Endpoint

```rust
#[derive(Deserialize)]
struct ActivateRequest {
    activation_code: String,
    hardware_fingerprint: String,
}

async fn activate_license(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ActivateRequest>,
) -> impl IntoResponse {
    // Look up activation code
    let activation = match state.db.get_activation(&req.activation_code) {
        Some(a) if !a.used => a,
        Some(_) => return (StatusCode::BAD_REQUEST, "Code already used"),
        None => return (StatusCode::NOT_FOUND, "Invalid code"),
    };
    
    // Get tier
    let tier = state.config.find_tier_by_name(&activation.tier)?;
    
    // Generate hardware-bound license
    let license = generate_license_with_binding(
        &state,
        &activation.email,
        tier,
        Some(&req.hardware_fingerprint),
    ).await?;
    
    // Mark activation as used
    state.db.mark_activation_used(&req.activation_code);
    
    // Return license
    let binary = state.generator.export_binary(&license)?;
    let base64 = base64::encode(&binary);
    
    (StatusCode::OK, Json(json!({
        "license_base64": base64,
        "tier": tier.name,
        "valid_until": license.data.valid_until,
    })))
}
```

### 3. Client Activation

```rust
// In your app
pub async fn activate(code: &str) -> Result<(), Error> {
    let fingerprint = get_hardware_fingerprint();
    
    let client = reqwest::Client::new();
    let response = client
        .post("https://my-license-server.fly.dev/api/v1/activate")
        .json(&json!({
            "activation_code": code,
            "hardware_fingerprint": fingerprint,
        }))
        .send()
        .await?;
    
    if !response.status().is_success() {
        return Err(Error::ActivationFailed(response.text().await?));
    }
    
    let data: serde_json::Value = response.json().await?;
    let license_base64 = data["license_base64"].as_str().unwrap();
    let license_bytes = base64::decode(license_base64)?;
    
    // Save to disk
    std::fs::write("license.lic", license_bytes)?;
    
    println!("✓ License activated!");
    println!("  Tier: {}", data["tier"]);
    println!("  Valid until: {}", data["valid_until"]);
    
    Ok(())
}

// CLI usage
fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.get(1).map(|s| s.as_str()) == Some("activate") {
        let code = args.get(2).expect("Usage: myapp activate <CODE>");
        
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            if let Err(e) = activate(code).await {
                eprintln!("Activation failed: {}", e);
                std::process::exit(1);
            }
        });
        return;
    }
    
    // Normal app...
}
```

```bash
$ myapp activate ACT-PRO-a1b2c3d4-e5f6
✓ License activated!
  Tier: pro
  Valid until: 2025-02-15T00:00:00Z
```

---

## Comparison

| Approach | Pros | Cons |
|----------|------|------|
| **Fingerprint at checkout** | Single step, no activation needed | Requires custom checkout flow |
| **Activation code** | Works with any payment flow, simple Stripe links | Extra step for user, requires online activation |
| **No hardware binding** | Simplest, no friction | License can be shared/copied |

---

## Recommended: Hybrid Approach

```rust
// If fingerprint provided at checkout → bind immediately
// If not → allow one-time activation within 7 days

async fn handle_payment(email: &str, tier: &str, fingerprint: Option<&str>) {
    if let Some(fp) = fingerprint {
        // Direct license generation
        generate_and_send_license(email, tier, Some(fp)).await;
    } else {
        // Send activation code
        let code = generate_activation_code(email, tier);
        send_activation_email(email, code).await;
    }
}
```

This gives you flexibility:
- Power users can use CLI to get fingerprint → paste in checkout
- Casual users just buy → get activation code → run `myapp activate <code>`

---

## Hardware Binding Tolerance

You can make binding more lenient using the `HardwareFingerprint` matching from FMECA:

```rust
// Instead of exact match, use 70% threshold
let match_result = current_fingerprint.match_score(&license_fingerprint);

if match_result.passed {  // >= 70% match
    // OK - some hardware can change
} else {
    // Reject
}
```

This allows:
- New network card (MAC changes) ✓
- New disk added (disk IDs change) ✓
- New motherboard + disk + NIC (everything changes) ✗
