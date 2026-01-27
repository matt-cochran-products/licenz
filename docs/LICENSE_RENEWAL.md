# License Renewal / Token Cycling

## Overview

Instead of issuing a 365-day license, you issue a **short-lived license** (e.g., 35 days) that gets automatically replaced on each billing cycle.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        LICENSE RENEWAL TIMELINE                              │
└─────────────────────────────────────────────────────────────────────────────┘

Month 1          Month 2          Month 3          Canceled
───┬───────────────┬───────────────┬───────────────┬───────────────
   │               │               │               │
   ▼               ▼               ▼               ▼
┌──────┐       ┌──────┐       ┌──────┐       
│Lic v1│       │Lic v2│       │Lic v3│       No new license
│35 day│       │35 day│       │35 day│       App stops working
└──────┘       └──────┘       └──────┘       after 35 days
   │               │               │               │
   │◀─── Valid ───▶│◀─── Valid ───▶│◀─── Valid ───▶│◀── Grace ──▶✗
   │               │               │               │
 Payment         Payment         Payment        Subscription
 #1              #2              #3             Canceled

```

## Why 35 Days?

- Monthly billing = ~30 days
- 35 days = 30 days + 5 day grace period
- If payment fails on day 30, user has 5 days before app stops
- Gives time for card updates, retry attempts

For yearly: use 370 days (365 + 5 day grace).

---

## Server Implementation

### Stripe Webhook Events to Handle

```rust
// Events that trigger license renewal
const RENEWAL_EVENTS: &[&str] = &[
    "invoice.paid",              // Subscription renewed
    "invoice.payment_succeeded", // Same thing, different event
    "checkout.session.completed", // Initial purchase
];

// Events that should NOT generate new licenses
const NON_RENEWAL_EVENTS: &[&str] = &[
    "customer.subscription.updated",  // Plan change (handle separately)
    "customer.subscription.deleted",  // Canceled - let it expire
    "invoice.payment_failed",         // Don't generate, but maybe notify
];
```

### Updated Webhook Handler

```rust
async fn handle_stripe_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // ... signature verification ...
    
    let event: serde_json::Value = serde_json::from_str(&body)?;
    let event_type = event["type"].as_str().unwrap_or("");
    let event_id = event["id"].as_str().unwrap_or("");
    
    // Idempotency check
    if state.is_processed(event_id).await {
        return (StatusCode::OK, "Already processed");
    }
    
    match event_type {
        // ============================================================
        // RENEWAL EVENTS - Generate new license
        // ============================================================
        "invoice.paid" => {
            let invoice = &event["data"]["object"];
            
            // Skip if not a subscription invoice
            let billing_reason = invoice["billing_reason"].as_str().unwrap_or("");
            if billing_reason == "manual" {
                return (StatusCode::OK, "Manual invoice, skipped");
            }
            
            // Get subscription details
            let subscription_id = invoice["subscription"].as_str().unwrap_or("");
            let customer_email = get_customer_email(&event);
            let price_id = extract_price_id(&event);
            
            // Determine billing interval for license duration
            let interval = invoice["lines"]["data"][0]["price"]["recurring"]["interval"]
                .as_str()
                .unwrap_or("month");
            
            let validity_days = match interval {
                "year" => 370,   // 365 + 5 day grace
                "month" => 35,  // 30 + 5 day grace
                "week" => 10,   // 7 + 3 day grace
                _ => 35,
            };
            
            // Get hardware fingerprint from subscription metadata
            let hardware_fp = get_hardware_fingerprint_from_subscription(
                &state.stripe_client,
                subscription_id,
            ).await;
            
            // Find tier
            let tier = state.config.find_tier_by_price(&price_id)?;
            
            // Generate NEW license (replaces old one)
            let license = generate_license(
                &state,
                &customer_email,
                tier,
                validity_days,
                hardware_fp.as_deref(),
                Some(subscription_id),
            ).await?;
            
            // Deliver to customer
            deliver_license(&state, &customer_email, &license, tier).await?;
            
            // Track
            state.mark_processed(event_id).await;
            
            info!(
                "License renewed: customer={}, tier={}, valid_days={}, subscription={}",
                customer_email, tier.name, validity_days, subscription_id
            );
            
            (StatusCode::OK, "License renewed")
        }
        
        "checkout.session.completed" => {
            // Initial purchase - same as renewal but might need to 
            // create subscription metadata with hardware fingerprint
            
            let session = &event["data"]["object"];
            let mode = session["mode"].as_str().unwrap_or("");
            
            if mode == "subscription" {
                // Store hardware fingerprint in subscription metadata
                // so we have it for future renewals
                let subscription_id = session["subscription"].as_str().unwrap_or("");
                let hardware_fp = session["metadata"]["hardware_fingerprint"]
                    .as_str()
                    .map(String::from);
                
                if let Some(fp) = &hardware_fp {
                    update_subscription_metadata(
                        &state.stripe_client,
                        subscription_id,
                        &[("hardware_fingerprint", fp)],
                    ).await?;
                }
                
                // Generate initial license
                // (invoice.paid will also fire, but idempotency handles it)
                let customer_email = session["customer_email"].as_str().unwrap_or("");
                let price_id = extract_price_id(&event);
                let tier = state.config.find_tier_by_price(&price_id)?;
                
                let validity_days = get_validity_days_from_price(&state.stripe_client, &price_id).await;
                
                let license = generate_license(
                    &state,
                    customer_email,
                    tier,
                    validity_days,
                    hardware_fp.as_deref(),
                    Some(subscription_id),
                ).await?;
                
                deliver_license(&state, customer_email, &license, tier).await?;
            }
            
            (StatusCode::OK, "License generated")
        }
        
        // ============================================================
        // NON-RENEWAL EVENTS - Don't generate license
        // ============================================================
        "customer.subscription.deleted" => {
            // Subscription canceled - DO NOTHING
            // The current license will naturally expire
            // This is the key insight: no revocation needed!
            
            let subscription_id = event["data"]["object"]["id"].as_str().unwrap_or("");
            info!("Subscription canceled: {} - license will expire naturally", subscription_id);
            
            (StatusCode::OK, "Noted, license will expire")
        }
        
        "invoice.payment_failed" => {
            // Payment failed - optionally notify customer
            // License continues until expiry (grace period)
            
            let customer_email = get_customer_email(&event);
            let attempt = event["data"]["object"]["attempt_count"].as_i64().unwrap_or(0);
            
            if attempt >= 2 {
                // Multiple failures - warn customer
                send_payment_failed_email(&state, &customer_email, attempt).await;
            }
            
            (StatusCode::OK, "Payment failure noted")
        }
        
        "customer.subscription.updated" => {
            // Plan change - check if upgrade/downgrade
            let subscription = &event["data"]["object"];
            let previous = &event["data"]["previous_attributes"];
            
            // If price changed, generate new license with new tier
            if previous.get("items").is_some() {
                let customer_email = get_customer_email(&event);
                let new_price_id = subscription["items"]["data"][0]["price"]["id"]
                    .as_str()
                    .unwrap_or("");
                
                if let Some(new_tier) = state.config.find_tier_by_price(new_price_id) {
                    // Get remaining days from current period
                    let period_end = subscription["current_period_end"].as_i64().unwrap_or(0);
                    let now = chrono::Utc::now().timestamp();
                    let remaining_days = ((period_end - now) / 86400) as u32 + 5; // +5 grace
                    
                    let hardware_fp = subscription["metadata"]["hardware_fingerprint"]
                        .as_str()
                        .map(String::from);
                    
                    let license = generate_license(
                        &state,
                        &customer_email,
                        new_tier,
                        remaining_days,
                        hardware_fp.as_deref(),
                        subscription["id"].as_str(),
                    ).await?;
                    
                    deliver_license(&state, &customer_email, &license, new_tier).await?;
                    
                    info!("License updated for plan change: {} -> {}", customer_email, new_tier.name);
                }
            }
            
            (StatusCode::OK, "Subscription update handled")
        }
        
        _ => (StatusCode::OK, "Event type not handled"),
    }
}

// Helper: Get hardware fingerprint stored in subscription
async fn get_hardware_fingerprint_from_subscription(
    stripe: &stripe::Client,
    subscription_id: &str,
) -> Option<String> {
    // Fetch subscription from Stripe API
    let subscription = stripe::Subscription::retrieve(stripe, subscription_id, &[])
        .await
        .ok()?;
    
    subscription.metadata
        .get("hardware_fingerprint")
        .cloned()
}

// Helper: Update subscription metadata
async fn update_subscription_metadata(
    stripe: &stripe::Client,
    subscription_id: &str,
    metadata: &[(&str, &str)],
) -> Result<(), Error> {
    let mut params = stripe::UpdateSubscription::default();
    params.metadata = Some(metadata.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect());
    
    stripe::Subscription::update(stripe, subscription_id, params).await?;
    Ok(())
}

// Helper: Determine validity based on billing interval
async fn get_validity_days_from_price(stripe: &stripe::Client, price_id: &str) -> u32 {
    if let Ok(price) = stripe::Price::retrieve(stripe, price_id, &[]).await {
        if let Some(recurring) = price.recurring {
            return match recurring.interval {
                stripe::RecurringInterval::Year => 370,
                stripe::RecurringInterval::Month => 35,
                stripe::RecurringInterval::Week => 10,
                stripe::RecurringInterval::Day => 2,
            };
        }
    }
    35 // Default to monthly
}
```

### License Generation with Renewal Metadata

```rust
async fn generate_license(
    state: &AppState,
    email: &str,
    tier: &TierConfig,
    validity_days: u32,
    hardware_fp: Option<&str>,
    subscription_id: Option<&str>,
) -> Result<SignedLicense, Error> {
    let now = chrono::Utc::now();
    
    let mut builder = LicenseData::builder()
        .id(&format!("LIC-{}", &uuid::Uuid::new_v4().to_string()[..8]))
        .serial(&format!("SN-{}", uuid::Uuid::new_v4()))
        .customer_id(email)
        .product_id(&state.config.product_id)
        .valid_days(validity_days as i64)
        .features(tier.features.clone())
        .metadata("tier", &tier.name)
        .metadata("issued_at", &now.to_rfc3339())
        .metadata("validity_days", &validity_days.to_string());
    
    // Link to subscription for tracking
    if let Some(sub_id) = subscription_id {
        builder = builder.metadata("subscription_id", sub_id);
    }
    
    // Hardware binding
    if let Some(fp) = hardware_fp {
        builder = builder.hardware_binding(
            HardwareBinding::new().with_machine_id(fp)
        );
    }
    
    let license_data = builder.build()?;
    let signed = state.generator.generate(license_data)?;
    
    Ok(signed)
}
```

---

## License Delivery Options

### Option 1: Email Each Renewal

```rust
async fn deliver_license(
    state: &AppState,
    email: &str,
    license: &SignedLicense,
    tier: &TierConfig,
) -> Result<(), Error> {
    let binary = state.generator.export_binary(license)?;
    
    send_license_email(
        &state.smtp,
        email,
        &format!("Your {} License (Renewed)", tier.name),
        &binary,
        &format!(
            "Your license has been renewed and is valid until {}.\n\n\
             Replace your existing license.lic file with the attached one.",
            license.data.valid_until.format("%B %d, %Y")
        ),
    ).await
}
```

**Pros:** Simple, works offline
**Cons:** User must manually replace file each month

### Option 2: In-App Auto-Refresh (Recommended)

Your app periodically checks for a new license and downloads it automatically.

```rust
// Client-side: Auto-refresh logic
pub struct LicenseManager {
    license: Option<ValidatedLicense>,
    license_path: PathBuf,
    refresh_endpoint: String,
    public_key: String,
}

impl LicenseManager {
    /// Check if license needs refresh and fetch if needed
    pub async fn maybe_refresh(&mut self) -> Result<(), Error> {
        let Some(license) = &self.license else {
            return Ok(()); // No license to refresh
        };
        
        // Refresh when < 7 days remaining
        if license.days_remaining() > 7 {
            return Ok(()); // Still plenty of time
        }
        
        // Try to fetch new license
        match self.fetch_new_license().await {
            Ok(new_license) => {
                // Save to disk
                let binary = new_license.to_binary()?;
                std::fs::write(&self.license_path, &binary)?;
                
                self.license = Some(new_license);
                info!("License auto-refreshed, valid until {}", self.license.as_ref().unwrap().valid_until);
            }
            Err(e) => {
                // Failed to refresh - that's OK, we still have days left
                warn!("License refresh failed ({}), will retry later: {}", license.days_remaining(), e);
            }
        }
        
        Ok(())
    }
    
    async fn fetch_new_license(&self) -> Result<ValidatedLicense, Error> {
        let license = self.license.as_ref().ok_or(Error::NoLicense)?;
        
        // Get hardware fingerprint
        let fingerprint = get_hardware_fingerprint();
        
        // Request new license from server
        let response = reqwest::Client::new()
            .post(&format!("{}/api/v1/licenses/refresh", self.refresh_endpoint))
            .json(&json!({
                "current_license_id": license.id,
                "customer_id": license.customer_id,
                "hardware_fingerprint": fingerprint,
            }))
            .send()
            .await?;
        
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(Error::RefreshFailed(error));
        }
        
        let data: serde_json::Value = response.json().await?;
        let license_base64 = data["license_base64"].as_str().ok_or(Error::InvalidResponse)?;
        let license_bytes = base64::decode(license_base64)?;
        
        // Verify new license
        let verifier = LicenseVerifier::from_pem(&self.public_key)?;
        let new_license = verifier.load_and_validate_bytes(&license_bytes)?;
        
        Ok(ValidatedLicense::new(new_license))
    }
}

// Usage in your app
#[tokio::main]
async fn main() {
    let mut license_manager = LicenseManager::new(
        "license.lic",
        "https://my-license-server.fly.dev",
        PUBLIC_KEY,
    );
    
    // Initial load
    license_manager.load().expect("License required");
    
    // Spawn background refresh task
    let manager = Arc::new(Mutex::new(license_manager));
    let manager_clone = manager.clone();
    
    tokio::spawn(async move {
        loop {
            // Check every 24 hours
            tokio::time::sleep(Duration::from_secs(86400)).await;
            
            let mut mgr = manager_clone.lock().await;
            if let Err(e) = mgr.maybe_refresh().await {
                error!("License refresh error: {}", e);
            }
        }
    });
    
    // Your app logic
    run_app(manager).await;
}
```

### Server: Refresh Endpoint

```rust
#[derive(Deserialize)]
struct RefreshRequest {
    current_license_id: String,
    customer_id: String,
    hardware_fingerprint: String,
}

async fn refresh_license(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> impl IntoResponse {
    // Look up subscription by customer
    let subscription = state.db
        .get_active_subscription_by_customer(&req.customer_id)
        .await;
    
    let Some(subscription) = subscription else {
        return (StatusCode::PAYMENT_REQUIRED, Json(json!({
            "error": "No active subscription",
            "renew_url": "https://yoursite.com/pricing"
        })));
    };
    
    // Verify hardware fingerprint matches
    if let Some(stored_fp) = &subscription.hardware_fingerprint {
        if stored_fp != &req.hardware_fingerprint {
            return (StatusCode::FORBIDDEN, Json(json!({
                "error": "Hardware mismatch - license bound to different machine"
            })));
        }
    }
    
    // Check subscription is actually active in Stripe
    let stripe_sub = stripe::Subscription::retrieve(
        &state.stripe_client,
        &subscription.stripe_subscription_id,
        &[],
    ).await;
    
    let Ok(stripe_sub) = stripe_sub else {
        return (StatusCode::PAYMENT_REQUIRED, Json(json!({
            "error": "Subscription not found"
        })));
    };
    
    if stripe_sub.status != stripe::SubscriptionStatus::Active 
        && stripe_sub.status != stripe::SubscriptionStatus::Trialing 
    {
        return (StatusCode::PAYMENT_REQUIRED, Json(json!({
            "error": "Subscription not active",
            "status": format!("{:?}", stripe_sub.status)
        })));
    }
    
    // Calculate remaining days in billing period
    let period_end = stripe_sub.current_period_end;
    let now = chrono::Utc::now().timestamp();
    let remaining_seconds = period_end - now;
    let validity_days = (remaining_seconds / 86400) as u32 + 5; // +5 grace
    
    // Get tier from price
    let price_id = stripe_sub.items.data[0].price.as_ref()
        .map(|p| p.id.as_str())
        .unwrap_or("");
    
    let tier = state.config.find_tier_by_price(price_id)
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Unknown tier"))?;
    
    // Generate fresh license
    let license = generate_license(
        &state,
        &req.customer_id,
        tier,
        validity_days,
        Some(&req.hardware_fingerprint),
        Some(&subscription.stripe_subscription_id),
    ).await?;
    
    let binary = state.generator.export_binary(&license)?;
    
    (StatusCode::OK, Json(json!({
        "license_base64": base64::encode(&binary),
        "tier": tier.name,
        "valid_until": license.data.valid_until.to_rfc3339(),
        "days_remaining": validity_days,
    })))
}
```

---

## Complete Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     AUTO-RENEWAL LICENSE FLOW                                │
└─────────────────────────────────────────────────────────────────────────────┘

Day 1: Initial Purchase
───────────────────────
Customer → Stripe checkout → invoice.paid webhook → License v1 (35 days)
                                                          │
                                                          ▼
                                                    [license.lic]
                                                    valid: Day 1-35

Day 28: App checks remaining days
─────────────────────────────────
App: "7 days remaining, let me refresh"
App → POST /api/v1/licenses/refresh
Server: checks Stripe subscription is active
Server: generates License v2 (valid until Day 35 + new period)
App: saves new license.lic
                                                          │
                                                          ▼
                                                    [license.lic]
                                                    valid: Day 28-63

Day 30: Stripe charges renewal
──────────────────────────────
Stripe → invoice.paid webhook → License v2 (35 days from now)
(App might already have this via refresh, idempotency handles it)

Day 60: Customer cancels
────────────────────────
Stripe: subscription.deleted webhook
Server: does NOTHING (no revocation needed!)
App: current license valid until ~Day 65
App: refresh fails ("No active subscription")
App: continues working until Day 65
Day 65: License expires, app shows "Subscription expired"

```

---

## Offline Fallback

What if the user is offline when refresh is needed?

```rust
impl LicenseManager {
    pub fn validate(&self) -> LicenseStatus {
        let Some(license) = &self.license else {
            return LicenseStatus::NoLicense;
        };
        
        let days = license.days_remaining();
        
        if days <= 0 {
            return LicenseStatus::Expired {
                expired_on: license.valid_until,
            };
        }
        
        if days <= 7 && !self.refresh_attempted_recently() {
            return LicenseStatus::NeedsRefresh {
                days_remaining: days,
            };
        }
        
        if days <= 3 {
            return LicenseStatus::ExpiringSoon {
                days_remaining: days,
            };
        }
        
        LicenseStatus::Valid {
            days_remaining: days,
            tier: license.metadata.get("tier").cloned(),
        }
    }
}

pub enum LicenseStatus {
    NoLicense,
    Valid { days_remaining: i64, tier: Option<String> },
    NeedsRefresh { days_remaining: i64 },
    ExpiringSoon { days_remaining: i64 },
    Expired { expired_on: DateTime<Utc> },
}

// In your app's UI
fn show_license_status(status: LicenseStatus) {
    match status {
        LicenseStatus::Valid { days_remaining, tier } => {
            // Show subtle indicator: "Pro • 28 days"
        }
        LicenseStatus::NeedsRefresh { days_remaining } => {
            // Show warning: "License expires in 7 days. Connect to internet to renew."
        }
        LicenseStatus::ExpiringSoon { days_remaining } => {
            // Show urgent warning: "License expires in 3 days!"
        }
        LicenseStatus::Expired { .. } => {
            // Show modal: "Your subscription has expired. Renew at..."
        }
        LicenseStatus::NoLicense => {
            // Show: "Running in free mode. Upgrade at..."
        }
    }
}
```

---

## Configuration Summary

### Server (product.toml)

```toml
product_id = "my-app"

# Validity is now dynamic based on billing interval!
# These are just the feature definitions

[[tiers]]
name = "starter"
features = ["basic", "export"]
price_ids = ["price_starter_monthly", "price_starter_yearly"]

[[tiers]]
name = "pro"  
features = ["basic", "export", "premium", "api"]
price_ids = ["price_pro_monthly", "price_pro_yearly"]
```

### Validity Days (Computed)

| Billing Interval | License Validity | Grace Period |
|------------------|------------------|--------------|
| Monthly          | 35 days          | 5 days       |
| Yearly           | 370 days         | 5 days       |
| Weekly           | 10 days          | 3 days       |

### Client Refresh Strategy

| Days Remaining | Action |
|----------------|--------|
| > 7            | No action |
| 3-7            | Background refresh attempt |
| 1-3            | Aggressive refresh + UI warning |
| 0              | App restricted, show renewal prompt |
