# Payment Provider Abstraction Layer

## Design Principles

1. **Provider Agnostic**: Core licensing logic knows nothing about Stripe, Paddle, LemonSqueezy, etc.
2. **Event-Driven**: Providers emit standardized events, licensing system reacts
3. **Idempotent**: Same event processed multiple times = same result
4. **Auditable**: Every license generation tied to a payment event

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PAYMENT PROVIDERS                                  │
├─────────────┬─────────────┬─────────────┬─────────────┬─────────────────────┤
│   Stripe    │   Paddle    │ LemonSqueezy│   PayPal    │   Manual/Custom     │
└──────┬──────┴──────┬──────┴──────┬──────┴──────┬──────┴──────────┬──────────┘
       │             │             │             │                 │
       ▼             ▼             ▼             ▼                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PROVIDER ADAPTERS                                     │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐    │
│  │StripeAdapter  │ │PaddleAdapter  │ │LemonAdapter   │ │ManualAdapter  │    │
│  │               │ │               │ │               │ │               │    │
│  │ • Verify sig  │ │ • Verify sig  │ │ • Verify sig  │ │ • API key     │    │
│  │ • Map events  │ │ • Map events  │ │ • Map events  │ │ • Map events  │    │
│  │ • Extract $   │ │ • Extract $   │ │ • Extract $   │ │ • Manual tier │    │
│  └───────┬───────┘ └───────┬───────┘ └───────┬───────┘ └───────┬───────┘    │
│          │                 │                 │                 │            │
│          └─────────────────┴─────────────────┴─────────────────┘            │
│                                    │                                         │
│                                    ▼                                         │
│                    ┌───────────────────────────────┐                        │
│                    │   PaymentEvent (Canonical)    │                        │
│                    │                               │                        │
│                    │ • event_id: String            │                        │
│                    │ • event_type: EventType       │                        │
│                    │ • customer: CustomerInfo      │                        │
│                    │ • product: ProductInfo        │                        │
│                    │ • amount: Money               │                        │
│                    │ • provider: ProviderInfo      │                        │
│                    │ • raw_payload: Value          │                        │
│                    └───────────────┬───────────────┘                        │
└────────────────────────────────────┼────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LICENSE ORCHESTRATOR                                 │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      Product Configuration                           │   │
│  │                                                                      │   │
│  │  product_id: "my-app"                                               │   │
│  │  tiers:                                                              │   │
│  │    - name: "starter"                                                │   │
│  │      features: ["basic"]                                            │   │
│  │      max_seats: 1                                                   │   │
│  │      price_patterns:                                                │   │
│  │        - provider: "*"                                              │   │
│  │          pattern: "*starter*"  # matches any price with "starter"  │   │
│  │        - provider: "stripe"                                         │   │
│  │          pattern: "price_starter_*"                                 │   │
│  │        - provider: "paddle"                                         │   │
│  │          pattern: "pri_starter_*"                                   │   │
│  │    - name: "pro"                                                    │   │
│  │      features: ["basic", "premium", "api"]                          │   │
│  │      max_seats: 10                                                  │   │
│  │      price_patterns: [...]                                          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                        │
│                                     ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     Event → License Mapping                          │   │
│  │                                                                      │   │
│  │  PaymentCompleted  → Generate new license                           │   │
│  │  SubscriptionRenewed → Extend existing license                      │   │
│  │  SubscriptionCanceled → Mark for expiry (no new license)            │   │
│  │  RefundIssued → Revoke license                                      │   │
│  │  SubscriptionUpgraded → Generate new license with new tier          │   │
│  │  SubscriptionDowngraded → Generate new license with new tier        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LICENSE GENERATION                                   │
│                                                                              │
│                    licenz-core (unchanged)                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Core Types

```rust
//! Payment provider abstraction types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Canonical payment event - all providers map to this
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentEvent {
    /// Unique event ID (from provider)
    pub event_id: String,
    
    /// Idempotency key (provider + event_id)
    pub idempotency_key: String,
    
    /// Type of event
    pub event_type: PaymentEventType,
    
    /// When the event occurred
    pub timestamp: DateTime<Utc>,
    
    /// Customer information
    pub customer: CustomerInfo,
    
    /// Product/subscription information
    pub product: ProductInfo,
    
    /// Payment amount (if applicable)
    pub amount: Option<Money>,
    
    /// Provider-specific information
    pub provider: ProviderInfo,
    
    /// Raw webhook payload for debugging
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_payload: Option<serde_json::Value>,
}

/// Standardized event types across all providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentEventType {
    /// One-time payment completed
    PaymentCompleted,
    
    /// New subscription started
    SubscriptionCreated,
    
    /// Subscription renewed (recurring payment)
    SubscriptionRenewed,
    
    /// Subscription canceled (will expire at period end)
    SubscriptionCanceled,
    
    /// Subscription immediately terminated
    SubscriptionTerminated,
    
    /// Subscription upgraded to higher tier
    SubscriptionUpgraded,
    
    /// Subscription downgraded to lower tier
    SubscriptionDowngraded,
    
    /// Payment failed (card declined, etc.)
    PaymentFailed,
    
    /// Refund issued
    RefundIssued,
    
    /// Chargeback/dispute opened
    DisputeOpened,
    
    /// Trial started
    TrialStarted,
    
    /// Trial ended (converted or expired)
    TrialEnded,
}

impl PaymentEventType {
    /// Does this event type result in license generation?
    pub fn generates_license(&self) -> bool {
        matches!(
            self,
            Self::PaymentCompleted
                | Self::SubscriptionCreated
                | Self::SubscriptionRenewed
                | Self::SubscriptionUpgraded
                | Self::SubscriptionDowngraded
                | Self::TrialStarted
        )
    }
    
    /// Does this event type result in license revocation?
    pub fn revokes_license(&self) -> bool {
        matches!(
            self,
            Self::RefundIssued | Self::SubscriptionTerminated | Self::DisputeOpened
        )
    }
}

/// Customer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerInfo {
    /// Provider's customer ID
    pub provider_customer_id: String,
    
    /// Customer email
    pub email: String,
    
    /// Customer name (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    
    /// Your internal customer ID (if mapped)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_customer_id: Option<String>,
    
    /// Additional metadata
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

/// Product/subscription information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductInfo {
    /// Provider's product/price ID
    pub provider_product_id: String,
    
    /// Provider's price/plan ID
    pub provider_price_id: String,
    
    /// Your internal product ID (mapped from config)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_product_id: Option<String>,
    
    /// Determined tier name (mapped from config)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    
    /// Subscription ID (for recurring)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    
    /// Current period end (for subscriptions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_period_end: Option<DateTime<Utc>>,
    
    /// Is this a trial?
    #[serde(default)]
    pub is_trial: bool,
    
    /// Quantity/seats purchased
    #[serde(default = "default_quantity")]
    pub quantity: u32,
}

fn default_quantity() -> u32 {
    1
}

/// Money amount with currency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Money {
    /// Amount in smallest currency unit (cents, pence, etc.)
    pub amount: i64,
    
    /// ISO 4217 currency code
    pub currency: String,
}

impl Money {
    pub fn new(amount: i64, currency: impl Into<String>) -> Self {
        Self {
            amount,
            currency: currency.into().to_uppercase(),
        }
    }
    
    /// Format as human-readable string
    pub fn display(&self) -> String {
        let major = self.amount / 100;
        let minor = (self.amount % 100).abs();
        format!("{}.{:02} {}", major, minor, self.currency)
    }
}

/// Provider information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    /// Provider name
    pub name: PaymentProvider,
    
    /// Provider's unique event ID
    pub event_id: String,
    
    /// Was the webhook signature verified?
    pub signature_verified: bool,
    
    /// Provider API version (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,
}

/// Supported payment providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PaymentProvider {
    Stripe,
    Paddle,
    LemonSqueezy,
    PayPal,
    Gumroad,
    FastSpring,
    Chargebee,
    /// For manual license generation via admin API
    Manual,
    /// Custom/unknown provider
    Custom,
}

impl PaymentProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stripe => "stripe",
            Self::Paddle => "paddle",
            Self::LemonSqueezy => "lemonsqueezy",
            Self::PayPal => "paypal",
            Self::Gumroad => "gumroad",
            Self::FastSpring => "fastspring",
            Self::Chargebee => "chargebee",
            Self::Manual => "manual",
            Self::Custom => "custom",
        }
    }
}
```

## Provider Adapter Trait

```rust
//! Provider adapter trait - implement this for each payment provider

use async_trait::async_trait;

/// Adapter for converting provider-specific webhooks to canonical events
#[async_trait]
pub trait PaymentProviderAdapter: Send + Sync {
    /// Provider name
    fn provider(&self) -> PaymentProvider;
    
    /// Verify webhook signature
    /// Returns the raw payload if valid, error if invalid
    fn verify_signature(
        &self,
        payload: &[u8],
        signature: &str,
        timestamp: Option<&str>,
    ) -> Result<(), WebhookError>;
    
    /// Parse webhook payload into canonical event
    fn parse_event(
        &self,
        payload: &[u8],
    ) -> Result<PaymentEvent, WebhookError>;
    
    /// Combined verify + parse (convenience method)
    fn process_webhook(
        &self,
        payload: &[u8],
        signature: &str,
        timestamp: Option<&str>,
    ) -> Result<PaymentEvent, WebhookError> {
        self.verify_signature(payload, signature, timestamp)?;
        self.parse_event(payload)
    }
    
    /// Get the HTTP header name for the signature
    fn signature_header(&self) -> &'static str;
    
    /// Get the HTTP header name for the timestamp (if separate)
    fn timestamp_header(&self) -> Option<&'static str> {
        None
    }
}

/// Webhook processing errors
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Timestamp too old: {age_seconds}s > {max_seconds}s")]
    TimestampTooOld { age_seconds: i64, max_seconds: i64 },
    
    #[error("Failed to parse payload: {0}")]
    ParseError(String),
    
    #[error("Unknown event type: {0}")]
    UnknownEventType(String),
    
    #[error("Missing required field: {0}")]
    MissingField(String),
    
    #[error("Provider error: {0}")]
    ProviderError(String),
}
```

## Example Adapter: Stripe

```rust
//! Stripe adapter implementation

use super::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub struct StripeAdapter {
    webhook_secret: String,
    max_age_seconds: i64,
}

impl StripeAdapter {
    pub fn new(webhook_secret: impl Into<String>) -> Self {
        Self {
            webhook_secret: webhook_secret.into(),
            max_age_seconds: 300, // 5 minutes
        }
    }
}

#[async_trait]
impl PaymentProviderAdapter for StripeAdapter {
    fn provider(&self) -> PaymentProvider {
        PaymentProvider::Stripe
    }
    
    fn signature_header(&self) -> &'static str {
        "Stripe-Signature"
    }
    
    fn verify_signature(
        &self,
        payload: &[u8],
        signature: &str,
        _timestamp: Option<&str>,
    ) -> Result<(), WebhookError> {
        // Parse Stripe signature header: t=timestamp,v1=signature
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
        
        let timestamp = timestamp.ok_or(WebhookError::InvalidSignature)?;
        let expected_sig = sig_v1.ok_or(WebhookError::InvalidSignature)?;
        
        // Check timestamp freshness
        let ts: i64 = timestamp.parse().map_err(|_| WebhookError::InvalidSignature)?;
        let now = chrono::Utc::now().timestamp();
        let age = now - ts;
        
        if age > self.max_age_seconds {
            return Err(WebhookError::TimestampTooOld {
                age_seconds: age,
                max_seconds: self.max_age_seconds,
            });
        }
        
        // Compute expected signature
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));
        
        let mut mac = Hmac::<Sha256>::new_from_slice(self.webhook_secret.as_bytes())
            .map_err(|_| WebhookError::InvalidSignature)?;
        mac.update(signed_payload.as_bytes());
        
        let computed = hex::encode(mac.finalize().into_bytes());
        
        // Constant-time comparison
        if computed.len() != expected_sig.len() {
            return Err(WebhookError::InvalidSignature);
        }
        
        let matches = computed
            .bytes()
            .zip(expected_sig.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        
        if matches != 0 {
            return Err(WebhookError::InvalidSignature);
        }
        
        Ok(())
    }
    
    fn parse_event(&self, payload: &[u8]) -> Result<PaymentEvent, WebhookError> {
        let event: serde_json::Value = serde_json::from_slice(payload)
            .map_err(|e| WebhookError::ParseError(e.to_string()))?;
        
        let event_type = event["type"]
            .as_str()
            .ok_or_else(|| WebhookError::MissingField("type".into()))?;
        
        let event_id = event["id"]
            .as_str()
            .ok_or_else(|| WebhookError::MissingField("id".into()))?;
        
        let data = &event["data"]["object"];
        
        let payment_event_type = match event_type {
            "checkout.session.completed" => PaymentEventType::PaymentCompleted,
            "customer.subscription.created" => PaymentEventType::SubscriptionCreated,
            "invoice.paid" => PaymentEventType::SubscriptionRenewed,
            "customer.subscription.updated" => {
                // Check if upgrade or downgrade based on previous_attributes
                if event["data"]["previous_attributes"]["items"].is_array() {
                    // Price changed - would need to compare old vs new to determine direction
                    PaymentEventType::SubscriptionUpgraded // Simplified
                } else {
                    return Err(WebhookError::UnknownEventType(event_type.into()));
                }
            }
            "customer.subscription.deleted" => PaymentEventType::SubscriptionTerminated,
            "charge.refunded" => PaymentEventType::RefundIssued,
            "charge.dispute.created" => PaymentEventType::DisputeOpened,
            _ => return Err(WebhookError::UnknownEventType(event_type.into())),
        };
        
        // Extract customer info
        let customer_id = data["customer"]
            .as_str()
            .unwrap_or("")
            .to_string();
        
        let customer_email = data["customer_email"]
            .as_str()
            .or_else(|| data["customer_details"]["email"].as_str())
            .unwrap_or("")
            .to_string();
        
        // Extract product info (simplified - real impl would handle line_items)
        let subscription_id = data["subscription"]
            .as_str()
            .map(String::from);
        
        let price_id = data["lines"]["data"][0]["price"]["id"]
            .as_str()
            .or_else(|| data["items"]["data"][0]["price"]["id"].as_str())
            .unwrap_or("")
            .to_string();
        
        let product_id = data["lines"]["data"][0]["price"]["product"]
            .as_str()
            .or_else(|| data["items"]["data"][0]["price"]["product"].as_str())
            .unwrap_or("")
            .to_string();
        
        // Extract amount
        let amount = data["amount_total"]
            .as_i64()
            .or_else(|| data["amount_paid"].as_i64());
        
        let currency = data["currency"]
            .as_str()
            .unwrap_or("usd")
            .to_uppercase();
        
        let timestamp = event["created"]
            .as_i64()
            .map(|ts| chrono::DateTime::from_timestamp(ts, 0).unwrap_or_else(chrono::Utc::now))
            .unwrap_or_else(chrono::Utc::now);
        
        Ok(PaymentEvent {
            event_id: event_id.to_string(),
            idempotency_key: format!("stripe:{}", event_id),
            event_type: payment_event_type,
            timestamp,
            customer: CustomerInfo {
                provider_customer_id: customer_id,
                email: customer_email,
                name: data["customer_details"]["name"].as_str().map(String::from),
                internal_customer_id: None,
                metadata: HashMap::new(),
            },
            product: ProductInfo {
                provider_product_id: product_id,
                provider_price_id: price_id,
                internal_product_id: None,
                tier: None, // Mapped later by orchestrator
                subscription_id,
                current_period_end: data["current_period_end"]
                    .as_i64()
                    .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
                is_trial: data["status"].as_str() == Some("trialing"),
                quantity: data["quantity"].as_u64().unwrap_or(1) as u32,
            },
            amount: amount.map(|a| Money::new(a, &currency)),
            provider: ProviderInfo {
                name: PaymentProvider::Stripe,
                event_id: event_id.to_string(),
                signature_verified: true,
                api_version: event["api_version"].as_str().map(String::from),
            },
            raw_payload: Some(event),
        })
    }
}
```

## Product Configuration (YAML/JSON)

```yaml
# product-config.yaml
product_id: "my-saas-app"
product_name: "My SaaS App"

# License defaults
license_defaults:
  validity_days: 35  # Slightly more than monthly billing
  hardware_binding: false
  
# Tier definitions
tiers:
  - name: "free"
    features: ["basic"]
    max_seats: 1
    validity_days: 36500  # 100 years (effectively unlimited)
    
  - name: "starter"
    features: ["basic", "email_support"]
    max_seats: 1
    validity_days: 35
    price_matchers:
      # Matches any provider with these patterns
      - pattern: "*starter*"
      - pattern: "*basic*"
      # Provider-specific overrides
      - provider: "stripe"
        patterns: ["price_starter_monthly", "price_starter_yearly"]
      - provider: "paddle"
        patterns: ["pri_01h*_starter"]
      - provider: "lemonsqueezy"
        patterns: ["variant_starter_*"]
        
  - name: "pro"
    features: ["basic", "premium", "api_access", "priority_support"]
    max_seats: 10
    validity_days: 35
    price_matchers:
      - pattern: "*pro*"
      - pattern: "*professional*"
      - provider: "stripe"
        patterns: ["price_pro_monthly", "price_pro_yearly"]
        
  - name: "enterprise"
    features: ["basic", "premium", "enterprise", "api_access", "sso", "audit_log", "dedicated_support"]
    max_seats: 0  # Unlimited
    validity_days: 35
    price_matchers:
      - pattern: "*enterprise*"
      - pattern: "*business*"

# Event handling rules
event_rules:
  payment_completed:
    action: "generate_license"
    
  subscription_created:
    action: "generate_license"
    
  subscription_renewed:
    action: "extend_license"
    
  subscription_canceled:
    action: "mark_non_renewing"
    # License continues until current_period_end
    
  subscription_terminated:
    action: "revoke_license"
    
  refund_issued:
    action: "revoke_license"
    conditions:
      - full_refund: true
      
  dispute_opened:
    action: "suspend_license"
    
  trial_started:
    action: "generate_license"
    override_validity_days: 14
```

## License Orchestrator

```rust
//! License orchestrator - maps payment events to license operations

pub struct LicenseOrchestrator {
    config: ProductConfig,
    generator: LicenseGenerator,
    license_store: Box<dyn LicenseStore>,
    event_log: Box<dyn EventLog>,
}

impl LicenseOrchestrator {
    /// Process a payment event and take appropriate action
    pub async fn process_event(&self, event: PaymentEvent) -> Result<ProcessingResult, OrchestratorError> {
        // Idempotency check
        if self.event_log.was_processed(&event.idempotency_key).await? {
            return Ok(ProcessingResult::AlreadyProcessed);
        }
        
        // Map price to tier
        let tier = self.config.match_tier(
            &event.product.provider_price_id,
            event.provider.name,
        ).ok_or_else(|| OrchestratorError::UnknownPrice(
            event.product.provider_price_id.clone()
        ))?;
        
        // Determine action based on event type
        let result = match event.event_type {
            PaymentEventType::PaymentCompleted |
            PaymentEventType::SubscriptionCreated |
            PaymentEventType::SubscriptionRenewed |
            PaymentEventType::TrialStarted => {
                self.generate_license(&event, &tier).await?
            }
            
            PaymentEventType::SubscriptionUpgraded |
            PaymentEventType::SubscriptionDowngraded => {
                self.update_license(&event, &tier).await?
            }
            
            PaymentEventType::RefundIssued |
            PaymentEventType::SubscriptionTerminated |
            PaymentEventType::DisputeOpened => {
                self.revoke_license(&event).await?
            }
            
            PaymentEventType::SubscriptionCanceled => {
                self.mark_non_renewing(&event).await?
            }
            
            _ => ProcessingResult::Ignored,
        };
        
        // Log successful processing
        self.event_log.mark_processed(&event.idempotency_key, &result).await?;
        
        Ok(result)
    }
    
    async fn generate_license(
        &self,
        event: &PaymentEvent,
        tier: &TierConfig,
    ) -> Result<ProcessingResult, OrchestratorError> {
        let validity_days = if event.product.is_trial {
            self.config.trial_days.unwrap_or(14)
        } else {
            tier.validity_days
        };
        
        let license_data = LicenseData::builder()
            .id(&format!("LIC-{}", &event.event_id[..8]))
            .serial(&format!("SN-{}", uuid::Uuid::new_v4()))
            .customer_id(&event.customer.email)
            .product_id(&self.config.product_id)
            .valid_days(validity_days as i64)
            .features(tier.features.clone())
            .max_seats(tier.max_seats)
            .metadata("provider", event.provider.name.as_str())
            .metadata("provider_customer_id", &event.customer.provider_customer_id)
            .metadata("tier", &tier.name)
            .build()?;
        
        let signed = self.generator.generate(license_data)?;
        let license_binary = self.generator.export_binary(&signed)?;
        
        // Store license
        self.license_store.store(
            &event.customer.email,
            &signed,
            &license_binary,
        ).await?;
        
        Ok(ProcessingResult::LicenseGenerated {
            license_id: signed.data.id.clone(),
            tier: tier.name.clone(),
            valid_until: signed.data.valid_until,
        })
    }
}
```

## HTTP Endpoint (Framework Agnostic)

```rust
/// Webhook handler that works with any provider
pub async fn handle_webhook(
    provider_name: &str,
    payload: Bytes,
    headers: &HeaderMap,
    state: &AppState,
) -> Result<impl IntoResponse, WebhookError> {
    // Get the appropriate adapter
    let adapter = state.adapters.get(provider_name)
        .ok_or_else(|| WebhookError::ProviderError(
            format!("Unknown provider: {}", provider_name)
        ))?;
    
    // Extract signature from headers
    let signature = headers
        .get(adapter.signature_header())
        .and_then(|v| v.to_str().ok())
        .ok_or(WebhookError::InvalidSignature)?;
    
    let timestamp = adapter.timestamp_header()
        .and_then(|h| headers.get(h))
        .and_then(|v| v.to_str().ok());
    
    // Process webhook
    let event = adapter.process_webhook(&payload, signature, timestamp)?;
    
    // Hand off to orchestrator
    let result = state.orchestrator.process_event(event).await?;
    
    Ok(Json(result))
}

// Routes (using Axum, but easily adapted)
pub fn webhook_routes() -> Router<AppState> {
    Router::new()
        .route("/webhooks/stripe", post(|s, b, h| handle_webhook("stripe", b, &h, &s)))
        .route("/webhooks/paddle", post(|s, b, h| handle_webhook("paddle", b, &h, &s)))
        .route("/webhooks/lemonsqueezy", post(|s, b, h| handle_webhook("lemonsqueezy", b, &h, &s)))
        .route("/webhooks/paypal", post(|s, b, h| handle_webhook("paypal", b, &h, &s)))
        // Generic endpoint that reads provider from path
        .route("/webhooks/:provider", post(generic_webhook_handler))
}
```

## Benefits of This Design

| Aspect | Benefit |
|--------|---------|
| **Loose coupling** | Add new provider by implementing one trait |
| **Single source of truth** | Tier→features mapping in config, not code |
| **Testability** | Mock adapters for testing without real webhooks |
| **Auditability** | Every license tied to idempotency_key |
| **Portability** | Switch providers without changing core logic |
| **Graceful migration** | Run multiple providers simultaneously |

## Adding a New Provider

1. Implement `PaymentProviderAdapter` trait
2. Add webhook secret to config
3. Add price patterns to product config
4. Register adapter in startup
5. Point provider webhook URL to `/webhooks/{provider}`

That's it. No changes to licensing logic, tier definitions, or event handling.
