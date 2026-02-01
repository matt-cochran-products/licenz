# Frequently Asked Questions

## General Questions

<details>
<summary><strong>What makes licenz different from other licensing solutions?</strong></summary>

Traditional licensing systems work like this: `License key → Call server → "Is it valid?"`

The license is just a lookup key. The server decides everything. No internet = no validation.

**licenz** makes the license itself the complete contract. Everything—expiry, features, limits, prepaid credits—is cryptographically signed and embedded in the license file. Validation happens offline. Usage tracking happens offline. No server required.

</details>

<details>
<summary><strong>Can I use licenz without running a server?</strong></summary>

**Yes!** That's the whole point. You can:

1. Generate keys locally with `licenz keygen`
2. Create licenses locally with `licenz generate`
3. Distribute licenses to customers (email, download, USB)
4. Customers validate and use them **completely offline**

The optional managed service (licenz.dev, planned) is just a convenience layer for dashboard UI, payment webhooks, and analytics. The core functionality is 100% free and open source.

</details>

<details>
<summary><strong>What languages does licenz support?</strong></summary>

- **Rust**: Native library (`licenz-core`)
- **Any other language**: Shell out to the `licenz` CLI

Since the CLI handles all operations (validation, usage tracking, etc.), you can integrate with Python, Node.js, Go, PHP, Ruby, Java, C#, or any language that can execute shell commands.

Native language bindings are planned for better ergonomics, but the CLI approach is production-ready today.

</details>

---

## Usage Tracking & Credits

<details>
<summary><strong>How does the hash chain work if usage is a running total?</strong></summary>

Great question! The hash chain doesn't store individual transactions—it creates **checkpoints** of the running total at key moments.

**How it works:**

```
Event 1: Use 1 credit
├─ Running total: 1
├─ Hash: SHA256(license_id + metric + amount:1 + total:1 + timestamp + prev_hash:0)
└─ Store: { total: 1, hash: abc123..., seq: 1 }

Event 2: Use 5 credits
├─ Running total: 6 (1 + 5)
├─ Hash: SHA256(license_id + metric + amount:5 + total:6 + timestamp + prev_hash:abc123)
└─ Store: { total: 6, hash: def456..., seq: 2 }

Event 3: Use 10 credits
├─ Running total: 16 (6 + 10)
├─ Hash: SHA256(license_id + metric + amount:10 + total:16 + timestamp + prev_hash:def456)
└─ Store: { total: 16, hash: ghi789..., seq: 3 }
```

**Key points:**

1. Each receipt includes:
   - The **incremental amount** used in this event
   - The **running total** after this event
   - The **previous hash** (chain link)
   - A **sequence number** (prevents reordering)

2. To verify the chain:
   - Start from the first receipt
   - Recompute each hash using the data + previous hash
   - Verify running totals are cumulative
   - Check sequence numbers are monotonic

3. **Why this prevents tampering:**
   - Can't reduce the total (breaks the hash chain)
   - Can't skip events (sequence numbers would have gaps)
   - Can't reorder events (breaks the chain)
   - Can't forge events (requires the signing key)

4. **Efficient storage:**
   - Only store checkpoints (not every single event)
   - Daily/weekly summaries for long-running systems
   - Full chain only needed for audit trails

**Example verification:**

```rust
fn verify_usage_chain(receipts: &[UsageReceipt]) -> bool {
    let mut prev_hash = [0u8; 32]; // Genesis
    let mut running_total = 0;
    
    for (i, receipt) in receipts.iter().enumerate() {
        // Check sequence
        if receipt.seq != i + 1 {
            return false; // Gap in sequence
        }
        
        // Check running total
        running_total += receipt.amount;
        if receipt.total != running_total {
            return false; // Total mismatch
        }
        
        // Verify hash chain
        let computed_hash = hash_receipt(receipt, &prev_hash);
        if computed_hash != receipt.hash {
            return false; // Chain broken
        }
        
        prev_hash = receipt.hash;
    }
    
    true
}
```

</details>

<details>
<summary><strong>Does licenz support rate limiting / throttling?</strong></summary>

**Yes**, but the consumer is responsible for checking the throttle gate.

Throttling is configured via the license **metadata** field:

```bash
# Create license with throttle limits
licenz generate \
  --key keys/private.pem \
  --customer "acme-corp" \
  --credits api_calls:100000 \
  --metadata rate_limit_per_second:100 \
  --metadata rate_limit_per_minute:5000 \
  --metadata rate_limit_per_hour:50000 \
  --output license.lic
```

**In your application:**

```rust
use licenz::Licenz;
use std::time::{Duration, Instant};

struct ThrottleGate {
    license: Licenz,
    last_check: Instant,
    calls_this_second: u32,
}

impl ThrottleGate {
    fn check_rate_limit(&mut self) -> Result<(), String> {
        // Get throttle limit from license metadata
        let limit_per_second: u32 = self.license
            .metadata
            .get("rate_limit_per_second")
            .and_then(|s| s.parse().ok())
            .unwrap_or(u32::MAX);
        
        // Reset counter if new second
        if self.last_check.elapsed() >= Duration::from_secs(1) {
            self.calls_this_second = 0;
            self.last_check = Instant::now();
        }
        
        // Check against limit
        if self.calls_this_second >= limit_per_second {
            return Err(format!("Rate limit exceeded: {} calls/sec", limit_per_second));
        }
        
        self.calls_this_second += 1;
        Ok(())
    }
    
    fn make_api_call(&mut self) -> Result<(), String> {
        // Check rate limit first
        self.check_rate_limit()?;
        
        // Then check/use credits
        self.license.use_credits("api_calls", 1)
            .map_err(|e| format!("Credit exhausted: {}", e))?;
        
        // Make the actual call
        do_api_call();
        
        Ok(())
    }
}
```

**Why consumer-side?**

- Throttling is time-based and requires real-time state
- The license is a static contract, not a runtime service
- Different deployments may need different throttling strategies (per-process, per-machine, distributed)
- Allows flexibility: in-memory counters, Redis, rate-limiting crates, etc.

**Via CLI:**

```bash
# Check metadata in license
licenz info --license license.lic --format json | jq '.metadata'

# Output:
# {
#   "rate_limit_per_second": "100",
#   "rate_limit_per_minute": "5000",
#   "rate_limit_per_hour": "50000"
# }
```

Then implement throttling in your application using your preferred rate-limiting library.

</details>

<details>
<summary><strong>What happens when credits run out?</strong></summary>

You control the behavior via the `exhaustion` policy in the license metadata:

```bash
licenz generate \
  --metadata exhaustion_policy:hard_stop \
  --credits api_calls:100000
```

**Exhaustion policies:**

| Policy | Behavior | Use Case |
|--------|----------|----------|
| `hard_stop` | Feature disabled at 0 credits | Prepaid API calls |
| `warn` | Allow usage, but warn user | Soft limits, overage billing |
| `grace:N` | Allow N more uses after exhaustion | Grace period before cutoff |
| `degrade:tier` | Switch to limited mode | Downgrade to free tier |

**Example:**

```rust
match licenz.use_credits("api_calls", 1) {
    Ok(remaining) => {
        println!("{} credits remaining", remaining);
    }
    Err(LicenseError::Exhausted { metric, remaining }) => {
        // Hard stop - show upgrade prompt
        show_upgrade_dialog();
        return Err("Out of API credits");
    }
}
```

</details>

<details>
<summary><strong>Can I reset credits periodically (monthly, annually)?</strong></summary>

**Yes**, via the `reset_policy` metadata:

```bash
licenz generate \
  --credits api_calls:100000 \
  --metadata reset_policy:monthly \
  --metadata reset_day:1
```

**Reset policies:**

- `never`: Credits never reset (prepaid, one-time)
- `monthly`: Reset on the 1st of each month
- `on_sync`: Reset when synced with server (subscription model)

**Implementation:**

The license stores the reset policy. Your application checks if a reset is due:

```rust
if licenz.should_reset_credits("api_calls")? {
    licenz.reset_credits("api_calls")?;
}

licenz.use_credits("api_calls", 1)?;
```

Or use the CLI:

```bash
# Check if reset is due
licenz usage check-reset --license license.lic --metric api_calls

# Reset if needed
licenz usage reset --license license.lic --metric api_calls
```

</details>

---

## Security & Tampering

<details>
<summary><strong>Can customers tamper with the license file?</strong></summary>

**No.** The license is cryptographically signed with your private key. Any modification breaks the signature.

```
┌─────────────────────────────────────────┐
│ LICENSE DATA                            │
│ - Expiry: 2025-12-31                    │
│ - Features: [premium, api]              │
│ - Credits: 100,000                      │
├─────────────────────────────────────────┤
│ SIGNATURE (RSA-4096)                    │
│ - Computed from license data            │
│ - Signed with YOUR private key          │
│ - Verified with embedded public key     │
└─────────────────────────────────────────┘
```

If a customer tries to:
- Change expiry date → Signature verification fails
- Add features → Signature verification fails
- Increase credits → Signature verification fails
- Copy signature from another license → Wrong data, fails verification

</details>

<details>
<summary><strong>Can customers tamper with usage tracking?</strong></summary>

**Harder, but possible locally.** The hash chain makes it detectable when synced.

**Local tampering:**

If a customer has full control of their machine, they can:
- Modify the local usage database
- Reset counters
- Delete usage history

**However:**

1. **Hash chain breaks** - Any modification is detectable when you verify the chain
2. **Checkpoints are signed** - Can't forge usage reports sent to your server
3. **Sync reveals tampering** - When they sync, you'll see the chain is broken

**Best practices:**

- For high-value usage, sync frequently (daily/weekly)
- For air-gapped deployments, verify usage reports when they renew
- Use the cryptographic receipts to prove authentic usage
- Consider hardware binding to prevent license sharing

</details>

<details>
<summary><strong>What if customers change their system clock?</strong></summary>

licenz detects clock manipulation using **monotonic sequence numbers** and **last-seen timestamps**.

```rust
// Each usage event has a sequence number
Receipt #1: seq=1, timestamp=2025-01-15T10:00:00Z
Receipt #2: seq=2, timestamp=2025-01-15T10:05:00Z
Receipt #3: seq=3, timestamp=2025-01-15T09:00:00Z  // ← Clock went backwards!
```

If the clock goes backwards:
- Sequence numbers keep incrementing (can't fake)
- Timestamp anomaly is detected
- License enters "suspicious" state
- Can require sync to continue

**Anti-tamper features:**

- Monotonic counters (can't be reset)
- Hardware fingerprints (detects VM cloning)
- Activation limits (prevents sharing)
- Grace periods (allows temporary clock issues)

</details>

---

## Deployment & Integration

<details>
<summary><strong>How do I integrate licenz with Stripe/Paddle?</strong></summary>

**Option 1: Manual (CLI-based)**

1. Customer pays via Stripe
2. Stripe webhook hits your server
3. Your server runs: `licenz generate ... --output license.lic`
4. Email license file to customer

**Option 2: Managed service (planned)**

The licenz.dev managed service will handle this automatically:
- Connect Stripe/Paddle/LemonSqueezy
- Webhooks automatically generate licenses
- Customer portal for downloads
- Renewal reminders

**Example webhook handler (manual):**

```rust
#[post("/webhooks/stripe")]
async fn stripe_webhook(payload: Json<StripeEvent>) -> Result<HttpResponse> {
    match payload.event_type {
        "checkout.session.completed" => {
            let customer_email = payload.customer_email;
            let product_id = payload.product_id;
            
            // Generate license
            let output = Command::new("licenz")
                .args(&[
                    "generate",
                    "--key", "keys/private.pem",
                    "--customer", &customer_email,
                    "--product", &product_id,
                    "--features", "premium,api",
                    "--credits", "api_calls:100000",
                    "--days", "365",
                    "--output", &format!("licenses/{}.lic", customer_email),
                ])
                .output()?;
            
            // Email license to customer
            send_email(&customer_email, "Your License", &license_file)?;
            
            Ok(HttpResponse::Ok())
        }
        _ => Ok(HttpResponse::Ok())
    }
}
```

</details>

<details>
<summary><strong>Can I use licenz in Docker/Kubernetes?</strong></summary>

**Yes!** licenz is container-aware and supports ephemeral environments.

**Hardware binding options for containers:**

```bash
# Option 1: No hardware binding (floating license)
licenz generate --no-hardware-binding

# Option 2: Bind to container instance ID
licenz generate --hardware-binding container_id

# Option 3: Bind to cloud instance ID (AWS, GCP, Azure)
licenz generate --hardware-binding cloud_instance

# Option 4: Custom identifier (e.g., Kubernetes pod name)
licenz generate --hardware-binding custom:POD_NAME
```

**In your Dockerfile:**

```dockerfile
FROM rust:1.75 as builder
RUN cargo install licenz-cli

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/licenz /usr/local/bin/
COPY license.lic /app/license.lic

CMD ["your-app"]
```

**Kubernetes deployment:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: license-config
data:
  license.lic: |
    <base64-encoded-license>
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        volumeMounts:
        - name: license
          mountPath: /app/license.lic
          subPath: license.lic
      volumes:
      - name: license
        configMap:
          name: license-config
```

</details>

<details>
<summary><strong>How do I handle license renewals?</strong></summary>

**Automatic renewal (subscription model):**

1. Customer's license expires in 30 days
2. Your billing system charges them
3. Generate new license with extended expiry
4. Customer's app syncs and downloads new license

**Manual renewal (perpetual + maintenance):**

1. Customer requests renewal
2. They export usage report: `licenz usage export`
3. Send report to you (email, portal)
4. You verify usage, generate new license
5. Send new license back to customer

**Grace periods:**

```bash
licenz generate \
  --days 365 \
  --grace-period 30  # 30 days after expiry
```

Allows apps to keep working for 30 days after expiry, giving customers time to renew.

</details>

---

## Air-Gapped & Offline Use

<details>
<summary><strong>How do I deploy to air-gapped environments?</strong></summary>

**Initial deployment:**

1. Generate license on internet-connected machine
2. Transfer `license.lic` via USB/CD/secure transfer
3. Customer installs on air-gapped machine
4. License validates and works offline

**Usage tracking:**

1. App tracks usage locally (hash-chained receipts)
2. Periodically export: `licenz usage export --output report.json`
3. Transfer `report.json` via USB to connected machine
4. Upload to your server for billing/analytics
5. Generate renewed license if needed
6. Transfer new license back via USB

**No network required at any point on the air-gapped machine.**

</details>

<details>
<summary><strong>Can I use licenz on submarines/aircraft/ships?</strong></summary>

**Yes!** That's exactly what it's designed for.

- No internet required
- Works in Faraday cages
- Handles intermittent connectivity
- Export/import usage via physical media
- Hardware binding to specific equipment

Real-world use cases:
- Defense systems (classified networks)
- Maritime (ships, oil rigs)
- Aviation (aircraft systems)
- Manufacturing (factory floor OT networks)
- Medical devices (isolated hospital networks)

</details>

---

## Troubleshooting

<details>
<summary><strong>License validation fails with "Invalid signature"</strong></summary>

**Causes:**

1. **Wrong public key** - Make sure you're using the public key that matches the private key used to sign
2. **Corrupted file** - License file was modified or corrupted during transfer
3. **Wrong file format** - Trying to verify a text file as binary or vice versa

**Debug:**

```bash
# Check license info (doesn't verify signature)
licenz info --license license.lic --no-verify

# Verify with specific key
licenz verify --key keys/public.pem --license license.lic --verbose
```

</details>

<details>
<summary><strong>"Hardware binding mismatch" error</strong></summary>

Your machine's hardware doesn't match the license binding.

**Check your hardware:**

```bash
licenz hardware
```

**Check license binding:**

```bash
licenz info --license license.lic | grep -A5 "Hardware Binding"
```

**Solutions:**

1. Generate new license with correct hardware ID
2. Use floating license (no hardware binding)
3. Use container-aware binding for Docker/K8s

</details>

<details>
<summary><strong>Usage tracking shows wrong totals</strong></summary>

**Possible causes:**

1. **Multiple processes** - Two processes modifying usage simultaneously
2. **File corruption** - Usage database was corrupted
3. **Clock issues** - System clock changed

**Fix:**

```bash
# Verify usage chain integrity
licenz usage verify --license license.lic

# If broken, export what you can
licenz usage export --license license.lic --best-effort

# Reset from last good checkpoint
licenz usage reset --license license.lic --from-checkpoint
```

</details>

---

## Contributing & Development

<details>
<summary><strong>How can I contribute?</strong></summary>

We'd love help with:

- **Native language bindings** (Python, Node.js, Go, etc.)
- **Additional CLI features**
- **Documentation improvements**
- **Security audits**
- **Real-world testing** in air-gapped environments

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

</details>

<details>
<summary><strong>Is there a roadmap?</strong></summary>

Yes! See the [README](../README2.md#roadmap) for current status and planned features.

</details>

<details>
<summary><strong>Can I use licenz in commercial products?</strong></summary>

**Yes!** licenz is MIT licensed. You can:

- Use it in commercial products
- Modify it for your needs
- Redistribute it
- Keep your modifications private

No attribution required (but appreciated!).

</details>

---

## Still have questions?

- 💬 [GitHub Discussions](https://github.com/licenz-dev/licenz/discussions)
- 🐛 [Issue Tracker](https://github.com/licenz-dev/licenz/issues)
- 📖 [Documentation](.)
