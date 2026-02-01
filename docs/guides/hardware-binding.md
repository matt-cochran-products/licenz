# Hardware Binding

Hardware binding ties a license to specific hardware, preventing customers from sharing license files across multiple machines.

## How It Works

The license contains hardware identifiers (MAC address, disk ID, hostname, etc.). When validating, licenz checks if the current machine's hardware matches what's in the license.

```
┌─────────────────────────────────────────┐
│ LICENSE                                 │
├─────────────────────────────────────────┤
│ Customer: acme-corp                     │
│ Expires: 2025-12-31                     │
│ Features: [premium, api]                │
│                                         │
│ Hardware Binding:                       │
│   MAC: AA:BB:CC:DD:EE:FF               │
│   Hostname: prod-server-01              │
│   Disk ID: DISK-12345                   │
└─────────────────────────────────────────┘
         │
         │ Validation checks:
         │ ✓ Signature valid
         │ ✓ Not expired
         │ ✓ Hardware matches
         ▼
    ┌─────────┐
    │ VALID ✓ │
    └─────────┘
```

If someone copies the license to a different machine, validation fails because the hardware doesn't match.

---

## Getting Hardware Info

### Check Current Machine's Hardware

```bash
licenz hardware
```

**Output:**
```
Hardware Information:
  MAC Addresses:
    - AA:BB:CC:DD:EE:FF
    - 11:22:33:44:55:66
  
  Disk IDs:
    - DISK-12345-ABCDE
  
  Hostname: prod-server-01
  
  Machine ID: a1b2c3d4e5f6g7h8
  
  Container: No
```

### Get as JSON

```bash
licenz hardware --format json
```

**Output:**
```json
{
  "mac_addresses": ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"],
  "disk_ids": ["DISK-12345-ABCDE"],
  "hostname": "prod-server-01",
  "machine_id": "a1b2c3d4e5f6g7h8",
  "container": false
}
```

---

## Creating Hardware-Bound Licenses

### Bind to Specific MAC Address

```bash
licenz generate \
  --key keys/private.pem \
  --customer "acme-corp" \
  --features premium,api \
  --days 365 \
  --bind-mac "AA:BB:CC:DD:EE:FF" \
  --output license.lic
```

### Bind to Hostname

```bash
licenz generate \
  --key keys/private.pem \
  --customer "acme-corp" \
  --bind-hostname "prod-server-01" \
  --output license.lic
```

### Bind to Multiple Factors (Stronger)

```bash
licenz generate \
  --key keys/private.pem \
  --customer "acme-corp" \
  --bind-mac "AA:BB:CC:DD:EE:FF" \
  --bind-hostname "prod-server-01" \
  --bind-disk "DISK-12345-ABCDE" \
  --output license.lic
```

### Allow Multiple MACs (Any Match)

Useful for machines with multiple network interfaces:

```bash
licenz generate \
  --key keys/private.pem \
  --customer "acme-corp" \
  --bind-mac "AA:BB:CC:DD:EE:FF" \
  --bind-mac "11:22:33:44:55:66" \
  --output license.lic
```

The license validates if **any** of the allowed MACs match.

---

## Validation

### Automatic Hardware Check

By default, `licenz verify` checks hardware binding:

```bash
licenz verify --key keys/public.pem --license license.lic
```

**Success:**
```
✓ Signature valid
✓ Not expired
✓ Hardware binding matches
License is VALID
```

**Failure:**
```
✗ Hardware binding mismatch
  Expected MAC: AA:BB:CC:DD:EE:FF
  Found MACs: 11:22:33:44:55:66, 99:88:77:66:55:44
License is INVALID
```

### Skip Hardware Check (Testing)

```bash
licenz verify --key keys/public.pem --license license.lic --no-hardware-check
```

---

## Use Cases

### 1. Single-Machine Licenses

Bind to specific hardware for desktop software or on-premise deployments:

```bash
# Customer runs this to get their hardware ID
licenz hardware --format json > hardware.json

# Send hardware.json to you
# You generate bound license
licenz generate \
  --key keys/private.pem \
  --customer "customer@example.com" \
  --bind-mac "$(jq -r '.mac_addresses[0]' hardware.json)" \
  --output license.lic

# Send license.lic back to customer
```

### 2. Floating Licenses (No Hardware Binding)

For cloud deployments or multi-machine licenses:

```bash
licenz generate \
  --key keys/private.pem \
  --customer "acme-corp" \
  --no-hardware-binding \
  --output license.lic
```

### 3. Container-Aware Binding

For Docker/Kubernetes, bind to container instance ID instead of hardware:

```bash
licenz generate \
  --key keys/private.pem \
  --customer "acme-corp" \
  --bind-container \
  --output license.lic
```

This binds to:
- AWS EC2 instance ID
- GCP instance ID  
- Azure VM ID
- Kubernetes pod name
- Docker container ID

### 4. Seat-Based Licenses

Allow N concurrent machines without hardware binding:

```bash
licenz generate \
  --key keys/private.pem \
  --customer "acme-corp" \
  --max-seats 10 \
  --no-hardware-binding \
  --output license.lic
```

The license tracks active machines and enforces the seat limit without binding to specific hardware.

---

## In Your Application (Rust)

### Detect Hardware

```rust
use licenz_core::detect_hardware;

fn main() {
    let hw = detect_hardware();
    
    println!("MAC addresses: {:?}", hw.mac_addresses);
    println!("Hostname: {:?}", hw.hostname);
    println!("Machine ID: {:?}", hw.machine_id);
}
```

### Validate with Hardware Check

```rust
use licenz_core::{require_license, LicenseVerifier};

const PUBLIC_KEY: &str = include_str!("../keys/public.pem");

fn main() {
    // Automatically checks hardware binding
    let license = require_license("license.lic", PUBLIC_KEY)
        .expect("Valid license required");
    
    println!("Licensed to: {}", license.customer_id);
}
```

### Custom Hardware Verification

```rust
use licenz_core::{LicenseVerifier, detect_hardware, verify_hardware_binding};

let verifier = LicenseVerifier::new(public_key);
let license = verifier.load_from_file("license.lic")?;

// Validate signature and expiry
verifier.validate(&license)?;

// Check hardware binding
let hw = detect_hardware();
match verify_hardware_binding(&license.data.hardware_binding, &hw) {
    Ok(_) => println!("Hardware matches"),
    Err(e) => {
        eprintln!("Hardware mismatch: {}", e);
        std::process::exit(1);
    }
}
```

---

## Security Considerations

### Strengths

✅ **Prevents casual sharing** - Can't just copy license file to another machine
✅ **Multiple factors** - Combine MAC + hostname + disk for stronger binding
✅ **Flexible** - Choose binding strength based on your needs

### Limitations

⚠️ **VM cloning** - Cloned VMs have identical hardware IDs (use activation limits)
⚠️ **MAC spoofing** - Advanced users can spoof MAC addresses (use machine_id)
⚠️ **Hardware changes** - Replacing network card breaks binding (offer re-binding)

### Best Practices

1. **Use machine_id when available** - Most reliable, survives hardware changes
2. **Allow multiple MACs** - Machines have multiple network interfaces
3. **Combine with activation limits** - Limit total activations even without hardware binding
4. **Offer re-binding** - Let customers transfer licenses to new hardware
5. **Use seat limits for teams** - Better than hardware binding for multi-user licenses

---

## Troubleshooting

### "Hardware binding mismatch" Error

**Check what the license expects:**
```bash
licenz info --license license.lic
```

**Check your current hardware:**
```bash
licenz hardware
```

**Compare the two and identify the mismatch.**

### Network Interface Changes

If a customer replaces their network card:

```bash
# Get new hardware info
licenz hardware --format json > new_hardware.json

# Generate new license with updated binding
licenz generate \
  --key keys/private.pem \
  --customer "customer@example.com" \
  --bind-mac "$(jq -r '.mac_addresses[0]' new_hardware.json)" \
  --output new_license.lic
```

### Container Environments

For Docker/Kubernetes, don't use MAC/disk binding:

```bash
# Option 1: No hardware binding
licenz generate --no-hardware-binding

# Option 2: Container-aware binding
licenz generate --bind-container

# Option 3: Seat limits
licenz generate --max-seats 10 --no-hardware-binding
```

---

## FAQ

<details>
<summary><strong>Should I always use hardware binding?</strong></summary>

**No.** It depends on your use case:

- **Desktop software**: Yes, prevents casual sharing
- **Cloud/SaaS**: No, use seat limits or API keys instead
- **On-premise servers**: Yes, bind to machine_id
- **Docker/K8s**: No, use container-aware binding or seat limits
- **Team licenses**: No, use seat limits

</details>

<details>
<summary><strong>Can customers change hardware?</strong></summary>

Yes, but they'll need a new license. Best practices:

1. Offer self-service re-binding (customer portal)
2. Allow N hardware changes per year
3. Track activation history to detect abuse
4. Use machine_id instead of MAC (survives minor changes)

</details>

<details>
<summary><strong>What if a customer has multiple network interfaces?</strong></summary>

Allow multiple MACs in the license:

```bash
licenz generate \
  --bind-mac "AA:BB:CC:DD:EE:FF" \
  --bind-mac "11:22:33:44:55:66"
```

The license validates if **any** MAC matches.

</details>

<details>
<summary><strong>How do I prevent VM cloning?</strong></summary>

VM cloning duplicates hardware IDs. Use:

1. **Activation limits** - Limit total activations
2. **Phone home** - Periodic server check-ins
3. **Usage tracking** - Detect simultaneous usage from "same" machine
4. **Cloud instance IDs** - Bind to AWS/GCP/Azure instance IDs (unique per VM)

</details>

---

## See Also

- [FAQ](FAQ.md) - Common questions about hardware binding
- [README](../README2.md) - Getting started guide
