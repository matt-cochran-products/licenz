# Quick Start

Get up and running with licenz in 5 minutes.

## Installation

```bash
cargo install licenz-cli
```

## 1. Generate Keys (Once)

```bash
licenz keygen --output ./keys
```

This creates:
- `keys/private.pem` - Keep secret! Used to sign licenses
- `keys/public.pem` - Embed in your app to verify licenses

## 2. Create a License

```bash
licenz generate \
  --key keys/private.pem \
  --customer "acme-corp" \
  --product "my-app" \
  --features premium,api \
  --credits api_calls:100000 \
  --days 365 \
  --output license.lic
```

This creates `license.lic` containing:
- Customer: acme-corp
- Expires: 365 days from now
- Features: premium, api
- Credits: 100,000 API calls
- Cryptographic signature

## 3. Validate the License

```bash
licenz verify --key keys/public.pem --license license.lic
```

**Output:**
```
✓ Signature valid
✓ Not expired (364 days remaining)
✓ Features: premium, api
✓ Credits: api_calls: 100,000 remaining
License is VALID
```

## 4. Use Credits

```bash
licenz usage record --license license.lic --metric api_calls --amount 1
```

**Output:**
```
Recorded: 1 api_calls
Remaining: 99,999
```

## 5. Check Usage

```bash
licenz usage show --license license.lic
```

**Output:**
```
License: LIC-001
Customer: acme-corp

Usage:
  api_calls: 1 / 100,000 (0.001%)

Credits remaining:
  api_calls: 99,999

Chain integrity: ✓ Valid
```

## That's It!

You've just:
- ✅ Generated cryptographic keys
- ✅ Created a signed license
- ✅ Validated it offline
- ✅ Tracked usage offline

**No server required. Works air-gapped.**

## Next Steps

### Integrate with Your App

**Rust:**
```rust
use licenz_core::require_license;

const PUBLIC_KEY: &str = include_str!("../keys/public.pem");

fn main() {
    let license = require_license("license.lic", PUBLIC_KEY)
        .expect("Valid license required");
    
    if license.has_feature("premium") {
        enable_premium_features();
    }
}
```

**Python:**
```python
import subprocess
result = subprocess.run(
    ['licenz', 'verify', '--key', 'keys/public.pem', '--license', 'license.lic'],
    capture_output=True
)
if result.returncode == 0:
    print("License valid!")
```

**Node.js:**
```javascript
const { execSync } = require('child_process');
try {
    execSync('licenz verify --key keys/public.pem --license license.lic');
    console.log('License valid!');
} catch (err) {
    console.error('License invalid!');
}
```

See [Language Integration](language-integration.md) for complete examples.

### Add More Features

- **[Hardware Binding](../guides/hardware-binding.md)** - Tie to specific machines
- **[Rate Limiting](../guides/rate-limiting.md)** - Throttle API calls
- **[Seat Management](../guides/seat-management.md)** - Concurrent users
- **[Air-Gapped Deployment](../guides/air-gapped.md)** - No internet required

### Learn More

- **[How It Works](../concepts/how-it-works.md)** - Understand the architecture
- **[CLI Reference](../reference/cli-commands.md)** - All commands
- **[FAQ](../FAQ_FULL.md)** - Common questions
