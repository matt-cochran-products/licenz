# General Questions

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
