//! Build script — runs on every cargo build/check/test.
//!
//! Ensures git hooks are installed so pre-push quality checks
//! run automatically. This is the only reliable way to guarantee
//! hooks are active for all developers regardless of environment
//! (devcontainer, WSL, macOS, Windows).

use std::process::Command;

fn main() {
    // Only re-run if the hook config or hook files change
    println!("cargo:rerun-if-changed=.git-hooks/pre-push");
    println!("cargo:rerun-if-changed=build.rs");

    // Check if core.hooksPath is already set correctly
    let output = Command::new("git")
        .args(["config", "core.hooksPath"])
        .output();

    let needs_set = match output {
        Ok(out) if out.status.success() => {
            let current = String::from_utf8_lossy(&out.stdout);
            current.trim() != ".git-hooks"
        }
        _ => true,
    };

    if needs_set {
        let result = Command::new("git")
            .args(["config", "core.hooksPath", ".git-hooks"])
            .status();

        match result {
            Ok(status) if status.success() => {
                // Silently configured — no noise in build output
            }
            _ => {
                // Non-fatal: git might not be available (e.g., docker build without git)
                // Hooks just won't be active in that environment
            }
        }
    }
}
