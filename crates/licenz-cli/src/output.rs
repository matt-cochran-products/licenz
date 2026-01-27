//! Output formatting utilities

use colored::Colorize;

/// Print a success message
pub fn success(msg: &str) {
    println!("{} {}", "✓".green().bold(), msg);
}

/// Print an error message
pub fn error(msg: &str) {
    println!("{} {}", "✗".red().bold(), msg);
}

/// Print an info message
pub fn info(msg: &str) {
    println!("{} {}", "ℹ".blue(), msg);
}

/// Print a warning message
pub fn warning(msg: &str) {
    println!("{} {}", "⚠".yellow(), msg);
}

/// Print a section header
pub fn section(title: &str) {
    println!();
    println!("{}", title.bold().cyan());
    println!("{}", "─".repeat(title.len()).dimmed());
}

/// Print a key-value pair
pub fn kv(key: &str, value: &str) {
    println!("  {} {}", format!("{}:", key).dimmed(), value);
}
