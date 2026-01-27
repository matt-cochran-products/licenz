use anyhow::Result;
use colored::Colorize;
use licenz_core::detect_hardware;

pub fn run() -> Result<()> {
    let hw = detect_hardware();

    println!();
    println!("{}", "Detected Hardware Information".bold().cyan());
    println!("{}", "═".repeat(50));
    println!();

    // MAC Addresses
    println!("{}", "MAC Addresses".bold());
    if hw.mac_addresses.is_empty() {
        println!("  {}", "(none detected)".dimmed());
    } else {
        for mac in &hw.mac_addresses {
            println!("  • {}", mac.green());
        }
    }
    println!();

    // Hostname
    println!("{}", "Hostname".bold());
    match &hw.hostname {
        Some(hostname) => println!("  • {}", hostname.green()),
        None => println!("  {}", "(none detected)".dimmed()),
    }
    println!();

    // Disk IDs
    println!("{}", "Disk IDs".bold());
    if hw.disk_ids.is_empty() {
        println!("  {}", "(none detected)".dimmed());
    } else {
        for disk in &hw.disk_ids {
            println!("  • {}", disk.green());
        }
    }
    println!();

    // Machine ID
    println!("{}", "Machine ID".bold());
    match &hw.machine_id {
        Some(id) => println!("  • {}", id.green()),
        None => println!("  {}", "(none detected)".dimmed()),
    }
    println!();

    // Usage hint
    println!("{}", "Usage".dimmed());
    println!(
        "  {}",
        "Use these values with --macs, --hostnames, or --diskids".dimmed()
    );
    println!(
        "  {}",
        "when generating hardware-bound licenses.".dimmed()
    );
    println!();

    Ok(())
}
