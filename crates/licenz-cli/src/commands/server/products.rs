//! Product-related server commands

use anyhow::Result;
use colored::Colorize;
use std::fs;
use std::path::Path;

use super::client::{block_on, create_client};
use super::config::require_credentials;

pub fn run_list(json: bool) -> Result<()> {
    let creds = require_credentials()?;
    let client = create_client(&creds)?;

    let response = block_on(client.list_products())?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response.data)?);
        return Ok(());
    }

    if response.data.is_empty() {
        println!("No products found");
        return Ok(());
    }

    println!("{}", "Products".bold().cyan());
    println!();

    for product in &response.data {
        println!(
            "  {} {} ({})",
            "●".green(),
            product.name.bold(),
            product.code.dimmed()
        );
        println!("    ID: {}", product.id);
        if let Some(ref desc) = product.description {
            if !desc.is_empty() {
                println!("    Description: {}", desc);
            }
        }
        if !product.default_features.is_empty() {
            println!("    Features: {}", product.default_features.join(", "));
        }
        if let Some(days) = product.default_valid_days {
            println!("    Default validity: {} days", days);
        }
        if product.key_pair_id.is_some() {
            println!("    Key pair: {}", "assigned".green());
        } else {
            println!("    Key pair: {}", "not assigned".yellow());
        }
        println!();
    }

    println!("Total: {} products", response.data.len());
    Ok(())
}

pub fn run_show(id: &str, json: bool) -> Result<()> {
    let creds = require_credentials()?;
    let client = create_client(&creds)?;

    let product = block_on(client.get_product(id))?;

    if json {
        println!("{}", serde_json::to_string_pretty(&product)?);
        return Ok(());
    }

    println!("{}", "Product Details".bold().cyan());
    println!();
    println!("  Name:           {}", product.name.bold());
    println!("  Code:           {}", product.code);
    println!("  ID:             {}", product.id);
    if let Some(ref desc) = product.description {
        if !desc.is_empty() {
            println!("  Description:    {}", desc);
        }
    }
    println!(
        "  Default Features: {}",
        if product.default_features.is_empty() {
            "none".dimmed().to_string()
        } else {
            product.default_features.join(", ")
        }
    );
    if let Some(days) = product.default_valid_days {
        println!("  Default Validity: {} days", days);
    }
    println!(
        "  Key Pair:       {}",
        product
            .key_pair_id
            .as_ref()
            .map(|id| id.to_string())
            .unwrap_or_else(|| "not assigned".to_string())
    );
    println!("  Created:        {}", product.created_at);

    Ok(())
}

pub fn run_public_key(id: &str, output: Option<&Path>) -> Result<()> {
    let creds = require_credentials()?;
    let client = create_client(&creds)?;

    let response = block_on(client.get_product_public_key(id))?;

    if let Some(path) = output {
        fs::write(path, &response.public_key)?;
        println!(
            "{} Public key saved to {}",
            "✓".green(),
            path.display()
        );
        println!("  Product: {} ({})", response.product_name, response.product_code);
    } else {
        // Print to stdout
        println!("{}", response.public_key);
    }

    Ok(())
}
