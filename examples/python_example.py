#!/usr/bin/env python3
"""
Example: Using Licenz from Python via CLI

This demonstrates how to integrate the license system into Python applications.
"""

import subprocess
import json
import sys
import os
from pathlib import Path


class LicenseManager:
    """Python wrapper for the Licenz CLI."""
    
    def __init__(self, cli_path: str = "licenz"):
        self.cli = cli_path
    
    def keygen(self, output_dir: str = "keys", size: int = 2048, force: bool = False) -> bool:
        """Generate RSA key pair."""
        cmd = [self.cli, "keygen", "--dir", output_dir, "--size", str(size)]
        if force:
            cmd.append("--force")
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    
    def generate(
        self,
        customer: str,
        product: str,
        serial: str = None,
        days: int = 365,
        features: list[str] = None,
        output: str = "license.lic",
        private_key: str = "keys/private.pem"
    ) -> bool:
        """Generate a new license."""
        cmd = [
            self.cli, "generate",
            "--customer", customer,
            "--product", product,
            "--days", str(days),
            "--key", private_key,
            "--output", output
        ]
        
        if serial:
            cmd.extend(["--serial", serial])
        if features:
            cmd.extend(["--features", ",".join(features)])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error: {result.stderr}")
        return result.returncode == 0
    
    def verify(
        self,
        license_path: str = "license.lic",
        public_key: str = "keys/public.pem",
        skip_hardware: bool = False
    ) -> bool:
        """Verify a license. Returns True if valid."""
        cmd = [
            self.cli, "verify",
            "--license", license_path,
            "--key", public_key
        ]
        
        if skip_hardware:
            cmd.append("--skip-hardware")
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    
    def info(
        self,
        license_path: str = "license.lic",
        public_key: str = "keys/public.pem"
    ) -> dict:
        """Get license information as JSON."""
        cmd = [
            self.cli, "info",
            "--license", license_path,
            "--key", public_key,
            "--json"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return json.loads(result.stdout)
        return None
    
    def get_hardware(self) -> dict:
        """Get current hardware information."""
        cmd = [self.cli, "hardware"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        # Parse the text output (not JSON in current implementation)
        return {"output": result.stdout}


def main():
    """Example usage."""
    lm = LicenseManager()
    
    # Step 1: Generate keys (do this once)
    print("Generating keys...")
    if not lm.keygen(force=True):
        print("Key generation failed!")
        sys.exit(1)
    print("✓ Keys generated")
    
    # Step 2: Generate a license
    print("\nGenerating license...")
    if not lm.generate(
        customer="ACME Corp",
        product="MyPythonApp",
        days=365,
        features=["basic", "premium"]
    ):
        print("License generation failed!")
        sys.exit(1)
    print("✓ License generated")
    
    # Step 3: Verify the license
    print("\nVerifying license...")
    if lm.verify(skip_hardware=True):
        print("✓ License is VALID")
    else:
        print("✗ License is INVALID")
        sys.exit(1)
    
    # Step 4: Get license info
    print("\nLicense details:")
    info = lm.info()
    if info:
        lic = info["license"]
        print(f"  Customer: {lic['customer_id']}")
        print(f"  Product:  {lic['product_id']}")
        print(f"  Features: {', '.join(lic['features'])}")
        print(f"  Expires:  {lic['valid_until']}")
        print(f"  Days remaining: {info['validation']['days_remaining']}")


if __name__ == "__main__":
    main()
