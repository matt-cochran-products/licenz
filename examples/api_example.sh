#!/bin/bash
#
# Example: Using Licenz HTTP API with curl
#
# Start the server first:
#   licenz-server --port 8080
#

SERVER="http://localhost:8080"

echo "=== Licenz API Examples ==="
echo ""

# Health check
echo "1. Health Check"
curl -s "$SERVER/health" | jq .
echo ""

# Generate a new key pair (returns public key, optionally private)
echo "2. Generate Key Pair"
curl -s -X POST "$SERVER/api/v1/keys/generate" \
  -H "Content-Type: application/json" \
  -d 'true' | jq .
echo ""

# Generate a license
echo "3. Generate License"
LICENSE_RESPONSE=$(curl -s -X POST "$SERVER/api/v1/licenses/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "customer_id": "ACME Corp",
    "product_id": "MyApp",
    "days": 365,
    "features": ["basic", "premium", "enterprise"],
    "max_seats": 10,
    "metadata": {
      "department": "Engineering",
      "contact": "admin@acme.com"
    }
  }')

echo "$LICENSE_RESPONSE" | jq .

# Extract the license_data for verification
LICENSE_DATA=$(echo "$LICENSE_RESPONSE" | jq -r '.license_data')
echo ""

# Verify the license
echo "4. Verify License"
curl -s -X POST "$SERVER/api/v1/licenses/verify" \
  -H "Content-Type: application/json" \
  -d "{
    \"license_data\": \"$LICENSE_DATA\",
    \"skip_hardware_check\": true
  }" | jq .
echo ""

# Verify with hardware info
echo "5. Verify License with Hardware Binding"
curl -s -X POST "$SERVER/api/v1/licenses/verify" \
  -H "Content-Type: application/json" \
  -d "{
    \"license_data\": \"$LICENSE_DATA\",
    \"hardware\": {
      \"mac_addresses\": [\"AA:BB:CC:DD:EE:FF\"],
      \"hostname\": \"my-server\",
      \"disk_ids\": [\"DISK-001\"]
    }
  }" | jq .
echo ""

echo "=== Done ==="
