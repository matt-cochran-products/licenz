#!/usr/bin/env bash
# Local CI Check Script
# Runs THE EXACT SAME checks as CI/CD to catch errors before push
#
# Usage:
#   ./scripts/check-local.sh          # Run all checks
#   ./scripts/check-local.sh --fast   # Skip slow checks (tests)
#   ./scripts/check-local.sh --fix    # Auto-fix what can be fixed

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Ensure cargo is in PATH
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi

# Verify cargo is available
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}ERROR: cargo not found in PATH${NC}"
    echo ""
    echo -e "${YELLOW}Please ensure Rust is installed:${NC}"
    echo -e "  Install Rust with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo ""
    exit 1
fi

# Parse arguments
FAST_MODE=false
FIX_MODE=false
for arg in "$@"; do
    case $arg in
        --fast) FAST_MODE=true ;;
        --fix) FIX_MODE=true ;;
    esac
done

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}  Local CI Check - Runs SAME checks as CI/CD pipeline${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

FAILED=false

# Helper functions
check_step() {
    local name="$1"
    echo -e "${BLUE}>> $name${NC}"
}

check_pass() {
    echo -e "${GREEN}   PASS${NC}"
    echo ""
}

check_fail() {
    local message="$1"
    echo -e "${RED}   FAIL: $message${NC}"
    echo ""
    FAILED=true
}

# =============================================================================
# CHECK 1: Cargo Format
# =============================================================================
check_step "Cargo Format Check"
if [ "$FIX_MODE" = true ]; then
    if cargo fmt --all; then
        check_pass
    else
        check_fail "cargo fmt failed"
    fi
else
    if cargo fmt --all -- --check; then
        check_pass
    else
        check_fail "Code not formatted. Run: cargo fmt --all"
        echo -e "${YELLOW}    Fix with: ./scripts/check-local.sh --fix${NC}"
    fi
fi

# =============================================================================
# CHECK 2: Cargo Clippy
# =============================================================================
check_step "Cargo Clippy (strict - same as CI)"
echo -e "${YELLOW}    Running: cargo clippy --all-targets --all-features -- -D warnings${NC}"

if [ "$FIX_MODE" = true ]; then
    if cargo clippy --all-targets --all-features --fix --allow-dirty --allow-staged -- -D warnings; then
        check_pass
    else
        check_fail "cargo clippy --fix failed"
    fi
else
    if cargo clippy --all-targets --all-features -- -D warnings; then
        check_pass
    else
        check_fail "Clippy found errors that will fail in CI"
        echo -e "${YELLOW}    Fix with: cargo clippy --all-targets --all-features --fix${NC}"
        echo -e "${YELLOW}    Or run:   ./scripts/check-local.sh --fix${NC}"
    fi
fi

# =============================================================================
# CHECK 3: Cargo Build
# =============================================================================
check_step "Cargo Build"
if cargo build --all-targets --all-features; then
    check_pass
else
    check_fail "cargo build failed"
fi

# =============================================================================
# CHECK 4: Cargo Test (skip in fast mode)
# =============================================================================
if [ "$FAST_MODE" = false ]; then
    check_step "Cargo Test"
    if cargo test --all-features; then
        check_pass
    else
        check_fail "Tests failed"
    fi
else
    echo -e "${YELLOW}   Skipping tests (--fast mode)${NC}"
    echo ""
fi

# =============================================================================
# CHECK 5: Documentation
# =============================================================================
check_step "Cargo Doc (documentation check)"
if RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features 2>&1; then
    check_pass
else
    check_fail "Documentation has warnings"
    echo -e "${YELLOW}    Run: RUSTDOCFLAGS=\"-D warnings\" cargo doc --no-deps --all-features${NC}"
fi

# =============================================================================
# SUMMARY
# =============================================================================
echo -e "${BLUE}============================================================${NC}"
if [ "$FAILED" = true ]; then
    echo -e "${RED}  CHECKS FAILED - Would fail in CI/CD${NC}"
    echo -e "${BLUE}============================================================${NC}"
    echo ""
    echo -e "${YELLOW}Fix issues with:${NC}"
    echo -e "  ./scripts/check-local.sh --fix    ${YELLOW}# Auto-fix what can be fixed${NC}"
    echo -e "  cargo clippy --fix                ${YELLOW}# Fix clippy issues${NC}"
    echo -e "  cargo fmt                         ${YELLOW}# Format code${NC}"
    echo ""
    exit 1
else
    echo -e "${GREEN}  ALL CHECKS PASSED - Ready to push!${NC}"
    echo -e "${BLUE}============================================================${NC}"
    echo ""
    echo -e "${GREEN}Your code will pass CI/CD checks.${NC}"
    echo ""
    exit 0
fi
