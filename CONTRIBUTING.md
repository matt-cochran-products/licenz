# Contributing to licenz

Thanks for your interest in contributing to licenz!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/licenz.git`
3. Create a branch: `git checkout -b my-feature`
4. Make your changes
5. Run tests: `cargo test --all-features`
6. Submit a pull request

## Development Setup

```bash
# Clone the repo
git clone https://github.com/matt-cochran/licenz.git
cd licenz

# Enable dev mode (sets up git hooks)
export LICENZ_DEV=1

# Build (default features)
cargo build

# Build with all features
cargo build --all-features

# Run tests
cargo test --all-features

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings

# Format code
cargo fmt

# Check docs build cleanly
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

### Feature Flags

The crate uses optional feature flags. Make sure your changes work across configurations:

```bash
# Default features only (hardware-detect)
cargo test

# All features
cargo test --all-features

# No default features
cargo test --no-default-features
```

## What We're Looking For

### High Priority
- Security audits and vulnerability reports
- Bug fixes with test cases
- Documentation improvements
- Performance optimizations

### Welcome Contributions
- Platform-specific hardware detection improvements
- Additional test coverage
- Example code and tutorials
- Typo fixes

### Please Discuss First
- New features (open an issue first)
- API changes
- Architectural changes

## Code Guidelines

### Style
- Run `cargo fmt` before committing
- Run `cargo clippy` and address warnings
- Write tests for new functionality

### Commits
- Use clear, descriptive commit messages
- One logical change per commit
- Reference issues where applicable: `Fix #123`

### Pull Requests
- Keep PRs focused on a single change
- Update documentation if needed
- Add tests for new functionality
- Ensure CI passes

## Security

If you discover a security vulnerability, please email security@licenz.dev instead of opening a public issue.

## Questions?

- Open a [GitHub Discussion](https://github.com/matt-cochran/licenz/discussions)
- Check existing [issues](https://github.com/matt-cochran/licenz/issues)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
