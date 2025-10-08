# Contributing to Pingora WAF

Thank you for your interest in contributing to Pingora WAF! We welcome contributions from the community and are excited to have you join us in building a high-performance, memory-safe Web Application Firewall.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Community](#community)

## 📜 Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we pledge to make participation in our project and our community a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Examples of behavior that contributes to creating a positive environment include:**

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Examples of unacceptable behavior include:**

- The use of sexualized language or imagery and unwelcome sexual attention or advances
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without explicit permission
- Other conduct which could reasonably be considered inappropriate in a professional setting

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by contacting the project team at **security@aarambhdevhub.com**. All complaints will be reviewed and investigated promptly and fairly.

## 🤝 How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

**Bug Report Template:**

```
**Description:**
A clear and concise description of what the bug is.

**To Reproduce:**
Steps to reproduce the behavior:
1. Configure WAF with '...'
2. Send request '...'
3. Observe error '...'

**Expected Behavior:**
What you expected to happen.

**Actual Behavior:**
What actually happened.

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Rust Version: [e.g., 1.70]
- Pingora WAF Version: [e.g., 0.1.0]
- Hardware: [e.g., 4 CPU, 8GB RAM]

**Logs:**
```
[Paste relevant logs here]
```

**Additional Context:**
Any other context about the problem.
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Use a clear and descriptive title**
- **Provide a detailed description** of the suggested enhancement
- **Explain why this enhancement would be useful** to most users
- **List any alternative solutions** you've considered
- **Include mockups or examples** if applicable

### Security Vulnerabilities

**⚠️ IMPORTANT:** Please do NOT create public issues for security vulnerabilities.

Instead, email us at **security@aarambhdevhub.com** with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and work with you to address the issue.

### Documentation Improvements

Documentation improvements are always welcome! This includes:

- Fixing typos or grammatical errors
- Improving clarity or adding examples
- Adding missing documentation
- Translating documentation
- Creating tutorials or guides

### Code Contributions

We accept the following types of code contributions:

- **Bug fixes** - Fixing existing issues
- **New features** - Adding new security rules, metrics, etc.
- **Performance improvements** - Optimizations and benchmarks
- **Test coverage** - Adding or improving tests
- **Code refactoring** - Improving code quality

## 🚀 Getting Started

### Prerequisites

- **Rust 1.70 or higher**
  ```
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  rustup update
  ```

- **Git**
  ```
  # Ubuntu/Debian
  sudo apt-get install git

  # macOS
  brew install git
  ```

- **Development tools**
  ```
  rustup component add rustfmt clippy
  ```

### Fork and Clone

1. **Fork the repository** on GitHub

2. **Clone your fork**:
   ```
   git clone https://github.com/YOUR_USERNAME/pingora-waf.git
   cd pingora-waf
   ```

3. **Add upstream remote**:
   ```
   git remote add upstream https://github.com/aarambhdevhub/pingora-waf.git
   ```

4. **Create a branch**:
   ```
   git checkout -b feature/my-awesome-feature
   ```

## 🛠️ Development Setup

### Build the Project

```
# Debug build (faster compilation)
cargo build

# Release build (optimized)
cargo build --release
```

### Run Tests

```
# Run all tests
cargo test

# Run specific test
cargo test test_sql_injection

# Run with output
cargo test -- --nocapture

# Run integration tests
cargo test --test integration_tests
```

### Run the WAF Locally

```
# Start mock backend
cargo run --example mock_backend_tokio &

# Run WAF in debug mode
RUST_LOG=debug cargo run

# Test it
curl http://localhost:6188/api/test
```

### Code Quality Checks

```
# Format code
cargo fmt

# Check formatting
cargo fmt -- --check

# Run Clippy (linter)
cargo clippy -- -D warnings

# Check for common issues
cargo clippy --all-targets --all-features
```

## 📁 Project Structure

```
pingora-waf/
├── src/
│   ├── main.rs              # Application entry point
│   ├── lib.rs               # Library exports
│   ├── waf/                 # Security rules
│   │   ├── mod.rs
│   │   ├── rules.rs         # Rule engine
│   │   ├── rate_limiter.rs  # Rate limiting logic
│   │   ├── ip_filter.rs     # IP filtering
│   │   ├── sql_injection.rs # SQL injection detection
│   │   ├── xss_detector.rs  # XSS detection
│   │   └── body_inspector.rs# Body inspection
│   ├── metrics/             # Prometheus metrics
│   │   ├── mod.rs
│   │   └── collector.rs
│   ├── config/              # Configuration loading
│   │   ├── mod.rs
│   │   └── loader.rs
│   └── proxy/               # Proxy implementation
│       ├── mod.rs
│       └── context.rs
├── config/                  # Configuration files
├── examples/                # Example programs
├── tests/                   # Integration tests
├── benches/                 # Benchmarks
└── docs/                    # Documentation
```

## 📝 Coding Standards

### Rust Style Guide

We follow the [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/). Key points:

#### Naming Conventions

```rust
// Types and traits: UpperCamelCase
struct SqlInjectionDetector { }
trait SecurityRule { }

// Functions and variables: snake_case
fn check_request() { }
let max_body_size = 1024;

// Constants: SCREAMING_SNAKE_CASE
const MAX_CONNECTIONS: usize = 100;

// Modules: snake_case
mod rate_limiter;
```

#### Code Organization

```rust
// Imports at the top, grouped logically
use std::sync::Arc;
use std::collections::HashMap;

use pingora::prelude::*;
use prometheus::IntCounter;

use crate::waf::SecurityRule;

// Type definitions
pub struct MyStruct { }

// Implementation
impl MyStruct {
    // Public methods first
    pub fn new() -> Self { }

    // Private methods after
    fn internal_method(&self) { }
}

// Traits
impl SecurityRule for MyStruct {
    fn check(&self) { }
}
```

#### Error Handling

```rust
// Use Result types
pub fn process_request() -> Result<Response, Error> {
    // Prefer early returns
    let data = get_data()?;

    if !is_valid(&data) {
        return Err(Error::InvalidData);
    }

    Ok(Response::new(data))
}

// Avoid unwrap() in production code
// Instead use expect() with descriptive messages
let value = config.get("key")
    .expect("key must be present in config");
```

#### Documentation

```rust
/// Checks a request for SQL injection patterns.
///
/// This function scans the request URI, headers, and body for common
/// SQL injection attack patterns including union-based, boolean-based,
/// and time-based blind injection attempts.
///
/// # Arguments
///
/// * `request` - The HTTP request header to check
/// * `body` - Optional request body to inspect
///
/// # Returns
///
/// Returns `Ok(())` if no SQL injection is detected, otherwise returns
/// an `Err(SecurityViolation)` with details about the threat.
///
/// # Examples
///
/// ```
/// let detector = SqlInjectionDetector::new(true, true);
/// let request = RequestHeader::build("GET", b"/?id=123", None)?;
/// assert!(detector.check(&request, None).is_ok());
/// ```
pub fn check(
    &self,
    request: &RequestHeader,
    body: Option<&[u8]>,
) -> Result<(), SecurityViolation> {
    // Implementation
}
```

### Performance Guidelines

- **Avoid allocations in hot paths** - Use references and slices
- **Use `Arc` for shared state** - Avoid `Mutex` when possible
- **Prefer `&str` over `String`** - When ownership isn't needed
- **Use lazy initialization** - For expensive static data
- **Profile before optimizing** - Measure, don't guess

Example:

```rust
// Good - minimal allocations
pub fn check_string(&self, input: &str) -> bool {
    PATTERNS.iter().any(|pattern| pattern.is_match(input))
}

// Avoid - unnecessary allocation
pub fn check_string(&self, input: &str) -> bool {
    let owned = input.to_string(); // Avoid this
    PATTERNS.iter().any(|pattern| pattern.is_match(&owned))
}
```

## 🧪 Testing Guidelines

### Test Coverage Requirements

- **New features**: Must include tests
- **Bug fixes**: Add regression test
- **Security rules**: Must have false positive/negative tests
- **Performance**: Include benchmarks for critical paths

### Writing Tests

#### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_injection_detection() {
        let detector = SqlInjectionDetector::new(true, true);

        // Test positive cases
        assert!(detector.check_string("1' OR '1'='1").is_err());
        assert!(detector.check_string("'; DROP TABLE users--").is_err());

        // Test negative cases (should not trigger)
        assert!(detector.check_string("normal text").is_ok());
        assert!(detector.check_string("user@example.com").is_ok());
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(10, 60, true);
        let ip = "192.168.1.1";

        // First 10 requests should pass
        for _ in 0..10 {
            assert!(limiter.check_rate_limit(ip).is_ok());
        }

        // 11th should fail
        assert!(limiter.check_rate_limit(ip).is_err());
    }
}
```

#### Integration Tests

```rust
// tests/integration_tests.rs
use reqwest::blocking::Client;

#[test]
fn test_waf_blocks_sql_injection() {
    let client = Client::new();

    let response = client
        .get("http://localhost:6188/api/users?id=1' OR '1'='1")
        .send()
        .expect("Failed to send request");

    assert_eq!(response.status(), 403);
}
```

#### Benchmarks

```rust
// benches/sql_detection_bench.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pingora_waf::SqlInjectionDetector;

fn benchmark_sql_detection(c: &mut Criterion) {
    let detector = SqlInjectionDetector::new(true, true);

    c.bench_function("sql_detection_malicious", |b| {
        b.iter(|| {
            detector.check_string(black_box("1' OR '1'='1"))
        });
    });

    c.bench_function("sql_detection_legitimate", |b| {
        b.iter(|| {
            detector.check_string(black_box("normal query string"))
        });
    });
}

criterion_group!(benches, benchmark_sql_detection);
criterion_main!(benches);
```

### Running Tests

```
# All tests
cargo test

# Specific test
cargo test test_sql_injection

# Integration tests only
cargo test --test integration_tests

# With logging
RUST_LOG=debug cargo test -- --nocapture

# Run benchmarks
cargo bench
```

## 💬 Commit Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/) specification.

### Commit Message Format

```html
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, no logic change)
- **refactor**: Code refactoring
- **perf**: Performance improvements
- **test**: Adding or updating tests
- **chore**: Maintenance tasks, dependency updates
- **security**: Security fixes

### Examples

```
# Feature
git commit -m "feat(sql): add hex encoding detection to SQL injection rules"

# Bug fix
git commit -m "fix(rate-limiter): prevent integer overflow in window calculation"

# Documentation
git commit -m "docs(readme): add deployment section with systemd example"

# Performance
git commit -m "perf(xss): optimize regex compilation with lazy_static"

# Breaking change
git commit -m "feat(config)!: change config format to YAML

BREAKING CHANGE: Configuration files must now be in YAML format.
Migration guide added to docs/migration.md"
```

### Commit Message Body

Include:
- **Motivation**: Why this change is needed
- **Implementation**: Brief description of how it works
- **Testing**: How you tested the change
- **Breaking changes**: If any, with migration guide

Example:

```
feat(waf): add custom rule support

Add support for user-defined security rules through the SecurityRule trait.
This allows users to extend the WAF with custom attack detection logic
without modifying core code.

- Added SecurityRule trait with check() method
- Implemented RuleEngine to manage multiple rules
- Added example custom rules in examples/custom_rules.rs
- Updated documentation with custom rule guide

Tested with 3 custom rules achieving 0% false positive rate.
```

## 🔄 Pull Request Process

### Before Submitting

1. **Update your branch** with the latest upstream:
   ```
   git fetch upstream
   git rebase upstream/main
   ```

2. **Ensure all tests pass**:
   ```
   cargo test
   cargo clippy -- -D warnings
   cargo fmt -- --check
   ```

3. **Update documentation** if needed

4. **Add/update tests** for your changes

5. **Run security checks**:
   ```
   cargo audit
   ```

### Creating a Pull Request

1. **Push your branch**:
   ```
   git push origin feature/my-awesome-feature
   ```

2. **Create PR** on GitHub with this template:

```
## Description
Brief description of what this PR does.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## How Has This Been Tested?
Describe the tests you ran and how to reproduce them.

- [ ] Unit tests
- [ ] Integration tests
- [ ] Manual testing
- [ ] Benchmark results (if applicable)

## Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] Any dependent changes have been merged and published

## Screenshots (if applicable)

## Related Issues
Closes #123
Fixes #456

## Additional Notes
Any additional information that reviewers should know.
```

### Review Process

1. **Automated checks** run first (CI/CD)
2. **Maintainer review** - Usually within 48 hours
3. **Address feedback** - Make requested changes
4. **Approval** - At least one maintainer approval required
5. **Merge** - Squash and merge to main

### What We Look For

- **Code quality**: Clean, readable, well-documented
- **Testing**: Adequate test coverage
- **Performance**: No significant performance regression
- **Security**: No new vulnerabilities introduced
- **Documentation**: Updated if needed
- **Commit messages**: Follow conventional commits

## 🐛 Issue Reporting

### Before Creating an Issue

- **Search existing issues** to avoid duplicates
- **Update to latest version** and see if issue persists
- **Check documentation** for solutions

### Issue Templates

We provide templates for:

- **Bug reports**
- **Feature requests**
- **Security vulnerabilities** (private)
- **Performance issues**
- **Documentation improvements**

### Issue Labels

We use these labels to categorize issues:

- `bug` - Something isn't working
- `enhancement` - New feature or request
- `documentation` - Documentation improvements
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention needed
- `security` - Security-related issue
- `performance` - Performance-related issue
- `wontfix` - This will not be worked on
- `duplicate` - This issue already exists

## 👥 Community

### Communication Channels

- **GitHub Discussions**: For questions and discussions
- **GitHub Issues**: For bugs and feature requests
- **Email**: security@aarambhdevhub.com (for security issues)

### Getting Help

If you need help with:

- **Using Pingora WAF**: Check documentation first, then GitHub Discussions
- **Contributing**: Read this guide, then ask in Discussions
- **Security issues**: Email security@aarambhdevhub.com directly

### Recognition

Contributors are recognized in:

- **README.md**: Contributors section
- **Release notes**: Credit in changelog
- **GitHub**: Contributor badge

## 🎯 Development Priorities

Current focus areas (in order):

1. **Security**: SQL injection, XSS, and other attack vectors
2. **Performance**: Maintaining 15K+ req/sec throughput
3. **Documentation**: Clear guides and examples
4. **Testing**: High test coverage and reliability
5. **Features**: New security rules and capabilities

## 📚 Additional Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Pingora Documentation](https://github.com/cloudflare/pingora)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Semantic Versioning](https://semver.org/)

## 🙏 Thank You!

Thank you for contributing to Pingora WAF! Your efforts help make the web more secure for everyone.

---

**Questions?** Feel free to ask in [GitHub Discussions](https://github.com/aarambhdevhub/pingora-waf/discussions)

**Found a security issue?** Email security@aarambhdevhub.com

**Want to chat?** Join our community discussions!

---

*Last updated: October 7, 2025*
*Maintained by: Aarambh dev hub*
