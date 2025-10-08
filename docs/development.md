# Development Guide

This guide is for developers who want to contribute to Pingora WAF or extend it with custom functionality.

## 📋 Table of Contents

- [Development Environment Setup](#development-environment-setup)
- [Project Architecture](#project-architecture)
- [Codebase Overview](#codebase-overview)
- [Building from Source](#building-from-source)
- [Running Tests](#running-tests)
- [Debugging](#debugging)
- [Adding New Features](#adding-new-features)
- [Performance Optimization](#performance-optimization)
- [Code Review Checklist](#code-review-checklist)
- [Release Process](#release-process)

## Development Environment Setup

### Prerequisites

Install required tools:

```
# Rust toolchain (1.70+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update

# Additional components
rustup component add rustfmt clippy rust-src

# Development tools
cargo install cargo-edit        # Manage dependencies
cargo install cargo-watch       # Auto-rebuild on changes
cargo install cargo-tree        # Dependency tree
cargo install cargo-audit       # Security audit
cargo install cargo-flamegraph  # Profiling
cargo install cargo-bloat       # Binary size analysis
```

### IDE Setup

#### Visual Studio Code

Install extensions:

```
code --install-extension rust-lang.rust-analyzer
code --install-extension tamasfe.even-better-toml
code --install-extension serayuzgur.crates
code --install-extension vadimcn.vscode-lldb
```

`.vscode/settings.json`:

```
{
  "rust-analyzer.checkOnSave.command": "clippy",
  "rust-analyzer.cargo.features": "all",
  "editor.formatOnSave": true,
  "[rust]": {
    "editor.defaultFormatter": "rust-lang.rust-analyzer",
    "editor.tabSize": 4
  }
}
```

`.vscode/launch.json`:

```
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "lldb",
      "request": "launch",
      "name": "Debug WAF",
      "cargo": {
        "args": ["build", "--bin=pingora-waf"],
        "filter": {
          "name": "pingora-waf",
          "kind": "bin"
        }
      },
      "args": [],
      "cwd": "${workspaceFolder}",
      "env": {
        "RUST_LOG": "debug"
      }
    }
  ]
}
```

#### IntelliJ IDEA / CLion

Install the Rust plugin and configure:

1. Go to Settings → Plugins → Install "Rust"
2. Settings → Languages & Frameworks → Rust → Enable external linter (Clippy)
3. Settings → Editor → Code Style → Rust → Set from rustfmt

### Clone and Setup

```
# Clone repository
git clone https://github.com/aarambhdevhub/pingora-waf.git
cd pingora-waf

# Add upstream if you forked
git remote add upstream https://github.com/aarambhdevhub/pingora-waf.git

# Install git hooks (optional but recommended)
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
cargo fmt -- --check
cargo clippy -- -D warnings
EOF
chmod +x .git/hooks/pre-commit
```

## Project Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Client Request                        │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                 Pingora WAF (Port 6188)                  │
│  ┌───────────────────────────────────────────────────┐  │
│  │            request_filter()                        │  │
│  │  -  IP Filter Check                                 │  │
│  │  -  Rate Limiter Check                              │  │
│  │  -  SQL Injection Detection (Headers/URI)          │  │
│  │  -  XSS Detection (Headers/URI)                     │  │
│  │  -  Content-Length Validation                       │  │
│  └───────────────────┬───────────────────────────────┘  │
│                      │ Pass                              │
│                      ▼                                    │
│  ┌───────────────────────────────────────────────────┐  │
│  │        request_body_filter()                       │  │
│  │  -  Accumulate Body Chunks                          │  │
│  │  -  Size Limit Enforcement                          │  │
│  │  -  SQL Injection Detection (Body)                  │  │
│  │  -  XSS Detection (Body)                            │  │
│  └───────────────────┬───────────────────────────────┘  │
│                      │ Pass                              │
│                      ▼                                    │
│  ┌───────────────────────────────────────────────────┐  │
│  │          upstream_peer()                           │  │
│  │  -  Select Backend Server                           │  │
│  │  -  Create HTTP Peer Connection                     │  │
│  └───────────────────┬───────────────────────────────┘  │
│                      │                                    │
│                      ▼                                    │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Forward to Backend → Response → logging()         │  │
│  └───────────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
              ┌────────────────┐
              │ Backend Server │
              │  (Port 8080)   │
              └────────────────┘
```

### Component Architecture

```
src/
├── main.rs                    // Application entry point
│   └── Server initialization
│   └── Service configuration
│   └── Cleanup tasks
│
├── lib.rs                     // Public API exports
│
├── waf/                       // Security rules engine
│   ├── mod.rs                 // Module exports
│   ├── rules.rs               // Rule engine & trait
│   ├── sql_injection.rs       // SQL injection detector
│   ├── xss_detector.rs        // XSS detector
│   ├── rate_limiter.rs        // Rate limiting
│   ├── ip_filter.rs           // IP whitelist/blacklist
│   └── body_inspector.rs      // Request body analysis
│
├── proxy/                     // Proxy implementation
│   ├── mod.rs                 // WafProxy struct
│   └── context.rs             // Per-request context
│
├── metrics/                   // Observability
│   ├── mod.rs
│   └── collector.rs           // Prometheus metrics
│
└── config/                    // Configuration
    ├── mod.rs
    └── loader.rs              // YAML config loader
```

## Codebase Overview

### Key Data Structures

#### WafProxy

The main proxy struct that implements `ProxyHttp` trait:

```
pub struct WafProxy {
    pub sql_detector: Arc<SqlInjectionDetector>,
    pub xss_detector: Arc<XssDetector>,
    pub rate_limiter: Arc<RateLimiter>,
    pub ip_filter: Arc<IpFilter>,
    pub metrics: Arc<MetricsCollector>,
    pub upstream_addr: (String, u16),
    pub max_body_size: usize,
}
```

#### ProxyContext

Per-request state:

```
pub struct ProxyContext {
    pub sql_detector: Arc<SqlInjectionDetector>,
    pub xss_detector: Arc<XssDetector>,
    pub rate_limiter: Arc<RateLimiter>,
    pub ip_filter: Arc<IpFilter>,
    pub body_inspector: BodyInspector,
    pub violations: Vec<SecurityViolation>,
}
```

#### SecurityViolation

Represents a detected threat:

```
pub struct SecurityViolation {
    pub threat_type: String,
    pub threat_level: ThreatLevel,
    pub description: String,
    pub blocked: bool,
}
```

### Request Processing Flow

1. **request_filter()** - Called before body arrives
   - IP filtering
   - Rate limiting
   - Header/URI inspection
   - Content-Length validation

2. **request_body_filter()** - Called for each body chunk
   - Accumulate body data
   - Size enforcement
   - Body content inspection

3. **upstream_peer()** - Select backend
   - Returns HttpPeer for backend connection

4. **logging()** - Post-request logging
   - Log request details
   - Log security violations
   - Clean up context

### Security Rule Interface

All security rules implement this trait:

```
pub trait SecurityRule: Send + Sync {
    fn check(
        &self,
        request: &RequestHeader,
        body: Option<&[u8]>
    ) -> Result<(), SecurityViolation>;

    fn name(&self) -> &str;
}
```

## Building from Source

### Debug Build (Fast Compilation)

```
# Basic debug build
cargo build

# With specific features
cargo build --features "custom-feature"

# All features
cargo build --all-features
```

### Release Build (Optimized)

```
# Standard release
cargo build --release

# Maximum optimization
RUSTFLAGS="-C target-cpu=native" cargo build --release

# With LTO (Link Time Optimization)
cargo build --release --config profile.release.lto=true
```

### Build Profiles

`Cargo.toml` profiles:

```
[profile.dev]
opt-level = 0
debug = true

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true

[profile.bench]
inherits = "release"
debug = true

[profile.test]
opt-level = 1
```

### Cross-Compilation

```
# Add target
rustup target add x86_64-unknown-linux-musl

# Build for musl (static linking)
cargo build --release --target x86_64-unknown-linux-musl

# For ARM64
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
```

## Running Tests

### Unit Tests

```
# All tests
cargo test

# Specific test
cargo test test_sql_injection_detection

# With output
cargo test -- --nocapture

# Show test names
cargo test -- --list

# Run ignored tests
cargo test -- --ignored

# Parallel execution control
cargo test -- --test-threads=4
```

### Integration Tests

```
# Start dependencies first
cargo run --example mock_backend_tokio &
BACKEND_PID=$!

# Run WAF
RUST_LOG=info cargo run &
WAF_PID=$!

# Wait for startup
sleep 2

# Run integration tests
cargo test --test integration_tests

# Cleanup
kill $WAF_PID $BACKEND_PID
```

### Test Coverage

```
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html --output-dir coverage

# View report
open coverage/index.html
```

### Writing Tests

#### Unit Test Template

```
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_name() {
        // Arrange
        let detector = SqlInjectionDetector::new(true, true);
        let input = "malicious input";

        // Act
        let result = detector.check_string(input);

        // Assert
        assert!(result.is_err(), "Should detect SQL injection");
    }

    #[test]
    #[should_panic(expected = "Invalid configuration")]
    fn test_invalid_config() {
        let _ = Config::new_invalid();
    }
}
```

#### Integration Test Template

```
// tests/integration_tests.rs
use reqwest::blocking::Client;

#[test]
fn test_waf_sql_injection_blocking() {
    let client = Client::new();

    let response = client
        .get("http://localhost:6188/test?id=1' OR '1'='1")
        .send()
        .expect("Request failed");

    assert_eq!(response.status(), 403, "Should block SQL injection");
}
```

## Debugging

### Enable Debug Logging

```
# All debug logs
RUST_LOG=debug cargo run

# Specific module
RUST_LOG=pingora_waf::waf::sql_injection=trace cargo run

# Multiple modules
RUST_LOG=pingora_waf=debug,pingora=info cargo run
```

### Using LLDB/GDB

```
# Build with debug symbols
cargo build

# Run with debugger
rust-lldb target/debug/pingora-waf

# Set breakpoint
(lldb) b src/waf/sql_injection.rs:50

# Run
(lldb) run

# Continue
(lldb) continue

# Print variable
(lldb) p detector

# Backtrace
(lldb) bt
```

### Memory Debugging

```
# Install valgrind
sudo apt-get install valgrind

# Run with valgrind
cargo build
valgrind --leak-check=full \
  --show-leak-kinds=all \
  --track-origins=yes \
  ./target/debug/pingora-waf
```

### Profiling

#### CPU Profiling with Flamegraph

```
# Install dependencies
cargo install flamegraph

# Generate flamegraph (requires root)
sudo cargo flamegraph

# View flamegraph.svg
firefox flamegraph.svg
```

#### Memory Profiling

```
# Install heaptrack
sudo apt-get install heaptrack

# Run with heaptrack
heaptrack ./target/release/pingora-waf

# Analyze results
heaptrack_gui heaptrack.pingora-waf.*.gz
```

### Benchmarking

```
# Run benchmarks
cargo bench

# Specific benchmark
cargo bench sql_detection

# Save baseline
cargo bench --bench sql_detection -- --save-baseline main

# Compare with baseline
cargo bench --bench sql_detection -- --baseline main
```

## Adding New Features

### Adding a New Security Rule

**Step 1**: Create the rule file

```
// src/waf/path_traversal.rs
use super::{SecurityRule, SecurityViolation, ThreatLevel};
use pingora::http::RequestHeader;
use regex::Regex;
use once_cell::sync::Lazy;

static PATH_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"\.\.[\\/]").unwrap(),
        Regex::new(r"%2e%2e[\\/]").unwrap(),
    ]
});

pub struct PathTraversalDetector {
    pub enabled: bool,
    pub block_mode: bool,
}

impl PathTraversalDetector {
    pub fn new(enabled: bool, block_mode: bool) -> Self {
        Self { enabled, block_mode }
    }

    fn check_string(&self, input: &str) -> bool {
        PATH_PATTERNS.iter().any(|p| p.is_match(input))
    }
}

impl SecurityRule for PathTraversalDetector {
    fn check(
        &self,
        request: &RequestHeader,
        _body: Option<&[u8]>,
    ) -> Result<(), SecurityViolation> {
        if !self.enabled {
            return Ok(());
        }

        let uri = request.uri.to_string();
        if self.check_string(&uri) {
            return Err(SecurityViolation {
                threat_type: "PATH_TRAVERSAL".to_string(),
                threat_level: ThreatLevel::High,
                description: format!("Path traversal: {}", uri),
                blocked: self.block_mode,
            });
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "Path Traversal Detector"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_traversal_detection() {
        let detector = PathTraversalDetector::new(true, true);

        assert!(detector.check_string("../../etc/passwd"));
        assert!(detector.check_string("..\\windows\\system32"));
        assert!(!detector.check_string("/normal/path"));
    }
}
```

**Step 2**: Export from module

```
// src/waf/mod.rs
pub mod path_traversal;
pub use path_traversal::*;
```

**Step 3**: Add to configuration

```
// src/config/loader.rs
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WafConfig {
    // ... existing fields
    pub path_traversal: RuleConfig,
}
```

**Step 4**: Integrate into proxy

```
// src/main.rs
let path_detector = Arc::new(PathTraversalDetector::new(
    config.path_traversal.enabled,
    config.path_traversal.block_mode,
));

// Add to proxy context
// src/proxy/context.rs
pub struct ProxyContext {
    // ... existing fields
    pub path_detector: Arc<PathTraversalDetector>,
}

// Check in request_filter
if let Err(violation) = ctx.path_detector.check(session.req_header(), None) {
    // Handle violation
}
```

**Step 5**: Add tests

```
// tests/security_tests.rs
#[test]
fn test_path_traversal_blocked() {
    let client = Client::new();
    let resp = client.get("http://localhost:6188/../../etc/passwd")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 403);
}
```

### Adding a New Metric

```
// src/metrics/collector.rs
use prometheus::IntCounter;
use once_cell::sync::Lazy;

static PATH_TRAVERSAL_BLOCKED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "waf_path_traversal_blocked",
        "Path traversal attempts blocked"
    ).expect("metric creation failed")
});

impl MetricsCollector {
    pub fn new() -> Self {
        prometheus::register(Box::new(PATH_TRAVERSAL_BLOCKED.clone()))
            .unwrap();
        // ... rest
    }

    pub fn increment_path_traversal_blocks(&self) {
        PATH_TRAVERSAL_BLOCKED.inc();
    }
}
```

### Adding a New Configuration Option

```
// src/config/loader.rs
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WafConfig {
    // ... existing

    #[serde(default = "default_timeout")]
    pub request_timeout_secs: u64,
}

fn default_timeout() -> u64 {
    30
}
```

## Performance Optimization

### Profiling Guidelines

1. **Identify bottlenecks** with flamegraph
2. **Measure, don't assume** - use benchmarks
3. **Optimize hot paths** first
4. **Document performance changes**

### Common Optimizations

#### Use `Arc` Instead of `Mutex` When Possible

```
// Good - immutable shared state
let detector = Arc::new(SqlInjectionDetector::new(...));

// Avoid if possible - requires locking
let detector = Arc::new(Mutex::new(SqlInjectionDetector::new(...)));
```

#### Lazy Static Initialization

```
use once_cell::sync::Lazy;

static PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"pattern1").unwrap(),
        Regex::new(r"pattern2").unwrap(),
    ]
});
```

#### Avoid Allocations in Hot Paths

```
// Good - uses references
fn check_string(&self, input: &str) -> bool {
    self.patterns.iter().any(|p| p.is_match(input))
}

// Bad - unnecessary allocation
fn check_string(&self, input: &str) -> bool {
    let owned = input.to_string(); // Avoid!
    self.patterns.iter().any(|p| p.is_match(&owned))
}
```

#### Use DashMap for Concurrent Access

```
use dashmap::DashMap;

// Good - lock-free concurrent map
let map: Arc<DashMap<String, Value>> = Arc::new(DashMap::new());

// Avoid - requires locking entire map
let map: Arc<Mutex<HashMap<String, Value>>> =
    Arc::new(Mutex::new(HashMap::new()));
```

### Benchmarking New Features

```
// benches/path_traversal_bench.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pingora_waf::PathTraversalDetector;

fn bench_path_traversal(c: &mut Criterion) {
    let detector = PathTraversalDetector::new(true, true);

    c.bench_function("path_traversal_malicious", |b| {
        b.iter(|| {
            detector.check_string(black_box("../../etc/passwd"))
        });
    });

    c.bench_function("path_traversal_safe", |b| {
        b.iter(|| {
            detector.check_string(black_box("/normal/path"))
        });
    });
}

criterion_group!(benches, bench_path_traversal);
criterion_main!(benches);
```

Run with:

```
cargo bench --bench path_traversal_bench
```

## Code Review Checklist

Before submitting a PR, ensure:

### Functionality
- [ ] Feature works as intended
- [ ] Edge cases handled
- [ ] Error handling is comprehensive
- [ ] No panics in production code

### Tests
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Test coverage > 80%
- [ ] Benchmarks for performance-critical code

### Code Quality
- [ ] Follows Rust style guidelines
- [ ] `cargo fmt` applied
- [ ] `cargo clippy` produces no warnings
- [ ] No compiler warnings
- [ ] Documentation updated
- [ ] Examples added if applicable

### Performance
- [ ] No unnecessary allocations
- [ ] Benchmarks show no regression
- [ ] Profiling data reviewed
- [ ] Resource usage acceptable

### Security
- [ ] No security vulnerabilities introduced
- [ ] Input validation present
- [ ] Sensitive data not logged
- [ ] `cargo audit` passes

### Documentation
- [ ] Public APIs documented
- [ ] Complex logic commented
- [ ] README updated if needed
- [ ] CHANGELOG updated

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes

### Release Checklist

1. **Update version** in `Cargo.toml`:
   ```
   [package]
   version = "0.2.0"
   ```

2. **Update CHANGELOG.md**:
   ```
   ## [0.2.0] - 2025-10-15

   ### Added
   - Path traversal detection
   - Custom rule API

   ### Fixed
   - SQL injection false positives

   ### Changed
   - Improved rate limiter performance
   ```

3. **Run full test suite**:
   ```
   cargo test --all-features
   cargo clippy -- -D warnings
   cargo audit
   ```

4. **Build release binary**:
   ```
   cargo build --release
   ```

5. **Create git tag**:
   ```
   git tag -a v0.2.0 -m "Release v0.2.0"
   git push origin v0.2.0
   ```

6. **Publish to crates.io** (if applicable):
   ```
   cargo publish
   ```

7. **Create GitHub release** with:
   - Release notes from CHANGELOG
   - Compiled binaries (optional)
   - Docker image tags

## Useful Development Commands

```
# Auto-rebuild on file changes
cargo watch -x build

# Auto-test on changes
cargo watch -x test

# Check compile without building
cargo check

# Update dependencies
cargo update

# View dependency tree
cargo tree

# Security audit
cargo audit

# Binary size analysis
cargo bloat --release

# Show build timings
cargo build --timings

# Clean build artifacts
cargo clean

# Format all code
cargo fmt --all

# Lint all code
cargo clippy --all-targets --all-features -- -D warnings
```

## Getting Help

- **Documentation**: Check [docs/](.)
- **Examples**: See [examples/](../examples/)
- **Issues**: [GitHub Issues](https://github.com/aarambhdevhub/pingora-waf/issues)
- **Discussions**: [GitHub Discussions](https://github.com/aarambhdevhub/pingora-waf/discussions)
- **Rust Help**: [Rust Users Forum](https://users.rust-lang.org/)

## Additional Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Pingora Documentation](https://github.com/cloudflare/pingora)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Async Rust Book](https://rust-lang.github.io/async-book/)
- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)

---

**Happy Coding! 🦀**

*Last Updated: October 8, 2025*
*Maintained by: Aarambh dev hub*
