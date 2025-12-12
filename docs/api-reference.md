# API Reference

Complete API documentation for Pingora WAF. This guide covers all public APIs, traits, and how to extend the WAF with custom security rules.

## Table of Contents

- [Core Traits](#core-traits)
- [Security Components](#security-components)
- [Configuration API](#configuration-api)
- [Metrics API](#metrics-api)
- [Custom Rules](#custom-rules)
- [Type Reference](#type-reference)
- [Examples](#examples)

## Core Traits

### SecurityRule Trait

The foundation for all security rules in Pingora WAF.

```
pub trait SecurityRule: Send + Sync {
    /// Check a request for security violations
    ///
    /// # Arguments
    /// * `request` - The HTTP request header to inspect
    /// * `body` - Optional request body bytes
    ///
    /// # Returns
    /// * `Ok(())` - Request is safe
    /// * `Err(SecurityViolation)` - Threat detected
    fn check(
        &self,
        request: &RequestHeader,
        body: Option<&[u8]>,
    ) -> Result<(), SecurityViolation>;

    /// Get the name of this security rule
    fn name(&self) -> &str;
}
```

**Usage Example:**

```
use pingora_waf::{SecurityRule, SecurityViolation, ThreatLevel};
use pingora::http::RequestHeader;

struct MyCustomRule {
    enabled: bool,
}

impl SecurityRule for MyCustomRule {
    fn check(
        &self,
        request: &RequestHeader,
        body: Option<&[u8]>,
    ) -> Result<(), SecurityViolation> {
        if !self.enabled {
            return Ok(());
        }

        let uri = request.uri.to_string();

        if uri.contains("malicious_pattern") {
            return Err(SecurityViolation {
                threat_type: "CUSTOM_THREAT".to_string(),
                threat_level: ThreatLevel::High,
                description: "Custom rule triggered".to_string(),
                blocked: true,
            });
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "My Custom Rule"
    }
}
```

## Security Components

### SqlInjectionDetector

Detects SQL injection attacks in requests.

```
pub struct SqlInjectionDetector {
    pub enabled: bool,
    pub block_mode: bool,
}

impl SqlInjectionDetector {
    /// Create a new SQL injection detector
    ///
    /// # Arguments
    /// * `enabled` - Whether detection is enabled
    /// * `block_mode` - true = block requests, false = log only
    ///
    /// # Example
    /// ```rust
    /// let detector = SqlInjectionDetector::new(true, true);
    /// ```
    pub fn new(enabled: bool, block_mode: bool) -> Self;
}
```

**Detected Patterns:**

- Union-based injection: `UNION SELECT`
- Boolean-based: `OR 1=1`, `AND 1=1`
- Comment injection: `--`, `/**/`
- Stacked queries: `; DROP TABLE`
- Time-based blind: `SLEEP()`, `BENCHMARK()`

**Example Usage:**

```
use pingora_waf::SqlInjectionDetector;
use pingora::http::RequestHeader;

let detector = SqlInjectionDetector::new(true, true);
let request = RequestHeader::build("GET", b"/?id=1' OR '1'='1", None)?;

match detector.check(&request, None) {
    Ok(()) => println!("Request is safe"),
    Err(violation) => println!("SQL injection detected: {:?}", violation),
}
```

### XssDetector

Detects cross-site scripting (XSS) attacks.

```
pub struct XssDetector {
    pub enabled: bool,
    pub block_mode: bool,
}

impl XssDetector {
    /// Create a new XSS detector
    ///
    /// # Arguments
    /// * `enabled` - Whether detection is enabled
    /// * `block_mode` - true = block requests, false = log only
    ///
    /// # Example
    /// ```rust
    /// let detector = XssDetector::new(true, true);
    /// ```
    pub fn new(enabled: bool, block_mode: bool) -> Self;
}
```

**Detected Patterns:**

- Script tags: `<script>`, `</script>`
- Event handlers: `onload=`, `onerror=`, `onclick=`
- JavaScript protocol: `javascript:`
- Dangerous tags: `<iframe>`, `<object>`, `<embed>`
- Inline JavaScript: `eval()`, `alert()`

**Example Usage:**

```
use pingora_waf::XssDetector;

let detector = XssDetector::new(true, true);
let body = b"<script>alert('XSS')</script>";

let request = RequestHeader::build("POST", b"/", None)?;
match detector.check(&request, Some(body)) {
    Ok(()) => println!("Request is safe"),
    Err(violation) => println!("XSS detected: {:?}", violation),
}
```

### RateLimiter

Per-IP rate limiting with sliding window algorithm.

```
pub struct RateLimiter {
    limits: Arc<DashMap<String, RateLimitEntry>>,
    max_requests: u32,
    window_duration: Duration,
    enabled: bool,
}

impl RateLimiter {
    /// Create a new rate limiter
    ///
    /// # Arguments
    /// * `max_requests` - Maximum requests per window
    /// * `window_secs` - Time window in seconds
    /// * `enabled` - Whether rate limiting is enabled
    ///
    /// # Example
    /// ```rust
    /// let limiter = RateLimiter::new(100, 60, true); // 100 req/min
    /// ```
    pub fn new(max_requests: u32, window_secs: u64, enabled: bool) -> Self;

    /// Check if a client IP has exceeded rate limit
    ///
    /// # Arguments
    /// * `client_ip` - The client's IP address
    ///
    /// # Returns
    /// * `Ok(())` - Within rate limit
    /// * `Err(SecurityViolation)` - Rate limit exceeded
    ///
    /// # Example
    /// ```rust
    /// match limiter.check_rate_limit("192.168.1.1") {
    ///     Ok(()) => println!("Request allowed"),
    ///     Err(violation) => println!("Rate limited: {:?}", violation),
    /// }
    /// ```
    pub fn check_rate_limit(&self, client_ip: &str) -> Result<(), SecurityViolation>;

    /// Clean up expired entries
    ///
    /// Should be called periodically to prevent memory growth.
    /// Automatically removes entries older than 2x window duration.
    ///
    /// # Example
    /// ```rust
    /// // Call every 5 minutes
    /// limiter.cleanup_old_entries();
    /// ```
    pub fn cleanup_old_entries(&self);
}
```

**Advanced Usage:**

```
use pingora_waf::RateLimiter;
use std::sync::Arc;
use std::time::Duration;

// Create rate limiter
let limiter = Arc::new(RateLimiter::new(1000, 60, true));

// Periodic cleanup in background thread
let limiter_clone = Arc::clone(&limiter);
std::thread::spawn(move || {
    loop {
        std::thread::sleep(Duration::from_secs(300));
        limiter_clone.cleanup_old_entries();
    }
});

// Use in request handling
match limiter.check_rate_limit("203.0.113.42") {
    Ok(()) => {
        // Process request
    }
    Err(violation) => {
        // Return 429 Too Many Requests
    }
}
```

### BotDetector

Detects and blocks malicious bots based on User-Agent patterns.

```
pub struct BotDetector {
    pub enabled: bool,
    pub block_mode: bool,
    pub allow_known_bots: bool,
}

impl BotDetector {
    /// Create a new bot detector
    ///
    /// # Arguments
    /// * `enabled` - Whether bot detection is enabled
    /// * `block_mode` - true = block bad bots, false = log only
    /// * `allow_known_bots` - Allow Googlebot, Bingbot, etc.
    pub fn new(enabled: bool, block_mode: bool, allow_known_bots: bool) -> Self;

    /// Add a custom bad bot pattern (regex)
    pub fn add_bad_bot_pattern(&mut self, pattern: &str) -> Result<(), String>;

    /// Add a custom good bot identifier (substring match)
    pub fn add_good_bot_identifier(&mut self, identifier: &str);

    /// Detect bot type from User-Agent
    pub fn detect_bot(&self, user_agent: Option<&str>) -> BotType;
}

pub enum BotType {
    GoodBot(String),      // Allowed (Googlebot, Bingbot)
    BadBot(String),       // Blocked (sqlmap, nikto)
    SuspiciousBot(String), // Missing/empty User-Agent
    NotBot,               // Normal user
}
```

**Example Usage:**

```rust
let mut detector = BotDetector::new(true, true, true);

// Add custom patterns
detector.add_bad_bot_pattern(r"(?i)mycrawler")?;
detector.add_good_bot_identifier("mymonitor");

// Check request
match detector.check(session.req_header(), None) {
    Ok(()) => { /* Request allowed */ }
    Err(violation) => { /* Bot detected */ }
}
```

### IpFilter

IP whitelist and blacklist filtering with CIDR notation support.

```
use ipnetwork::IpNetwork;

pub struct IpFilter {
    pub whitelist: Vec<IpNetwork>,
    pub blacklist: Vec<IpNetwork>,
    pub enabled: bool,
}

impl IpFilter {
    /// Create a new IP filter
    ///
    /// # Arguments
    /// * `enabled` - Whether IP filtering is enabled
    ///
    /// # Example
    /// ```rust
    /// let mut filter = IpFilter::new(true);
    /// ```
    pub fn new(enabled: bool) -> Self;

    /// Add an IP or CIDR range to the whitelist
    ///
    /// # Arguments
    /// * `ip_or_cidr` - IP address or CIDR notation string
    ///
    /// # Supported Formats
    /// * Single IP: `"192.168.1.1"` (treated as /32)
    /// * CIDR range: `"10.0.0.0/8"`, `"192.168.0.0/16"`
    /// * IPv6: `"::1"`, `"2001:db8::/32"`
    ///
    /// # Example
    /// ```rust
    /// filter.add_to_whitelist("192.168.1.1")?;      // Single IP
    /// filter.add_to_whitelist("10.0.0.0/8")?;       // CIDR range
    /// filter.add_to_whitelist("2001:db8::/32")?;    // IPv6 CIDR
    /// ```
    pub fn add_to_whitelist(&mut self, ip_or_cidr: &str) -> Result<(), String>;

    /// Add an IP or CIDR range to the blacklist
    ///
    /// # Arguments
    /// * `ip_or_cidr` - IP address or CIDR notation string
    ///
    /// # Example
    /// ```rust
    /// filter.add_to_blacklist("192.168.1.100")?;    // Single IP
    /// filter.add_to_blacklist("198.51.100.0/24")?;  // CIDR range
    /// ```
    pub fn add_to_blacklist(&mut self, ip_or_cidr: &str) -> Result<(), String>;

    /// Check if an IP is allowed
    ///
    /// # Arguments
    /// * `ip_str` - IP address as string
    ///
    /// # Returns
    /// * `Ok(())` - IP is allowed
    /// * `Err(SecurityViolation)` - IP is blocked
    ///
    /// # Example
    /// ```rust
    /// match filter.check_ip("192.168.1.1") {
    ///     Ok(()) => println!("IP allowed"),
    ///     Err(violation) => println!("IP blocked: {:?}", violation),
    /// }
    /// ```
    pub fn check_ip(&self, ip_str: &str) -> Result<(), SecurityViolation>;

    /// Get the number of whitelist entries
    pub fn whitelist_count(&self) -> usize;

    /// Get the number of blacklist entries
    pub fn blacklist_count(&self) -> usize;
}
```

**CIDR Whitelist Mode:**

```
let mut filter = IpFilter::new(true);

// Add trusted network ranges
filter.add_to_whitelist("10.0.0.0/8")?;       // Entire 10.x.x.x network
filter.add_to_whitelist("192.168.0.0/16")?;   // Entire 192.168.x.x network

// All IPs in whitelisted ranges are allowed
assert!(filter.check_ip("10.0.0.1").is_ok());
assert!(filter.check_ip("10.255.255.255").is_ok());
assert!(filter.check_ip("192.168.1.100").is_ok());

// IPs outside ranges are blocked
assert!(filter.check_ip("172.16.0.1").is_err());
```

**CIDR Blacklist Mode:**

```
let mut filter = IpFilter::new(true);

// Block malicious network ranges
filter.add_to_blacklist("198.51.100.0/24")?;  // Block entire subnet
filter.add_to_blacklist("203.0.113.50")?;     // Block specific IP

// All IPs in blacklisted ranges are blocked
assert!(filter.check_ip("198.51.100.1").is_err());
assert!(filter.check_ip("198.51.100.255").is_err());
assert!(filter.check_ip("203.0.113.50").is_err());

// Other IPs are allowed
assert!(filter.check_ip("10.0.0.1").is_ok());
```

### BodyInspector

Inspects and limits request body size.

```
pub struct BodyInspector {
    pub max_body_size: usize,
    pub buffer: Arc<Mutex<Vec<u8>>>,
    pub enabled: bool,
}

impl BodyInspector {
    /// Create a new body inspector
    ///
    /// # Arguments
    /// * `max_body_size` - Maximum body size in bytes
    /// * `enabled` - Whether inspection is enabled
    ///
    /// # Example
    /// ```rust
    /// let inspector = BodyInspector::new(1048576, true); // 1MB limit
    /// ```
    pub fn new(max_body_size: usize, enabled: bool) -> Self;

    /// Append a chunk to the buffer
    ///
    /// # Arguments
    /// * `chunk` - Body chunk to append
    ///
    /// # Returns
    /// * `Ok(())` - Chunk appended successfully
    /// * `Err(Error)` - Size limit exceeded
    ///
    /// # Example
    /// ```rust
    /// use bytes::Bytes;
    ///
    /// let chunk = Bytes::from("request body data");
    /// inspector.append_chunk(&chunk)?;
    /// ```
    pub fn append_chunk(&self, chunk: &Bytes) -> Result<(), Error>;

    /// Get the complete buffered body
    ///
    /// # Returns
    /// Complete body as byte vector
    ///
    /// # Example
    /// ```rust
    /// let body = inspector.get_body();
    /// println!("Body size: {} bytes", body.len());
    /// ```
    pub fn get_body(&self) -> Vec<u8>;

    /// Clear the buffer
    ///
    /// Should be called after each request
    ///
    /// # Example
    /// ```rust
    /// inspector.clear();
    /// ```
    pub fn clear(&self);

    /// Get current buffer size
    ///
    /// # Example
    /// ```rust
    /// let size = inspector.current_size();
    /// ```
    pub fn current_size(&self) -> usize;
}
```

## Configuration API

### WafConfig

Main configuration structure loaded from YAML.

```
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WafConfig {
    pub sql_injection: RuleConfig,
    pub xss: RuleConfig,
    pub rate_limit: RateLimitConfig,
    pub ip_filter: IpFilterConfig,
    pub max_body_size: usize,
}

impl WafConfig {
    /// Load configuration from YAML file
    ///
    /// # Arguments
    /// * `path` - Path to YAML config file
    ///
    /// # Returns
    /// * `Ok(WafConfig)` - Configuration loaded successfully
    /// * `Err(Box<dyn Error>)` - Failed to load or parse config
    ///
    /// # Example
    /// ```rust
    /// let config = WafConfig::from_file("config/waf_rules.yaml")?;
    /// println!("SQL injection enabled: {}", config.sql_injection.enabled);
    /// ```
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>>;

    /// Get default configuration
    ///
    /// # Example
    /// ```rust
    /// let config = WafConfig::default();
    /// ```
    pub fn default() -> Self;
}
```

### RuleConfig

Configuration for individual security rules.

```
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuleConfig {
    /// Whether this rule is enabled
    pub enabled: bool,

    /// true = block requests, false = log only
    pub block_mode: bool,
}
```

### RateLimitConfig

Rate limiting configuration.

```
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled
    pub enabled: bool,

    /// Maximum requests per window
    pub max_requests: u32,

    /// Time window in seconds
    pub window_secs: u64,
}
```

### IpFilterConfig

IP filtering configuration.

```
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IpFilterConfig {
    /// Whether IP filtering is enabled
    pub enabled: bool,

    /// List of allowed IPs
    pub whitelist: Vec<String>,

    /// List of blocked IPs
    pub blacklist: Vec<String>,
}
```

## Metrics API

### MetricsCollector

Prometheus metrics collection.

```
pub struct MetricsCollector {
    pub registry: Arc<Registry>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    ///
    /// Automatically registers metrics with Prometheus default registry
    ///
    /// # Example
    /// ```rust
    /// let metrics = Arc::new(MetricsCollector::new());
    /// ```
    pub fn new() -> Self;

    /// Increment allowed requests counter
    ///
    /// # Example
    /// ```rust
    /// metrics.increment_allowed_requests();
    /// ```
    pub fn increment_allowed_requests(&self);

    /// Increment blocked requests counter
    ///
    /// # Arguments
    /// * `reason` - Block reason (e.g., "sql_injection", "xss", "rate_limit")
    ///
    /// # Example
    /// ```rust
    /// metrics.increment_blocked_requests("sql_injection");
    /// ```
    pub fn increment_blocked_requests(&self, reason: &str);
}
```

**Available Metrics:**

- `waf_total_requests` - Total requests processed
- `waf_allowed_requests` - Requests that passed all checks
- `waf_blocked_requests{reason}` - Blocked requests by reason

**Block Reasons:**

- `sql_injection` - SQL injection detected in URI/headers
- `sql_injection_body` - SQL injection in request body
- `xss` - XSS detected in URI/headers
- `xss_body` - XSS in request body
- `rate_limit` - Rate limit exceeded
- `body_too_large` - Body size limit exceeded
- `ip_blacklist` - IP is blacklisted

## Custom Rules

### Creating a Custom Rule

Step-by-step guide to creating custom security rules.

#### Step 1: Define Your Rule Struct

```
use pingora_waf::{SecurityRule, SecurityViolation, ThreatLevel};
use pingora::http::RequestHeader;
use regex::Regex;

pub struct PathTraversalRule {
    enabled: bool,
    block_mode: bool,
    patterns: Vec<Regex>,
}

impl PathTraversalRule {
    pub fn new(enabled: bool, block_mode: bool) -> Self {
        let patterns = vec![
            Regex::new(r"\.\./").unwrap(),
            Regex::new(r"\.\.\%2F").unwrap(),
            Regex::new(r"\.\.\%5C").unwrap(),
        ];

        Self {
            enabled,
            block_mode,
            patterns,
        }
    }
}
```

#### Step 2: Implement SecurityRule Trait

```
impl SecurityRule for PathTraversalRule {
    fn check(
        &self,
        request: &RequestHeader,
        _body: Option<&[u8]>,
    ) -> Result<(), SecurityViolation> {
        if !self.enabled {
            return Ok(());
        }

        let uri = request.uri.to_string();

        // Check for path traversal patterns
        for pattern in &self.patterns {
            if pattern.is_match(&uri) {
                return Err(SecurityViolation {
                    threat_type: "PATH_TRAVERSAL".to_string(),
                    threat_level: ThreatLevel::High,
                    description: format!("Path traversal detected: {}", uri),
                    blocked: self.block_mode,
                });
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "Path Traversal Detector"
    }
}
```

#### Step 3: Integrate with WAF

```
// In your main.rs or custom proxy
use std::sync::Arc;

let path_traversal_rule = Arc::new(PathTraversalRule::new(true, true));

// Add to your request filter
async fn request_filter(
    &self,
    session: &mut Session,
    ctx: &mut Self::CTX,
) -> Result<bool> {
    // Check custom rule
    if let Err(violation) = self.path_traversal_rule.check(session.req_header(), None) {
        error!("Path traversal detected: {:?}", violation);

        if violation.blocked {
            let _ = session.respond_error(403).await;
            return Ok(true); // Block request
        }
    }

    Ok(false)
}
```

### Advanced Custom Rule Example

```
use pingora_waf::*;
use std::collections::HashSet;
use once_cell::sync::Lazy;

// Detect suspicious user agents
pub struct SuspiciousUserAgentRule {
    enabled: bool,
    block_mode: bool,
}

static SUSPICIOUS_AGENTS: Lazy<HashSet<&str>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.insert("sqlmap");
    set.insert("nikto");
    set.insert("nmap");
    set.insert("masscan");
    set.insert("metasploit");
    set
});

impl SuspiciousUserAgentRule {
    pub fn new(enabled: bool, block_mode: bool) -> Self {
        Self { enabled, block_mode }
    }

    fn is_suspicious(&self, user_agent: &str) -> bool {
        let ua_lower = user_agent.to_lowercase();
        SUSPICIOUS_AGENTS.iter().any(|agent| ua_lower.contains(agent))
    }
}

impl SecurityRule for SuspiciousUserAgentRule {
    fn check(
        &self,
        request: &RequestHeader,
        _body: Option<&[u8]>,
    ) -> Result<(), SecurityViolation> {
        if !self.enabled {
            return Ok(());
        }

        if let Some(ua_header) = request.headers.get("user-agent") {
            if let Ok(ua_str) = ua_header.to_str() {
                if self.is_suspicious(ua_str) {
                    return Err(SecurityViolation {
                        threat_type: "SUSPICIOUS_USER_AGENT".to_string(),
                        threat_level: ThreatLevel::Medium,
                        description: format!("Suspicious user agent: {}", ua_str),
                        blocked: self.block_mode,
                    });
                }
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "Suspicious User Agent Detector"
    }
}
```

### Rule with Configuration

```
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomRuleConfig {
    pub enabled: bool,
    pub block_mode: bool,
    pub patterns: Vec<String>,
}

pub struct ConfigurableRule {
    config: CustomRuleConfig,
    compiled_patterns: Vec<Regex>,
}

impl ConfigurableRule {
    pub fn from_config(config: CustomRuleConfig) -> Result<Self, regex::Error> {
        let compiled_patterns = config
            .patterns
            .iter()
            .map(|p| Regex::new(p))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            config,
            compiled_patterns,
        })
    }
}

impl SecurityRule for ConfigurableRule {
    fn check(
        &self,
        request: &RequestHeader,
        _body: Option<&[u8]>,
    ) -> Result<(), SecurityViolation> {
        if !self.config.enabled {
            return Ok(());
        }

        let uri = request.uri.to_string();

        for pattern in &self.compiled_patterns {
            if pattern.is_match(&uri) {
                return Err(SecurityViolation {
                    threat_type: "CUSTOM_PATTERN_MATCH".to_string(),
                    threat_level: ThreatLevel::Medium,
                    description: format!("Custom pattern matched: {}", uri),
                    blocked: self.config.block_mode,
                });
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "Configurable Custom Rule"
    }
}
```

## Type Reference

### SecurityViolation

Represents a detected security threat.

```
#[derive(Debug, Clone)]
pub struct SecurityViolation {
    /// Type of threat (e.g., "SQL_INJECTION", "XSS")
    pub threat_type: String,

    /// Severity level
    pub threat_level: ThreatLevel,

    /// Human-readable description
    pub description: String,

    /// Whether the request should be blocked
    pub blocked: bool,
}
```

### ThreatLevel

Severity levels for threats.

```
#[derive(Debug, Clone, Copy)]
pub enum ThreatLevel {
    Low,      // Minor issues, monitoring recommended
    Medium,   // Potential threats, investigation needed
    High,     // Clear threats, blocking recommended
    Critical, // Severe threats, immediate blocking required
}
```

### ProxyContext

Request context passed through the proxy pipeline.

```
pub struct ProxyContext {
    pub sql_detector: Arc<SqlInjectionDetector>,
    pub xss_detector: Arc<XssDetector>,
    pub rate_limiter: Arc<RateLimiter>,
    pub ip_filter: Arc<IpFilter>,
    pub body_inspector: BodyInspector,
    pub violations: Vec<SecurityViolation>,
}

impl ProxyContext {
    pub fn new(
        sql_detector: Arc<SqlInjectionDetector>,
        xss_detector: Arc<XssDetector>,
        rate_limiter: Arc<RateLimiter>,
        ip_filter: Arc<IpFilter>,
        max_body_size: usize,
    ) -> Self;
}
```

## Examples

### Complete Custom WAF Implementation

```
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use pingora_waf::*;
use std::sync::Arc;

struct CustomWafProxy {
    sql_detector: Arc<SqlInjectionDetector>,
    xss_detector: Arc<XssDetector>,
    custom_rules: Vec<Arc<dyn SecurityRule>>,
    metrics: Arc<MetricsCollector>,
}

#[async_trait::async_trait]
impl ProxyHttp for CustomWafProxy {
    type CTX = ProxyContext;

    fn new_ctx(&self) -> Self::CTX {
        ProxyContext::new(
            self.sql_detector.clone(),
            self.xss_detector.clone(),
            Arc::new(RateLimiter::new(1000, 60, true)),
            Arc::new(IpFilter::new(false)),
            1048576,
        )
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        // Check built-in rules
        if let Err(violation) = ctx.sql_detector.check(session.req_header(), None) {
            self.metrics.increment_blocked_requests("sql_injection");
            let _ = session.respond_error(403).await;
            return Ok(true);
        }

        // Check custom rules
        for rule in &self.custom_rules {
            if let Err(violation) = rule.check(session.req_header(), None) {
                log::warn!("Custom rule triggered: {}", rule.name());
                self.metrics.increment_blocked_requests("custom_rule");

                if violation.blocked {
                    let _ = session.respond_error(403).await;
                    return Ok(true);
                }
            }
        }

        self.metrics.increment_allowed_requests();
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = Box::new(HttpPeer::new(
            ("backend.example.com", 443),
            true,
            "backend.example.com".to_string(),
        ));
        Ok(peer)
    }
}

fn main() {
    // Create custom rules
    let mut custom_rules: Vec<Arc<dyn SecurityRule>> = vec![];
    custom_rules.push(Arc::new(PathTraversalRule::new(true, true)));
    custom_rules.push(Arc::new(SuspiciousUserAgentRule::new(true, true)));

    // Create WAF proxy
    let proxy = CustomWafProxy {
        sql_detector: Arc::new(SqlInjectionDetector::new(true, true)),
        xss_detector: Arc::new(XssDetector::new(true, true)),
        custom_rules,
        metrics: Arc::new(MetricsCollector::new()),
    };

    // Start server
    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let mut service = http_proxy_service(&server.configuration, proxy);
    service.add_tcp("0.0.0.0:6188");
    server.add_service(service);

    server.run_forever();
}
```

### Testing Custom Rules

```
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_traversal_detection() {
        let rule = PathTraversalRule::new(true, true);

        // Should detect path traversal
        let req = RequestHeader::build("GET", b"/../etc/passwd", None).unwrap();
        assert!(rule.check(&req, None).is_err());

        // Should allow normal paths
        let req = RequestHeader::build("GET", b"/api/users", None).unwrap();
        assert!(rule.check(&req, None).is_ok());
    }

    #[test]
    fn test_suspicious_user_agent() {
        let rule = SuspiciousUserAgentRule::new(true, true);

        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("User-Agent", "sqlmap/1.0").unwrap();

        assert!(rule.check(&req, None).is_err());
    }
}
```

## Error Handling

### Pingora Error Types

```
use pingora::{Error, ErrorType};

// Create error
let err = Error::new(ErrorType::InvalidHTTPHeader);

// With context
let mut err = Error::new(ErrorType::InvalidHTTPHeader);
err.set_context("Request body too large");

// String error
let err = Error::new_str("Custom error message");
```

### Converting SecurityViolation to Error

```
fn violation_to_error(violation: &SecurityViolation) -> pingora::Error {
    let error_type = match violation.threat_level {
        ThreatLevel::Critical | ThreatLevel::High => ErrorType::InvalidHTTPHeader,
        _ => ErrorType::InvalidHTTPHeader,
    };

    let mut err = pingora::Error::new(error_type);
    err.set_context(violation.description.clone());
    err
}
```

## Best Practices

### 1. Use Arc for Shared State

```
// Good
let detector = Arc::new(SqlInjectionDetector::new(true, true));

// Share across threads
let detector_clone = Arc::clone(&detector);
```

### 2. Lazy Static for Expensive Initialization

```
use once_cell::sync::Lazy;

static PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"pattern1").unwrap(),
        Regex::new(r"pattern2").unwrap(),
    ]
});
```

### 3. Early Returns

```
fn check(&self, request: &RequestHeader, body: Option<&[u8]>) -> Result<(), SecurityViolation> {
    if !self.enabled {
        return Ok(());
    }

    // Continue checking...
}
```

### 4. Avoid Allocations in Hot Paths

```
// Good - use references
fn check_string(&self, input: &str) -> bool {
    self.patterns.iter().any(|p| p.is_match(input))
}

// Avoid - unnecessary allocation
fn check_string(&self, input: &str) -> bool {
    let owned = input.to_string();
    self.patterns.iter().any(|p| p.is_match(&owned))
}
```

### 5. Error Context

```
// Provide helpful context
return Err(SecurityViolation {
    threat_type: "SQL_INJECTION".to_string(),
    threat_level: ThreatLevel::Critical,
    description: format!("SQL injection in URI: {}", uri), // Include details
    blocked: self.block_mode,
});
```

## Performance Considerations

### Regex Compilation

```
// Compile once, reuse many times
static SQL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)\bunion\b.*\bselect\b").unwrap(),
        // More patterns...
    ]
});
```

### Memory Pooling

```
use parking_lot::Mutex;

// Reuse buffers
let buffer_pool: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));

fn get_buffer(pool: &Arc<Mutex<Vec<Vec<u8>>>>) -> Vec<u8> {
    pool.lock().pop().unwrap_or_else(|| Vec::with_capacity(1024))
}

fn return_buffer(pool: &Arc<Mutex<Vec<Vec<u8>>>>, mut buffer: Vec<u8>) {
    buffer.clear();
    pool.lock().push(buffer);
}
```

## See Also

- [Security Rules Documentation](security-rules.md)
- [Configuration Guide](configuration.md)
- [Examples](examples.md)
- [Development Guide](development.md)

---

**Need help?** [Open an issue](https://github.com/aarambhdevhub/pingora-waf/issues) or [ask in discussions](https://github.com/aarambhdevhub/pingora-waf/discussions)
