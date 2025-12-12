# Configuration Guide

This guide covers all configuration options for Pingora WAF, including security rules, rate limiting, IP filtering, and advanced settings.

## Table of Contents

- [Configuration Files](#configuration-files)
- [Basic Configuration](#basic-configuration)
- [SQL Injection Detection](#sql-injection-detection)
- [XSS Prevention](#xss-prevention)
- [Rate Limiting](#rate-limiting)
- [IP Filtering](#ip-filtering)
- [Body Size Limits](#body-size-limits)
- [Backend Configuration](#backend-configuration)
- [Logging Configuration](#logging-configuration)
- [Environment Variables](#environment-variables)
- [Advanced Configuration](#advanced-configuration)
- [Configuration Examples](#configuration-examples)
- [Best Practices](#best-practices)

## Configuration Files

Pingora WAF uses YAML configuration files located in the `config/` directory:

```
config/
├── waf_rules.yaml           # Main security rules configuration
├── waf_rules_testing.yaml   # Testing/development configuration
├── waf_rules_production.yaml # Production configuration (optional)
└── server.yaml              # Server-level configuration (optional)
```

### Default Configuration Location

By default, the WAF loads: `config/waf_rules.yaml`

To use a different configuration:

```
# Method 1: Environment variable
WAF_CONFIG=config/waf_rules_production.yaml ./target/release/pingora-waf

# Method 2: Command-line argument (if implemented)
./target/release/pingora-waf --config config/waf_rules_production.yaml
```

## Basic Configuration

### Minimal Configuration

The simplest working configuration:

```
# config/waf_rules.yaml
sql_injection:
  enabled: true
  block_mode: true

xss:
  enabled: true
  block_mode: true

rate_limit:
  enabled: false

ip_filter:
  enabled: false

max_body_size: 1048576  # 1MB
```

### Full Configuration Template

```
# SQL Injection Protection
sql_injection:
  enabled: true           # Enable/disable SQL injection detection
  block_mode: true        # true = block requests, false = log only

# Cross-Site Scripting (XSS) Protection
xss:
  enabled: true           # Enable/disable XSS detection
  block_mode: true        # true = block requests, false = log only

# Rate Limiting
rate_limit:
  enabled: true           # Enable/disable rate limiting
  max_requests: 1000      # Maximum requests per window
  window_secs: 60         # Time window in seconds

# IP Address Filtering
ip_filter:
  enabled: false          # Enable/disable IP filtering
  whitelist: []           # List of allowed IP addresses/ranges
  blacklist: []           # List of blocked IP addresses/ranges

# Request Body Size Limit
max_body_size: 1048576    # Maximum request body size in bytes (1MB)
```

## SQL Injection Detection

### Configuration Options

```
sql_injection:
  enabled: true      # Master switch for SQL injection detection
  block_mode: true   # Whether to block or just log
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable SQL injection detection |
| `block_mode` | boolean | `true` | `true` = block requests, `false` = log only |

### Detection Patterns

The SQL injection detector checks for:

1. **Union-based injection**
   - `UNION SELECT`
   - `SELECT * FROM`

2. **Boolean-based injection**
   - `OR 1=1`
   - `AND 1=1`
   - `OR 'a'='a'`

3. **Comment-based injection**
   - `--` (SQL comments)
   - `/**/` (multi-line comments)
   - `'--` (quote with comment)

4. **Time-based injection**
   - `SLEEP()`
   - `BENCHMARK()`
   - `WAITFOR DELAY`

5. **Stacked queries**
   - `; DROP TABLE`
   - `; DELETE FROM`

6. **SQL functions**
   - `xp_cmdshell`
   - `sp_executesql`

### Examples

#### Development Mode (Log Only)

```
sql_injection:
  enabled: true
  block_mode: false  # Log violations but don't block
```

Useful for:
- Testing new applications
- Identifying false positives
- Development environments

#### Production Mode (Block)

```
sql_injection:
  enabled: true
  block_mode: true   # Block all SQL injection attempts
```

Required for:
- Production environments
- High-security applications
- Compliance requirements

#### Disabled (Not Recommended)

```
sql_injection:
  enabled: false
```

**Warning**: Only disable if you have another SQL injection protection mechanism.

### False Positive Handling

If legitimate requests are being blocked:

1. **Check logs** to identify the pattern:
   ```
   grep "SQL injection" /var/log/pingora-waf/error.log
   ```

2. **Temporarily disable blocking**:
   ```
   sql_injection:
     block_mode: false
   ```

3. **Report false positives** to help improve detection

## XSS Prevention

### Configuration Options

```
xss:
  enabled: true      # Master switch for XSS detection
  block_mode: true   # Whether to block or just log
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable XSS detection |
| `block_mode` | boolean | `true` | `true` = block requests, `false` = log only |

### Detection Patterns

The XSS detector checks for:

1. **Script tags**
   - `<script>`
   - `</script>`
   - `<script src=...>`

2. **Event handlers**
   - `onload=`
   - `onerror=`
   - `onclick=`
   - `onmouseover=`

3. **JavaScript protocol**
   - `javascript:`
   - `javascript:alert()`

4. **Dangerous tags**
   - `<iframe>`
   - `<object>`
   - `<embed>`
   - `<img>` with event handlers

5. **JavaScript functions**
   - `eval()`
   - `alert()`
   - `expression()`

### Examples

#### Strict Mode (Block All)

```
xss:
  enabled: true
  block_mode: true
```

#### Monitoring Mode (Log Only)

```
xss:
  enabled: true
  block_mode: false  # Useful for testing
```

#### Disabled (Not Recommended)

```
xss:
  enabled: false
```

### Safe Headers

These headers are excluded from XSS checks to avoid false positives:

- `Accept`
- `Accept-Encoding`
- `Accept-Language`
- `Content-Type`
- `User-Agent`
- `Cache-Control`
- `Connection`
- `Referer`
- `Origin`
- `Host`

## Rate Limiting

### Configuration Options

```
rate_limit:
  enabled: true
  max_requests: 1000    # Requests allowed per window
  window_secs: 60       # Time window in seconds
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable rate limiting |
| `max_requests` | integer | `1000` | Maximum requests per window |
| `window_secs` | integer | `60` | Time window in seconds |

### Calculation

**Requests per second** = `max_requests / window_secs`

Examples:
- `1000 / 60` = ~17 req/sec per IP
- `5000 / 60` = ~83 req/sec per IP
- `100 / 60` = ~1.7 req/sec per IP

### Rate Limiting Strategies

#### 1. Aggressive (Low Traffic Sites)

```
rate_limit:
  enabled: true
  max_requests: 100     # Very restrictive
  window_secs: 60
```

**Use for**:
- Login endpoints
- Password reset pages
- API authentication

**Result**: ~1.7 req/sec per IP

#### 2. Moderate (Standard Web Applications)

```
rate_limit:
  enabled: true
  max_requests: 1000    # Balanced
  window_secs: 60
```

**Use for**:
- General web applications
- Public APIs
- Content sites

**Result**: ~17 req/sec per IP

#### 3. Relaxed (High Traffic Sites)

```
rate_limit:
  enabled: true
  max_requests: 5000    # Permissive
  window_secs: 60
```

**Use for**:
- High-traffic websites
- CDN origins
- Media streaming

**Result**: ~83 req/sec per IP

#### 4. Per-Endpoint Rate Limiting (Advanced)

For different limits per endpoint, you'll need custom configuration:

```
rate_limit:
  enabled: true
  default:
    max_requests: 1000
    window_secs: 60
  endpoints:
    - path: "/api/login"
      max_requests: 10
      window_secs: 60
    - path: "/api/data"
      max_requests: 5000
      window_secs: 60
```

**Note**: Per-endpoint rate limiting requires code modifications.

#### 5. Disabled (Testing/Development)

```
rate_limit:
  enabled: false
```

**Use for**:
- Load testing
- Development environments
- Performance benchmarking

### Rate Limit Response

When rate limit is exceeded:
- **HTTP Status**: `429 Too Many Requests`
- **Response Body**: Empty
- **Metric**: `waf_blocked_requests{reason="rate_limit"}` incremented

### Tuning Guidelines

| Traffic Type | max_requests | window_secs | req/sec |
|--------------|--------------|-------------|---------|
| Very Low (Login) | 10 | 60 | 0.17 |
| Low (Forms) | 100 | 60 | 1.7 |
| Medium (Web) | 1000 | 60 | 17 |
| High (API) | 5000 | 60 | 83 |
| Very High (CDN) | 10000 | 60 | 167 |

## IP Filtering

### Configuration Options

```
ip_filter:
  enabled: true
  whitelist:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.1.100"
  blacklist:
    - "192.0.2.1"
    - "198.51.100.0/24"
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable/disable IP filtering |
| `whitelist` | array | `[]` | Allowed IP addresses/ranges |
| `blacklist` | array | `[]` | Blocked IP addresses/ranges |

### IP Address Formats

#### Single IP Address

```
whitelist:
  - "192.168.1.1"
  - "10.0.0.5"
```

#### CIDR Notation (Subnet)

```
whitelist:
  - "10.0.0.0/8"          # 10.0.0.0 - 10.255.255.255
  - "172.16.0.0/12"       # 172.16.0.0 - 172.31.255.255
  - "192.168.0.0/16"      # 192.168.0.0 - 192.168.255.255
```

### Filtering Modes

#### 1. Whitelist Mode (Most Restrictive)

Only allow specific IPs:

```
ip_filter:
  enabled: true
  whitelist:
    - "10.0.0.0/8"        # Internal network only
  blacklist: []
```

**Behavior**:
- IPs in whitelist → Allowed
- All other IPs → Blocked with 403

**Use for**:
- Admin panels
- Internal APIs
- Management interfaces

#### 2. Blacklist Mode (Most Common)

Block specific IPs, allow all others:

```
ip_filter:
  enabled: true
  whitelist: []           # Empty = allow all by default
  blacklist:
    - "192.0.2.1"         # Known attacker
    - "198.51.100.0/24"   # Malicious subnet
```

**Behavior**:
- IPs in blacklist → Blocked with 403
- All other IPs → Allowed

**Use for**:
- Production websites
- Public APIs
- General protection

#### 3. Mixed Mode

Combine whitelist and blacklist:

```
ip_filter:
  enabled: true
  whitelist:
    - "10.0.0.0/8"        # Internal network
  blacklist:
    - "10.0.0.50"         # Specific internal IP to block
```

**Behavior**:
- Whitelist checked first
- Then blacklist is checked
- If not in whitelist → Blocked

#### 4. Disabled (Default)

```
ip_filter:
  enabled: false
```

### Common IP Ranges

#### Private Networks (RFC 1918 - IPv4)

```
whitelist:
  - "10.0.0.0/8"          # Class A private (16M hosts)
  - "172.16.0.0/12"       # Class B private (1M hosts)
  - "192.168.0.0/16"      # Class C private (65K hosts)
```

#### IPv6 Networks

```
whitelist:
  - "fc00::/7"            # Unique Local Addresses (ULA)
  - "fe80::/10"           # Link-Local Addresses
  - "2001:db8::/32"       # Documentation prefix
```

#### Localhost

```
whitelist:
  - "127.0.0.1"           # IPv4 localhost (single IP)
  - "127.0.0.0/8"         # IPv4 loopback range (CIDR)
  - "::1"                 # IPv6 localhost
```

#### Cloud Provider Ranges

**AWS (Example)**:
```
whitelist:
  - "3.0.0.0/8"           # AWS IP range (partial)
```

**GCP (Example)**:
```
whitelist:
  - "35.190.0.0/16"       # GCP range (partial)
```

**Note**: Check current ranges from cloud providers.

### X-Forwarded-For Support

The WAF automatically checks `X-Forwarded-For` header:

```
# Configuration stays the same
ip_filter:
  enabled: true
  blacklist:
    - "192.0.2.1"
```

Request handling:
1. Check `X-Forwarded-For` header first
2. Fallback to direct client IP
3. Apply whitelist/blacklist rules

## Bot Detection

### Configuration Options

```
bot_detection:
  enabled: true
  block_mode: true
  allow_known_bots: true
  custom_bad_bots: []
  custom_good_bots: []
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable bot detection |
| `block_mode` | boolean | `true` | `true` = block bad bots, `false` = log only |
| `allow_known_bots` | boolean | `true` | Allow Googlebot, Bingbot, etc. |
| `custom_bad_bots` | array | `[]` | Additional regex patterns to block |
| `custom_good_bots` | array | `[]` | Additional identifiers to allow |

### Detection Modes

#### Block Bad Bots (Default)

```yaml
bot_detection:
  enabled: true
  block_mode: true
  allow_known_bots: true
```

Blocks: `sqlmap`, `nikto`, `scrapy`, `curl/`, `wget/`, etc.
Allows: `Googlebot`, `Bingbot`, `Slackbot`, etc.

#### Log Only Mode

```yaml
bot_detection:
  enabled: true
  block_mode: false  # Log but don't block
```

#### Custom Patterns

```yaml
bot_detection:
  custom_bad_bots:
    - "(?i)mycrawler"      # Regex pattern
    - "(?i)badbot\\d+"
  custom_good_bots:
    - "mymonitor"          # Substring match
    - "internaltool"
```

## Body Size Limits

### Configuration

```
max_body_size: 1048576  # Bytes (1MB)
```

### Common Sizes

| Size | Bytes | Description |
|------|-------|-------------|
| 1 KB | 1024 | Tiny requests |
| 10 KB | 10240 | Small forms |
| 100 KB | 102400 | Medium forms |
| 1 MB | 1048576 | **Default** - General use |
| 5 MB | 5242880 | File uploads |
| 10 MB | 10485760 | Large files |
| 50 MB | 52428800 | Video uploads |

### Examples

#### Strict (Small Forms Only)

```
max_body_size: 102400  # 100KB
```

**Use for**:
- Login forms
- Contact forms
- JSON APIs

#### Standard (Default)

```
max_body_size: 1048576  # 1MB
```

**Use for**:
- General web applications
- Most APIs
- Standard forms

#### Relaxed (File Uploads)

```
max_body_size: 10485760  # 10MB
```

**Use for**:
- Image uploads
- Document uploads
- Profile pictures

#### Very Relaxed (Media Uploads)

```
max_body_size: 52428800  # 50MB
```

**Use for**:
- Video uploads
- Large file sharing
- Media platforms

**Warning**: Large sizes increase memory usage and DoS risk.

### Size Limit Enforcement

The WAF checks body size at two points:

1. **Early Check** - `Content-Length` header
   - Rejects before body is received
   - Returns `413 Payload Too Large`
   - Most efficient

2. **Runtime Check** - During body streaming
   - Monitors actual bytes received
   - Safety net for missing/incorrect Content-Length
   - Returns `413 Payload Too Large`

### Response on Violation

```
HTTP/1.1 413 Payload Too Large
Content-Type: text/plain
Content-Length: 19

Request body too large
```

Metric incremented: `waf_blocked_requests{reason="body_too_large"}`

## Backend Configuration

### Configuring Backend Server

Backend is configured in `src/main.rs`:

```
// src/main.rs (around line 30)
let waf_proxy = WafProxy::new(
    ("127.0.0.1".to_string(), 8080),    // Backend address
    sql_detector,
    xss_detector,
    rate_limiter.clone(),
    ip_filter,
    metrics.clone(),
    config.max_body_size,
);
```

### Backend Options

#### Local HTTP Backend

```
("127.0.0.1".to_string(), 8080)
```

#### Remote Backend

```
("api.example.com".to_string(), 80)
```

#### HTTPS Backend (Port 443)

```
("secure-api.example.com".to_string(), 443)
```

#### Docker Container

```
("backend-container".to_string(), 8080)
```

#### Kubernetes Service

```
("backend-service.default.svc.cluster.local".to_string(), 80)
```

### Multiple Backends (Future)

Currently, only one backend is supported. For load balancing:

1. Use an external load balancer
2. Or deploy multiple WAF instances

## Logging Configuration

### Log Levels

Set via `RUST_LOG` environment variable:

```
# Error only
RUST_LOG=error ./target/release/pingora-waf

# Warning and above
RUST_LOG=warn ./target/release/pingora-waf

# Info and above (recommended for production)
RUST_LOG=info ./target/release/pingora-waf

# Debug (verbose)
RUST_LOG=debug ./target/release/pingora-waf

# Trace (very verbose)
RUST_LOG=trace ./target/release/pingora-waf
```

### Module-Specific Logging

```
# Only WAF module debug logs
RUST_LOG=pingora_waf=debug,info ./target/release/pingora-waf

# Multiple modules
RUST_LOG=pingora_waf::proxy=debug,pingora_waf::waf=trace ./target/release/pingora-waf
```

### Log Output

#### Console (Default)

```
RUST_LOG=info ./target/release/pingora-waf
```

#### File

```
RUST_LOG=info ./target/release/pingora-waf 2>&1 | tee /var/log/pingora-waf/waf.log
```

#### Systemd Journal

```
# Logs automatically go to journalctl
sudo journalctl -u pingora-waf -f
```

### Log Format

```
[2025-10-08T08:00:00Z INFO  pingora_waf::proxy] Request completed - IP: 192.168.1.1, Method: GET, URI: /api/test, Status: 200
[2025-10-08T08:00:01Z ERROR pingora_waf::proxy] SQL injection detected: SecurityViolation { threat_type: "SQL_INJECTION", ... }
```

## Environment Variables

### Core Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `RUST_LOG` | Logging level | `info` |
| `RUST_BACKTRACE` | Stack traces on panic | `1` or `full` |
| `WAF_CONFIG` | Config file path | `config/production.yaml` |

### Usage

```
# Set for single run
RUST_LOG=debug RUST_BACKTRACE=1 ./target/release/pingora-waf

# Set in systemd service
Environment="RUST_LOG=info"
Environment="RUST_BACKTRACE=1"

# Set in Docker
docker run -e RUST_LOG=info -e RUST_BACKTRACE=1 pingora-waf

# Set in Kubernetes
env:
  - name: RUST_LOG
    value: "info"
```

## Advanced Configuration

### Custom Configuration Path

Modify `src/main.rs`:

```
// Check for custom config path from environment
let config_path = std::env::var("WAF_CONFIG")
    .unwrap_or_else(|_| "config/waf_rules.yaml".to_string());

let config = WafConfig::from_file(&config_path)
    .unwrap_or_else(|_| {
        info!("Using default configuration");
        WafConfig::default()
    });
```

### Hot Reload (Future Feature)

Currently, configuration changes require restart:

```
# Restart to apply config changes
sudo systemctl restart pingora-waf
```

Planned for future versions:
- Configuration file watching
- Reload on SIGHUP signal
- Zero-downtime config updates

### Performance Tuning

In `src/main.rs`:

```
// Set worker threads (default: CPU count)
let mut server_conf = Opt::default();
server_conf.threads = 8;  // Manually set thread count

let mut server = Server::new(Some(server_conf)).unwrap();
```

## Configuration Examples

### Example 1: Development Environment

```
# config/waf_rules_dev.yaml
sql_injection:
  enabled: true
  block_mode: false  # Log only

xss:
  enabled: true
  block_mode: false  # Log only

rate_limit:
  enabled: false     # Disabled for testing

ip_filter:
  enabled: false

max_body_size: 10485760  # 10MB for testing
```

### Example 2: Production Web Application

```
# config/waf_rules_production.yaml
sql_injection:
  enabled: true
  block_mode: true   # Block all attacks

xss:
  enabled: true
  block_mode: true   # Block all attacks

rate_limit:
  enabled: true
  max_requests: 5000
  window_secs: 60

ip_filter:
  enabled: true
  whitelist: []
  blacklist:
    - "192.0.2.1"
    - "198.51.100.0/24"

max_body_size: 5242880  # 5MB
```

### Example 3: API Gateway

```
# config/waf_rules_api.yaml
sql_injection:
  enabled: true
  block_mode: true

xss:
  enabled: false     # APIs typically don't need XSS protection

rate_limit:
  enabled: true
  max_requests: 10000  # High throughput
  window_secs: 60

ip_filter:
  enabled: true
  whitelist:
    - "10.0.0.0/8"   # Only internal network

max_body_size: 1048576  # 1MB JSON payloads
```

### Example 4: Admin Panel

```
# config/waf_rules_admin.yaml
sql_injection:
  enabled: true
  block_mode: true

xss:
  enabled: true
  block_mode: true

rate_limit:
  enabled: true
  max_requests: 100   # Very restrictive
  window_secs: 60

ip_filter:
  enabled: true
  whitelist:
    - "10.0.0.0/8"    # Internal only
    - "203.0.113.5"   # Admin home IP

max_body_size: 524288  # 512KB
```

### Example 5: High-Security Application

```
# config/waf_rules_secure.yaml
sql_injection:
  enabled: true
  block_mode: true   # Zero tolerance

xss:
  enabled: true
  block_mode: true   # Zero tolerance

rate_limit:
  enabled: true
  max_requests: 500  # Conservative limit
  window_secs: 60

ip_filter:
  enabled: true
  whitelist:
    - "192.168.1.0/24"  # Specific network only

max_body_size: 102400  # 100KB - minimal
```

## Best Practices

### Security Best Practices

1. **Always enable blocking in production**
   ```
   sql_injection:
     block_mode: true  # Never false in production
   xss:
     block_mode: true
   ```

2. **Use appropriate rate limits**
   - Start conservative, increase as needed
   - Monitor metrics for legitimate users hitting limits

3. **Enable IP filtering when possible**
   - Whitelist for admin panels
   - Blacklist known attackers

4. **Set reasonable body size limits**
   - Start small (1MB)
   - Increase only if needed
   - Monitor for DoS attempts

5. **Enable all relevant security rules**
   - Don't disable unless you have a good reason
   - Document why any rule is disabled

### Performance Best Practices

1. **Tune rate limiting carefully**
   - Too strict = false positives
   - Too loose = ineffective

2. **Monitor metrics regularly**
   - Track block rates
   - Identify patterns

3. **Review logs periodically**
   - Check for false positives
   - Adjust rules as needed

4. **Test configuration changes**
   - Use `block_mode: false` initially
   - Monitor for a period
   - Then enable blocking

### Operational Best Practices

1. **Version control your configs**
   ```
   git add config/waf_rules.yaml
   git commit -m "Update rate limits"
   ```

2. **Use environment-specific configs**
   - `waf_rules_dev.yaml`
   - `waf_rules_staging.yaml`
   - `waf_rules_production.yaml`

3. **Document custom configurations**
   - Add comments explaining why
   - Include ticket/issue references

4. **Test before deploying**
   - Test in staging first
   - Gradually roll out changes

5. **Have a rollback plan**
   - Keep previous working config
   - Know how to quickly revert

### Monitoring Best Practices

1. **Set up alerts**
   - High block rate
   - Configuration errors
   - Service down

2. **Monitor metrics**
   - `waf_blocked_requests`
   - `waf_allowed_requests`
   - Block rate by reason

3. **Review logs**
   - Weekly review minimum
   - Look for patterns
   - Adjust rules accordingly

## Validation

### Validate Configuration Syntax

```
# Check YAML syntax
yamllint config/waf_rules.yaml

# Test load configuration
cargo test --test config_tests
```

### Test Configuration

```
# Start with test config
WAF_CONFIG=config/waf_rules_test.yaml RUST_LOG=debug cargo run

# Run security tests
cargo run --example security_test

# Check metrics
curl http://localhost:6190/metrics | grep waf_
```

## Troubleshooting

### Configuration Not Loading

```
# Check file exists
ls -la config/waf_rules.yaml

# Check permissions
chmod 644 config/waf_rules.yaml

# Check YAML syntax
yamllint config/waf_rules.yaml

# Check logs
RUST_LOG=debug cargo run
```

### Changes Not Applied

Configuration changes require restart:

```
# Restart service
sudo systemctl restart pingora-waf

# Or kill and restart
pkill pingora-waf
RUST_LOG=info ./target/release/pingora-waf
```

### Invalid Configuration Values

Check logs for errors:

```
[ERROR] Invalid configuration: max_requests must be positive
```

Validate ranges:
- `max_requests`: > 0
- `window_secs`: > 0
- `max_body_size`: > 0

## Next Steps

- **[Security Rules](security-rules.md)** - Detailed security rules documentation
- **[Deployment](deployment.md)** - Production deployment guide
- **[Monitoring](monitoring.md)** - Set up metrics and alerts
- **[Performance](performance.md)** - Optimize for your workload

---

**Questions?** Check [FAQ](faq.md) or ask in [Discussions](https://github.com/aarambhdevhub/pingora-waf/discussions)

**Last Updated**: October 8, 2025
**Version**: 0.1.0
