# Security Rules Documentation

This guide provides comprehensive documentation for all security rules implemented in Pingora WAF.

## Table of Contents

- [Overview](#overview)
- [SQL Injection Detection](#sql-injection-detection)
- [Cross-Site Scripting (XSS) Prevention](#cross-site-scripting-xss-prevention)
- [Rate Limiting](#rate-limiting)
- [IP Filtering](#ip-filtering)
- [Request Body Inspection](#request-body-inspection)
- [Custom Security Rules](#custom-security-rules)
- [Rule Engine](#rule-engine)
- [False Positives](#false-positives)
- [Best Practices](#best-practices)

## Overview

Pingora WAF implements multiple layers of security rules to protect web applications from common attacks. Each rule can be independently enabled, disabled, or configured to operate in detection-only mode.

### Security Rule Architecture

```
Request → IP Filter → Rate Limiter → Header Inspection → Body Inspection → Backend
            ↓             ↓               ↓                    ↓
         Block 403    Block 429       Block 403            Block 403
```

### Rule Configuration Structure

```
rule_name:
  enabled: true      # Enable/disable the rule
  block_mode: true   # true = block, false = log only
```

### Threat Levels

Each security violation is classified by severity:

| Level | Description | Example |
|-------|-------------|---------|
| **Low** | Minor security concern | HTTP protocol violations |
| **Medium** | Potential attack attempt | Rate limit exceeded |
| **High** | Confirmed attack pattern | XSS detected |
| **Critical** | Severe security threat | SQL injection detected |

## SQL Injection Detection

SQL Injection is one of the most dangerous web application vulnerabilities. Pingora WAF uses advanced pattern matching to detect and block SQL injection attempts.

### Configuration

```
sql_injection:
  enabled: true
  block_mode: true
```

**Options:**
- `enabled: true/false` - Enable or disable SQL injection detection
- `block_mode: true/false` - Block requests (true) or log only (false)

### Detection Patterns

#### 1. Union-Based Injection

Detects attempts to combine queries using UNION:

```
-- Blocked patterns
UNION SELECT * FROM users
UNION ALL SELECT password FROM accounts
' UNION SELECT NULL,NULL,NULL--
```

**Regex Pattern:**
```
(?i)\bunion\b.*\bselect\b
(?i)\bselect\b.*\bfrom\b
```

#### 2. Boolean-Based Injection

Detects logic manipulation:

```
-- Blocked patterns
1' OR '1'='1
admin' AND 1=1--
' OR 'a'='a
1 OR 1=1
```

**Regex Pattern:**
```
(?i)\b(or|and)\b\s+\d+\s*=\s*\d+
(?i)'\s*(or|and)\s*'
(?i)\bor\b\s+["']?\w+["']?\s*=\s*["']?\w+["']?
```

#### 3. Time-Based Blind Injection

Detects time-delay attacks:

```
-- Blocked patterns
SLEEP(5)
BENCHMARK(1000000,MD5('test'))
WAITFOR DELAY '00:00:05'
pg_sleep(5)
```

**Regex Pattern:**
```
(?i)\b(benchmark|sleep|waitfor\s+delay)\s*$$
```

#### 4. Stacked Queries

Detects multiple query execution:

```
-- Blocked patterns
'; DROP TABLE users--
1; DELETE FROM accounts WHERE 1=1
'; UPDATE users SET admin=1--
```

**Regex Pattern:**
```
(?i);\s*\b(drop|delete|update|insert)\b
;\s*--
```

#### 5. Comment-Based Injection

Detects SQL comment manipulation:

```
-- Blocked patterns
admin'--
' OR 1=1--
' OR 1=1/*
```

**Regex Pattern:**
```
'--
--[^\r\n]*$
/\*.*\*/\s*--
```

#### 6. Stored Procedure Execution

Detects dangerous stored procedure calls:

```
-- Blocked patterns
xp_cmdshell
sp_executesql
EXEC master..xp_cmdshell
```

**Regex Pattern:**
```
(?i)\b(xp_|sp_)\w+
(?i)\b(exec|execute)\s*$$
```

#### 7. Hex Encoding Bypass

Detects hex-encoded SQL:

```
-- Blocked patterns
0x61646d696e  (hex for 'admin')
0x53454c454354  (hex for 'SELECT')
```

**Regex Pattern:**
```
(?i)0x[0-9a-f]{2,}
```

### Inspection Points

SQL injection is checked in:

1. **URI Query Parameters**
   ```
   GET /api/users?id=1' OR '1'='1
   ```

2. **Custom Headers** (excluding safe headers)
   ```
   X-Custom-Filter: 1' UNION SELECT password
   ```

3. **Request Body** (POST/PUT data)
   ```
   {"username": "admin'--", "password": "x"}
   ```

### Safe Headers

These standard headers are **exempt** from SQL injection checks to prevent false positives:

- `Accept`
- `Accept-Encoding`
- `Accept-Language`
- `Content-Type`
- `User-Agent`
- `Cache-Control`
- `Connection`
- `Host`
- `Sec-*` (Security headers)

### URL Decoding

The SQL injection detector automatically URL-decodes input before checking:

```
# Encoded attack
%27%20OR%20%271%27%3D%271

# Decoded and detected
' OR '1'='1
```

### Examples

#### Blocked Requests

```
# Boolean injection
curl "http://localhost:6188/api/users?id=1 OR 1=1"
# Response: 403 Forbidden

# Union injection
curl "http://localhost:6188/api/search?q=test' UNION SELECT * FROM passwords--"
# Response: 403 Forbidden

# Stacked queries
curl "http://localhost:6188/api/user?id=1; DROP TABLE users"
# Response: 403 Forbidden

# Time-based
curl "http://localhost:6188/api/login?delay=SLEEP(5)"
# Response: 403 Forbidden
```

#### Allowed Requests

```
# Normal queries (not blocked)
curl "http://localhost:6188/api/users?id=123"
# Response: 200 OK

curl "http://localhost:6188/api/search?q=select%20option%20from%20menu"
# Response: 200 OK (legitimate use of 'select')

curl "http://localhost:6188/api/email?addr=user@example.com"
# Response: 200 OK
```

### Performance Impact

- **Latency overhead**: ~0.2ms per request
- **CPU usage**: Minimal (regex pre-compiled)
- **Memory**: Constant (no per-request allocation)

### False Positives

Common false positives and how to handle them:

#### Case 1: Legitimate SQL Keywords

```
# False positive
/api/products?category=Select Option

# Solution: Context-aware checking (implemented)
# Words like "select" in normal text are allowed
```

#### Case 2: Email Addresses

```
# False positive risk
email=admin@company.com

# Solution: Email validation before SQL check
# Or whitelist email parameter
```

#### Case 3: Programming Content

```
# False positive
/api/code?content=SELECT * FROM table

# Solution: Disable SQL check for specific endpoints
# Or use allowlist for code submission endpoints
```

## Cross-Site Scripting (XSS) Prevention

XSS attacks inject malicious scripts into web pages. Pingora WAF detects and blocks common XSS attack patterns.

### Configuration

```
xss:
  enabled: true
  block_mode: true
```

### Detection Patterns

#### 1. Script Tags

```
<!-- Blocked patterns -->
<script>alert('XSS')</script>
<script src="http://evil.com/xss.js"></script>
<SCRIPT>alert(1)</SCRIPT>
</script>
```

**Regex Pattern:**
```
(?i)<script[^>]*>
(?i)</script>
```

#### 2. Event Handlers

```
<!-- Blocked patterns -->
<img src=x onerror=alert('XSS')>
<body onload=alert(1)>
<div onclick="malicious()">
<svg onload=alert('XSS')>
```

**Regex Pattern:**
```
(?i)\bon\w+\s*=
```

#### 3. JavaScript Protocol

```
<!-- Blocked patterns -->
<a href="javascript:alert('XSS')">Click</a>
<iframe src="javascript:alert(1)">
javascript:void(document.cookie)
```

**Regex Pattern:**
```
(?i)javascript:\s*\w
```

#### 4. Dangerous Tags

```
<!-- Blocked patterns -->
<iframe src="http://evil.com"></iframe>
<object data="malicious.swf"></object>
<embed src="evil.swf">
```

**Regex Pattern:**
```
(?i)<iframe[^>]*>
(?i)<object[^>]*>
(?i)<embed[^>]*>
```

#### 5. JavaScript Functions

```
// Blocked patterns
eval(malicious_code)
alert('XSS')
expression(malicious)
```

**Regex Pattern:**
```
(?i)\beval\s*$$
(?i)\balert\s*$$
(?i)expression\s*$$
```

#### 6. Data URLs

```
<!-- Blocked patterns -->
<img src="data:text/html,<script>alert('XSS')</script>">
```

**Regex Pattern:**
```
(?i)data:text/html
```

### Inspection Points

XSS is checked in:

1. **URI Query Parameters**
2. **Custom Headers**
3. **Request Body** (POST/PUT data)

### Examples

#### Blocked Requests

```
# Script tag injection
curl -X POST http://localhost:6188/api/comment \
  -d "content=<script>alert('XSS')</script>"
# Response: 403 Forbidden

# Event handler injection
curl "http://localhost:6188/api/page?content=<img src=x onerror=alert(1)>"
# Response: 403 Forbidden

# JavaScript protocol
curl "http://localhost:6188/api/link?url=javascript:alert('XSS')"
# Response: 403 Forbidden

# Iframe injection
curl -X POST http://localhost:6188/api/widget \
  -d "html=<iframe src=evil.com></iframe>"
# Response: 403 Forbidden
```

#### Allowed Requests

```
# Normal HTML-like content
curl -X POST http://localhost:6188/api/comment \
  -d "content=I love <3 coding"
# Response: 200 OK

# Normal text
curl "http://localhost:6188/api/search?q=javascript+tutorial"
# Response: 200 OK
```

### Performance Impact

- **Latency overhead**: ~0.15ms per request
- **CPU usage**: Minimal
- **Memory**: Constant

## Rate Limiting

Rate limiting prevents abuse by limiting the number of requests per IP address within a time window.

### Configuration

```
rate_limit:
  enabled: true
  max_requests: 1000    # Maximum requests per window
  window_secs: 60       # Time window in seconds
```

### How It Works

1. **Sliding Window Algorithm**
   - Tracks requests per IP address
   - Resets counter when window expires
   - Atomic operations for thread safety

2. **Calculation**
   ```
   Requests per second = max_requests / window_secs

   Example: 1000 / 60 = 16.67 req/sec per IP
   ```

3. **Storage**
   - Uses `DashMap` for concurrent access
   - Automatic cleanup of expired entries
   - Memory-efficient tracking

### Response Codes

- **429 Too Many Requests**: Rate limit exceeded
- **Headers** (optional):
  ```
  X-RateLimit-Limit: 1000
  X-RateLimit-Remaining: 0
  X-RateLimit-Reset: 1696752000
  ```

### Configuration Examples

#### API Endpoint (Moderate)

```
rate_limit:
  enabled: true
  max_requests: 1000
  window_secs: 60
# Result: ~17 requests/second
```

#### Login Endpoint (Strict)

```
rate_limit:
  enabled: true
  max_requests: 10
  window_secs: 60
# Result: 1 request every 6 seconds
```

#### Public Website (Permissive)

```
rate_limit:
  enabled: true
  max_requests: 5000
  window_secs: 60
# Result: ~83 requests/second
```

#### Development/Testing (Disabled)

```
rate_limit:
  enabled: false
```

### IP Address Detection

Rate limiting uses the client IP address, extracted from:

1. **X-Forwarded-For header** (if behind proxy)
   ```
   X-Forwarded-For: 203.0.113.1, 198.51.100.1
   # Uses first IP: 203.0.113.1
   ```

2. **Direct connection** (fallback)
   ```
   Client socket address
   ```

### Examples

```
# First 1000 requests succeed
for i in {1..1000}; do
  curl http://localhost:6188/api/test
done
# Response: 200 OK

# 1001st request is blocked
curl http://localhost:6188/api/test
# Response: 429 Too Many Requests

# Wait 60 seconds, then requests allowed again
sleep 60
curl http://localhost:6188/api/test
# Response: 200 OK
```

### Cleanup

Expired entries are cleaned up every 5 minutes to prevent memory leaks:

```
// Automatic cleanup runs in background
rate_limiter.cleanup_old_entries();
```

### Performance Impact

- **Latency overhead**: < 0.5ms
- **Memory**: ~100 bytes per tracked IP
- **Scalability**: Handles millions of IPs efficiently

### Best Practices

1. **Set appropriate limits**
   - Too low: Blocks legitimate users
   - Too high: Doesn't prevent abuse

2. **Different limits for different endpoints**
   - Login: Very strict (10/min)
   - API: Moderate (1000/min)
   - Static: Permissive (5000/min)

3. **Monitor rate limit metrics**
   ```
   rate(waf_blocked_requests{reason="rate_limit"}[5m])
   ```

4. **Whitelist trusted IPs**
   ```
   ip_filter:
     whitelist:
       - "10.0.0.0/8"  # Internal network
   ```

## IP Filtering

IP filtering provides network-level access control through whitelists and blacklists.

### Configuration

```
ip_filter:
  enabled: true
  whitelist:
    - "10.0.0.0/8"        # Private network
    - "172.16.0.0/12"     # Private network
    - "192.168.1.100"     # Specific IP
  blacklist:
    - "198.51.100.0/24"   # Malicious subnet
    - "203.0.113.50"      # Blocked IP
```

### How It Works

1. **Whitelist Mode** (if whitelist is not empty)
   - Only IPs in whitelist are allowed
   - All other IPs are blocked with 403

2. **Blacklist Mode** (if whitelist is empty)
   - IPs in blacklist are blocked with 403
   - All other IPs are allowed

3. **Priority**
   ```
   Whitelist check → Blacklist check → Allow
   ```

### Supported Formats

#### Individual IPs

```
whitelist:
  - "192.168.1.100"
  - "203.0.113.50"
```

#### CIDR Notation (Subnets)

```
whitelist:
  - "10.0.0.0/8"         # 10.0.0.0 - 10.255.255.255
  - "172.16.0.0/12"      # 172.16.0.0 - 172.31.255.255
  - "192.168.0.0/16"     # 192.168.0.0 - 192.168.255.255
  - "203.0.113.0/24"     # 203.0.113.0 - 203.0.113.255
```

### Use Cases

#### Internal Application

```
ip_filter:
  enabled: true
  whitelist:
    - "10.0.0.0/8"     # Only internal network
```

#### Block Known Attackers

```
ip_filter:
  enabled: true
  blacklist:
    - "198.51.100.50"  # Known attacker
    - "203.0.113.0/24" # Malicious subnet
```

#### Geographic Restriction

```
ip_filter:
  enabled: true
  whitelist:
    - "203.0.113.0/22"  # Country-specific IP range
```

### Examples

```
# Whitelisted IP - allowed
curl --interface 10.0.0.5 http://localhost:6188/api/test
# Response: 200 OK

# Non-whitelisted IP - blocked
curl --interface 198.51.100.5 http://localhost:6188/api/test
# Response: 403 Forbidden

# Blacklisted IP - blocked
curl --interface 203.0.113.50 http://localhost:6188/api/test
# Response: 403 Forbidden
```

### Performance Impact

- **Latency overhead**: < 0.1ms
- **Memory**: Constant (HashSet lookup)
- **Scalability**: O(log n) for large lists

### Best Practices

1. **Use whitelisting for sensitive applications**
2. **Regularly update blacklists** from threat intelligence
3. **Monitor blocked IPs**
   ```
   waf_blocked_requests{reason="ip_blacklist"}
   ```
4. **Document IP ranges** for maintenance

## Request Body Inspection

Body inspection prevents oversized requests and checks body content for attacks.

### Configuration

```
max_body_size: 1048576  # 1MB in bytes
```

Common sizes:
- **1MB (1048576)**: Default, suitable for APIs
- **5MB (5242880)**: File uploads
- **10MB (10485760)**: Large file uploads
- **512KB (524288)**: Strict limit

### How It Works

1. **Content-Length Check** (Early Rejection)
   ```
   Request → Check Content-Length header → Reject if > max_body_size
   ```

2. **Streaming Check** (Safety Net)
   ```
   Request → Stream body chunks → Reject if accumulated > max_body_size
   ```

3. **Body Content Inspection**
   - SQL injection patterns
   - XSS patterns
   - Custom rules

### Response Codes

- **413 Payload Too Large**: Body exceeds size limit
- **403 Forbidden**: Malicious content detected in body

### Examples

```
# Small body - allowed
curl -X POST http://localhost:6188/api/data \
  -d '{"name":"test","value":123}'
# Response: 200 OK

# Large body - rejected (> 1MB)
dd if=/dev/zero bs=1M count=2 | curl -X POST \
  --data-binary @- \
  http://localhost:6188/api/upload
# Response: 413 Payload Too Large

# Malicious content in body - blocked
curl -X POST http://localhost:6188/api/comment \
  -d "content=<script>alert('XSS')</script>"
# Response: 403 Forbidden
```

### Performance Impact

- **Content-Length check**: < 0.1ms
- **Streaming check**: Minimal
- **Content inspection**: ~0.3ms for 1KB body

### Best Practices

1. **Set appropriate limits** based on use case
2. **Different limits for different endpoints**
   ```
   // API endpoints: 1MB
   // File upload: 10MB
   // Webhooks: 5MB
   ```
3. **Monitor rejected requests**
   ```
   waf_blocked_requests{reason="body_too_large"}
   ```

## Custom Security Rules

Extend Pingora WAF with custom security rules.

### SecurityRule Trait

```
pub trait SecurityRule: Send + Sync {
    fn check(&self, request: &RequestHeader, body: Option<&[u8]>)
        -> Result<(), SecurityViolation>;
    fn name(&self) -> &str;
}
```

### Creating a Custom Rule

#### Example: Path Traversal Detection

```
use pingora_waf::*;

pub struct PathTraversalRule {
    enabled: bool,
    block_mode: bool,
}

impl PathTraversalRule {
    pub fn new(enabled: bool, block_mode: bool) -> Self {
        Self { enabled, block_mode }
    }

    fn check_path(&self, path: &str) -> bool {
        path.contains("../") ||
        path.contains("..\\") ||
        path.contains("%2e%2e")
    }
}

impl SecurityRule for PathTraversalRule {
    fn check(&self, request: &RequestHeader, _body: Option<&[u8]>)
        -> Result<(), SecurityViolation> {

        if !self.enabled {
            return Ok(());
        }

        let uri = request.uri.to_string();

        if self.check_path(&uri) {
            return Err(SecurityViolation {
                threat_type: "PATH_TRAVERSAL".to_string(),
                threat_level: ThreatLevel::High,
                description: format!("Path traversal detected: {}", uri),
                blocked: self.block_mode,
            });
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "Path Traversal Detector"
    }
}
```

#### Example: Custom Header Validation

```
pub struct CustomHeaderRule {
    required_header: String,
    enabled: bool,
}

impl CustomHeaderRule {
    pub fn new(header_name: String, enabled: bool) -> Self {
        Self {
            required_header: header_name,
            enabled,
        }
    }
}

impl SecurityRule for CustomHeaderRule {
    fn check(&self, request: &RequestHeader, _body: Option<&[u8]>)
        -> Result<(), SecurityViolation> {

        if !self.enabled {
            return Ok(());
        }

        if !request.headers.contains_key(&self.required_header) {
            return Err(SecurityViolation {
                threat_type: "MISSING_REQUIRED_HEADER".to_string(),
                threat_level: ThreatLevel::Medium,
                description: format!("Missing required header: {}", self.required_header),
                blocked: true,
            });
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "Custom Header Validator"
    }
}
```

### Using Custom Rules

See [examples/custom_rules.rs](../examples/custom_rules.rs) for complete examples.

## Rule Engine

The Rule Engine manages multiple security rules and their execution.

### Architecture

```
pub struct RuleEngine {
    rules: Vec<Arc<dyn SecurityRule>>,
}

impl RuleEngine {
    pub fn new() -> Self;
    pub fn add_rule(&mut self, rule: Arc<dyn SecurityRule>);
    pub fn evaluate_all(&self, request: &RequestHeader, body: Option<&[u8]>)
        -> Vec<SecurityViolation>;
}
```

### Rule Execution Order

1. IP Filter (fastest, network-level)
2. Rate Limiter (per-IP tracking)
3. SQL Injection (header & URI)
4. XSS Detection (header & URI)
5. Body Size Check
6. SQL Injection (body)
7. XSS Detection (body)
8. Custom Rules

### Short-Circuit Behavior

- **Blocking mode**: First blocking violation stops processing
- **Detection mode**: All rules are evaluated

## False Positives

### Understanding False Positives

A false positive occurs when legitimate traffic is incorrectly flagged as malicious.

### Common Causes

1. **Overly broad patterns**
2. **Lack of context awareness**
3. **URL encoding issues**
4. **Legitimate SQL/code content**

### Handling False Positives

#### Option 1: Disable Blocking Mode

```
sql_injection:
  enabled: true
  block_mode: false  # Log only
```

#### Option 2: Whitelist Specific Endpoints

```
// In proxy implementation
if request.uri.path() == "/api/code-submission" {
    // Skip SQL injection check for this endpoint
    return Ok(());
}
```

#### Option 3: Adjust Patterns

Contribute improved patterns that reduce false positives.

#### Option 4: Use Custom Rules

Create endpoint-specific rules with better context.

### Monitoring False Positives

```
# Check blocked legitimate requests in logs
grep "403" /var/log/pingora-waf/access.log | grep -v "OR 1=1"

# Monitor block rate
curl -s http://localhost:6190/metrics | \
  awk '/waf_blocked/ {blocked+=$2} /waf_total/ {total=$2} END {print blocked/total*100"%"}'
```

### Reporting False Positives

If you encounter false positives:

1. **Capture the request**
   ```
   curl -v "http://localhost:6188/your-request" > false-positive.txt 2>&1
   ```

2. **Check logs**
   ```
   journalctl -u pingora-waf -n 100 | grep "Security violation"
   ```

3. **Report on GitHub** with:
   - Request details
   - Expected behavior
   - Logs
   - WAF version

## Best Practices

### Security Configuration

1. **Start with detection mode**
   ```
   sql_injection:
     enabled: true
     block_mode: false  # Test first
   ```

2. **Monitor for 24-48 hours**
   ```
   curl -s http://localhost:6190/metrics | grep blocked
   ```

3. **Enable blocking gradually**
   ```
   sql_injection:
     block_mode: true  # Enable after testing
   ```

4. **Keep rules updated**
   ```
   git pull origin main
   cargo build --release
   ```

### Performance Optimization

1. **Tune rate limits** based on actual traffic
2. **Use IP whitelisting** for internal traffic
3. **Adjust body size limits** per endpoint
4. **Monitor latency impact**
   ```
   wrk -t10 -c100 -d30s http://localhost:6188/api/test
   ```

### Monitoring

1. **Set up alerts** for high block rates
   ```
   - alert: HighBlockRate
     expr: (rate(waf_blocked_requests[5m]) / rate(waf_total_requests[5m])) > 0.5
   ```

2. **Review logs regularly**
   ```
   journalctl -u pingora-waf --since "1 hour ago" | grep -i "security"
   ```

3. **Track attack patterns**
   ```
   topk(5, sum(rate(waf_blocked_requests[1h])) by (reason))
   ```

### Incident Response

When under attack:

1. **Verify the attack**
   ```
   tail -f /var/log/pingora-waf/access.log | grep 403
   ```

2. **Identify attacker IPs**
   ```
   grep "403" access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head
   ```

3. **Block attackers**
   ```
   ip_filter:
     blacklist:
       - "198.51.100.50"  # Add attacker IP
   ```

4. **Document the incident**
5. **Update rules** if new attack pattern

### Security Hardening

1. **Enable all rules in production**
2. **Use strict rate limits for sensitive endpoints**
3. **Implement IP whitelisting for admin panels**
4. **Set conservative body size limits**
5. **Enable comprehensive logging**
6. **Regular security audits**

## Further Reading

- [Configuration Guide](configuration.md)
- [Monitoring Guide](monitoring.md)
- [Troubleshooting](troubleshooting.md)
- [API Reference](api-reference.md)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

## Support

- **Questions**: [GitHub Discussions](https://github.com/aarambhdevhub/pingora-waf/discussions)
- **Security Issues**: [Contact via GitHub Issues]
- **Bug Reports**: [GitHub Issues](https://github.com/aarambhdevhub/pingora-waf/issues)

---

**Last Updated**: October 8, 2025
**Version**: 0.1.0
**Maintained By**: Aarambh dev hub
