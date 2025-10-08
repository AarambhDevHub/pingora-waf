# Getting Started with Pingora WAF

This guide will help you get Pingora WAF up and running in minutes.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [First Run](#first-run)
- [Basic Configuration](#basic-configuration)
- [Testing Your WAF](#testing-your-waf)
- [Understanding the Output](#understanding-the-output)
- [Common First Steps](#common-first-steps)
- [Troubleshooting](#troubleshooting)
- [Next Steps](#next-steps)

## Prerequisites

Before you begin, ensure you have:

### Required

- **Rust 1.70 or higher**
  ```
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source $HOME/.cargo/env
  ```

- **Git**
  ```
  # Ubuntu/Debian
  sudo apt-get update && sudo apt-get install -y git

  # macOS
  brew install git

  # Fedora/RHEL
  sudo dnf install git
  ```

### Recommended

- **Linux or macOS** (Windows via WSL2)
- **2GB RAM minimum** (4GB recommended)
- **2 CPU cores** (4+ for production)
- **10GB disk space** for build artifacts

### Optional (for testing)

- **wrk** - HTTP benchmarking tool
- **curl** - HTTP client
- **Docker** - For containerized deployment

### Verify Prerequisites

```
# Check Rust version
rustc --version
# Expected: rustc 1.70.0 or higher

# Check Cargo
cargo --version
# Expected: cargo 1.70.0 or higher

# Check Git
git --version
# Expected: git version 2.x.x

# Check system resources
free -h  # Check available memory
nproc    # Check CPU cores
```

## Installation

### Method 1: From Source (Recommended)

This is the recommended method for most users.

```
# 1. Clone the repository
git clone https://github.com/aarambhdevhub/pingora-waf.git
cd pingora-waf

# 2. Build release version (takes 5-10 minutes first time)
cargo build --release

# 3. Verify the build
ls -lh target/release/pingora-waf
# Should see a ~20MB binary

# 4. Optional: Run tests
cargo test
```

**Build Output:**
```
   Compiling pingora-waf v0.1.0 (/path/to/pingora-waf)
    Finished release [optimized] target(s) in 8m 42s
```

### Method 2: Using Cargo Install

Install directly from the repository:

```
# Install from GitHub
cargo install --git https://github.com/aarambhdevhub/pingora-waf.git

# The binary will be in ~/.cargo/bin/pingora-waf
which pingora-waf
```

### Method 3: Docker

Use Docker for isolated deployment:

```
# Option A: Build from source
git clone https://github.com/aarambhdevhub/pingora-waf.git
cd pingora-waf
docker build -t pingora-waf:latest .

# Option B: Pull pre-built image (when available)
docker pull aarambhdevhub/pingora-waf:latest

# Run container
docker run -d \
  --name waf \
  -p 6188:6188 \
  -p 6190:6190 \
  pingora-waf:latest
```

### Method 4: Pre-built Binaries (Coming Soon)

Download pre-compiled binaries from [releases page](https://github.com/aarambhdevhub/pingora-waf/releases).

```
# Download latest release
wget https://github.com/aarambhdevhub/pingora-waf/releases/download/v0.1.0/pingora-waf-linux-amd64

# Make executable
chmod +x pingora-waf-linux-amd64

# Move to system path
sudo mv pingora-waf-linux-amd64 /usr/local/bin/pingora-waf
```

## First Run

### Step 1: Start a Test Backend

For testing, use the included mock backend server:

```
# Terminal 1: Start mock backend
cd pingora-waf
cargo run --example mock_backend_tokio
```

**Expected Output:**
```
╔═══════════════════════════════════════════════╗
║   Mock Backend Server (Tokio)                 ║
╚═══════════════════════════════════════════════╝
📡 Listening on: http://127.0.0.1:8080
🔥 Ready to handle WAF proxy requests
```

The backend is now ready to receive proxied requests from the WAF.

### Step 2: Review Default Configuration

Check the default configuration file:

```
cat config/waf_rules.yaml
```

**Default Configuration:**
```
sql_injection:
  enabled: true       # SQL injection detection ON
  block_mode: true    # Blocking mode (403 response)

xss:
  enabled: true       # XSS detection ON
  block_mode: true    # Blocking mode

rate_limit:
  enabled: true       # Rate limiting ON
  max_requests: 1000  # 1000 requests per minute per IP
  window_secs: 60     # 60 second window

ip_filter:
  enabled: false      # IP filtering OFF (no restrictions)
  whitelist: []
  blacklist: []

max_body_size: 1048576  # 1MB request body limit
```

This is a good starting configuration for testing.

### Step 3: Start Pingora WAF

```
# Terminal 2: Start WAF with info logging
RUST_LOG=info ./target/release/pingora-waf
```

**Expected Output:**
```
[2025-10-08T02:35:12Z INFO  pingora_waf] Using default configuration
╔═══════════════════════════════════════════════╗
║   Pingora WAF Proxy                           ║
╚═══════════════════════════════════════════════╝
🔒 WAF Proxy:     http://0.0.0.0:6188
📊 Metrics:       http://0.0.0.0:6190/metrics
🚀 Status:        Running
```

The WAF is now running and ready to accept requests!

### Step 4: Test Your First Request

```
# Terminal 3: Send a normal request
curl http://localhost:6188/api/test
```

**Expected Response:**
```
{"status":"ok","request_id":1,"path":"/api/test","latency_ms":0}
```

✅ Success! The WAF proxied your request to the backend.

### Step 5: Test Security Features

#### Test SQL Injection Protection

```
# This should be BLOCKED (403 Forbidden)
curl "http://localhost:6188/api/test?id=1' OR '1'='1"
```

**Expected Response:**
```
HTTP/1.1 403 Forbidden
```

#### Test XSS Protection

```
# This should be BLOCKED
curl -X POST http://localhost:6188/api/comment \
  -H "Content-Type: text/plain" \
  -d "<script>alert('XSS')</script>"
```

**Expected Response:**
```
HTTP/1.1 403 Forbidden
```

#### Test Rate Limiting

```
# Send 101 requests rapidly (will hit rate limit)
for i in {1..101}; do
  curl -s http://localhost:6188/api/test > /dev/null
  echo "Request $i"
done
```

**Expected**: First 100 succeed, 101st gets 429 Too Many Requests

### Step 6: Check Metrics

```
# View WAF metrics
curl http://localhost:6190/metrics | grep waf_
```

**Expected Output:**
```
waf_total_requests 103
waf_allowed_requests 100
waf_blocked_requests{reason="rate_limit"} 1
waf_blocked_requests{reason="sql_injection"} 1
waf_blocked_requests{reason="xss_body"} 1
```

## Basic Configuration

### Configure Your Backend Service

To protect your actual backend, edit `src/main.rs`:

```
// Find this section (around line 30)
let waf_proxy = WafProxy::new(
    ("127.0.0.1".to_string(), 8080),  // <-- Change this line
    sql_detector,
    xss_detector,
    rate_limiter.clone(),
    ip_filter,
    metrics.clone(),
    config.max_body_size,
);
```

**Examples:**

```
// Local backend on different port
("127.0.0.1".to_string(), 3000)

// Remote backend (HTTP)
("api.example.com".to_string(), 80)

// Remote backend (HTTPS - requires reverse proxy)
("backend.example.com".to_string(), 443)

// Internal network
("10.0.1.50".to_string(), 8080)
```

After editing, rebuild:

```
cargo build --release
```

### Adjust Security Settings

Edit `config/waf_rules.yaml` to customize security:

#### Example 1: Development Mode (Less Strict)

```
sql_injection:
  enabled: true
  block_mode: false  # Log only, don't block

xss:
  enabled: true
  block_mode: false  # Log only

rate_limit:
  enabled: false     # Disabled for testing

ip_filter:
  enabled: false

max_body_size: 10485760  # 10MB for testing
```

#### Example 2: Production Mode (Strict)

```
sql_injection:
  enabled: true
  block_mode: true   # Block attacks

xss:
  enabled: true
  block_mode: true

rate_limit:
  enabled: true
  max_requests: 5000  # Higher limit for production
  window_secs: 60

ip_filter:
  enabled: true
  whitelist:
    - "10.0.0.0/8"    # Internal network only
  blacklist:
    - "192.0.2.1"     # Known bad IPs

max_body_size: 5242880  # 5MB
```

#### Example 3: API Gateway Mode

```
sql_injection:
  enabled: true
  block_mode: true

xss:
  enabled: false      # APIs don't typically need XSS protection

rate_limit:
  enabled: true
  max_requests: 10000  # Higher for API traffic
  window_secs: 60

ip_filter:
  enabled: false

max_body_size: 1048576  # 1MB for API payloads
```

### Environment Variables

You can configure logging via environment variables:

```
# Info level (recommended for production)
RUST_LOG=info ./target/release/pingora-waf

# Debug level (verbose, for troubleshooting)
RUST_LOG=debug ./target/release/pingora-waf

# Trace level (very verbose, for development)
RUST_LOG=trace ./target/release/pingora-waf

# Specific module logging
RUST_LOG=pingora_waf=debug,pingora_proxy=info ./target/release/pingora-waf
```

## Testing Your WAF

### Comprehensive Security Test

Run the built-in security test suite:

```
# Ensure backend and WAF are running, then:
cargo run --example security_test
```

**Expected Output:**
```
╔═══════════════════════════════════════════════╗
║   WAF Security Verification Tests             ║
╚═══════════════════════════════════════════════╝

✅ Test 1: Legitimate requests
   ✓ Normal request allowed (200 OK)

🛡️  Test 2: SQL Injection in URI
   ✓ Blocked: /api/users?id=1 OR 1=1
   ✓ Blocked: /api/users?id=1' UNION SELECT * FROM passwords--
   ✓ Blocked: /api/users?id=1; DROP TABLE users
   ✓ Blocked: /api/login?user=admin'--&pass=x

🛡️  Test 3: XSS Attacks in Body
   ✓ Blocked XSS: <script>alert('XSS')</script>
   ✓ Blocked XSS: <img src=x onerror=alert('XSS')>
   ✓ Blocked XSS: <iframe src=javascript:alert(1)>
   ✓ Blocked XSS: <body onload=alert(1)>

🛡️  Test 4: SQL Injection in Custom Headers
   ✓ Blocked SQL injection in header

🛡️  Test 5: Rate Limiting (sending 110 rapid requests)
   ✓ Rate limited at request #101

🛡️  Test 6: Large Request Body (2MB)
   ✓ Large body rejected

╔═══════════════════════════════════════════════╗
║   Test Summary                                ║
╚═══════════════════════════════════════════════╝
Total Tests: 12
✅ Passed: 12
❌ Failed: 0
Success Rate: 100.0%

🎉 All security tests passed! WAF is working correctly.

📊 Check metrics: http://localhost:6190/metrics
```

### Performance Test

Test throughput and latency:

```
# Install wrk (if not already installed)
# Ubuntu/Debian:
sudo apt-get install wrk

# macOS:
brew install wrk

# Run load test (10 threads, 100 connections, 30 seconds)
wrk -t10 -c100 -d30s http://localhost:6188/api/test
```

**Expected Results:**
```
Running 30s test @ http://localhost:6188/api/test
  10 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     6.60ms    1.33ms  42.73ms   82.15%
    Req/Sec     1.52k   202.16     2.83k    77.03%
  455,801 requests in 30.10s, 96.93MB read
Requests/sec:  15,143.26
Transfer/sec:      3.22MB
```

**Good Results:**
- ✅ Throughput: 10,000+ req/sec
- ✅ Average latency: < 10ms
- ✅ Max latency: < 50ms
- ✅ Success rate: 100%

### Manual Testing

Test specific scenarios:

```
# 1. Normal GET request
curl -v http://localhost:6188/api/users

# 2. POST with JSON body
curl -X POST http://localhost:6188/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"John","email":"john@example.com"}'

# 3. Request with authentication
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:6188/api/protected

# 4. SQL injection attempt (should fail with 403)
curl "http://localhost:6188/search?q=test' UNION SELECT password FROM users--"

# 5. XSS attempt (should fail with 403)
curl -X POST http://localhost:6188/comment \
  -d "text=<img src=x onerror=alert(document.cookie)>"

# 6. Large payload (should fail with 413 or 403)
dd if=/dev/zero bs=1M count=2 | curl -X POST \
  --data-binary @- \
  http://localhost:6188/upload

# 7. Rapid requests (should hit rate limit)
for i in {1..120}; do
  curl -s http://localhost:6188/api/test > /dev/null
  echo "Request $i sent"
done
```

## Understanding the Output

### WAF Logs

When running with `RUST_LOG=info`, you'll see:

```
[2025-10-08T02:35:15Z INFO  pingora_waf::proxy] Request completed - IP: 127.0.0.1, Method: GET, URI: /api/test, Status: 200
[2025-10-08T02:35:18Z ERROR pingora_waf::proxy] SQL injection detected: SecurityViolation { threat_type: "SQL_INJECTION", threat_level: Critical, description: "SQL injection detected in URI: /api/test?id=1' OR '1'='1", blocked: true }
[2025-10-08T02:35:20Z WARN  pingora_waf::proxy] Security violation - IP: 127.0.0.1, Type: XSS, Level: High, Blocked: true
```

### HTTP Response Codes

- **200 OK**: Request allowed and proxied successfully
- **403 Forbidden**: Blocked by security rule (SQL injection, XSS, etc.)
- **413 Payload Too Large**: Request body exceeds size limit
- **429 Too Many Requests**: Rate limit exceeded
- **502 Bad Gateway**: Backend connection failed

### Metrics Explained

```
# Total requests processed
waf_total_requests 1234

# Requests that passed all checks
waf_allowed_requests 1200

# Blocked requests by reason
waf_blocked_requests{reason="sql_injection"} 20
waf_blocked_requests{reason="xss"} 10
waf_blocked_requests{reason="xss_body"} 2
waf_blocked_requests{reason="rate_limit"} 1
waf_blocked_requests{reason="body_too_large"} 1
```

**Calculate block rate:**
```
Block Rate = (Total - Allowed) / Total * 100%
           = (1234 - 1200) / 1234 * 100%
           = 2.76%
```

## Common First Steps

### 1. Protecting Your Application

```
# Edit backend configuration
nano src/main.rs  # Change line 30

# Rebuild
cargo build --release

# Deploy
sudo systemctl restart pingora-waf
```

### 2. Customizing Security Rules

```
# Edit rules
nano config/waf_rules.yaml

# No rebuild needed, just restart
sudo systemctl restart pingora-waf
```

### 3. Adding IP Whitelist

```
# config/waf_rules.yaml
ip_filter:
  enabled: true
  whitelist:
    - "YOUR_OFFICE_IP"
    - "10.0.0.0/8"
```

### 4. Setting Up Monitoring

```
# Install Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-amd64.tar.gz
tar xvfz prometheus-*.tar.gz
cd prometheus-*

# Create prometheus.yml
cat > prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'pingora-waf'
    static_configs:
      - targets: ['localhost:6190']
EOF

# Start Prometheus
./prometheus --config.file=prometheus.yml

# Open http://localhost:9090
```

### 5. Creating Systemd Service

```
# Copy service file
sudo cp docs/pingora-waf.service /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable pingora-waf
sudo systemctl start pingora-waf

# Check status
sudo systemctl status pingora-waf
```

## Troubleshooting

### WAF Won't Start

**Problem**: `Address already in use (os error 98)`

**Solution**:
```
# Find and kill process using port 6188
sudo lsof -ti:6188 | xargs sudo kill -9

# Or use different port (edit src/main.rs)
```

### Backend Connection Refused

**Problem**: `Fail to connect to 127.0.0.1:8080`

**Solution**:
```
# Check if backend is running
curl http://localhost:8080

# Start test backend
cargo run --example mock_backend_tokio

# Or check backend address in src/main.rs
```

### All Requests Blocked

**Problem**: Legitimate traffic getting 403

**Solution**:
```
# Enable debug logging
RUST_LOG=debug ./target/release/pingora-waf

# Or disable blocking temporarily
# Edit config/waf_rules.yaml:
sql_injection:
  block_mode: false
xss:
  block_mode: false
```

### Metrics Not Working

**Problem**: `curl http://localhost:6190/metrics` fails

**Solution**:
```
# Check if WAF is running
ps aux | grep pingora-waf

# Check firewall
sudo ufw allow 6190/tcp

# Test locally
curl http://127.0.0.1:6190/metrics
```

### High CPU Usage

**Problem**: CPU at 100%

**Solution**:
```
# Check request rate
curl -s http://localhost:6190/metrics | grep waf_total_requests

# Reduce rate limit or add more instances
# Edit config/waf_rules.yaml
rate_limit:
  max_requests: 500  # Lower limit
```

### Build Errors

**Problem**: Compilation fails

**Solution**:
```
# Update Rust
rustup update

# Clean and rebuild
cargo clean
cargo build --release

# Check dependencies
cargo update
```

## Next Steps

Congratulations! Your WAF is now running. Here's what to do next:

### For Development

1. **[Custom Rules](api-reference.md#custom-rules)** - Write your own security rules
2. **[Examples](examples.md)** - Explore code examples
3. **[Development Guide](development.md)** - Contribute to the project

### For Production

1. **[Deployment Guide](deployment.md)** - Production setup with systemd
2. **[Security Rules](security-rules.md)** - Fine-tune security configuration
3. **[Monitoring](monitoring.md)** - Set up Prometheus and Grafana
4. **[Performance Tuning](performance.md)** - Optimize for your workload

### For Operations

1. **[Configuration Reference](configuration.md)** - Complete configuration options
2. **[Troubleshooting](troubleshooting.md)** - Common issues and solutions
3. **[FAQ](faq.md)** - Frequently asked questions

## Quick Reference Card

```
# Start WAF
RUST_LOG=info ./target/release/pingora-waf

# Start test backend
cargo run --example mock_backend_tokio

# Run security tests
cargo run --example security_test

# View metrics
curl http://localhost:6190/metrics | grep waf_

# Load test
wrk -t10 -c100 -d30s http://localhost:6188/api/test

# Check logs (systemd)
journalctl -u pingora-waf -f

# Restart service
sudo systemctl restart pingora-waf
```

## Need Help?

- **Documentation**: [Full docs](README.md)
- **GitHub Issues**: [Report bugs](https://github.com/aarambhdevhub/pingora-waf/issues)
- **Discussions**: [Ask questions](https://github.com/aarambhdevhub/pingora-waf/discussions)
- **Security**: security@aarambhdevhub.com
- **Community**: Join our discussions!

---

**Ready for production?** Continue to [Deployment Guide](deployment.md)

**Want to customize?** Check out [Configuration Reference](configuration.md)

**Having issues?** See [Troubleshooting Guide](troubleshooting.md)
