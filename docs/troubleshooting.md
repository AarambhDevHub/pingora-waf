# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with Pingora WAF.

## 📋 Table of Contents

- [Quick Diagnostic Commands](#quick-diagnostic-commands)
- [Installation Issues](#installation-issues)
- [Configuration Problems](#configuration-problems)
- [Runtime Errors](#runtime-errors)
- [Performance Issues](#performance-issues)
- [Security & Blocking Issues](#security--blocking-issues)
- [Monitoring & Metrics](#monitoring--metrics)
- [Network & Connectivity](#network--connectivity)
- [Deployment Issues](#deployment-issues)
- [Getting Help](#getting-help)

## 🔍 Quick Diagnostic Commands

Run these commands first to gather information:

```
# Check if WAF is running
ps aux | grep pingora-waf
sudo systemctl status pingora-waf

# Check port usage
sudo netstat -tlnp | grep -E '6188|6190'
sudo lsof -i :6188
sudo lsof -i :6190

# View recent logs
sudo journalctl -u pingora-waf -n 100
sudo journalctl -u pingora-waf --since "10 minutes ago"

# Check system resources
free -h
df -h
top -n 1 -b | head -20

# Test connectivity
curl http://localhost:6188/
curl http://localhost:6190/metrics

# Check configuration
cat config/waf_rules.yaml
./target/release/pingora-waf --version
```

## 🛠️ Installation Issues

### Issue: Rust Compilation Fails

**Symptoms:**
```
error: failed to compile pingora-waf
```

**Solutions:**

1. **Update Rust to latest version:**
```
rustup update stable
rustc --version
# Should be 1.70.0 or higher
```

2. **Clear cargo cache:**
```
cargo clean
rm -rf ~/.cargo/registry/index/*
cargo build --release
```

3. **Check system dependencies:**
```
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential pkg-config libssl-dev

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install openssl-devel

# macOS
xcode-select --install
brew install openssl
```

4. **Fix OpenSSL linking issues:**
```
# Set OpenSSL path (macOS)
export OPENSSL_DIR=$(brew --prefix openssl)
cargo build --release

# Or for Ubuntu
export OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu
export OPENSSL_INCLUDE_DIR=/usr/include
cargo build --release
```

### Issue: Missing Dependencies

**Symptoms:**
```
error: linker `cc` not found
```

**Solution:**
```
# Install C compiler
sudo apt-get install gcc  # Debian/Ubuntu
sudo yum install gcc       # CentOS/RHEL
xcode-select --install     # macOS
```

### Issue: Out of Memory During Build

**Symptoms:**
```
error: could not compile due to previous error
Killed
```

**Solutions:**

1. **Build with fewer parallel jobs:**
```
cargo build --release -j 1
```

2. **Increase swap space:**
```
# Create 4GB swap file
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

3. **Use a larger machine or build server**

### Issue: Binary Not Found After Install

**Symptoms:**
```
pingora-waf: command not found
```

**Solution:**
```
# Find the binary
find . -name pingora-waf -type f

# Add to PATH or create symlink
sudo ln -s $(pwd)/target/release/pingora-waf /usr/local/bin/
```

## ⚙️ Configuration Problems

### Issue: Configuration File Not Found

**Symptoms:**
```
Error: Failed to load configuration: No such file or directory
```

**Solutions:**

1. **Check file exists:**
```
ls -la config/waf_rules.yaml
```

2. **Use absolute path:**
```
# Edit src/main.rs
let config = WafConfig::from_file("/opt/pingora-waf/config/waf_rules.yaml")
```

3. **Set working directory:**
```
cd /opt/pingora-waf
./target/release/pingora-waf
```

### Issue: Invalid YAML Configuration

**Symptoms:**
```
Error: Failed to parse configuration: invalid type at line 5
```

**Solutions:**

1. **Validate YAML syntax:**
```
# Install yamllint
pip install yamllint

# Check syntax
yamllint config/waf_rules.yaml
```

2. **Check for common issues:**
```
# Bad: Inconsistent indentation
rate_limit:
  enabled: true
   max_requests: 1000  # Too many spaces

# Good: Consistent 2-space indentation
rate_limit:
  enabled: true
  max_requests: 1000

# Bad: Missing quotes for special characters
blacklist:
  - 192.168.1.1/24  # May cause issues

# Good: Use quotes
blacklist:
  - "192.168.1.1/24"
```

3. **Use default configuration:**
```
# Rename broken config
mv config/waf_rules.yaml config/waf_rules.yaml.bak

# Copy default
cp config/waf_rules.yaml.example config/waf_rules.yaml
```

### Issue: Configuration Changes Not Applied

**Symptoms:**
Configuration changes don't take effect.

**Solutions:**

1. **Restart the service:**
```
sudo systemctl restart pingora-waf
```

2. **Check if config is being loaded:**
```
# Add logging in main.rs
RUST_LOG=debug ./target/release/pingora-waf
# Look for "Using configuration from..."
```

3. **Rebuild if config is hardcoded:**
```
cargo build --release
```

### Issue: Hot Reload Not Working

**Symptoms:**
Configuration changes are not picked up.

**Solutions:**

1. **Check enable flag:**
```yaml
hot_reload:
  enabled: true
```

2. **Check file permissions:**
Ensure the user running `pingora-waf` has read access to the config file.

3. **Check logs:**
Look for "Configuration reloaded" or "Failed to reload configuration".

## 🔴 Runtime Errors

### Issue: Backend Connection Refused

**Symptoms:**
```
[ERROR] Fail to connect to 127.0.0.1:8080
Connection refused (os error 111)
```

**Diagnostic Steps:**

1. **Check if backend is running:**
```
curl http://127.0.0.1:8080
netstat -tlnp | grep 8080
```

2. **Verify backend address in config:**
```
// src/main.rs
let waf_proxy = WafProxy::new(
    ("127.0.0.1".to_string(), 8080),  // Check this!
    // ...
);
```

**Solutions:**

1. **Start backend service:**
```
# For testing
cargo run --example mock_backend_tokio
```

2. **Update backend address:**
```
// Change to correct backend
("your-backend.com".to_string(), 443)
```

3. **Check firewall rules:**
```
sudo iptables -L -n | grep 8080
sudo ufw status
```

4. **Test direct connection:**
```
telnet 127.0.0.1 8080
# Or
nc -zv 127.0.0.1 8080
```

### Issue: Port Already in Use

**Symptoms:**
```
Error: Address already in use (os error 98)
```

**Solutions:**

1. **Find process using the port:**
```
sudo lsof -ti:6188
sudo lsof -ti:6190
```

2. **Kill the process:**
```
sudo lsof -ti:6188 | xargs kill -9
sudo lsof -ti:6190 | xargs kill -9
```

3. **Change port in code:**
```
// src/main.rs
proxy_service.add_tcp("0.0.0.0:6189");  // Changed port
```

4. **Check for zombie processes:**
```
ps aux | grep pingora-waf | grep defunct
```

### Issue: Permission Denied

**Symptoms:**
```
Error: Permission denied (os error 13)
```

**Solutions:**

1. **Run with sudo (not recommended for production):**
```
sudo ./target/release/pingora-waf
```

2. **Use capability instead (recommended):**
```
sudo setcap 'cap_net_bind_service=+ep' ./target/release/pingora-waf
./target/release/pingora-waf
```

3. **Change to non-privileged port (>1024):**
```
proxy_service.add_tcp("0.0.0.0:8080");  // Port > 1024
```

4. **Fix file permissions:**
```
sudo chown -R $USER:$USER /opt/pingora-waf
chmod +x ./target/release/pingora-waf
```

### Issue: Segmentation Fault or Crash

**Symptoms:**
```
Segmentation fault (core dumped)
```

**Diagnostic Steps:**

1. **Enable backtrace:**
```
RUST_BACKTRACE=full ./target/release/pingora-waf
```

2. **Run with debug symbols:**
```
cargo build
RUST_BACKTRACE=full ./target/debug/pingora-waf
```

3. **Check system limits:**
```
ulimit -a
# Increase if needed
ulimit -n 65536
```

**Solutions:**

1. **Update dependencies:**
```
cargo update
cargo build --release
```

2. **Check for known issues:**
```
# Search GitHub issues
# https://github.com/aarambhdevhub/pingora-waf/issues
```

3. **Report with backtrace:**
```
# Save full backtrace
RUST_BACKTRACE=full ./target/release/pingora-waf 2>&1 | tee crash.log
# Submit to GitHub issues
```

## 🐌 Performance Issues

### Issue: High Latency

**Symptoms:**
Average latency > 50ms

**Diagnostic Steps:**

1. **Measure baseline:**
```
# Test without WAF
curl -w "@curl-format.txt" -o /dev/null -s http://backend:8080

# Test with WAF
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:6188

# curl-format.txt:
time_total: %{time_total}s
time_connect: %{time_connect}s
time_starttransfer: %{time_starttransfer}s
```

2. **Check CPU usage:**
```
top -p $(pgrep pingora-waf)
```

3. **Profile the application:**
```
# Install perf
sudo apt-get install linux-tools-generic

# Profile
sudo perf record -F 99 -p $(pgrep pingora-waf) sleep 30
sudo perf report
```

**Solutions:**

1. **Increase worker threads:**
```
// src/main.rs
let mut server_conf = Opt::default();
server_conf.threads = num_cpus::get();
```

2. **Disable debug logging:**
```
# Change from debug to info
RUST_LOG=info ./target/release/pingora-waf
```

3. **Optimize rate limiter:**
```
// Clean up old entries more frequently
std::thread::spawn(move || {
    loop {
        std::thread::sleep(Duration::from_secs(60)); // More frequent
        rate_limiter.cleanup_old_entries();
    }
});
```

4. **Use release build:**
```
# Never use debug build in production
cargo build --release
```

### Issue: High Memory Usage

**Symptoms:**
Memory usage > 500MB

**Diagnostic Steps:**

1. **Check memory usage:**
```
ps aux | grep pingora-waf
pmap $(pgrep pingora-waf)
```

2. **Monitor over time:**
```
while true; do
  ps -p $(pgrep pingora-waf) -o rss,vsz,cmd
  sleep 5
done
```

**Solutions:**

1. **Reduce rate limiter window:**
```
rate_limit:
  window_secs: 30  # Smaller window = less memory
```

2. **Clear rate limiter more often:**
```
// Cleanup every 60 seconds instead of 300
std::thread::sleep(Duration::from_secs(60));
```

3. **Reduce body buffer size:**
```
max_body_size: 524288  # 512KB instead of 1MB
```

4. **Check for memory leaks:**
```
# Use valgrind
valgrind --leak-check=full ./target/debug/pingora-waf
```

### Issue: Low Throughput

**Symptoms:**
Requests/sec < 5,000

**Diagnostic Steps:**

1. **Benchmark baseline:**
```
# Direct to backend
wrk -t10 -c100 -d30s http://backend:8080

# Through WAF
wrk -t10 -c100 -d30s http://localhost:6188
```

2. **Check system limits:**
```
ulimit -n  # Should be 65536 or higher
sysctl net.core.somaxconn  # Should be 65536
```

**Solutions:**

1. **Increase system limits:**
```
# In /etc/sysctl.conf
net.core.somaxconn=65536
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.ip_local_port_range=1024 65535

# Apply
sudo sysctl -p
```

2. **Increase file descriptors:**
```
# In /etc/security/limits.conf
* soft nofile 65536
* hard nofile 65536

# Apply
ulimit -n 65536
```

3. **Use more CPU cores:**
```
server_conf.threads = num_cpus::get();
```

4. **Disable unnecessary checks (temporarily):**
```
# For testing only
sql_injection:
  enabled: false
xss:
  enabled: false
```

## 🛡️ Security & Blocking Issues

### Issue: Legitimate Traffic Blocked (False Positives)

**Symptoms:**
```
403 Forbidden on valid requests
High block rate in metrics
```

**Diagnostic Steps:**

1. **Check logs for violations:**
```
sudo journalctl -u pingora-waf | grep "Security violation"
```

2. **Identify pattern:**
```
# Count by threat type
grep "threat_type" /var/log/pingora-waf/error.log | \
  awk -F'"' '{print $4}' | sort | uniq -c
```

3. **Test specific request:**
```
curl -v "http://localhost:6188/api/test?suspicious=param"
```

**Solutions:**

1. **Switch to log-only mode:**
```
sql_injection:
  enabled: true
  block_mode: false  # Log but don't block
```

2. **Add to whitelist:**
```
ip_filter:
  enabled: true
  whitelist:
    - "YOUR_IP_ADDRESS"
```

3. **Adjust patterns:**
```
// In src/waf/sql_injection.rs
// Comment out overly aggressive patterns
// Regex::new(r"pattern_causing_false_positive").unwrap(),
```

4. **Increase rate limits:**
```
rate_limit:
  max_requests: 10000  # Much higher
  window_secs: 60
```

### Issue: Path Traversal False Positives

**Symptoms:**
Legitimate paths containing `..` (e.g. in query params) are blocked.

**Solutions:**

1. **Check encoding:**
Ensure clients are properly URL-encoding parameters if they contain valid dots.

2. **Disable strict traversal checks:**
If necessary, you can toggle `block_mode: false` for path traversal while debugging.

### Issue: Attacks Not Being Blocked (False Negatives)

**Symptoms:**
Known attack patterns passing through

**Diagnostic Steps:**

1. **Test with known attacks:**
```
curl "http://localhost:6188/api?id=1' OR '1'='1"
# Should return 403
```

2. **Check if rules are enabled:**
```
cat config/waf_rules.yaml | grep enabled
```

3. **Verify logs show detection:**
```
grep "SQL injection" /var/log/pingora-waf/error.log
```

**Solutions:**

1. **Enable blocking mode:**
```
sql_injection:
  enabled: true
  block_mode: true  # Must be true to block
```

2. **Add missing patterns:**
```
// In src/waf/sql_injection.rs
static SQL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Add new patterns here
        Regex::new(r"your_pattern").unwrap(),
    ]
});
```

3. **Update to latest version:**
```
git pull origin main
cargo build --release
```

4. **Verify URL decoding:**
```
// Ensure patterns check decoded URLs
let decoded = urlencoding::decode(input)
    .unwrap_or(std::borrow::Cow::Borrowed(input));
```

### Issue: Rate Limiting Not Working

**Symptoms:**
Clients exceed configured rate limits

**Diagnostic Steps:**

1. **Check if enabled:**
```
rate_limit:
  enabled: true  # Must be true
```

2. **Test rate limiting:**
```
# Send 150 requests rapidly
for i in {1..150}; do
  curl -s http://localhost:6188/api/test > /dev/null
  echo "Request $i"
done
# Should see 429 errors after limit
```

3. **Check metrics:**
```
curl http://localhost:6190/metrics | grep rate_limit
```

**Solutions:**

1. **Verify IP detection:**
```
// Check logs show correct IP
RUST_LOG=debug ./target/release/pingora-waf
// Look for "IP: x.x.x.x" in logs
```

2. **Check X-Forwarded-For handling:**
```
// In src/proxy/mod.rs get_client_ip()
// Ensure it's reading headers correctly
```

3. **Restart to clear state:**
```
sudo systemctl restart pingora-waf
```

4. **Reduce window for testing:**
```
rate_limit:
  max_requests: 10   # Very low
  window_secs: 10    # Short window
```

## 📊 Monitoring & Metrics

### Issue: Metrics Endpoint Not Responding

**Symptoms:**
```
curl: (7) Failed to connect to localhost port 6190
```

**Diagnostic Steps:**

1. **Check if port is open:**
```
sudo netstat -tlnp | grep 6190
```

2. **Test locally:**
```
curl http://127.0.0.1:6190/metrics
```

3. **Check firewall:**
```
sudo iptables -L -n | grep 6190
sudo ufw status | grep 6190
```

**Solutions:**

1. **Open firewall port:**
```
sudo ufw allow 6190/tcp
sudo iptables -A INPUT -p tcp --dport 6190 -j ACCEPT
```

2. **Bind to correct interface:**
```
// src/main.rs
metrics_service.add_tcp("0.0.0.0:6190");  // Listen on all
```

3. **Check if service started:**
```
RUST_LOG=debug ./target/release/pingora-waf 2>&1 | grep metrics
```

### Issue: Metrics Show Zero Values

**Symptoms:**
All metrics return 0

**Solutions:**

1. **Send test traffic:**
```
curl http://localhost:6188/api/test
curl http://localhost:6190/metrics | grep waf_
```

2. **Check metric registration:**
```
// In src/metrics/collector.rs
// Ensure metrics are registered
prometheus::register(Box::new(TOTAL_REQUESTS.clone())).unwrap();
```

3. **Restart metrics collection:**
```
sudo systemctl restart pingora-waf
```

### Issue: Prometheus Not Scraping

**Symptoms:**
Metrics not appearing in Prometheus

**Solutions:**

1. **Verify Prometheus config:**
```
# prometheus.yml
scrape_configs:
  - job_name: 'pingora-waf'
    static_configs:
      - targets: ['localhost:6190']  # Correct target
```

2. **Check Prometheus logs:**
```
docker logs prometheus
# Or
journalctl -u prometheus -f
```

3. **Test scrape endpoint:**
```
curl http://localhost:6190/metrics
# Should return Prometheus format metrics
```

4. **Reload Prometheus:**
```
curl -X POST http://localhost:9090/-/reload
# Or
sudo systemctl reload prometheus
```

## 🌐 Network & Connectivity

### Issue: Cannot Access WAF from External Network

**Symptoms:**
WAF works on localhost but not from external IPs

**Solutions:**

1. **Check binding address:**
```
// Must bind to 0.0.0.0, not 127.0.0.1
proxy_service.add_tcp("0.0.0.0:6188");
```

2. **Configure firewall:**
```
# UFW
sudo ufw allow 6188/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 6188 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4
```

3. **Check cloud security groups (AWS/GCP/Azure):**
- Add inbound rule for port 6188
- Source: 0.0.0.0/0 (or specific IPs)

4. **Verify network interface:**
```
ip addr show
netstat -tlnp | grep 6188
```

### Issue: SSL/TLS Certificate Errors

**Symptoms:**
```
SSL certificate problem: self signed certificate
```

**Note:** Pingora WAF doesn't handle TLS directly. Use a reverse proxy.

**Solution:**

1. **Use Nginx as TLS terminator:**
```
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:6188;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

2. **Or use Let's Encrypt with Certbot:**
```
sudo certbot --nginx -d yourdomain.com
```

### Issue: Timeout Errors

**Symptoms:**
```
upstream request timeout
```

**Solutions:**

1. **Increase timeouts:**
```
# In Nginx
proxy_connect_timeout 10s;
proxy_send_timeout 60s;
proxy_read_timeout 60s;
```

2. **Check backend performance:**
```
# Test backend directly
time curl http://backend:8080/api/slow-endpoint
```

3. **Optimize backend queries:**
- Add database indexes
- Cache frequent queries
- Optimize application code

## 🚀 Deployment Issues

### Issue: Systemd Service Won't Start

**Symptoms:**
```
Failed to start pingora-waf.service
```

**Diagnostic Steps:**

1. **Check service status:**
```
sudo systemctl status pingora-waf
```

2. **View full logs:**
```
sudo journalctl -u pingora-waf -n 100 --no-pager
```

3. **Test binary manually:**
```
sudo -u www-data /opt/pingora-waf/target/release/pingora-waf
```

**Solutions:**

1. **Fix permissions:**
```
sudo chown -R www-data:www-data /opt/pingora-waf
sudo chmod +x /opt/pingora-waf/target/release/pingora-waf
```

2. **Fix working directory:**
```
# In pingora-waf.service
WorkingDirectory=/opt/pingora-waf
```

3. **Add missing environment variables:**
```
Environment="RUST_LOG=info"
Environment="LD_LIBRARY_PATH=/usr/local/lib"
```

4. **Check SELinux (if enabled):**
```
sudo setenforce 0  # Temporarily disable
sudo systemctl start pingora-waf
# If works, fix SELinux policy
```

### Issue: Docker Container Exits Immediately

**Symptoms:**
```
docker ps -a
# Shows: Exited (1) 2 seconds ago
```

**Solutions:**

1. **Check container logs:**
```
docker logs pingora-waf
```

2. **Run interactively:**
```
docker run -it --rm pingora-waf /bin/bash
# Then run binary manually
./usr/local/bin/pingora-waf
```

3. **Fix Dockerfile:**
```
# Ensure config is copied
COPY config /etc/pingora-waf/config

# Set working directory
WORKDIR /opt/pingora-waf

# Use exec form
CMD ["pingora-waf"]
```

4. **Check environment:**
```
ENV RUST_LOG=info
ENV PATH=/usr/local/bin:$PATH
```

### Issue: Kubernetes Pod CrashLoopBackOff

**Symptoms:**
```
kubectl get pods
# Shows: CrashLoopBackOff
```

**Solutions:**

1. **Check pod logs:**
```
kubectl logs deployment/pingora-waf
kubectl logs deployment/pingora-waf --previous
```

2. **Describe pod:**
```
kubectl describe pod pingora-waf-xxx
```

3. **Check liveness probe:**
```
# Increase initial delay
livenessProbe:
  httpGet:
    path: /metrics
    port: 6190
  initialDelaySeconds: 30  # Increased
```

4. **Check resource limits:**
```
resources:
  limits:
    memory: "512Mi"  # Increase if needed
    cpu: "1000m"
```

5. **Check config map:**
```
kubectl get configmap waf-config -o yaml
```

## 🆘 Getting Help

### Before Asking for Help

Gather this information:

1. **System Information:**
```
uname -a
cat /etc/os-release
rustc --version
./target/release/pingora-waf --version
```

2. **Configuration:**
```
cat config/waf_rules.yaml
```

3. **Logs (last 100 lines):**
```
sudo journalctl -u pingora-waf -n 100 --no-pager
```

4. **Error messages** (exact text)

5. **Steps to reproduce**

### Where to Get Help

1. **Documentation**: Check [docs/](README.md) first
2. **FAQ**: See [faq.md](faq.md)
3. **GitHub Issues**: [Report bugs](https://github.com/aarambhdevhub/pingora-waf/issues)
4. **Discussions**: [Ask questions](https://github.com/aarambhdevhub/pingora-waf/discussions)
5. **Email**: [Contact via GitHub Issues] (security issues only)

### Creating a Good Bug Report

Include:

```
**Environment:**
- OS: Ubuntu 22.04
- Rust: 1.70.0
- WAF Version: 0.1.0

**Expected Behavior:**
WAF should block SQL injection

**Actual Behavior:**
Request passes through

**Steps to Reproduce:**
1. Start WAF with config X
2. Send request: curl "http://..."
3. Observe result

**Logs:**
[Paste relevant logs]

**Configuration:**
[Paste waf_rules.yaml]
```

## 📚 Additional Resources

- **Architecture**: [architecture.md](architecture.md)
- **Configuration**: [configuration.md](configuration.md)
- **Performance**: [performance.md](performance.md)
- **Security Rules**: [security-rules.md](security-rules.md)
- **Examples**: [examples.md](examples.md)

## 🔄 Common Quick Fixes

### Reset to Clean State

```
# Stop service
sudo systemctl stop pingora-waf

# Clean build
cd /opt/pingora-waf
cargo clean
cargo build --release

# Reset config
cp config/waf_rules.yaml.example config/waf_rules.yaml

# Restart
sudo systemctl start pingora-waf
sudo systemctl status pingora-waf
```

### Force Restart

```
# Kill all instances
sudo pkill -9 pingora-waf

# Clean state
sudo systemctl reset-failed pingora-waf

# Start fresh
sudo systemctl start pingora-waf
```

### Emergency Disable WAF

```
# Stop WAF
sudo systemctl stop pingora-waf

# Point traffic directly to backend
# (Update load balancer/nginx config)
```

---

**Still having issues?** [Open an issue](https://github.com/aarambhdevhub/pingora-waf/issues/new) with details!

**Last Updated**: October 8, 2025
**Maintained By**: Aarambh dev hub
