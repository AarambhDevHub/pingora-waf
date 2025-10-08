# Performance Guide

This guide covers performance optimization, benchmarking, and tuning strategies for Pingora WAF to achieve maximum throughput and minimal latency.

## Table of Contents

- [Performance Overview](#performance-overview)
- [Baseline Benchmarks](#baseline-benchmarks)
- [System Requirements](#system-requirements)
- [Operating System Tuning](#operating-system-tuning)
- [Application Configuration](#application-configuration)
- [Rate Limiting Optimization](#rate-limiting-optimization)
- [Security Rules Performance](#security-rules-performance)
- [Resource Management](#resource-management)
- [Benchmarking Tools](#benchmarking-tools)
- [Load Testing](#load-testing)
- [Scaling Strategies](#scaling-strategies)
- [Performance Monitoring](#performance-monitoring)
- [Troubleshooting Performance](#troubleshooting-performance)
- [Production Optimization Checklist](#production-optimization-checklist)

## Performance Overview

### Measured Performance

**Official Benchmark Results** (Single instance, 4-core CPU, 8GB RAM):

```
Throughput:        15,143 req/sec
Avg Latency:       6.60ms
Max Latency:       42.73ms
Latency Stdev:     1.33ms
Memory Usage:      ~100MB
CPU Usage:         30-40%
Success Rate:      100%
```

### Performance Characteristics

| Workload Type | Expected Performance | Notes |
|---------------|---------------------|--------|
| **API Gateway** | 10,000-15,000 req/s | With all security rules enabled |
| **Static Content** | 20,000-30,000 req/s | Minimal inspection needed |
| **File Uploads** | 5,000-8,000 req/s | Body inspection overhead |
| **WebSocket** | 50,000+ connections | Long-lived connections |

### Comparison with Other WAFs

| WAF Solution | Throughput | Latency | Memory | Language |
|--------------|-----------|---------|---------|----------|
| **Pingora WAF** | **15,143** | **6.60ms** | **100MB** | **Rust** |
| ModSecurity + Nginx | ~5,000 | 15-30ms | 250MB | C |
| AWS WAF | ~10,000 | 8-12ms | Managed | Managed |
| HAProxy | ~10,000 | 8-12ms | 150MB | C |

**Performance Advantage**: **3x faster than ModSecurity** with lower resource usage.

## Baseline Benchmarks

### Recommended Benchmarking Setup

```
# Install benchmarking tools
sudo apt-get install wrk apache2-utils

# Or on macOS
brew install wrk

# Start backend
cargo run --example mock_backend_tokio &

# Start WAF
RUST_LOG=info ./target/release/pingora-waf &

# Wait for startup
sleep 2
```

### Running Benchmarks

#### Quick Performance Test

```
wrk -t10 -c100 -d30s http://localhost:6188/api/test
```

Expected output:
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

#### Latency Distribution Test

```
wrk -t10 -c100 -d60s --latency http://localhost:6188/api/test
```

Expected latency distribution:
```
Latency Distribution
  50%    6.45ms
  75%    7.12ms
  90%    8.31ms
  99%   11.24ms
```

#### Apache Bench Test

```
ab -n 100000 -c 100 http://localhost:6188/api/test
```

#### Different Request Patterns

```
# 1. GET requests only
wrk -t10 -c100 -d30s http://localhost:6188/api/test

# 2. POST with small body
wrk -t10 -c100 -d30s -s post-small.lua http://localhost:6188/api/data

# 3. POST with large body
wrk -t10 -c100 -d30s -s post-large.lua http://localhost:6188/api/upload

# 4. Mixed workload
wrk -t10 -c100 -d30s -s mixed.lua http://localhost:6188/
```

**post-small.lua**:
```
wrk.method = "POST"
wrk.body = '{"user":"test","data":"small payload"}'
wrk.headers["Content-Type"] = "application/json"
```

**post-large.lua**:
```
wrk.method = "POST"
wrk.body = string.rep("x", 10240)  -- 10KB
wrk.headers["Content-Type"] = "application/octet-stream"
```

## System Requirements

### Minimum Requirements

| Resource | Minimum | Recommended | High-Traffic |
|----------|---------|-------------|--------------|
| **CPU** | 1 core | 4 cores | 8+ cores |
| **RAM** | 512MB | 2GB | 4GB+ |
| **Network** | 100 Mbps | 1 Gbps | 10 Gbps |
| **Storage** | 1GB | 10GB | 50GB+ (logs) |

### CPU Considerations

```
# Check CPU count
nproc

# Check CPU info
lscpu

# Monitor CPU usage
htop
```

**Recommendations**:
- **Single core**: Max ~5,000 req/s
- **4 cores**: Max ~15,000 req/s
- **8 cores**: Max ~30,000 req/s
- **16+ cores**: 50,000+ req/s with scaling

### Memory Requirements

Base memory usage:
```
Idle:           ~50 MB
Active:         ~100 MB
Under load:     ~150 MB (15k req/s)
Peak:           ~200 MB
```

Calculate required memory:
```
# Formula: Base + (Connections × 50KB)
# For 1000 concurrent connections:
# 100MB + (1000 × 0.05MB) = 150MB
```

### Network Bandwidth

```
# Calculate required bandwidth
# Formula: Throughput × Avg Response Size
# Example: 15,000 req/s × 2KB = 30 MB/s = 240 Mbps

# Monitor network usage
iftop
nethogs
```

## Operating System Tuning

### Linux Kernel Parameters

Edit `/etc/sysctl.conf`:

```
# Network tuning
net.core.somaxconn = 65536
net.core.netdev_max_backlog = 65536
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30

# Memory tuning
vm.swappiness = 10
vm.overcommit_memory = 1

# File handling
fs.file-max = 2097152
fs.nr_open = 2097152
```

Apply changes:
```
sudo sysctl -p
```

### File Descriptor Limits

Edit `/etc/security/limits.conf`:

```
*  soft  nofile  65536
*  hard  nofile  65536
root soft nofile 65536
root hard nofile 65536
```

For current session:
```
ulimit -n 65536

# Verify
ulimit -n
```

### TCP Settings

```
# Enable TCP Fast Open
sudo sysctl -w net.ipv4.tcp_fastopen=3

# TCP window scaling
sudo sysctl -w net.ipv4.tcp_window_scaling=1

# TCP timestamps
sudo sysctl -w net.ipv4.tcp_timestamps=1

# Increase TCP buffer sizes
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"
```

### Disable Transparent Huge Pages

```
# Check current status
cat /sys/kernel/mm/transparent_hugepage/enabled

# Disable
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/defrag
```

Make permanent in `/etc/rc.local`:
```
#!/bin/bash
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag
```

## Application Configuration

### Thread Configuration

Edit `src/main.rs`:

```
use num_cpus;

fn main() {
    // Use all CPU cores
    let mut server_conf = Opt::default();
    server_conf.threads = num_cpus::get();

    let mut server = Server::new(Some(server_conf)).unwrap();
    // ... rest of configuration
}
```

**Recommendations**:
- **CPU-bound**: threads = CPU cores
- **I/O-bound**: threads = CPU cores × 2
- **Mixed**: threads = CPU cores × 1.5

Add to `Cargo.toml`:
```
[dependencies]
num_cpus = "1.16"
```

### Worker Configuration

```
// For high-throughput scenarios
let mut server_conf = Opt::default();
server_conf.threads = num_cpus::get();
server_conf.work_stealing = true;  // Enable work stealing
```

### Connection Pooling

Configure upstream connection pooling:

```
// In src/main.rs
// TODO: Configure connection pool size based on expected load
// Default is usually sufficient for most use cases
```

## Rate Limiting Optimization

### Configuration Based on Traffic

```
# Low traffic (< 100 req/s)
rate_limit:
  enabled: true
  max_requests: 1000
  window_secs: 60

# Medium traffic (100-1000 req/s)
rate_limit:
  enabled: true
  max_requests: 5000
  window_secs: 60

# High traffic (1000+ req/s)
rate_limit:
  enabled: true
  max_requests: 10000
  window_secs: 60

# For load testing (disable)
rate_limit:
  enabled: false
```

### Rate Limiter Cleanup

Add automatic cleanup to `src/main.rs`:

```
// Periodic cleanup to prevent memory growth
let rate_limiter_clone = rate_limiter.clone();
std::thread::spawn(move || {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(300)); // Every 5 minutes
        rate_limiter_clone.cleanup_old_entries();
        info!("Cleaned up rate limiter entries");
    }
});
```

### Memory Impact

```
Rate limit entries: ~100 bytes per IP
1000 unique IPs: ~100 KB
10,000 unique IPs: ~1 MB
100,000 unique IPs: ~10 MB
```

## Security Rules Performance

### Rule Performance Impact

| Rule | Latency Overhead | CPU Impact | Memory Impact |
|------|------------------|------------|---------------|
| SQL Injection | +0.2-0.5ms | Low | Minimal |
| XSS Detection | +0.1-0.3ms | Low | Minimal |
| Rate Limiting | +0.05-0.1ms | Very Low | ~1MB per 10K IPs |
| IP Filtering | +0.01ms | Very Low | ~100KB |
| Body Inspection | +1-5ms | Medium | Depends on body size |

### Optimize SQL Injection Detection

Pre-compile regexes with `once_cell::sync::Lazy`:

```
use once_cell::sync::Lazy;
use regex::Regex;

static SQL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)\bunion\b.*\bselect\b").unwrap(),
        // ... other patterns
    ]
});
```

**Performance gain**: ~30% faster than compiling on each check.

### Optimize XSS Detection

Use efficient pattern matching:

```
// Fast path for common cases
fn check_string(&self, input: &str) -> bool {
    // Quick length check
    if input.len() < 3 {
        return false;
    }

    // Check for obvious patterns first
    if !input.contains('<') && !input.contains("javascript:") {
        return false;
    }

    // Full regex check only if needed
    XSS_PATTERNS.iter().any(|pattern| pattern.is_match(input))
}
```

### Disable Rules for Testing

For pure performance testing:

```
sql_injection:
  enabled: false  # Disable during benchmarks

xss:
  enabled: false

rate_limit:
  enabled: false
```

Expected performance gain: **20-30% throughput increase**.

## Resource Management

### Memory Management

#### Monitor Memory Usage

```
# Real-time memory monitoring
watch -n 1 'ps aux | grep pingora-waf'

# Detailed memory info
pmap $(pgrep pingora-waf)

# Memory profiling
valgrind --tool=massif ./target/release/pingora-waf
```

#### Memory Limits

Set memory limits in systemd service:

```
[Service]
MemoryLimit=512M
MemoryMax=1G
```

### Connection Management

#### Maximum Connections

```
// Configure max connections per worker
// In production, tune based on:
// - Available memory
// - Expected concurrent connections
// - Backend capacity
```

#### Connection Timeouts

```
// Set appropriate timeouts
let peer = HttpPeer::new(
    upstream_addr,
    false,
    "".to_string(),
);

// TODO: Configure timeouts based on backend response times
// - Connect timeout: 5s (typical)
// - Read timeout: 30s (adjust for slow backends)
// - Write timeout: 30s
```

### CPU Affinity

Pin workers to specific CPU cores:

```
# Using taskset
taskset -c 0-3 ./target/release/pingora-waf

# Or in systemd service
[Service]
CPUAffinity=0-3
```

## Benchmarking Tools

### wrk (Recommended)

**Installation**:
```
sudo apt-get install wrk  # Ubuntu/Debian
brew install wrk          # macOS
```

**Usage**:
```
# Basic test
wrk -t10 -c100 -d30s http://localhost:6188/api/test

# With latency percentiles
wrk -t10 -c100 -d30s --latency http://localhost:6188/api/test

# Custom script
wrk -t10 -c100 -d30s -s script.lua http://localhost:6188/
```

### Apache Bench (ab)

```
# Simple test
ab -n 100000 -c 100 http://localhost:6188/api/test

# With keep-alive
ab -n 100000 -c 100 -k http://localhost:6188/api/test

# POST requests
ab -n 10000 -c 100 -p data.json -T application/json http://localhost:6188/api/data
```

### hey

**Installation**:
```
go install github.com/rakyll/hey@latest
```

**Usage**:
```
# Basic test
hey -n 100000 -c 100 http://localhost:6188/api/test

# With rate limiting
hey -n 100000 -c 100 -q 1000 http://localhost:6188/api/test
```

### Custom Load Test

```
cargo run --example load_test
```

## Load Testing

### Test Scenarios

#### 1. Steady State Load

```
# Simulate normal traffic
wrk -t10 -c50 -d300s -R 5000 http://localhost:6188/api/test
```

#### 2. Spike Test

```
# Sudden traffic spike
for i in {1..5}; do
    wrk -t20 -c200 -d10s http://localhost:6188/api/test &
done
wait
```

#### 3. Soak Test (Endurance)

```
# Long-running test to detect memory leaks
wrk -t10 -c100 -d3600s http://localhost:6188/api/test
```

#### 4. Stress Test

```
# Find breaking point
for c in 100 200 400 800 1600; do
    echo "Testing with $c connections..."
    wrk -t10 -c$c -d30s http://localhost:6188/api/test
    sleep 5
done
```

### Load Testing Script

Create `benchmark.sh`:

```
#!/bin/bash

echo "Pingora WAF Performance Benchmark"
echo "=================================="
echo ""

# Configuration
HOST="http://localhost:6188"
DURATION="30s"

# Test 1: Light load
echo "Test 1: Light Load (50 connections)"
wrk -t4 -c50 -d$DURATION $HOST/api/test

# Test 2: Medium load
echo ""
echo "Test 2: Medium Load (100 connections)"
wrk -t8 -c100 -d$DURATION $HOST/api/test

# Test 3: Heavy load
echo ""
echo "Test 3: Heavy Load (200 connections)"
wrk -t10 -c200 -d$DURATION $HOST/api/test

# Test 4: With security checks
echo ""
echo "Test 4: SQL Injection Blocking"
wrk -t10 -c100 -d$DURATION "$HOST/api/test?id=1%20OR%201=1"

# Get metrics
echo ""
echo "Current Metrics:"
curl -s http://localhost:6190/metrics | grep "^waf_"

echo ""
echo "Benchmark Complete!"
```

Run:
```
chmod +x benchmark.sh
./benchmark.sh
```

## Scaling Strategies

### Vertical Scaling

**Single Instance Optimization**:

1. **Increase CPU cores**: Linear scaling up to 8-16 cores
2. **Add RAM**: Improve connection handling
3. **Faster storage**: SSD for logs
4. **Better network**: 10Gbps NIC

**Expected Results**:
```
4 cores:  ~15,000 req/s
8 cores:  ~30,000 req/s
16 cores: ~50,000 req/s
```

### Horizontal Scaling

**Multiple Instances with Load Balancer**:

```
                    ┌──────────────┐
Client ────────────>│ Load Balancer│
                    │  (Nginx/HAProxy)
                    └──────┬───────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
    ┌─────▼─────┐    ┌────▼─────┐    ┌────▼─────┐
    │   WAF 1   │    │  WAF 2   │    │  WAF 3   │
    │ 15k req/s │    │ 15k req/s│    │ 15k req/s│
    └─────┬─────┘    └────┬─────┘    └────┬─────┘
          │                │                │
          └────────────────┼────────────────┘
                           │
                    ┌──────▼───────┐
                    │   Backend    │
                    └──────────────┘
```

**Nginx Load Balancer**:

```
upstream waf_cluster {
    least_conn;  # or ip_hash for sticky sessions
    server 10.0.1.10:6188 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:6188 max_fails=3 fail_timeout=30s;
    server 10.0.1.12:6188 max_fails=3 fail_timeout=30s;
    keepalive 64;
}

server {
    listen 80;

    location / {
        proxy_pass http://waf_cluster;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
```

**Expected Total Throughput**:
```
3 instances:  ~45,000 req/s
5 instances:  ~75,000 req/s
10 instances: ~150,000 req/s
```

### Cloud Auto-Scaling

**Kubernetes HPA**:

```
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: pingora-waf-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: pingora-waf
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "10000"
```

## Performance Monitoring

### Real-Time Metrics

```
# Live dashboard
watch -n 1 'curl -s http://localhost:6190/metrics | grep waf_'

# Grafana queries
rate(waf_total_requests[1m])          # Requests per second
histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))  # p99 latency
```

### Prometheus Queries

```
# Request rate
rate(waf_total_requests[5m])

# Latency percentiles (if instrumented)
histogram_quantile(0.50, rate(http_request_duration_seconds_bucket[5m]))  # p50
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))  # p95
histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))  # p99

# Error rate
rate(waf_blocked_requests[5m]) / rate(waf_total_requests[5m])

# CPU utilization per second
rate(process_cpu_seconds_total[1m])

# Memory usage
process_resident_memory_bytes
```

### Performance Alerts

```
# prometheus-alerts.yml
groups:
  - name: performance_alerts
    rules:
      - alert: HighLatency
        expr: histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m])) > 0.1
        for: 5m
        annotations:
          summary: "High p99 latency detected"

      - alert: HighCPU
        expr: rate(process_cpu_seconds_total[1m]) > 0.8
        for: 5m
        annotations:
          summary: "High CPU usage"

      - alert: LowThroughput
        expr: rate(waf_total_requests[5m]) < 1000
        for: 5m
        annotations:
          summary: "Throughput dropped below expected"
```

## Troubleshooting Performance

### Low Throughput

**Symptoms**: < 5,000 req/s on capable hardware

**Possible Causes**:

1. **Rate limiting too restrictive**
   ```
   # Increase limits
   rate_limit:
     max_requests: 10000
     window_secs: 60
   ```

2. **Backend bottleneck**
   ```
   # Test backend directly
   wrk -t10 -c100 -d30s http://localhost:8080/api/test
   ```

3. **File descriptor limit**
   ```
   # Check and increase
   ulimit -n
   ulimit -n 65536
   ```

4. **Network bandwidth**
   ```
   # Monitor network
   iftop
   nethogs
   ```

### High Latency

**Symptoms**: > 50ms average latency

**Possible Causes**:

1. **Body inspection on large payloads**
   ```
   # Reduce max body size
   max_body_size: 524288  # 512KB
   ```

2. **Complex regex patterns**
   ```
   # Profile regex performance
   RUST_LOG=debug cargo run
   ```

3. **CPU throttling**
   ```
   # Check CPU frequency
   cat /proc/cpuinfo | grep MHz

   # Disable power saving
   sudo cpupower frequency-set -g performance
   ```

### Memory Leaks

**Symptoms**: Memory usage growing over time

**Detection**:
```
# Monitor memory over time
watch -n 10 'ps aux | grep pingora-waf | awk "{print \$6}"'

# Use valgrind
valgrind --leak-check=full --show-leak-kinds=all ./target/release/pingora-waf
```

**Common Causes**:
- Rate limiter not cleaning up old entries
- Connection leaks
- Log buffer growth

**Solutions**:
- Enable periodic cleanup (see Rate Limiting Optimization)
- Set memory limits in systemd
- Configure log rotation

### CPU Saturation

**Symptoms**: 100% CPU usage, low throughput

**Possible Causes**:

1. **Inefficient regex**
   ```
   // Optimize with fast-path checks
   if !input.contains('<') { return false; }
   ```

2. **Too many threads**
   ```
   // Reduce threads to match CPU cores
   server_conf.threads = num_cpus::get();
   ```

3. **Blocking operations**
   ```
   // Ensure all I/O is async
   // Avoid blocking calls in hot paths
   ```

## Production Optimization Checklist

### Pre-Production

- [ ] Run load tests matching expected traffic
- [ ] Perform soak test (24+ hours)
- [ ] Test failover scenarios
- [ ] Verify resource limits
- [ ] Configure monitoring and alerts
- [ ] Document baseline performance
- [ ] Test auto-scaling (if applicable)

### System Configuration

- [ ] Set file descriptor limits (65536+)
- [ ] Configure TCP parameters
- [ ] Disable transparent huge pages
- [ ] Enable TCP Fast Open
- [ ] Set appropriate swappiness
- [ ] Configure CPU affinity

### Application Configuration

- [ ] Set threads = CPU cores
- [ ] Configure rate limits for expected traffic
- [ ] Optimize body size limits
- [ ] Enable periodic cleanup tasks
- [ ] Configure appropriate timeouts
- [ ] Set memory limits

### Monitoring

- [ ] Prometheus metrics enabled
- [ ] Grafana dashboards configured
- [ ] Performance alerts set up
- [ ] Log rotation configured
- [ ] Baseline metrics documented
- [ ] Capacity planning documented

### Testing

- [ ] Benchmark results documented
- [ ] Load test scripts prepared
- [ ] Performance regression tests
- [ ] Capacity testing completed
- [ ] Failover testing done

## Performance Tuning Examples

### Example 1: High-Throughput API

```
# config/waf_rules_high_throughput.yaml
sql_injection:
  enabled: true
  block_mode: true

xss:
  enabled: true
  block_mode: true

rate_limit:
  enabled: true
  max_requests: 10000
  window_secs: 60

ip_filter:
  enabled: false

max_body_size: 524288  # 512KB - smaller for APIs
```

```
// src/main.rs
let mut server_conf = Opt::default();
server_conf.threads = num_cpus::get();
server_conf.work_stealing = true;
```

**Expected**: 20,000+ req/s

### Example 2: File Upload Service

```
# config/waf_rules_file_upload.yaml
sql_injection:
  enabled: true
  block_mode: true

xss:
  enabled: false  # Disable for binary files

rate_limit:
  enabled: true
  max_requests: 100  # Strict for uploads
  window_secs: 60

max_body_size: 52428800  # 50MB
```

**Expected**: 5,000-8,000 req/s

### Example 3: Low-Latency Requirements

```
# config/waf_rules_low_latency.yaml
sql_injection:
  enabled: true
  block_mode: false  # Log only for minimal overhead

xss:
  enabled: true
  block_mode: false

rate_limit:
  enabled: false  # Disable for lowest latency

max_body_size: 1048576
```

**Expected**: < 3ms latency, 25,000+ req/s

## Summary

### Key Performance Factors

1. **Hardware**: More cores = more throughput
2. **OS Tuning**: Essential for high performance
3. **Rate Limiting**: Adjust based on expected traffic
4. **Body Size**: Smaller limits = better performance
5. **Thread Count**: Match CPU cores
6. **Monitoring**: Essential for optimization

### Quick Wins

- Set `ulimit -n 65536`
- Configure sysctl parameters
- Adjust rate limits appropriately
- Use release build (`--release`)
- Disable unnecessary rules for testing
- Enable periodic cleanup

### Performance Goals

| Scenario | Throughput Goal | Latency Goal |
|----------|----------------|--------------|
| API Gateway | 10,000+ req/s | < 10ms |
| Static Content | 20,000+ req/s | < 5ms |
| File Uploads | 5,000+ req/s | < 50ms |
| WebSocket | 50,000+ conn | < 5ms |

---

**Need Help?**
- [Troubleshooting Guide](troubleshooting.md)
- [GitHub Discussions](https://github.com/aarambhdevhub/pingora-waf/discussions)
- Performance issues: Create an issue with benchmark results

**Last Updated**: October 8, 2025
