# Pingora WAF Examples

This guide provides practical examples for using Pingora WAF in various scenarios.

## 📋 Table of Contents

- [Basic Usage](#basic-usage)
- [Testing Security Rules](#testing-security-rules)
- [Custom Security Rules](#custom-security-rules)
- [Load Testing](#load-testing)
- [Docker Examples](#docker-examples)
- [Kubernetes Examples](#kubernetes-examples)
- [Integration Examples](#integration-examples)
- [Advanced Scenarios](#advanced-scenarios)

## Basic Usage

### Example 1: Simple Proxy Setup

**Scenario**: Protect a single backend service running on port 8080.

#### Configuration (config/waf_rules.yaml)

```
sql_injection:
  enabled: true
  block_mode: true

xss:
  enabled: true
  block_mode: true

rate_limit:
  enabled: true
  max_requests: 1000
  window_secs: 60

ip_filter:
  enabled: false

max_body_size: 1048576
```

#### Start Backend and WAF

```
# Terminal 1: Start backend
cargo run --example mock_backend_tokio

# Terminal 2: Start WAF
RUST_LOG=info ./target/release/pingora-waf

# Terminal 3: Test requests
curl http://localhost:6188/api/users
curl http://localhost:6188/api/products
```

### Example 2: Development Mode (Log Only)

**Scenario**: Test without blocking requests during development.

```
sql_injection:
  enabled: true
  block_mode: false  # Log only, don't block

xss:
  enabled: true
  block_mode: false  # Log only

rate_limit:
  enabled: false  # Disable for testing
```

```
# Start with debug logging
RUST_LOG=debug ./target/release/pingora-waf

# All requests will be logged but not blocked
curl "http://localhost:6188/api/test?id=1' OR '1'='1"
# Returns 200 but logs: "SQL injection detected"
```

### Example 3: Multiple Backends

**Scenario**: Route to different backends based on path.

```
// src/main.rs - Modify upstream_peer method
async fn upstream_peer(
    &self,
    session: &mut Session,
    _ctx: &mut Self::CTX,
) -> Result<Box<HttpPeer>> {
    let path = session.req_header().uri.path();

    let (host, port) = if path.starts_with("/api/v1") {
        ("backend-v1.internal", 8080)
    } else if path.starts_with("/api/v2") {
        ("backend-v2.internal", 8081)
    } else {
        ("default-backend.internal", 8080)
    };

    let peer = Box::new(HttpPeer::new(
        (host, port),
        false,
        "".to_string(),
    ));
    Ok(peer)
}
```

## Testing Security Rules

### Example 4: SQL Injection Tests

```
#!/bin/bash
# test_sql_injection.sh

echo "Testing SQL Injection Detection"
echo "================================"

# Test 1: Basic OR injection
curl -s "http://localhost:6188/api/users?id=1 OR 1=1"
echo "Test 1: OR injection - $(if [ $? -eq 0 ]; then echo 'PASS'; else echo 'FAIL'; fi)"

# Test 2: Union-based injection
curl -s "http://localhost:6188/api/users?id=1' UNION SELECT * FROM passwords--"
echo "Test 2: UNION injection - $(if [ $? -eq 0 ]; then echo 'PASS'; else echo 'FAIL'; fi)"

# Test 3: Drop table
curl -s "http://localhost:6188/api/users?id=1; DROP TABLE users"
echo "Test 3: DROP TABLE - $(if [ $? -eq 0 ]; then echo 'PASS'; else echo 'FAIL'; fi)"

# Test 4: Comment-based
curl -s "http://localhost:6188/api/login?user=admin'--&pass=any"
echo "Test 4: Comment injection - $(if [ $? -eq 0 ]; then echo 'PASS'; else echo 'FAIL'; fi)"

# Test 5: Time-based blind
curl -s "http://localhost:6188/api/users?id=1 AND SLEEP(5)"
echo "Test 5: Time-based blind - $(if [ $? -eq 0 ]; then echo 'PASS'; else echo 'FAIL'; fi)"

echo ""
echo "✅ All SQL injection patterns should be blocked (403)"
```

### Example 5: XSS Attack Tests

```
#!/bin/bash
# test_xss_attacks.sh

echo "Testing XSS Detection"
echo "===================="

# Test 1: Script tag
curl -X POST http://localhost:6188/api/comment \
  -H "Content-Type: text/plain" \
  -d "<script>alert('XSS')</script>"
echo "Test 1: Script tag"

# Test 2: Event handler
curl -X POST http://localhost:6188/api/comment \
  -H "Content-Type: text/plain" \
  -d "<img src=x onerror=alert('XSS')>"
echo "Test 2: Event handler"

# Test 3: JavaScript protocol
curl -X POST http://localhost:6188/api/comment \
  -H "Content-Type: text/plain" \
  -d "<a href='javascript:alert(1)'>Click</a>"
echo "Test 3: JavaScript protocol"

# Test 4: Iframe injection
curl -X POST http://localhost:6188/api/comment \
  -H "Content-Type: text/plain" \
  -d "<iframe src=javascript:alert(1)></iframe>"
echo "Test 4: Iframe injection"

echo ""
echo "✅ All XSS attacks should be blocked (403)"
```

### Example 6: Rate Limiting Test

```
#!/bin/bash
# test_rate_limiting.sh

echo "Testing Rate Limiting"
echo "===================="

BLOCKED=0
ALLOWED=0

for i in {1..120}; do
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:6188/api/test)

  if [ "$RESPONSE" == "429" ]; then
    BLOCKED=$((BLOCKED + 1))
  elif [ "$RESPONSE" == "200" ]; then
    ALLOWED=$((ALLOWED + 1))
  fi

  if [ $((i % 20)) -eq 0 ]; then
    echo "Sent $i requests - Allowed: $ALLOWED, Blocked: $BLOCKED"
  fi
done

echo ""
echo "Final Results:"
echo "✅ Allowed: $ALLOWED"
echo "⛔ Blocked: $BLOCKED"
echo ""
echo "Expected: ~100 allowed, ~20 blocked (with default 100 req/60s limit)"
```

## Custom Security Rules

### Example 7: Path Traversal Detection

**File**: `examples/path_traversal_rule.rs`

```
use pingora_waf::*;
use regex::Regex;
use once_cell::sync::Lazy;

static PATH_TRAVERSAL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c)").unwrap()
});

pub struct PathTraversalRule {
    pub enabled: bool,
    pub block_mode: bool,
}

impl PathTraversalRule {
    pub fn new(enabled: bool, block_mode: bool) -> Self {
        Self { enabled, block_mode }
    }
}

impl SecurityRule for PathTraversalRule {
    fn check(
        &self,
        request: &pingora::http::RequestHeader,
        _body: Option<&[u8]>,
    ) -> Result<(), SecurityViolation> {
        if !self.enabled {
            return Ok(());
        }

        let uri = request.uri.to_string();
        let decoded = urlencoding::decode(&uri).unwrap_or(std::borrow::Cow::Borrowed(&uri));

        if PATH_TRAVERSAL_PATTERN.is_match(&decoded) {
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

// Usage
fn main() {
    let rule = PathTraversalRule::new(true, true);

    // Test cases
    let test_uris = vec![
        "/api/file?path=../../../etc/passwd",  // Should block
        "/api/file?path=..\\..\\..\\windows\\system32\\config\\sam",  // Should block
        "/api/file?path=normal/file.txt",  // Should allow
    ];

    for uri in test_uris {
        println!("Testing: {}", uri);
        // Test logic here
    }
}
```

### Example 8: User-Agent Blacklist

```
use pingora_waf::*;
use std::collections::HashSet;

pub struct UserAgentBlacklist {
    pub enabled: bool,
    pub blocked_agents: HashSet<String>,
}

impl UserAgentBlacklist {
    pub fn new(enabled: bool) -> Self {
        let mut blocked_agents = HashSet::new();

        // Common scanners and bots
        blocked_agents.insert("sqlmap".to_lowercase());
        blocked_agents.insert("nikto".to_lowercase());
        blocked_agents.insert("nmap".to_lowercase());
        blocked_agents.insert("masscan".to_lowercase());
        blocked_agents.insert("metasploit".to_lowercase());
        blocked_agents.insert("burp".to_lowercase());
        blocked_agents.insert("havij".to_lowercase());

        Self {
            enabled,
            blocked_agents,
        }
    }
}

impl SecurityRule for UserAgentBlacklist {
    fn check(
        &self,
        request: &pingora::http::RequestHeader,
        _body: Option<&[u8]>,
    ) -> Result<(), SecurityViolation> {
        if !self.enabled {
            return Ok(());
        }

        if let Some(ua) = request.headers.get("user-agent") {
            if let Ok(ua_str) = ua.to_str() {
                let ua_lower = ua_str.to_lowercase();

                for blocked in &self.blocked_agents {
                    if ua_lower.contains(blocked) {
                        return Err(SecurityViolation {
                            threat_type: "MALICIOUS_USER_AGENT".to_string(),
                            threat_level: ThreatLevel::Medium,
                            description: format!("Blocked user agent: {}", ua_str),
                            blocked: true,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "User-Agent Blacklist"
    }
}
```

### Example 9: GeoIP Blocking (Conceptual)

```
use pingora_waf::*;
use std::collections::HashSet;

pub struct GeoIpFilter {
    pub enabled: bool,
    pub blocked_countries: HashSet<String>,
}

impl GeoIpFilter {
    pub fn new(enabled: bool, blocked_countries: Vec<String>) -> Self {
        Self {
            enabled,
            blocked_countries: blocked_countries.into_iter().collect(),
        }
    }

    fn get_country_from_ip(&self, ip: &str) -> Option<String> {
        // In real implementation, use MaxMind GeoIP2 or similar
        // For now, this is a placeholder
        // Example: geoip2::lookup(ip).country_code()
        None
    }
}

impl SecurityRule for GeoIpFilter {
    fn check(
        &self,
        request: &pingora::http::RequestHeader,
        _body: Option<&[u8]>,
    ) -> Result<(), SecurityViolation> {
        if !self.enabled {
            return Ok(());
        }

        // Get client IP from X-Forwarded-For or connection
        let client_ip = request.headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .unwrap_or("unknown");

        if let Some(country) = self.get_country_from_ip(client_ip) {
            if self.blocked_countries.contains(&country) {
                return Err(SecurityViolation {
                    threat_type: "GEOBLOCKED".to_string(),
                    threat_level: ThreatLevel::Medium,
                    description: format!("Request from blocked country: {}", country),
                    blocked: true,
                });
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "GeoIP Filter"
    }
}
```

## Load Testing

### Example 10: Gradual Load Test

```
#!/bin/bash
# gradual_load_test.sh

echo "Gradual Load Test"
echo "================="

THREADS=(1 2 4 8 10)
CONNECTIONS=(10 25 50 100 200)

for t in "${THREADS[@]}"; do
  for c in "${CONNECTIONS[@]}"; do
    echo ""
    echo "Testing: $t threads, $c connections"
    echo "-----------------------------------"

    wrk -t$t -c$c -d10s --latency http://localhost:6188/api/test | \
      grep -E "Requests/sec|Latency|requests"

    sleep 2
  done
done

echo ""
echo "✅ Gradual load test complete"
```

### Example 11: Sustained Load Test

```
#!/bin/bash
# sustained_load_test.sh

echo "Sustained Load Test (5 minutes)"
echo "==============================="

START_TIME=$(date +%s)

wrk -t10 -c100 -d300s --latency \
  --script=report.lua \
  http://localhost:6188/api/test

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "Test Duration: ${DURATION}s"
echo ""
echo "Check metrics:"
echo "curl http://localhost:6190/metrics | grep waf_"
```

### Example 12: Performance Comparison

```
#!/bin/bash
# compare_performance.sh

echo "Performance Comparison"
echo "====================="

# Test 1: Without WAF (direct backend)
echo "Test 1: Direct Backend (no WAF)"
wrk -t10 -c100 -d30s http://localhost:8080/api/test | \
  grep "Requests/sec" | tee direct.txt

sleep 5

# Test 2: With WAF (all rules enabled)
echo ""
echo "Test 2: Through WAF (all rules)"
wrk -t10 -c100 -d30s http://localhost:6188/api/test | \
  grep "Requests/sec" | tee waf_full.txt

sleep 5

# Test 3: With WAF (minimal rules)
echo ""
echo "Test 3: Through WAF (minimal rules)"
# Temporarily use minimal config
wrk -t10 -c100 -d30s http://localhost:6188/api/test | \
  grep "Requests/sec" | tee waf_minimal.txt

echo ""
echo "Results Summary:"
echo "================"
cat direct.txt
cat waf_full.txt
cat waf_minimal.txt

rm -f direct.txt waf_full.txt waf_minimal.txt
```

## Docker Examples

### Example 13: Docker Compose Full Stack

**File**: `docker-compose.yml`

```
version: '3.8'

services:
  # Web Application Firewall
  waf:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: pingora-waf
    ports:
      - "80:6188"      # HTTP traffic
      - "6190:6190"    # Metrics
    environment:
      - RUST_LOG=info
      - UPSTREAM_HOST=backend
      - UPSTREAM_PORT=8080
    volumes:
      - ./config:/app/config:ro
    depends_on:
      - backend
    restart: unless-stopped
    networks:
      - waf-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:6190/metrics"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Backend Application
  backend:
    image: nginx:alpine
    container_name: backend-app
    volumes:
      - ./backend:/usr/share/nginx/html:ro
    expose:
      - "8080"
    networks:
      - waf-network
    restart: unless-stopped

  # Prometheus for Metrics
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
    networks:
      - waf-network
    restart: unless-stopped

  # Grafana for Visualization
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_INSTALL_PLUGINS=grafana-piechart-panel
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
      - ./grafana/datasources:/etc/grafana/provisioning/datasources:ro
    networks:
      - waf-network
    restart: unless-stopped

networks:
  waf-network:
    driver: bridge

volumes:
  prometheus-data:
  grafana-data:
```

**Usage**:

```
# Start everything
docker-compose up -d

# View logs
docker-compose logs -f waf

# Test
curl http://localhost/api/test

# View metrics
curl http://localhost:9090

# View dashboards
open http://localhost:3000

# Stop everything
docker-compose down
```

### Example 14: Docker Multi-Stage Build

**File**: `Dockerfile.optimized`

```
# Stage 1: Builder
FROM rust:1.70-slim as builder

WORKDIR /app

# Install dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source
COPY src ./src
COPY config ./config
COPY examples ./examples

# Build release
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 waf && \
    chown -R waf:waf /app

# Copy binary from builder
COPY --from=builder /app/target/release/pingora-waf /usr/local/bin/
COPY --from=builder /app/config /app/config

# Switch to non-root user
USER waf

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:6190/metrics || exit 1

# Expose ports
EXPOSE 6188 6190

# Run
CMD ["pingora-waf"]
```

**Build and run**:

```
# Build optimized image
docker build -f Dockerfile.optimized -t pingora-waf:optimized .

# Run
docker run -d \
  -p 6188:6188 \
  -p 6190:6190 \
  -v $(pwd)/config:/app/config:ro \
  -e RUST_LOG=info \
  --name waf \
  pingora-waf:optimized

# Check logs
docker logs -f waf

# Check health
docker ps
```

## Kubernetes Examples

### Example 15: Basic Deployment

**File**: `k8s/deployment.yaml`

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: waf-config
  namespace: default
data:
  waf_rules.yaml: |
    sql_injection:
      enabled: true
      block_mode: true
    xss:
      enabled: true
      block_mode: true
    rate_limit:
      enabled: true
      max_requests: 5000
      window_secs: 60
    ip_filter:
      enabled: false
    max_body_size: 5242880

***
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pingora-waf
  namespace: default
  labels:
    app: pingora-waf
spec:
  replicas: 3
  selector:
    matchLabels:
      app: pingora-waf
  template:
    metadata:
      labels:
        app: pingora-waf
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "6190"
        prometheus.io/path: "/metrics"
    spec:
      containers:
      - name: waf
        image: aarambhdevhub/pingora-waf:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 6188
          name: http
          protocol: TCP
        - containerPort: 6190
          name: metrics
          protocol: TCP
        env:
        - name: RUST_LOG
          value: "info"
        - name: RUST_BACKTRACE
          value: "1"
        resources:
          requests:
            cpu: "500m"
            memory: "256Mi"
          limits:
            cpu: "2000m"
            memory: "512Mi"
        livenessProbe:
          httpGet:
            path: /metrics
            port: 6190
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /metrics
            port: 6190
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 2
        volumeMounts:
        - name: config
          mountPath: /etc/pingora-waf/config
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: waf-config

***
apiVersion: v1
kind: Service
metadata:
  name: pingora-waf
  namespace: default
  labels:
    app: pingora-waf
spec:
  type: LoadBalancer
  selector:
    app: pingora-waf
  ports:
  - name: http
    port: 80
    targetPort: 6188
    protocol: TCP
  - name: metrics
    port: 6190
    targetPort: 6190
    protocol: TCP

***
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: pingora-waf-hpa
  namespace: default
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
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Pods
        value: 1
        periodSeconds: 60
```

**Deploy**:

```
# Create namespace
kubectl create namespace waf

# Apply configuration
kubectl apply -f k8s/deployment.yaml -n waf

# Check status
kubectl get pods -n waf
kubectl get svc -n waf

# View logs
kubectl logs -f deployment/pingora-waf -n waf

# Scale manually
kubectl scale deployment pingora-waf --replicas=5 -n waf

# Check HPA
kubectl get hpa -n waf
```

### Example 16: Ingress Configuration

**File**: `k8s/ingress.yaml`

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: waf-ingress
  namespace: default
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - api.example.com
    secretName: api-tls
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: pingora-waf
            port:
              number: 80
```

## Integration Examples

### Example 17: Nginx + Pingora WAF

**File**: `nginx.conf`

```
upstream pingora_waf {
    server 127.0.0.1:6188;
    keepalive 64;
}

server {
    listen 80;
    server_name example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://pingora_waf;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### Example 18: Prometheus Integration

**File**: `prometheus.yml`

```
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'production'
    replica: '1'

# WAF Metrics
scrape_configs:
  - job_name: 'pingora-waf'
    static_configs:
      - targets: ['localhost:6190']
        labels:
          instance: 'waf-1'
          environment: 'production'

    metric_relabel_configs:
      # Add custom labels
      - source_labels: [__name__]
        regex: 'waf_.*'
        target_label: 'component'
        replacement: 'security'

# Alert Rules
rule_files:
  - 'alerts/waf_alerts.yml'

# Alertmanager
alerting:
  alertmanagers:
    - static_configs:
        - targets: ['localhost:9093']
```

### Example 19: Python Integration Test

```
#!/usr/bin/env python3
# test_waf_integration.py

import requests
import time
from typing import List, Dict

class WAFTester:
    def __init__(self, base_url: str = "http://localhost:6188"):
        self.base_url = base_url
        self.results = []

    def test_legitimate_request(self):
        """Test that normal requests pass through"""
        response = requests.get(f"{self.base_url}/api/test")
        assert response.status_code == 200, "Legitimate request should pass"
        self.results.append(("Legitimate Request", "PASS"))

    def test_sql_injection(self):
        """Test SQL injection blocking"""
        payloads = [
            "1' OR '1'='1",
            "'; DROP TABLE users--",
            "1 UNION SELECT * FROM passwords",
        ]

        for payload in payloads:
            response = requests.get(
                f"{self.base_url}/api/users",
                params={"id": payload}
            )
            assert response.status_code == 403, f"SQL injection should be blocked: {payload}"

        self.results.append(("SQL Injection", "PASS"))

    def test_xss_attack(self):
        """Test XSS blocking"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<iframe src=javascript:alert(1)>",
        ]

        for payload in payloads:
            response = requests.post(
                f"{self.base_url}/api/comment",
                data=payload
            )
            assert response.status_code == 403, f"XSS should be blocked: {payload}"

        self.results.append(("XSS Attack", "PASS"))

    def test_rate_limiting(self):
        """Test rate limiting"""
        blocked = False

        for i in range(150):
            response = requests.get(f"{self.base_url}/api/test")
            if response.status_code == 429:
                blocked = True
                break
            time.sleep(0.01)

        assert blocked, "Rate limiting should trigger"
        self.results.append(("Rate Limiting", "PASS"))

    def run_all_tests(self):
        """Run all tests"""
        print("Running WAF Integration Tests")
        print("=" * 50)

        tests = [
            self.test_legitimate_request,
            self.test_sql_injection,
            self.test_xss_attack,
            self.test_rate_limiting,
        ]

        for test in tests:
            try:
                test()
            except AssertionError as e:
                self.results.append((test.__doc__, f"FAIL: {e}"))

        # Print results
        print("\nResults:")
        print("-" * 50)
        for test_name, result in self.results:
            print(f"{test_name}: {result}")

        # Summary
        passed = sum(1 for _, r in self.results if r == "PASS")
        total = len(self.results)
        print(f"\nSummary: {passed}/{total} tests passed")

        return passed == total

if __name__ == "__main__":
    tester = WAFTester()
    success = tester.run_all_tests()
    exit(0 if success else 1)
```

**Run**:

```
python3 test_waf_integration.py
```

## Advanced Scenarios

### Example 20: Custom Metrics

```
// Add custom metrics to your WAF
use prometheus::{IntCounter, IntGauge, Histogram, HistogramOpts};
use once_cell::sync::Lazy;

static CUSTOM_BLOCKED_REQUESTS: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "waf_custom_rule_blocks",
        "Requests blocked by custom rules"
    ).expect("metric creation failed")
});

static ACTIVE_CONNECTIONS: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new(
        "waf_active_connections",
        "Currently active connections"
    ).expect("metric creation failed")
});

static REQUEST_DURATION: Lazy<Histogram> = Lazy::new(|| {
    Histogram::with_opts(
        HistogramOpts::new(
            "waf_request_duration_seconds",
            "Request processing duration"
        ).buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0])
    ).expect("metric creation failed")
});

// Register in your metrics collector
prometheus::register(Box::new(CUSTOM_BLOCKED_REQUESTS.clone())).unwrap();
prometheus::register(Box::new(ACTIVE_CONNECTIONS.clone())).unwrap();
prometheus::register(Box::new(REQUEST_DURATION.clone())).unwrap();

// Use in your code
CUSTOM_BLOCKED_REQUESTS.inc();
ACTIVE_CONNECTIONS.set(100);

let timer = REQUEST_DURATION.start_timer();
// ... process request
timer.observe_duration();
```

### Example 21: Dynamic Configuration Reload

```
// Watch for configuration file changes and reload
use notify::{Watcher, RecursiveMode, watcher};
use std::sync::mpsc::channel;
use std::time::Duration;

fn watch_config_file() {
    let (tx, rx) = channel();

    let mut watcher = watcher(tx, Duration::from_secs(2)).unwrap();
    watcher.watch("config/waf_rules.yaml", RecursiveMode::NonRecursive).unwrap();

    loop {
        match rx.recv() {
            Ok(event) => {
                println!("Config file changed: {:?}", event);
                // Reload configuration
                match WafConfig::from_file("config/waf_rules.yaml") {
                    Ok(new_config) => {
                        println!("Configuration reloaded successfully");
                        // Update running configuration
                    }
                    Err(e) => {
                        eprintln!("Failed to reload config: {}", e);
                    }
                }
            }
            Err(e) => eprintln!("Watch error: {}", e),
        }
    }
}
```

### Example 22: Request Logging to File

```
use std::fs::OpenOptions;
use std::io::Write;
use chrono::Local;

fn log_security_violation(violation: &SecurityViolation, client_ip: &str, uri: &str) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    let log_entry = format!(
        "[{}] {} - {} - {} - {}\n",
        timestamp,
        violation.threat_type,
        client_ip,
        uri,
        violation.description
    );

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/pingora-waf/security.log")
        .expect("Failed to open log file");

    file.write_all(log_entry.as_bytes())
        .expect("Failed to write log");
}
```

## More Examples

For more examples, check:

- **[GitHub Repository](https://github.com/aarambhdevhub/pingora-waf/tree/main/examples)** - Full code examples
- **[Tests Directory](https://github.com/aarambhdevhub/pingora-waf/tree/main/tests)** - Integration tests
- **[Benchmarks](https://github.com/aarambhdevhub/pingora-waf/tree/main/benches)** - Performance benchmarks

## Need Help?

- **Questions**: [GitHub Discussions](https://github.com/aarambhdevhub/pingora-waf/discussions)
- **Issues**: [Report a bug](https://github.com/aarambhdevhub/pingora-waf/issues)
- **Security**: Email [Contact via GitHub Issues]

---

**Last Updated**: October 8, 2025
**Maintained By**: Aarambh dev hub
