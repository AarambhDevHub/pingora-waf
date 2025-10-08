# Monitoring Guide

This guide covers monitoring, observability, and operational insights for Pingora WAF.

## Table of Contents

- [Overview](#overview)
- [Prometheus Metrics](#prometheus-metrics)
- [Grafana Dashboards](#grafana-dashboards)
- [Alerting](#alerting)
- [Logging](#logging)
- [Health Checks](#health-checks)
- [Performance Monitoring](#performance-monitoring)
- [Security Analytics](#security-analytics)
- [Troubleshooting](#troubleshooting)

## Overview

Pingora WAF provides comprehensive observability through:

- **Prometheus Metrics** - Real-time performance and security metrics
- **Structured Logging** - Detailed request and security event logs
- **Health Endpoints** - Service health and readiness checks
- **Grafana Dashboards** - Pre-built visualization templates

### Monitoring Architecture

```
┌─────────────┐
│ Pingora WAF │
│  :6188      │
└──────┬──────┘
       │
       ├─→ Prometheus Metrics (:6190/metrics)
       ├─→ Logs (stdout/journal)
       └─→ Traces (optional)
              │
              ▼
       ┌──────────────┐
       │  Prometheus  │
       │    :9090     │
       └──────┬───────┘
              │
              ▼
       ┌──────────────┐
       │   Grafana    │
       │    :3000     │
       └──────────────┘
              │
              ▼
       ┌──────────────┐
       │ Alertmanager │
       │    :9093     │
       └──────────────┘
```

## Prometheus Metrics

### Metrics Endpoint

The WAF exposes Prometheus metrics at:

```
http://localhost:6190/metrics
```

### Available Metrics

#### Request Metrics

**waf_total_requests**
- **Type**: Counter
- **Description**: Total number of HTTP requests processed
- **Labels**: None

```
# Request rate (per second)
rate(waf_total_requests[5m])

# Total requests today
increase(waf_total_requests[1d])
```

**waf_allowed_requests**
- **Type**: Counter
- **Description**: Number of requests that passed all security checks
- **Labels**: None

```
# Success rate
(waf_allowed_requests / waf_total_requests) * 100

# Allowed request rate
rate(waf_allowed_requests[5m])
```

**waf_blocked_requests**
- **Type**: Counter
- **Description**: Number of requests blocked by the WAF
- **Labels**: `reason` (sql_injection, xss, xss_body, rate_limit, body_too_large, ip_blacklist)

```
# Block rate by reason
rate(waf_blocked_requests[5m])

# Top blocked reasons
topk(5, sum(rate(waf_blocked_requests[5m])) by (reason))

# SQL injection blocks
waf_blocked_requests{reason="sql_injection"}
```

### Prometheus Configuration

Create `prometheus.yml`:

```
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'production'
    replica: '1'

# Alertmanager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets:
            - alertmanager:9093

# Load rules once and periodically evaluate them
rule_files:
  - "alerts/waf_alerts.yml"
  - "alerts/performance_alerts.yml"

# Scrape configurations
scrape_configs:
  - job_name: 'pingora-waf'
    static_configs:
      - targets: ['localhost:6190']
    scrape_interval: 10s
    scrape_timeout: 5s
    metrics_path: '/metrics'

  # Multiple WAF instances
  - job_name: 'pingora-waf-cluster'
    static_configs:
      - targets:
          - 'waf-1:6190'
          - 'waf-2:6190'
          - 'waf-3:6190'
    labels:
      environment: 'production'
```

### Useful Prometheus Queries

#### Traffic Analysis

```
# Requests per second (5-minute average)
rate(waf_total_requests[5m])

# Requests per hour
rate(waf_total_requests[1h]) * 3600

# Daily traffic volume
sum(increase(waf_total_requests[1d]))

# Peak request rate (5-minute window)
max_over_time(rate(waf_total_requests[5m])[1h:])
```

#### Security Metrics

```
# Block rate percentage
(rate(waf_blocked_requests[5m]) / rate(waf_total_requests[5m])) * 100

# Attack types distribution
sum by (reason) (rate(waf_blocked_requests[5m]))

# SQL injection attempts per minute
rate(waf_blocked_requests{reason="sql_injection"}[1m]) * 60

# XSS attacks over time
increase(waf_blocked_requests{reason=~"xss.*"}[1h])

# Rate limiting effectiveness
rate(waf_blocked_requests{reason="rate_limit"}[5m])
```

#### Performance Metrics

```
# Success rate
(rate(waf_allowed_requests[5m]) / rate(waf_total_requests[5m])) * 100

# Error rate
1 - (rate(waf_allowed_requests[5m]) / rate(waf_total_requests[5m]))

# Capacity prediction (requests per day)
rate(waf_total_requests[5m]) * 86400
```

#### Comparative Analysis

```
# Compare block rates across instances
sum by (instance) (rate(waf_blocked_requests[5m]))

# Week-over-week comparison
rate(waf_total_requests[5m]) / rate(waf_total_requests[5m] offset 7d)

# Attack trend (24-hour comparison)
increase(waf_blocked_requests[1h]) - increase(waf_blocked_requests[1h] offset 24h)
```

## Grafana Dashboards

### Installing Grafana

```
# Docker
docker run -d \
  --name=grafana \
  -p 3000:3000 \
  grafana/grafana:latest

# Ubuntu/Debian
sudo apt-get install -y software-properties-common
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install grafana

sudo systemctl enable grafana-server
sudo systemctl start grafana-server
```

Access Grafana at `http://localhost:3000` (default: admin/admin)

### Add Prometheus Data Source

1. **Navigate to**: Configuration → Data Sources
2. **Click**: Add data source
3. **Select**: Prometheus
4. **Configure**:
   - Name: `Prometheus`
   - URL: `http://localhost:9090`
   - Access: `Server (default)`
5. **Click**: Save & Test

### Dashboard: WAF Overview

Create a new dashboard with these panels:

#### Panel 1: Request Rate

```
{
  "title": "Request Rate (req/sec)",
  "type": "graph",
  "targets": [
    {
      "expr": "rate(waf_total_requests[5m])",
      "legendFormat": "Total Requests"
    },
    {
      "expr": "rate(waf_allowed_requests[5m])",
      "legendFormat": "Allowed"
    },
    {
      "expr": "rate(waf_blocked_requests[5m])",
      "legendFormat": "Blocked"
    }
  ]
}
```

**Query**:
```
rate(waf_total_requests[5m])
rate(waf_allowed_requests[5m])
sum(rate(waf_blocked_requests[5m])) by (reason)
```

#### Panel 2: Success Rate Gauge

```
{
  "title": "Success Rate",
  "type": "gauge",
  "targets": [
    {
      "expr": "(waf_allowed_requests / waf_total_requests) * 100"
    }
  ],
  "options": {
    "min": 0,
    "max": 100,
    "thresholds": {
      "steps": [
        { "value": 0, "color": "red" },
        { "value": 80, "color": "yellow" },
        { "value": 95, "color": "green" }
      ]
    }
  }
}
```

#### Panel 3: Attack Types (Pie Chart)

```
{
  "title": "Blocked Requests by Type",
  "type": "piechart",
  "targets": [
    {
      "expr": "sum by (reason) (waf_blocked_requests)",
      "legendFormat": "{{reason}}"
    }
  ]
}
```

#### Panel 4: Traffic Volume (Bar Graph)

```
# Hourly traffic
sum(increase(waf_total_requests[1h]))
```

#### Panel 5: Real-time Stats (Stat Panel)

```
# Total requests (24h)
sum(increase(waf_total_requests[24h]))

# Blocked today
sum(increase(waf_blocked_requests[24h]))

# Current req/sec
rate(waf_total_requests[1m])
```

### Complete Dashboard JSON

Save as `grafana-waf-dashboard.json`:

```
{
  "dashboard": {
    "title": "Pingora WAF Security Dashboard",
    "tags": ["waf", "security"],
    "timezone": "browser",
    "schemaVersion": 16,
    "version": 1,
    "refresh": "10s",

    "panels": [
      {
        "id": 1,
        "title": "Request Rate",
        "type": "graph",
        "gridPos": { "h": 8, "w": 12, "x": 0, "y": 0 },
        "targets": [
          {
            "expr": "rate(waf_total_requests[5m])",
            "legendFormat": "Total"
          },
          {
            "expr": "rate(waf_allowed_requests[5m])",
            "legendFormat": "Allowed"
          },
          {
            "expr": "sum(rate(waf_blocked_requests[5m]))",
            "legendFormat": "Blocked"
          }
        ],
        "yaxes": [
          { "format": "reqps", "label": "Requests/sec" }
        ]
      },

      {
        "id": 2,
        "title": "Success Rate",
        "type": "gauge",
        "gridPos": { "h": 8, "w": 12, "x": 12, "y": 0 },
        "targets": [
          {
            "expr": "(waf_allowed_requests / waf_total_requests) * 100"
          }
        ],
        "options": {
          "showThresholdLabels": true,
          "showThresholdMarkers": true
        },
        "fieldConfig": {
          "defaults": {
            "min": 0,
            "max": 100,
            "thresholds": {
              "steps": [
                { "value": 0, "color": "red" },
                { "value": 80, "color": "yellow" },
                { "value": 95, "color": "green" }
              ]
            },
            "unit": "percent"
          }
        }
      },

      {
        "id": 3,
        "title": "Attack Types",
        "type": "piechart",
        "gridPos": { "h": 8, "w": 12, "x": 0, "y": 8 },
        "targets": [
          {
            "expr": "sum by (reason) (waf_blocked_requests)",
            "legendFormat": "{{reason}}"
          }
        ]
      },

      {
        "id": 4,
        "title": "Blocked Requests Over Time",
        "type": "graph",
        "gridPos": { "h": 8, "w": 12, "x": 12, "y": 8 },
        "targets": [
          {
            "expr": "sum by (reason) (rate(waf_blocked_requests[5m]))",
            "legendFormat": "{{reason}}"
          }
        ]
      },

      {
        "id": 5,
        "title": "24h Statistics",
        "type": "stat",
        "gridPos": { "h": 4, "w": 24, "x": 0, "y": 16 },
        "targets": [
          {
            "expr": "sum(increase(waf_total_requests[24h]))",
            "legendFormat": "Total Requests"
          },
          {
            "expr": "sum(increase(waf_blocked_requests[24h]))",
            "legendFormat": "Blocked"
          },
          {
            "expr": "rate(waf_total_requests[1m])",
            "legendFormat": "Current Rate"
          }
        ],
        "options": {
          "orientation": "horizontal",
          "textMode": "value_and_name"
        }
      }
    ]
  }
}
```

Import: Grafana UI → Dashboards → Import → Paste JSON

## Alerting

### Prometheus Alert Rules

Create `alerts/waf_alerts.yml`:

```
groups:
  - name: waf_critical
    interval: 30s
    rules:
      # Service Down
      - alert: WAFServiceDown
        expr: up{job="pingora-waf"} == 0
        for: 1m
        labels:
          severity: critical
          component: waf
        annotations:
          summary: "WAF service is down"
          description: "Pingora WAF instance {{ $labels.instance }} has been down for more than 1 minute"
          runbook_url: "https://docs.example.com/runbooks/waf-down"

      # High Block Rate
      - alert: HighWAFBlockRate
        expr: |
          (
            rate(waf_blocked_requests[5m])
            /
            rate(waf_total_requests[5m])
          ) > 0.5
        for: 2m
        labels:
          severity: warning
          component: waf
        annotations:
          summary: "High WAF block rate detected"
          description: "More than 50% of requests are being blocked (current: {{ $value | humanizePercentage }})"

      # SQL Injection Attack Spike
      - alert: SQLInjectionAttackSpike
        expr: rate(waf_blocked_requests{reason="sql_injection"}[1m]) > 10
        for: 1m
        labels:
          severity: critical
          component: security
          attack_type: sql_injection
        annotations:
          summary: "SQL injection attack spike detected"
          description: "High rate of SQL injection attempts: {{ $value | printf \"%.2f\" }}/sec on {{ $labels.instance }}"
          dashboard_url: "https://grafana.example.com/d/waf/security"

      # XSS Attack Spike
      - alert: XSSAttackSpike
        expr: rate(waf_blocked_requests{reason=~"xss.*"}[1m]) > 10
        for: 1m
        labels:
          severity: critical
          component: security
          attack_type: xss
        annotations:
          summary: "XSS attack spike detected"
          description: "High rate of XSS attempts: {{ $value | printf \"%.2f\" }}/sec"

      # DDoS Indication
      - alert: PossibleDDoSAttack
        expr: rate(waf_total_requests[1m]) > 50000
        for: 2m
        labels:
          severity: critical
          component: security
          attack_type: ddos
        annotations:
          summary: "Possible DDoS attack detected"
          description: "Extremely high request rate: {{ $value | printf \"%.0f\" }} req/sec"

  - name: waf_warnings
    interval: 1m
    rules:
      # Rate Limiting Active
      - alert: ManyClientsRateLimited
        expr: rate(waf_blocked_requests{reason="rate_limit"}[5m]) > 100
        for: 2m
        labels:
          severity: warning
          component: waf
        annotations:
          summary: "Many clients hitting rate limits"
          description: "{{ $value | printf \"%.0f\" }} clients/sec are being rate limited"

      # Large Body Attacks
      - alert: LargeBodyAttacks
        expr: rate(waf_blocked_requests{reason="body_too_large"}[5m]) > 5
        for: 2m
        labels:
          severity: warning
          component: waf
        annotations:
          summary: "Multiple large body attempts"
          description: "Clients attempting to send oversized requests: {{ $value | printf \"%.2f\" }}/sec"

      # Low Success Rate
      - alert: LowSuccessRate
        expr: |
          (
            rate(waf_allowed_requests[5m])
            /
            rate(waf_total_requests[5m])
          ) < 0.5
        for: 5m
        labels:
          severity: warning
          component: waf
        annotations:
          summary: "Low success rate"
          description: "Success rate is {{ $value | humanizePercentage }}"

  - name: waf_performance
    interval: 1m
    rules:
      # High Traffic
      - alert: HighTrafficVolume
        expr: rate(waf_total_requests[5m]) > 10000
        for: 5m
        labels:
          severity: info
          component: performance
        annotations:
          summary: "High traffic volume"
          description: "Request rate: {{ $value | printf \"%.0f\" }} req/sec"

      # Capacity Warning
      - alert: ApproachingCapacity
        expr: rate(waf_total_requests[5m]) > 12000
        for: 2m
        labels:
          severity: warning
          component: capacity
        annotations:
          summary: "Approaching capacity limits"
          description: "Current load: {{ $value | printf \"%.0f\" }} req/sec (80% of tested capacity)"
```

### Alertmanager Configuration

Create `alertmanager.yml`:

```
global:
  resolve_timeout: 5m
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: 'alerts@example.com'
  smtp_auth_username: 'alerts@example.com'
  smtp_auth_password: 'your-password'

# Notification templates
templates:
  - '/etc/alertmanager/templates/*.tmpl'

# Route tree
route:
  receiver: 'default'
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h

  routes:
    # Critical alerts - immediate notification
    - match:
        severity: critical
      receiver: 'pagerduty'
      continue: true

    - match:
        severity: critical
      receiver: 'slack-critical'

    # Security alerts - special handling
    - match:
        component: security
      receiver: 'security-team'
      group_wait: 5s

    # Warnings - less urgent
    - match:
        severity: warning
      receiver: 'slack-warnings'
      repeat_interval: 4h

# Notification receivers
receivers:
  - name: 'default'
    email_configs:
      - to: 'ops@example.com'

  - name: 'slack-critical'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
        channel: '#alerts-critical'
        title: '🚨 Critical Alert'
        text: |
          {{ range .Alerts }}
          *Alert:* {{ .Annotations.summary }}
          *Description:* {{ .Annotations.description }}
          *Severity:* {{ .Labels.severity }}
          *Instance:* {{ .Labels.instance }}
          {{ end }}

  - name: 'slack-warnings'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
        channel: '#alerts-warnings'
        title: '⚠️ Warning'

  - name: 'security-team'
    email_configs:
      - to: 'security@example.com'
        headers:
          Subject: 'Security Alert: {{ .GroupLabels.attack_type }}'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
        channel: '#security-alerts'

  - name: 'pagerduty'
    pagerduty_configs:
      - service_key: 'YOUR_PAGERDUTY_KEY'
        description: '{{ .Annotations.summary }}'

# Inhibition rules (suppress alerts)
inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'instance']
```

## Logging

### Log Configuration

Pingora WAF uses structured logging via the `log` and `env_logger` crates.

**Configure log level**:

```
# Info level (default)
RUST_LOG=info ./target/release/pingora-waf

# Debug level (verbose)
RUST_LOG=debug ./target/release/pingora-waf

# Specific module
RUST_LOG=pingora_waf::proxy=debug ./target/release/pingora-waf

# Multiple modules
RUST_LOG=pingora_waf=debug,pingora=info ./target/release/pingora-waf
```

### Log Formats

**Request Logs** (INFO level):
```
[2025-10-08T08:00:00Z INFO  pingora_waf::proxy] Request completed - IP: 192.168.1.100, Method: GET, URI: /api/users, Status: 200
```

**Security Violation Logs** (WARN level):
```
[2025-10-08T08:00:00Z WARN  pingora_waf::proxy] Security violation - IP: 203.0.113.42, Type: SQL_INJECTION, Level: Critical, Blocked: true
```

**Error Logs** (ERROR level):
```
[2025-10-08T08:00:00Z ERROR pingora_proxy] Fail to proxy: Upstream ConnectRefused
```

### Centralized Logging

#### Using Journald (Systemd)

```
# View logs
journalctl -u pingora-waf -f

# Filter by priority
journalctl -u pingora-waf -p err

# Last 100 lines
journalctl -u pingora-waf -n 100

# Export to file
journalctl -u pingora-waf --since "1 hour ago" > waf.log
```

#### Using Fluentd

Create `fluent.conf`:

```
<source>
  @type tail
  path /var/log/pingora-waf/*.log
  pos_file /var/log/td-agent/pingora-waf.pos
  tag waf.access
  <parse>
    @type regexp
    expression /^$$(?<time>[^$$]*)$$ (?<level>\w+)\s+(?<message>.*)$/
    time_format %Y-%m-%dT%H:%M:%SZ
  </parse>
</source>

<filter waf.access>
  @type record_transformer
  <record>
    hostname ${hostname}
    service pingora-waf
  </record>
</filter>

<match waf.**>
  @type elasticsearch
  host elasticsearch
  port 9200
  logstash_format true
  logstash_prefix waf
</match>
```

#### Using Loki

**Promtail configuration** (`promtail.yml`):

```
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: waf-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: pingora-waf
          __path__: /var/log/pingora-waf/*.log
    pipeline_stages:
      - regex:
          expression: '^$$(?P<timestamp>[^$$]*)$$ (?P<level>\w+)\s+(?P<module>[^ ]+) (?P<message>.*)$'
      - labels:
          level:
          module:
```

### Log Analysis Queries

```
# Count errors in last hour
journalctl -u pingora-waf --since "1 hour ago" | grep ERROR | wc -l

# Top IPs being blocked
journalctl -u pingora-waf | grep "Security violation" | \
  grep -oP 'IP: \K[0-9.]+' | sort | uniq -c | sort -rn | head -10

# SQL injection attempts
journalctl -u pingora-waf | grep "SQL_INJECTION" | wc -l

# Requests per minute (last 5 minutes)
journalctl -u pingora-waf --since "5 minutes ago" | \
  grep "Request completed" | wc -l
```

## Health Checks

### Metrics Endpoint Health

```
# Check if WAF is responding
curl -f http://localhost:6190/metrics > /dev/null 2>&1 && echo "Healthy" || echo "Unhealthy"

# Kubernetes liveness probe
livenessProbe:
  httpGet:
    path: /metrics
    port: 6190
  initialDelaySeconds: 10
  periodSeconds: 10

# Kubernetes readiness probe
readinessProbe:
  httpGet:
    path: /metrics
    port: 6190
  initialDelaySeconds: 5
  periodSeconds: 5
```

### Custom Health Check Script

Create `health-check.sh`:

```
#!/bin/bash

# Check if WAF is running
if ! pgrep -f pingora-waf > /dev/null; then
    echo "ERROR: WAF process not running"
    exit 1
fi

# Check metrics endpoint
if ! curl -sf http://localhost:6190/metrics > /dev/null; then
    echo "ERROR: Metrics endpoint unreachable"
    exit 1
fi

# Check if accepting requests
if ! curl -sf -m 5 http://localhost:6188/health > /dev/null 2>&1; then
    echo "WARNING: Proxy endpoint slow or unresponsive"
fi

# Check metrics values
TOTAL=$(curl -s http://localhost:6190/metrics | grep "^waf_total_requests " | awk '{print $2}')
if [ -z "$TOTAL" ]; then
    echo "ERROR: No metrics data"
    exit 1
fi

echo "OK: WAF healthy (Total requests: $TOTAL)"
exit 0
```

Make executable and use:

```
chmod +x health-check.sh
./health-check.sh
```

## Performance Monitoring

### Key Performance Indicators

Monitor these KPIs:

1. **Throughput**: `rate(waf_total_requests[5m])`
2. **Success Rate**: `(waf_allowed_requests / waf_total_requests) * 100`
3. **Block Rate**: `(waf_blocked_requests / waf_total_requests) * 100`
4. **Attack Types**: `sum by (reason) (waf_blocked_requests)`

### Performance Dashboards

Create queries for:

```
# Throughput trend (24h)
rate(waf_total_requests[5m])

# Capacity utilization (vs 15K baseline)
(rate(waf_total_requests[5m]) / 15000) * 100

# Performance degradation alert
rate(waf_total_requests[5m]) < rate(waf_total_requests[5m] offset 1h) * 0.5
```

## Security Analytics

### Attack Pattern Analysis

```
# Hourly attack summary
sum by (reason) (increase(waf_blocked_requests[1h]))

# Attack time series
increase(waf_blocked_requests[5m])

# Top attack types (24h)
topk(5, sum by (reason) (increase(waf_blocked_requests[24h])))
```

### Threat Intelligence

Create dashboards showing:

1. **Attack trends** over time
2. **Geographic distribution** (if GeoIP enabled)
3. **Attack vector** breakdown
4. **Time-of-day** patterns
5. **Anomaly detection**

## Troubleshooting

### Metrics Not Updating

```
# Check if WAF is processing requests
curl http://localhost:6188/api/test

# Verify metrics endpoint
curl http://localhost:6190/metrics | grep waf_total_requests

# Check Prometheus targets
curl http://localhost:9090/api/v1/targets
```

### High Memory Usage

```
# Check memory
ps aux | grep pingora-waf

# Monitor over time
watch -n 1 'ps aux | grep pingora-waf | awk "{print \$6/1024\" MB\"}"'
```

### Missing Metrics in Grafana

1. Check Prometheus data source connection
2. Verify time range selection
3. Check if metrics exist: `curl http://localhost:6190/metrics`
4. Restart Grafana: `systemctl restart grafana-server`

## Best Practices

### Monitoring Checklist

- ✅ Prometheus scraping WAF every 10-15 seconds
- ✅ Grafana dashboards created and accessible
- ✅ Critical alerts configured (service down, attack spikes)
- ✅ Log rotation configured
- ✅ Metrics retention policy set (default 15 days)
- ✅ Regular backup of dashboards and alert rules
- ✅ Team access to monitoring tools
- ✅ Runbooks for common alerts

### Alert Tuning

Start with conservative thresholds and adjust based on:

- False positive rate
- Mean time to detect (MTTD)
- Mean time to respond (MTTR)
- Business impact

### Retention Policies

```
# Prometheus retention
storage:
  tsdb:
    retention.time: 15d
    retention.size: 50GB
```

---

**Next Steps:**
- Review [Troubleshooting](troubleshooting.md) guide
- Optimize [Performance](performance.md)

**Need Help?** [GitHub Discussions](https://github.com/aarambhdevhub/pingora-waf/discussions)
