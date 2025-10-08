# Deployment Guide

This guide covers deploying Pingora WAF in production environments, from single-server setups to large-scale Kubernetes deployments.

## 📋 Table of Contents

- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Deployment Methods](#deployment-methods)
  - [Systemd Service](#systemd-service)
  - [Docker](#docker)
  - [Docker Compose](#docker-compose)
  - [Kubernetes](#kubernetes)
  - [Cloud Platforms](#cloud-platforms)
- [Production Configuration](#production-configuration)
- [High Availability](#high-availability)
- [Security Hardening](#security-hardening)
- [Monitoring Setup](#monitoring-setup)
- [Backup and Recovery](#backup-and-recovery)
- [Scaling Guidelines](#scaling-guidelines)

## Pre-Deployment Checklist

Before deploying to production, ensure:

### ✅ Infrastructure

- [ ] Backend application is accessible from WAF server
- [ ] Network connectivity between WAF and backend verified
- [ ] Firewall rules configured (ports 6188, 6190)
- [ ] SSL/TLS certificates obtained (if using HTTPS)
- [ ] DNS records configured
- [ ] Load balancer configured (if multi-instance)

### ✅ Configuration

- [ ] `config/waf_rules.yaml` reviewed and customized
- [ ] Backend address configured in `src/main.rs`
- [ ] Rate limits adjusted for expected traffic
- [ ] IP whitelist/blacklist configured
- [ ] Body size limits set appropriately
- [ ] All security rules tested

### ✅ Testing

- [ ] Security tests pass: `cargo run --example security_test`
- [ ] Load testing completed: `wrk -t10 -c100 -d30s http://localhost:6188/api/test`
- [ ] False positive rate acceptable (< 0.1%)
- [ ] Performance targets met (15K+ req/sec)
- [ ] Integration with backend verified

### ✅ Monitoring

- [ ] Prometheus configured and tested
- [ ] Grafana dashboards imported
- [ ] Alerting rules configured
- [ ] Log aggregation setup (ELK, Loki, etc.)
- [ ] Health check endpoints verified

### ✅ Documentation

- [ ] Runbook created for on-call team
- [ ] Configuration documented
- [ ] Rollback procedure documented
- [ ] Contact information updated

## Deployment Methods

### Systemd Service

#### Recommended for: Single server or small deployments

#### 1. Prepare Installation Directory

```
# Create installation directory
sudo mkdir -p /opt/pingora-waf
sudo mkdir -p /var/log/pingora-waf
sudo mkdir -p /etc/pingora-waf

# Copy files
sudo cp -r target/release/pingora-waf /opt/pingora-waf/
sudo cp -r config /etc/pingora-waf/

# Create user for WAF
sudo useradd -r -s /bin/false -d /opt/pingora-waf pingora-waf
sudo chown -R pingora-waf:pingora-waf /opt/pingora-waf
sudo chown -R pingora-waf:pingora-waf /var/log/pingora-waf
sudo chown -R pingora-waf:pingora-waf /etc/pingora-waf
```

#### 2. Create Systemd Service File

Create `/etc/systemd/system/pingora-waf.service`:

```
[Unit]
Description=Pingora WAF - Web Application Firewall
Documentation=https://github.com/aarambhdevhub/pingora-waf
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
Type=simple
User=pingora-waf
Group=pingora-waf
WorkingDirectory=/opt/pingora-waf

# Environment variables
Environment="RUST_LOG=info"
Environment="RUST_BACKTRACE=1"
Environment="WAF_CONFIG=/etc/pingora-waf/config/waf_rules.yaml"

# Start command
ExecStart=/opt/pingora-waf/pingora-waf
ExecReload=/bin/kill -HUP $MAINPID

# Restart policy
Restart=always
RestartSec=5s
StartLimitInterval=0

# Output
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pingora-waf

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/pingora-waf
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
SecureBits=keep-caps

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096
MemoryLimit=1G
CPUQuota=200%

# Watchdog
WatchdogSec=30s

[Install]
WantedBy=multi-user.target
```

#### 3. Enable and Start Service

```
# Reload systemd
sudo systemctl daemon-reload

# Enable on boot
sudo systemctl enable pingora-waf

# Start service
sudo systemctl start pingora-waf

# Check status
sudo systemctl status pingora-waf

# View logs
sudo journalctl -u pingora-waf -f
```

#### 4. Service Management

```
# Start
sudo systemctl start pingora-waf

# Stop
sudo systemctl stop pingora-waf

# Restart
sudo systemctl restart pingora-waf

# Reload (graceful)
sudo systemctl reload pingora-waf

# View logs (last 100 lines)
sudo journalctl -u pingora-waf -n 100

# View logs (follow)
sudo journalctl -u pingora-waf -f

# View logs (since boot)
sudo journalctl -u pingora-waf -b
```

### Docker

#### Recommended for: Development, testing, and containerized production

#### 1. Dockerfile

Create `Dockerfile`:

```
# Build stage
FROM rust:1.70-slim as builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config ./config
COPY examples ./examples

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create user
RUN useradd -m -u 1000 -s /bin/bash pingora-waf

# Copy binary and config
COPY --from=builder /app/target/release/pingora-waf /usr/local/bin/
COPY --from=builder /app/config /etc/pingora-waf/config

# Set permissions
RUN chown -R pingora-waf:pingora-waf /etc/pingora-waf

# Switch to non-root user
USER pingora-waf

# Expose ports
EXPOSE 6188 6190

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:6190/metrics || exit 1

# Environment
ENV RUST_LOG=info

# Start WAF
CMD ["pingora-waf"]
```

#### 2. Build and Run

```
# Build image
docker build -t pingora-waf:latest .

# Run container
docker run -d \
  --name pingora-waf \
  -p 6188:6188 \
  -p 6190:6190 \
  -v $(pwd)/config:/etc/pingora-waf/config:ro \
  -e RUST_LOG=info \
  --restart unless-stopped \
  pingora-waf:latest

# Check logs
docker logs -f pingora-waf

# Check status
docker ps | grep pingora-waf
```

#### 3. Docker Management

```
# Start
docker start pingora-waf

# Stop
docker stop pingora-waf

# Restart
docker restart pingora-waf

# View logs
docker logs -f pingora-waf

# Execute command in container
docker exec -it pingora-waf bash

# Update container
docker pull pingora-waf:latest
docker stop pingora-waf
docker rm pingora-waf
docker run -d ... # (same run command as above)
```

### Docker Compose

#### Recommended for: Multi-container setups with monitoring stack

#### 1. docker-compose.yml

```
version: '3.8'

services:
  # Pingora WAF
  waf:
    build: .
    image: pingora-waf:latest
    container_name: pingora-waf
    restart: unless-stopped
    ports:
      - "6188:6188"   # Proxy port
      - "6190:6190"   # Metrics port
    environment:
      - RUST_LOG=info
      - RUST_BACKTRACE=1
    volumes:
      - ./config:/etc/pingora-waf/config:ro
      - waf-logs:/var/log/pingora-waf
    networks:
      - waf-network
    depends_on:
      - backend
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:6190/metrics"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 1G
        reservations:
          cpus: '1'
          memory: 512M

  # Backend application (example)
  backend:
    image: your-backend-image:latest
    container_name: backend-app
    restart: unless-stopped
    expose:
      - "8080"
    networks:
      - waf-network
    environment:
      - APP_ENV=production

  # Prometheus
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'
      - '--web.console.libraries=/usr/share/prometheus/console_libraries'
      - '--web.console.templates=/usr/share/prometheus/consoles'
    networks:
      - waf-network

  # Grafana
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}
      - GF_INSTALL_PLUGINS=grafana-piechart-panel
      - GF_SERVER_ROOT_URL=http://localhost:3000
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
      - ./grafana/datasources:/etc/grafana/provisioning/datasources:ro
    networks:
      - waf-network
    depends_on:
      - prometheus

  # Alertmanager (optional)
  alertmanager:
    image: prom/alertmanager:latest
    container_name: alertmanager
    restart: unless-stopped
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro
      - alertmanager-data:/alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
    networks:
      - waf-network

networks:
  waf-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

volumes:
  waf-logs:
  prometheus-data:
  grafana-data:
  alertmanager-data:
```

#### 2. Prometheus Configuration

Create `prometheus.yml`:

```
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'pingora-waf-prod'
    environment: 'production'

# Alertmanager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']

# Load rules
rule_files:
  - '/etc/prometheus/alerts/*.yml'

# Scrape configurations
scrape_configs:
  - job_name: 'pingora-waf'
    static_configs:
      - targets: ['waf:6190']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
```

#### 3. Deploy with Docker Compose

```
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f waf

# Check status
docker-compose ps

# Scale WAF instances
docker-compose up -d --scale waf=3

# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

### Kubernetes

#### Recommended for: Large-scale production deployments

#### 1. Namespace

Create `k8s/namespace.yaml`:

```
apiVersion: v1
kind: Namespace
metadata:
  name: pingora-waf
  labels:
    name: pingora-waf
    environment: production
```

#### 2. ConfigMap

Create `k8s/configmap.yaml`:

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: waf-config
  namespace: pingora-waf
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
      enabled: true
      whitelist:
        - "10.0.0.0/8"
      blacklist: []
    max_body_size: 5242880
```

#### 3. Deployment

Create `k8s/deployment.yaml`:

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pingora-waf
  namespace: pingora-waf
  labels:
    app: pingora-waf
    version: v0.1.0
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: pingora-waf
  template:
    metadata:
      labels:
        app: pingora-waf
        version: v0.1.0
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "6190"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: pingora-waf
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000

      containers:
      - name: waf
        image: aarambhdevhub/pingora-waf:0.1.0
        imagePullPolicy: Always

        ports:
        - name: proxy
          containerPort: 6188
          protocol: TCP
        - name: metrics
          containerPort: 6190
          protocol: TCP

        env:
        - name: RUST_LOG
          value: "info"
        - name: RUST_BACKTRACE
          value: "1"
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace

        resources:
          limits:
            cpu: "1000m"
            memory: "512Mi"
          requests:
            cpu: "500m"
            memory: "256Mi"

        livenessProbe:
          httpGet:
            path: /metrics
            port: 6190
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 3

        readinessProbe:
          httpGet:
            path: /metrics
            port: 6190
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          successThreshold: 1
          failureThreshold: 3

        volumeMounts:
        - name: config
          mountPath: /etc/pingora-waf/config
          readOnly: true
        - name: tmp
          mountPath: /tmp

      volumes:
      - name: config
        configMap:
          name: waf-config
      - name: tmp
        emptyDir: {}

      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - pingora-waf
              topologyKey: kubernetes.io/hostname
```

#### 4. Service

Create `k8s/service.yaml`:

```
apiVersion: v1
kind: Service
metadata:
  name: pingora-waf
  namespace: pingora-waf
  labels:
    app: pingora-waf
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "6190"
spec:
  type: LoadBalancer
  sessionAffinity: ClientIP
  sessionAffinityConfig:
    clientIP:
      timeoutSeconds: 10800
  ports:
  - name: proxy
    port: 80
    targetPort: 6188
    protocol: TCP
  - name: metrics
    port: 6190
    targetPort: 6190
    protocol: TCP
  selector:
    app: pingora-waf

***
apiVersion: v1
kind: Service
metadata:
  name: pingora-waf-headless
  namespace: pingora-waf
  labels:
    app: pingora-waf
spec:
  clusterIP: None
  ports:
  - name: proxy
    port: 6188
    targetPort: 6188
  - name: metrics
    port: 6190
    targetPort: 6190
  selector:
    app: pingora-waf
```

#### 5. ServiceAccount & RBAC

Create `k8s/rbac.yaml`:

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pingora-waf
  namespace: pingora-waf

***
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pingora-waf
  namespace: pingora-waf
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]

***
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pingora-waf
  namespace: pingora-waf
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pingora-waf
subjects:
- kind: ServiceAccount
  name: pingora-waf
  namespace: pingora-waf
```

#### 6. Horizontal Pod Autoscaler

Create `k8s/hpa.yaml`:

```
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: pingora-waf-hpa
  namespace: pingora-waf
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: pingora-waf
  minReplicas: 3
  maxReplicas: 20
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
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 4
        periodSeconds: 15
      selectPolicy: Max
```

#### 7. PodDisruptionBudget

Create `k8s/pdb.yaml`:

```
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: pingora-waf-pdb
  namespace: pingora-waf
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: pingora-waf
```

#### 8. Ingress (Optional)

Create `k8s/ingress.yaml`:

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: pingora-waf-ingress
  namespace: pingora-waf
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - waf.yourdomain.com
    secretName: waf-tls-cert
  rules:
  - host: waf.yourdomain.com
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

#### 9. Deploy to Kubernetes

```
# Apply all manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/hpa.yaml
kubectl apply -f k8s/pdb.yaml
kubectl apply -f k8s/ingress.yaml

# Or apply all at once
kubectl apply -f k8s/

# Check deployment status
kubectl get all -n pingora-waf

# View pods
kubectl get pods -n pingora-waf -w

# Check logs
kubectl logs -f -l app=pingora-waf -n pingora-waf

# Get service endpoint
kubectl get svc pingora-waf -n pingora-waf

# Test the WAF
kubectl port-forward -n pingora-waf svc/pingora-waf 6188:80
curl http://localhost:6188/api/test
```

#### 10. Update Deployment

```
# Update image
kubectl set image deployment/pingora-waf waf=aarambhdevhub/pingora-waf:0.2.0 -n pingora-waf

# Watch rollout
kubectl rollout status deployment/pingora-waf -n pingora-waf

# Rollback if needed
kubectl rollout undo deployment/pingora-waf -n pingora-waf

# Update config
kubectl edit configmap waf-config -n pingora-waf
kubectl rollout restart deployment/pingora-waf -n pingora-waf
```

### Cloud Platforms

#### AWS Elastic Container Service (ECS)

```
# Build and push to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com

docker build -t pingora-waf .
docker tag pingora-waf:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/pingora-waf:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/pingora-waf:latest

# Create ECS task definition and service via AWS Console or CLI
```

#### Google Cloud Run

```
# Build and push to Google Container Registry
gcloud builds submit --tag gcr.io/PROJECT-ID/pingora-waf

# Deploy to Cloud Run
gcloud run deploy pingora-waf \
  --image gcr.io/PROJECT-ID/pingora-waf \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --port 6188 \
  --memory 512Mi \
  --cpu 2
```

#### Azure Container Instances

```
# Create resource group
az group create --name pingora-waf-rg --location eastus

# Deploy container
az container create \
  --resource-group pingora-waf-rg \
  --name pingora-waf \
  --image aarambhdevhub/pingora-waf:latest \
  --dns-name-label pingora-waf \
  --ports 6188 6190
```

## Production Configuration

### Environment-Specific Config

Create `config/waf_rules.production.yaml`:

```
sql_injection:
  enabled: true
  block_mode: true

xss:
  enabled: true
  block_mode: true

rate_limit:
  enabled: true
  max_requests: 10000  # Production traffic
  window_secs: 60

ip_filter:
  enabled: true
  whitelist:
    - "10.0.0.0/8"      # Internal network
    - "172.16.0.0/12"   # Private network
    - "192.168.0.0/16"  # Local network
  blacklist: []         # Populated from threat intelligence

max_body_size: 10485760  # 10MB for production
```

### Backend Configuration

Update `src/main.rs` for production:

```
let upstream_host = std::env::var("BACKEND_HOST")
    .unwrap_or_else(|_| "backend.internal".to_string());
let upstream_port = std::env::var("BACKEND_PORT")
    .unwrap_or_else(|_| "8080".to_string())
    .parse()
    .unwrap_or(8080);

let waf_proxy = WafProxy::new(
    (upstream_host, upstream_port),
    // ... rest of configuration
);
```

## High Availability

### Multi-Instance Setup

```
# Deploy 3+ instances
# Use load balancer (Nginx, HAProxy, or cloud LB)

# Nginx example
upstream pingora_waf_backend {
    least_conn;
    server waf1.internal:6188 max_fails=3 fail_timeout=30s;
    server waf2.internal:6188 max_fails=3 fail_timeout=30s;
    server waf3.internal:6188 max_fails=3 fail_timeout=30s;
    keepalive 64;
}

server {
    listen 80;
    location / {
        proxy_pass http://pingora_waf_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_next_upstream error timeout http_502 http_503;
    }
}
```

### Health Checks

```
# Application health check
curl http://localhost:6190/metrics

# Script for monitoring
#!/bin/bash
if curl -f -s http://localhost:6190/metrics > /dev/null; then
    echo "WAF is healthy"
    exit 0
else
    echo "WAF is unhealthy"
    exit 1
fi
```

## Security Hardening

### OS-Level Security

```
# Firewall (UFW)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 6188/tcp  # WAF proxy
sudo ufw allow 6190/tcp  # Metrics (restrict to monitoring network)
sudo ufw allow 22/tcp    # SSH (restrict to bastion)
sudo ufw enable

# SELinux (RHEL/CentOS)
sudo semanage port -a -t http_port_t -p tcp 6188
sudo semanage port -a -t http_port_t -p tcp 6190

# File permissions
sudo chmod 750 /opt/pingora-waf
sudo chmod 640 /etc/pingora-waf/config/waf_rules.yaml
```

### TLS/SSL Configuration

Use Nginx/HAProxy for TLS termination:

```
server {
    listen 443 ssl http2;
    ssl_certificate /etc/ssl/certs/your-cert.pem;
    ssl_certificate_key /etc/ssl/private/your-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://localhost:6188;
    }
}
```

## Monitoring Setup

See [monitoring.md](monitoring.md) for complete guide.

Quick setup:

```
# Start Prometheus
docker run -d -p 9090:9090 \
  -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus

# Start Grafana
docker run -d -p 3000:3000 grafana/grafana

# Import dashboard from docs/grafana/dashboards/
```

## Backup and Recovery

### Configuration Backup

```
# Backup script
#!/bin/bash
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/var/backups/pingora-waf"

mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/config-$DATE.tar.gz \
  /etc/pingora-waf/config \
  /opt/pingora-waf

# Keep last 30 days
find $BACKUP_DIR -name "config-*.tar.gz" -mtime +30 -delete
```

### Disaster Recovery

```
# 1. Stop WAF
sudo systemctl stop pingora-waf

# 2. Restore from backup
tar -xzf /var/backups/pingora-waf/config-latest.tar.gz -C /

# 3. Restart WAF
sudo systemctl start pingora-waf

# 4. Verify
curl http://localhost:6190/metrics
```

## Scaling Guidelines

### Vertical Scaling

| Traffic | CPU | Memory | Instances |
|---------|-----|--------|-----------|
| < 1K req/s | 1 core | 512MB | 1 |
| 1-5K req/s | 2 cores | 1GB | 1-2 |
| 5-20K req/s | 4 cores | 2GB | 2-3 |
| 20-50K req/s | 8 cores | 4GB | 3-5 |
| 50K+ req/s | Multiple instances with load balancer |

### Horizontal Scaling

```
# Add more instances based on:
# - CPU usage > 70%
# - Memory usage > 80%
# - Request latency > 20ms p99
# - Request rate approaching capacity

# Auto-scaling with Kubernetes HPA
kubectl autoscale deployment pingora-waf \
  --cpu-percent=70 \
  --min=3 \
  --max=20 \
  -n pingora-waf
```

## Troubleshooting Deployment

See [troubleshooting.md](troubleshooting.md) for detailed guide.

Common issues:

```
# Service won't start
sudo journalctl -u pingora-waf -n 50

# Port in use
sudo lsof -i :6188

# Permission denied
sudo chown -R pingora-waf:pingora-waf /opt/pingora-waf

# Config not found
ls -la /etc/pingora-waf/config/
```

## Deployment Checklist

Final checklist before going live:

- [ ] Load testing completed
- [ ] Security testing passed
- [ ] Monitoring configured
- [ ] Alerting setup
- [ ] Backup configured
- [ ] Runbook documented
- [ ] Team trained
- [ ] Rollback plan tested
- [ ] DNS updated
- [ ] SSL certificates valid

## Next Steps

- [Monitoring Guide](monitoring.md) - Set up observability
- [Performance Tuning](performance.md) - Optimize for your workload
- [Security Rules](security-rules.md) - Configure security policies
- [Troubleshooting](troubleshooting.md) - Common issues

---

**Need help with deployment?** [Open an issue](https://github.com/aarambhdevhub/pingora-waf/issues) or [join discussions](https://github.com/aarambhdevhub/pingora-waf/discussions)
