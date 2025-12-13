pub mod context;

use crate::metrics::MetricsCollector;
use crate::waf::*;
use async_trait::async_trait;
use context::ProxyContext;
use log::{error, info, warn};
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;

pub struct WafProxy {
    pub sql_detector: Arc<SqlInjectionDetector>,
    pub xss_detector: Arc<XssDetector>,
    pub path_traversal_detector: Arc<PathTraversalDetector>,
    pub command_injection_detector: Arc<CommandInjectionDetector>,
    pub rate_limiter: Arc<RateLimiter>,
    pub ip_filter: Arc<IpFilter>,
    pub bot_detector: Arc<BotDetector>,
    pub metrics: Arc<MetricsCollector>,
    pub upstream_addr: (String, u16),
    pub max_body_size: usize,
}

impl WafProxy {
    pub fn new(
        upstream_addr: (String, u16),
        sql_detector: Arc<SqlInjectionDetector>,
        xss_detector: Arc<XssDetector>,
        path_traversal_detector: Arc<PathTraversalDetector>,
        command_injection_detector: Arc<CommandInjectionDetector>,
        rate_limiter: Arc<RateLimiter>,
        ip_filter: Arc<IpFilter>,
        bot_detector: Arc<BotDetector>,
        metrics: Arc<MetricsCollector>,
        max_body_size: usize,
    ) -> Self {
        Self {
            sql_detector,
            xss_detector,
            path_traversal_detector,
            command_injection_detector,
            rate_limiter,
            ip_filter,
            bot_detector,
            metrics,
            upstream_addr,
            max_body_size,
        }
    }

    fn get_client_ip(&self, session: &Session) -> String {
        // Try X-Forwarded-For header first
        if let Some(xff) = session.req_header().headers.get("X-Forwarded-For") {
            if let Ok(xff_str) = xff.to_str() {
                if let Some(first_ip) = xff_str.split(',').next() {
                    return first_ip.trim().to_string();
                }
            }
        }

        // Fallback to client address
        session
            .client_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

#[async_trait]
impl ProxyHttp for WafProxy {
    type CTX = ProxyContext;

    fn new_ctx(&self) -> Self::CTX {
        ProxyContext::new(
            self.sql_detector.clone(),
            self.xss_detector.clone(),
            self.rate_limiter.clone(),
            self.ip_filter.clone(),
            self.max_body_size,
        )
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let client_ip = self.get_client_ip(session);

        // IP filtering
        if let Err(violation) = ctx.ip_filter.check_ip(&client_ip) {
            error!("IP filter violation: {:?}", violation);
            ctx.violations.push(violation.clone());
            self.metrics.increment_blocked_requests("ip_blacklist");

            if violation.blocked {
                let _ = session.respond_error(403).await;
                return Ok(true);
            }
        }

        // Rate limiting
        if let Err(violation) = ctx.rate_limiter.check_rate_limit(&client_ip) {
            warn!("Rate limit violation: {:?}", violation);
            ctx.violations.push(violation.clone());
            self.metrics.increment_blocked_requests("rate_limit");

            if violation.blocked {
                let _ = session.respond_error(429).await;
                return Ok(true);
            }
        }

        // Bot detection
        if let Err(violation) = self.bot_detector.check(session.req_header(), None) {
            warn!("Bot detection violation: {:?}", violation);
            ctx.violations.push(violation.clone());
            let reason = if violation.threat_type == "BAD_BOT" {
                "bad_bot"
            } else {
                "suspicious_bot"
            };
            self.metrics.increment_blocked_requests(reason);

            if violation.blocked {
                let _ = session.respond_error(403).await;
                return Ok(true);
            }
        }

        // Check if request has a body
        let has_body = session
            .req_header()
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .map(|len| len > 0)
            .unwrap_or(false);

        // Only do full security check for requests WITHOUT body
        // Requests WITH body will be checked in request_body_filter
        if !has_body {
            // SQL injection detection (header and URI only)
            if let Err(violation) = ctx.sql_detector.check(session.req_header(), None) {
                error!("SQL injection detected: {:?}", violation);
                ctx.violations.push(violation.clone());
                self.metrics.increment_blocked_requests("sql_injection");

                if violation.blocked {
                    let _ = session.respond_error(403).await;
                    return Ok(true);
                }
            }

            // XSS detection
            if let Err(violation) = ctx.xss_detector.check(session.req_header(), None) {
                error!("XSS attack detected: {:?}", violation);
                ctx.violations.push(violation.clone());
                self.metrics.increment_blocked_requests("xss");

                if violation.blocked {
                    let _ = session.respond_error(403).await;
                    return Ok(true);
                }
            }

            // Path traversal detection
            if let Err(violation) = self
                .path_traversal_detector
                .check(session.req_header(), None)
            {
                error!("Path traversal detected: {:?}", violation);
                ctx.violations.push(violation.clone());
                self.metrics.increment_blocked_requests("path_traversal");

                if violation.blocked {
                    let _ = session.respond_error(403).await;
                    return Ok(true);
                }
            }

            // Command injection detection
            if let Err(violation) = self
                .command_injection_detector
                .check(session.req_header(), None)
            {
                error!("Command injection detected: {:?}", violation);
                ctx.violations.push(violation.clone());
                self.metrics.increment_blocked_requests("command_injection");

                if violation.blocked {
                    let _ = session.respond_error(403).await;
                    return Ok(true);
                }
            }
        }

        self.metrics.increment_allowed_requests();
        Ok(false)
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Accumulate body chunks
        if let Some(chunk) = body {
            if let Err(e) = ctx.body_inspector.append_chunk(chunk) {
                error!("Body size limit exceeded: {}", e);
                // Use Error::explain for dynamic error messages
                return Err(Error::explain(
                    ErrorType::Custom("BodySizeLimitExceeded"),
                    format!("Body size limit exceeded: {}", e),
                ));
            }
        }

        // CRITICAL: Only inspect when we have the COMPLETE body
        // This ensures the request doesn't reach the backend before inspection
        if end_of_stream {
            let full_body = ctx.body_inspector.get_body();

            if !full_body.is_empty() {
                // SQL injection check on complete body
                if let Err(violation) = ctx
                    .sql_detector
                    .check(session.req_header(), Some(&full_body))
                {
                    error!("SQL injection in body: {:?}", violation);
                    ctx.violations.push(violation.clone());
                    self.metrics
                        .increment_blocked_requests("sql_injection_body");

                    if violation.blocked {
                        // Return error to STOP the request from reaching upstream
                        let _ = session.respond_error(403).await;
                        return Err(pingora::Error::new_str(
                            "SQL injection detected in request body",
                        ));
                    }
                }

                // XSS check on complete body
                if let Err(violation) = ctx
                    .xss_detector
                    .check(session.req_header(), Some(&full_body))
                {
                    error!("XSS in body: {:?}", violation);
                    ctx.violations.push(violation.clone());
                    self.metrics.increment_blocked_requests("xss_body");

                    if violation.blocked {
                        // Return error to STOP the request from reaching upstream
                        let _ = session.respond_error(403).await;
                        return Err(pingora::Error::new_str("XSS detected in request body"));
                    }
                }

                // Path traversal check on complete body
                if let Err(violation) = self
                    .path_traversal_detector
                    .check(session.req_header(), Some(&full_body))
                {
                    error!("Path traversal in body: {:?}", violation);
                    ctx.violations.push(violation.clone());
                    self.metrics
                        .increment_blocked_requests("path_traversal_body");

                    if violation.blocked {
                        return Err(pingora::Error::new_str(
                            "Path traversal detected in request body",
                        ));
                    }
                }

                // Command injection check on complete body
                if let Err(violation) = self
                    .command_injection_detector
                    .check(session.req_header(), Some(&full_body))
                {
                    error!("Command injection in body: {:?}", violation);
                    ctx.violations.push(violation.clone());
                    self.metrics
                        .increment_blocked_requests("command_injection_body");

                    if violation.blocked {
                        return Err(pingora::Error::new_str(
                            "Command injection detected in request body",
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // CRITICAL SAFETY CHECK: Block if any violations were detected
        for violation in &ctx.violations {
            if violation.blocked {
                error!(
                    "Blocking upstream connection due to security violation: {:?}",
                    violation
                );
                return Err(pingora::Error::new_str(
                    "Request blocked by WAF security policy",
                ));
            }
        }

        let peer = Box::new(HttpPeer::new(
            (self.upstream_addr.0.as_str(), self.upstream_addr.1),
            false,
            "".to_string(),
        ));
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        _upstream_request: &mut pingora::http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Final safety check before sending to upstream
        if ctx.violations.iter().any(|v| v.blocked) {
            return Err(pingora::Error::new_str(
                "Request blocked by WAF - security violation detected",
            ));
        }

        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let response_code = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());

        let client_ip = self.get_client_ip(session);
        let method = session.req_header().method.as_str();
        let uri = session.req_header().uri.to_string();

        if let Some(error) = e {
            error!(
                "Request failed - IP: {}, Method: {}, URI: {}, Error: {:?}",
                client_ip, method, uri, error
            );
        } else {
            info!(
                "Request completed - IP: {}, Method: {}, URI: {}, Status: {}",
                client_ip, method, uri, response_code
            );
        }

        // Log violations
        for violation in &ctx.violations {
            warn!(
                "Security violation - IP: {}, Type: {}, Level: {:?}, Blocked: {}, Description: {}",
                client_ip,
                violation.threat_type,
                violation.threat_level,
                violation.blocked,
                violation.description
            );
        }

        // Clear body buffer for next request
        ctx.body_inspector.clear();
    }
}
