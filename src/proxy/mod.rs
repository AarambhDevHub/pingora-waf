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
    pub rate_limiter: Arc<RateLimiter>,
    pub ip_filter: Arc<IpFilter>,
    pub metrics: Arc<MetricsCollector>,
    pub upstream_addr: (String, u16),
    pub max_body_size: usize,
}

impl WafProxy {
    pub fn new(
        upstream_addr: (String, u16),
        sql_detector: Arc<SqlInjectionDetector>,
        xss_detector: Arc<XssDetector>,
        rate_limiter: Arc<RateLimiter>,
        ip_filter: Arc<IpFilter>,
        metrics: Arc<MetricsCollector>,
        max_body_size: usize,
    ) -> Self {
        Self {
            sql_detector,
            xss_detector,
            rate_limiter,
            ip_filter,
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

        // Check Content-Length before body arrives
        if let Some(content_length) = session.req_header().headers.get("content-length") {
            if let Ok(length_str) = content_length.to_str() {
                if let Ok(length) = length_str.parse::<usize>() {
                    if length > self.max_body_size {
                        error!(
                            "Request body size {} exceeds limit {} - IP: {}",
                            length, self.max_body_size, client_ip
                        );
                        self.metrics.increment_blocked_requests("body_too_large");
                        let _ = session.respond_error(413).await;
                        return Ok(true); // Block request
                    }
                }
            }
        }

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

        // SQL injection detection (header and URI only at this stage)
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
        if let Some(chunk) = body {
            // Check size limit
            match ctx.body_inspector.append_chunk(chunk) {
                Ok(_) => {}
                Err(e) => {
                    error!("Body size limit exceeded: {:?}", e);
                    self.metrics.increment_blocked_requests("body_too_large");
                    // Don't propagate the error, just respond with 413
                    let _ = session.respond_error(413).await;
                    return Ok(()); // Return Ok to prevent 500 error
                }
            }

            // Only inspect when we have the full body
            if end_of_stream {
                let full_body = ctx.body_inspector.get_body();

                // Skip empty bodies
                if full_body.is_empty() {
                    return Ok(());
                }

                // Create a dummy request for body-only checks
                // Use the actual URI from the session if possible
                let uri_bytes = session.req_header().uri.to_string();
                let dummy_req = RequestHeader::build(
                    session.req_header().method.as_str(),
                    uri_bytes.as_bytes(),
                    None,
                )
                .unwrap_or_else(|_| RequestHeader::build("POST", b"/", None).unwrap());

                // SQL injection check on body
                if let Err(violation) = ctx.sql_detector.check(&dummy_req, Some(&full_body)) {
                    error!("SQL injection in body: {:?}", violation);
                    ctx.violations.push(violation.clone());
                    self.metrics
                        .increment_blocked_requests("sql_injection_body");

                    if violation.blocked {
                        let _ = session.respond_error(403).await;
                        return Ok(()); // Return Ok, error already sent
                    }
                }

                // XSS check on body
                if let Err(violation) = ctx.xss_detector.check(&dummy_req, Some(&full_body)) {
                    error!("XSS in body: {:?}", violation);
                    ctx.violations.push(violation.clone());
                    self.metrics.increment_blocked_requests("xss_body");

                    if violation.blocked {
                        let _ = session.respond_error(403).await;
                        return Ok(()); // Return Ok, error already sent
                    }
                }
            }
        }

        Ok(())
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = Box::new(HttpPeer::new(
            (self.upstream_addr.0.as_str(), self.upstream_addr.1),
            false,
            "".to_string(),
        ));
        Ok(peer)
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
                "Security violation - IP: {}, Type: {}, Level: {:?}, Blocked: {}",
                client_ip, violation.threat_type, violation.threat_level, violation.blocked
            );
        }

        ctx.body_inspector.clear();
    }
}
