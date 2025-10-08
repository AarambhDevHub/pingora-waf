use crate::waf::*;
use std::sync::Arc;

pub struct ProxyContext {
    pub sql_detector: Arc<SqlInjectionDetector>,
    pub xss_detector: Arc<XssDetector>,
    pub rate_limiter: Arc<RateLimiter>,
    pub ip_filter: Arc<IpFilter>,
    pub body_inspector: BodyInspector,
    pub violations: Vec<SecurityViolation>,
}

impl ProxyContext {
    pub fn new(
        sql_detector: Arc<SqlInjectionDetector>,
        xss_detector: Arc<XssDetector>,
        rate_limiter: Arc<RateLimiter>,
        ip_filter: Arc<IpFilter>,
        max_body_size: usize,
    ) -> Self {
        Self {
            sql_detector,
            xss_detector,
            rate_limiter,
            ip_filter,
            body_inspector: BodyInspector::new(max_body_size, true),
            violations: Vec::new(),
        }
    }
}
