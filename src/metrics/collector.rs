use once_cell::sync::Lazy;
use prometheus::{IntCounter, IntCounterVec, Opts, Registry};
use std::sync::Arc;

// Use global registry for Pingora's built-in Prometheus service
static TOTAL_REQUESTS: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("waf_total_requests", "Total HTTP requests").expect("metric creation failed")
});

static ALLOWED_REQUESTS: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("waf_allowed_requests", "Allowed HTTP requests")
        .expect("metric creation failed")
});

static BLOCKED_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        Opts::new("waf_blocked_requests", "Blocked HTTP requests"),
        &["reason"],
    )
    .expect("metric creation failed")
});

pub struct MetricsCollector {
    pub registry: Arc<Registry>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        // Register with default registry (used by Pingora)
        prometheus::register(Box::new(TOTAL_REQUESTS.clone())).unwrap();
        prometheus::register(Box::new(ALLOWED_REQUESTS.clone())).unwrap();
        prometheus::register(Box::new(BLOCKED_REQUESTS.clone())).unwrap();

        Self {
            registry: Arc::new(prometheus::default_registry().clone()),
        }
    }

    pub fn increment_allowed_requests(&self) {
        TOTAL_REQUESTS.inc();
        ALLOWED_REQUESTS.inc();
    }

    pub fn increment_blocked_requests(&self, reason: &str) {
        TOTAL_REQUESTS.inc();
        BLOCKED_REQUESTS.with_label_values(&[reason]).inc();
    }
}
