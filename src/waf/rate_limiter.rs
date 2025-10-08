use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use super::{SecurityViolation, ThreatLevel};

#[derive(Clone)]
pub struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

pub struct RateLimiter {
    limits: Arc<DashMap<String, RateLimitEntry>>,
    max_requests: u32,
    window_duration: Duration,
    enabled: bool,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64, enabled: bool) -> Self {
        Self {
            limits: Arc::new(DashMap::new()),
            max_requests,
            window_duration: Duration::from_secs(window_secs),
            enabled,
        }
    }

    pub fn check_rate_limit(&self, client_ip: &str) -> Result<(), SecurityViolation> {
        if !self.enabled {
            return Ok(());
        }

        let now = Instant::now();

        let mut entry = self.limits.entry(client_ip.to_string()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(entry.window_start) > self.window_duration {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;

        if entry.count > self.max_requests {
            return Err(SecurityViolation {
                threat_type: "RATE_LIMIT_EXCEEDED".to_string(),
                threat_level: ThreatLevel::Medium,
                description: format!(
                    "Rate limit exceeded: {} requests in {:?}",
                    entry.count, self.window_duration
                ),
                blocked: true,
            });
        }

        Ok(())
    }

    pub fn cleanup_old_entries(&self) {
        let now = Instant::now();
        self.limits.retain(|_, entry| {
            now.duration_since(entry.window_start) <= self.window_duration * 2
        });
    }
}
