use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WafConfig {
    pub sql_injection: RuleConfig,
    pub xss: RuleConfig,
    pub rate_limit: RateLimitConfig,
    pub ip_filter: IpFilterConfig,
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuleConfig {
    pub enabled: bool,
    pub block_mode: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    #[serde(default = "default_max_requests")]
    pub max_requests: u32,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IpFilterConfig {
    pub enabled: bool,
    #[serde(default)] // Empty vec if missing
    pub whitelist: Vec<String>,
    #[serde(default)] // Empty vec if missing
    pub blacklist: Vec<String>,
}

// Default value functions
fn default_max_body_size() -> usize {
    1048576 // 1MB
}

fn default_max_requests() -> u32 {
    1000
}

fn default_window_secs() -> u64 {
    60
}

impl WafConfig {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: WafConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn default() -> Self {
        Self {
            sql_injection: RuleConfig {
                enabled: true,
                block_mode: true,
            },
            xss: RuleConfig {
                enabled: true,
                block_mode: true,
            },
            rate_limit: RateLimitConfig {
                enabled: true,
                max_requests: 100,
                window_secs: 60,
            },
            ip_filter: IpFilterConfig {
                enabled: false,
                whitelist: vec![],
                blacklist: vec![],
            },
            max_body_size: 1048576, // 1MB
        }
    }
}
