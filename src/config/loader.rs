use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WafConfig {
    pub sql_injection: RuleConfig,
    pub xss: RuleConfig,
    #[serde(default)]
    pub path_traversal: RuleConfig,
    #[serde(default)]
    pub command_injection: RuleConfig,
    pub rate_limit: RateLimitConfig,
    pub ip_filter: IpFilterConfig,
    #[serde(default)]
    pub bot_detection: BotDetectionConfig,
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    #[serde(default)]
    pub hot_reload: HotReloadConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuleConfig {
    pub enabled: bool,
    pub block_mode: bool,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_mode: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HotReloadConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_watch_interval")]
    pub watch_interval_secs: u64,
}

impl Default for HotReloadConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            watch_interval_secs: 5,
        }
    }
}

fn default_watch_interval() -> u64 {
    5
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BotDetectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub block_mode: bool,
    #[serde(default = "default_true")]
    pub allow_known_bots: bool,
    #[serde(default)]
    pub custom_bad_bots: Vec<String>,
    #[serde(default)]
    pub custom_good_bots: Vec<String>,
}

impl Default for BotDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_mode: true,
            allow_known_bots: true,
            custom_bad_bots: vec![],
            custom_good_bots: vec![],
        }
    }
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

fn default_true() -> bool {
    true
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
            path_traversal: RuleConfig {
                enabled: true,
                block_mode: true,
            },
            command_injection: RuleConfig {
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
            bot_detection: BotDetectionConfig::default(),
            max_body_size: 1048576, // 1MB
            hot_reload: HotReloadConfig::default(),
        }
    }
}
