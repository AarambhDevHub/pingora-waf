use crate::WafConfig;
use log::{error, info, warn};
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Hot configuration reload configuration
#[derive(Debug, Clone)]
pub struct HotReloadConfig {
    pub enabled: bool,
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

/// Configuration change callback type
pub type ConfigChangeCallback = Box<dyn Fn(WafConfig) + Send + Sync>;

/// Configuration file watcher for hot reload
pub struct ConfigWatcher {
    config_path: String,
    watcher: Option<RecommendedWatcher>,
    enabled: bool,
}

impl ConfigWatcher {
    /// Create a new config watcher
    pub fn new(config_path: &str) -> Self {
        Self {
            config_path: config_path.to_string(),
            watcher: None,
            enabled: false,
        }
    }

    /// Start watching the configuration file for changes
    ///
    /// # Arguments
    /// * `callback` - Function to call when config changes, receives new WafConfig
    ///
    /// # Returns
    /// Returns a receiver that can be used to get reload events
    pub fn start_watching(
        &mut self,
        callback: Arc<ConfigChangeCallback>,
    ) -> Result<mpsc::Receiver<WafConfig>, String> {
        let (tx, rx) = mpsc::channel::<WafConfig>();
        let config_path = self.config_path.clone();
        let config_path_for_watcher = self.config_path.clone();

        // Create debounced watcher
        let (notify_tx, notify_rx) = mpsc::channel::<Result<Event, notify::Error>>();

        let watcher = RecommendedWatcher::new(
            move |res| {
                let _ = notify_tx.send(res);
            },
            Config::default().with_poll_interval(Duration::from_secs(2)),
        )
        .map_err(|e| format!("Failed to create file watcher: {}", e))?;

        self.watcher = Some(watcher);

        if let Some(ref mut w) = self.watcher {
            let path = Path::new(&config_path_for_watcher);
            w.watch(path, RecursiveMode::NonRecursive)
                .map_err(|e| format!("Failed to watch config file: {}", e))?;
        }

        // Spawn thread to handle file change events
        thread::spawn(move || {
            let mut last_reload = std::time::Instant::now();
            let debounce_duration = Duration::from_secs(2);

            loop {
                match notify_rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(Ok(event)) => {
                        // Check if it's a modify event
                        if event.kind.is_modify() || event.kind.is_create() {
                            // Debounce rapid changes
                            if last_reload.elapsed() < debounce_duration {
                                continue;
                            }

                            info!("Configuration file changed, reloading...");

                            // Give the file system time to finish writing
                            thread::sleep(Duration::from_millis(100));

                            // Reload configuration
                            match WafConfig::from_file(&config_path) {
                                Ok(new_config) => {
                                    info!("Configuration reloaded successfully");
                                    callback(new_config.clone());
                                    let _ = tx.send(new_config);
                                    last_reload = std::time::Instant::now();
                                }
                                Err(e) => {
                                    error!("Failed to reload configuration: {}", e);
                                    warn!("Keeping previous configuration");
                                }
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        error!("File watch error: {}", e);
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        // Just continue, no events
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        info!("Config watcher channel disconnected");
                        break;
                    }
                }
            }
        });

        self.enabled = true;
        info!("Started watching configuration file: {}", self.config_path);

        Ok(rx)
    }

    /// Get the current config path
    pub fn config_path(&self) -> &str {
        &self.config_path
    }

    /// Check if watcher is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Reload configuration from file
pub fn reload_config(path: &str) -> Result<WafConfig, Box<dyn std::error::Error>> {
    info!("Reloading configuration from: {}", path);
    let config = WafConfig::from_file(path)?;
    info!("Configuration reloaded successfully");
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_watcher_creation() {
        let watcher = ConfigWatcher::new("config/waf_rules.yaml");
        assert_eq!(watcher.config_path(), "config/waf_rules.yaml");
        assert!(!watcher.is_enabled());
    }

    #[test]
    fn test_reload_config_success() {
        let result = reload_config("config/waf_rules.yaml");
        assert!(result.is_ok());
    }

    #[test]
    fn test_reload_config_not_found() {
        let result = reload_config("nonexistent.yaml");
        assert!(result.is_err());
    }

    #[test]
    fn test_hot_reload_config_default() {
        let config = HotReloadConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.watch_interval_secs, 5);
    }
}
