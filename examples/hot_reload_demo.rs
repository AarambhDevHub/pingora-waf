//! Hot Configuration Reload Demo
//!
//! Run with: cargo run --example hot_reload_demo
//!
//! This example demonstrates the hot configuration reload feature.
//! It shows how to set up a config watcher and react to config changes.

use pingora_waf::config::{ConfigWatcher, WafConfig};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn main() {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    println!("╔═══════════════════════════════════════════════╗");
    println!("║   Hot Configuration Reload Demo               ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    let config_path = "config/waf_rules.yaml";

    // Load initial config
    let initial_config = WafConfig::from_file(config_path).unwrap_or_else(|e| {
        eprintln!("Failed to load config: {}", e);
        WafConfig::default()
    });

    println!("📋 Initial Configuration:");
    println!(
        "   SQL Injection: enabled={}, block={}",
        initial_config.sql_injection.enabled, initial_config.sql_injection.block_mode
    );
    println!(
        "   XSS: enabled={}, block={}",
        initial_config.xss.enabled, initial_config.xss.block_mode
    );
    println!(
        "   Path Traversal: enabled={}, block={}",
        initial_config.path_traversal.enabled, initial_config.path_traversal.block_mode
    );
    println!(
        "   Command Injection: enabled={}, block={}",
        initial_config.command_injection.enabled, initial_config.command_injection.block_mode
    );
    println!(
        "   Hot Reload: enabled={}",
        initial_config.hot_reload.enabled
    );
    println!();

    // Create config watcher
    let mut watcher = ConfigWatcher::new(config_path);

    // Define callback for config changes
    let callback: Arc<Box<dyn Fn(WafConfig) + Send + Sync>> = Arc::new(Box::new(|new_config| {
        println!("\n🔄 Configuration Reloaded!");
        println!(
            "   SQL Injection: enabled={}, block={}",
            new_config.sql_injection.enabled, new_config.sql_injection.block_mode
        );
        println!(
            "   XSS: enabled={}, block={}",
            new_config.xss.enabled, new_config.xss.block_mode
        );
        println!(
            "   Path Traversal: enabled={}, block={}",
            new_config.path_traversal.enabled, new_config.path_traversal.block_mode
        );
        println!(
            "   Command Injection: enabled={}, block={}",
            new_config.command_injection.enabled, new_config.command_injection.block_mode
        );
    }));

    // Start watching for changes
    match watcher.start_watching(callback) {
        Ok(rx) => {
            println!("👀 Watching config file: {}", config_path);
            println!("   Modify the config file to see hot reload in action.");
            println!("   Press Ctrl+C to exit.\n");

            // Keep receiving config updates
            loop {
                match rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(config) => {
                        println!("📦 Received new config via channel");
                        println!("   Max body size: {} bytes", config.max_body_size);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Just keep waiting
                        print!(".");
                        std::io::Write::flush(&mut std::io::stdout()).unwrap();
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        println!("\n❌ Config watcher disconnected");
                        break;
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to start config watcher: {}", e);
            eprintln!("\n💡 Manual reload demonstration:");

            // Demonstrate manual reload
            thread::sleep(Duration::from_secs(2));

            println!("\n📋 Attempting manual config reload...");
            match pingora_waf::config::reload_config(config_path) {
                Ok(new_config) => {
                    println!("✅ Manual reload successful!");
                    println!(
                        "   SQL Injection enabled: {}",
                        new_config.sql_injection.enabled
                    );
                }
                Err(e) => {
                    eprintln!("❌ Manual reload failed: {}", e);
                }
            }
        }
    }
}
