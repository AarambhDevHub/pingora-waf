use clap::Parser;
use log::{error, info};
use pingora::prelude::*;
use pingora::server::configuration::Opt;
use pingora_proxy::http_proxy_service;
use pingora_waf::*;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config/waf_rules.yaml")]
    config: String,

    /// Upstream backend host
    #[arg(short = 'u', long)]
    upstream_host: Option<String>,

    /// Upstream backend port
    #[arg(short = 'p', long)]
    upstream_port: Option<u16>,

    /// WAF listening address
    #[arg(short = 'l', long, default_value = "0.0.0.0")]
    listen_addr: String,

    /// WAF listening port
    #[arg(short = 'P', long, default_value = "6188")]
    listen_port: u16,

    /// Metrics port
    #[arg(short = 'm', long, default_value = "6190")]
    metrics_port: u16,

    /// Enable testing mode (relaxed rate limits)
    #[arg(short = 't', long)]
    testing_mode: bool,
}

fn main() {
    env_logger::init();

    // Parse command-line arguments
    let args = Args::parse();

    info!("Starting Pingora WAF...");
    info!("Loading configuration from: {}", args.config);

    // Determine config path (check for testing mode)
    let config_path = if args.testing_mode {
        info!("Testing mode enabled - using relaxed configuration");
        "config/waf_rules_testing.yaml"
    } else {
        args.config.as_str()
    };

    // Load configuration
    let config = WafConfig::from_file(config_path).unwrap_or_else(|e| {
        error!("Failed to load configuration from {}: {}", config_path, e);
        error!("Using default configuration");
        WafConfig::default()
    });

    info!("Configuration loaded successfully");

    // Initialize security components
    let sql_detector = Arc::new(SqlInjectionDetector::new(
        config.sql_injection.enabled,
        config.sql_injection.block_mode,
    ));

    let xss_detector = Arc::new(XssDetector::new(config.xss.enabled, config.xss.block_mode));

    let path_traversal_detector = Arc::new(PathTraversalDetector::new(
        config.path_traversal.enabled,
        config.path_traversal.block_mode,
    ));

    let command_injection_detector = Arc::new(CommandInjectionDetector::new(
        config.command_injection.enabled,
        config.command_injection.block_mode,
    ));

    let rate_limiter = Arc::new(RateLimiter::new(
        config.rate_limit.max_requests,
        config.rate_limit.window_secs,
        config.rate_limit.enabled,
    ));

    let mut ip_filter = IpFilter::new(config.ip_filter.enabled);
    for ip in &config.ip_filter.whitelist {
        let _ = ip_filter.add_to_whitelist(ip);
    }
    for ip in &config.ip_filter.blacklist {
        let _ = ip_filter.add_to_blacklist(ip);
    }
    let ip_filter = Arc::new(ip_filter);

    let mut bot_detector = BotDetector::new(
        config.bot_detection.enabled,
        config.bot_detection.block_mode,
        config.bot_detection.allow_known_bots,
    );
    for pattern in &config.bot_detection.custom_bad_bots {
        if let Err(e) = bot_detector.add_bad_bot_pattern(pattern) {
            error!("Invalid bot pattern '{}': {}", pattern, e);
        }
    }
    for identifier in &config.bot_detection.custom_good_bots {
        bot_detector.add_good_bot_identifier(identifier);
    }
    let bot_detector = Arc::new(bot_detector);

    let metrics = Arc::new(MetricsCollector::new());

    let upstream_host = args
        .upstream_host
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let upstream_port = args.upstream_port.unwrap_or(8080);

    info!("Upstream backend: {}:{}", upstream_host, upstream_port);

    // Create WAF proxy
    let waf_proxy = WafProxy::new(
        (upstream_host.clone(), upstream_port),
        sql_detector,
        xss_detector,
        path_traversal_detector,
        command_injection_detector,
        rate_limiter.clone(),
        ip_filter,
        bot_detector,
        metrics.clone(),
        config.max_body_size,
    );

    // Start server
    let mut server = Server::new(Some(Opt::default())).unwrap();
    server.bootstrap();

    // Add proxy service
    let mut proxy_service = http_proxy_service(&server.configuration, waf_proxy);
    let listen_address = format!("{}:{}", args.listen_addr, args.listen_port);
    proxy_service.add_tcp(&listen_address);
    server.add_service(proxy_service);

    // Add built-in Prometheus metrics service
    let metrics_address = format!("{}:{}", args.listen_addr, args.metrics_port);
    let mut prometheus_service_http =
        pingora::services::listening::Service::prometheus_http_service();
    prometheus_service_http.add_tcp(&metrics_address);
    server.add_service(prometheus_service_http);

    // Periodic cleanup task
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(300));
            rate_limiter.cleanup_old_entries();
            info!("Cleaned up rate limiter entries");
        }
    });

    info!("╔═══════════════════════════════════════════════╗");
    info!("║   Pingora WAF Proxy                           ║");
    info!("╚═══════════════════════════════════════════════╝");
    info!(
        "🔒 WAF Proxy:     http://{}:{}",
        args.listen_addr, args.listen_port
    );
    info!(
        "📊 Metrics:       http://{}:{}/metrics",
        args.listen_addr, args.metrics_port
    );
    info!("🎯 Upstream:      {}:{}", upstream_host, upstream_port);
    info!("📋 Config:        {}", config_path);
    info!("🚀 Status:        Running");

    server.run_forever();
}
