use pingora::prelude::*;
use pingora_waf::*;
use regex::Regex;
use std::sync::Arc;

// Custom rule: Block requests with suspicious user agents
pub struct SuspiciousUserAgentRule {
    patterns: Vec<Regex>,
    block_mode: bool,
}

impl SuspiciousUserAgentRule {
    pub fn new(block_mode: bool) -> Self {
        let patterns = vec![
            Regex::new(r"(?i)(bot|crawler|spider|scraper)").unwrap(),
            Regex::new(r"(?i)(nmap|nikto|sqlmap|masscan)").unwrap(),
            Regex::new(r"(?i)(metasploit|burp|havij)").unwrap(),
        ];

        Self {
            patterns,
            block_mode,
        }
    }
}

impl SecurityRule for SuspiciousUserAgentRule {
    fn check(
        &self,
        request: &pingora::http::RequestHeader,
        _body: Option<&[u8]>,
    ) -> Result<(), SecurityViolation> {
        if let Some(ua) = request.headers.get("User-Agent") {
            if let Ok(ua_str) = ua.to_str() {
                for pattern in &self.patterns {
                    if pattern.is_match(ua_str) {
                        return Err(SecurityViolation {
                            threat_type: "SUSPICIOUS_USER_AGENT".to_string(),
                            threat_level: ThreatLevel::Medium,
                            description: format!("Suspicious user agent detected: {}", ua_str),
                            blocked: self.block_mode,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "Suspicious User Agent Detector"
    }
}

// Custom rule: Enforce HTTPS only
pub struct HttpsOnlyRule {
    enforce: bool,
}

impl HttpsOnlyRule {
    pub fn new(enforce: bool) -> Self {
        Self { enforce }
    }
}

impl SecurityRule for HttpsOnlyRule {
    fn check(
        &self,
        request: &pingora::http::RequestHeader,
        _body: Option<&[u8]>,
    ) -> Result<(), SecurityViolation> {
        if !self.enforce {
            return Ok(());
        }

        // Check if request came over HTTPS
        let is_https = request
            .headers
            .get("X-Forwarded-Proto")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "https")
            .unwrap_or(false);

        if !is_https {
            return Err(SecurityViolation {
                threat_type: "HTTP_NOT_ALLOWED".to_string(),
                threat_level: ThreatLevel::Low,
                description: "HTTPS required - HTTP not allowed".to_string(),
                blocked: true,
            });
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "HTTPS Only Rule"
    }
}

// Custom rule: Path traversal detection
pub struct PathTraversalRule {
    block_mode: bool,
}

impl PathTraversalRule {
    pub fn new(block_mode: bool) -> Self {
        Self { block_mode }
    }

    fn check_path(&self, path: &str) -> bool {
        path.contains("../") || path.contains("..\\") || path.contains("%2e%2e")
    }
}

impl SecurityRule for PathTraversalRule {
    fn check(
        &self,
        request: &pingora::http::RequestHeader,
        _body: Option<&[u8]>,
    ) -> Result<(), SecurityViolation> {
        let uri = request.uri.to_string();

        if self.check_path(&uri) {
            return Err(SecurityViolation {
                threat_type: "PATH_TRAVERSAL".to_string(),
                threat_level: ThreatLevel::High,
                description: format!("Path traversal detected in URI: {}", uri),
                blocked: self.block_mode,
            });
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "Path Traversal Detector"
    }
}

fn main() {
    println!("Custom WAF Rules Examples\n");

    // Create custom rules
    let ua_rule = Arc::new(SuspiciousUserAgentRule::new(true));
    let https_rule = Arc::new(HttpsOnlyRule::new(true));
    let path_rule = Arc::new(PathTraversalRule::new(true));

    println!("✓ Suspicious User Agent Rule: {}", ua_rule.name());
    println!("✓ HTTPS Only Rule: {}", https_rule.name());
    println!("✓ Path Traversal Rule: {}", path_rule.name());

    println!("\nTo use these custom rules, add them to your WafProxy:");
    println!(
        "
    let mut rule_engine = RuleEngine::new();
    rule_engine.add_rule(Arc::new(SuspiciousUserAgentRule::new(true)));
    rule_engine.add_rule(Arc::new(HttpsOnlyRule::new(true)));
    r
    ule_engine.add_rule(Arc::new(PathTraversalRule::new(true)));
    "
    );
}
