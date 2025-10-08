use super::{SecurityRule, SecurityViolation, ThreatLevel};
use once_cell::sync::Lazy;
use pingora::http::RequestHeader;
use regex::Regex;
use std::collections::HashSet;

static SQL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Union-based injection
        Regex::new(r"(?i)\bunion\b.*\bselect\b").unwrap(),
        Regex::new(r"(?i)\bselect\b.*\bfrom\b").unwrap(),
        // Classic boolean injection patterns
        Regex::new(r"(?i)\b(or|and)\b\s+\d+\s*=\s*\d+").unwrap(),
        Regex::new(r#"(?i)'\s*(or|and)\s*'"#).unwrap(),
        Regex::new(r#"(?i)\bor\b\s+["']?\w+["']?\s*=\s*["']?\w+["']?"#).unwrap(),
        // Data manipulation
        Regex::new(r"(?i)\binsert\b.*\binto\b").unwrap(),
        Regex::new(r"(?i)\bdelete\b.*\bfrom\b").unwrap(),
        Regex::new(r"(?i)\bdrop\b.*\b(table|database)\b").unwrap(),
        Regex::new(r"(?i)\bupdate\b.*\bset\b").unwrap(),
        // Statement termination and comments
        Regex::new(r"(?i);\s*\b(drop|delete|update|insert)\b").unwrap(),
        Regex::new(r";s*--").unwrap(),
        Regex::new(r"'--").unwrap(),
        Regex::new(r"--[^\r\n]*$").unwrap(),
        // SQL execution
        Regex::new(r"(?i)\b(exec|execute)\s*\(").unwrap(),
        Regex::new(r"(?i)\b(xp_|sp_)\w+").unwrap(),
        // Time-based blind injection
        Regex::new(r"(?i)\b(benchmark|sleep|waitfor\s+delay)\s*\(").unwrap(),
        // Hex encoding bypass attempts
        Regex::new(r"(?i)0x[0-9a-f]{2,}").unwrap(),
    ]
});

static SAFE_HEADERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.insert("accept");
    set.insert("accept-encoding");
    set.insert("accept-language");
    set.insert("content-type");
    set.insert("user-agent");
    set.insert("cache-control");
    set.insert("connection");
    set.insert("upgrade-insecure-requests");
    set.insert("sec-fetch-mode");
    set.insert("sec-fetch-site");
    set.insert("sec-fetch-dest");
    set.insert("sec-ch-ua");
    set.insert("sec-ch-ua-mobile");
    set.insert("sec-ch-ua-platform");
    set.insert("host");
    set
});

pub struct SqlInjectionDetector {
    pub enabled: bool,
    pub block_mode: bool,
}

impl SqlInjectionDetector {
    pub fn new(enabled: bool, block_mode: bool) -> Self {
        Self {
            enabled,
            block_mode,
        }
    }

    fn check_string(&self, input: &str) -> bool {
        if input.len() < 3 {
            return false;
        }

        // URL decode first
        let decoded = urlencoding::decode(input).unwrap_or(std::borrow::Cow::Borrowed(input));

        SQL_PATTERNS
            .iter()
            .any(|pattern| pattern.is_match(&decoded))
    }

    fn is_safe_header(&self, header_name: &str) -> bool {
        SAFE_HEADERS.contains(header_name.to_lowercase().as_str())
    }
}

impl SecurityRule for SqlInjectionDetector {
    fn check(&self, request: &RequestHeader, body: Option<&[u8]>) -> Result<(), SecurityViolation> {
        if !self.enabled {
            return Ok(());
        }

        let uri = request.uri.to_string();
        if self.check_string(&uri) {
            return Err(SecurityViolation {
                threat_type: "SQL_INJECTION".to_string(),
                threat_level: ThreatLevel::Critical,
                description: format!("SQL injection detected in URI: {}", uri),
                blocked: self.block_mode,
            });
        }

        for (name, value) in request.headers.iter() {
            let header_name = name.as_str();

            if self.is_safe_header(header_name) {
                continue;
            }

            if let Ok(val) = value.to_str() {
                if self.check_string(val) {
                    return Err(SecurityViolation {
                        threat_type: "SQL_INJECTION".to_string(),
                        threat_level: ThreatLevel::Critical,
                        description: format!("SQL injection detected in header {}: {}", name, val),
                        blocked: self.block_mode,
                    });
                }
            }
        }

        if let Some(body_bytes) = body {
            if let Ok(body_str) = std::str::from_utf8(body_bytes) {
                if self.check_string(body_str) {
                    return Err(SecurityViolation {
                        threat_type: "SQL_INJECTION".to_string(),
                        threat_level: ThreatLevel::Critical,
                        description: "SQL injection detected in request body".to_string(),
                        blocked: self.block_mode,
                    });
                }
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "SQL Injection Detector"
    }
}
