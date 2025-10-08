use super::{SecurityRule, SecurityViolation, ThreatLevel};
use once_cell::sync::Lazy;
use pingora::http::RequestHeader;
use regex::Regex;
use std::collections::HashSet;

static XSS_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Script tags
        Regex::new(r"(?i)<script[^>]*>").unwrap(),
        Regex::new(r"(?i)</script>").unwrap(),
        // Event handlers
        Regex::new(r"(?i)\bon\w+\s*=").unwrap(),
        // JavaScript protocol
        Regex::new(r"(?i)javascript:\s*\w").unwrap(),
        // Dangerous tags with attributes
        Regex::new(r"(?i)<iframe[^>]*>").unwrap(),
        Regex::new(r"(?i)<object[^>]*>").unwrap(),
        Regex::new(r"(?i)<embed[^>]*>").unwrap(),
        Regex::new(r"(?i)<img[^>]*\bon\w+").unwrap(),
        Regex::new(r"(?i)<body[^>]*\bon\w+").unwrap(),
        // JavaScript functions
        Regex::new(r"(?i)\beval\s*\(").unwrap(),
        Regex::new(r"(?i)\balert\s*\(").unwrap(),
        Regex::new(r"(?i)expression\s*\(").unwrap(),
        // Data URLs with scripts
        Regex::new(r"(?i)data:text/html").unwrap(),
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
    set.insert("referer");
    set.insert("origin");
    set.insert("host");
    set
});

pub struct XssDetector {
    pub enabled: bool,
    pub block_mode: bool,
}

impl XssDetector {
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

        let decoded = urlencoding::decode(input).unwrap_or(std::borrow::Cow::Borrowed(input));
        XSS_PATTERNS
            .iter()
            .any(|pattern| pattern.is_match(&decoded))
    }

    fn is_safe_header(&self, header_name: &str) -> bool {
        SAFE_HEADERS.contains(header_name.to_lowercase().as_str())
    }
}

impl SecurityRule for XssDetector {
    fn check(&self, request: &RequestHeader, body: Option<&[u8]>) -> Result<(), SecurityViolation> {
        if !self.enabled {
            return Ok(());
        }

        let uri = request.uri.to_string();
        if self.check_string(&uri) {
            return Err(SecurityViolation {
                threat_type: "XSS".to_string(),
                threat_level: ThreatLevel::High,
                description: format!("XSS attack detected in URI: {}", uri),
                blocked: self.block_mode,
            });
        }

        for (name, value) in request.headers.iter() {
            if self.is_safe_header(name.as_str()) {
                continue;
            }

            if let Ok(val) = value.to_str() {
                if self.check_string(val) {
                    return Err(SecurityViolation {
                        threat_type: "XSS".to_string(),
                        threat_level: ThreatLevel::High,
                        description: format!("XSS attack detected in header {}", name),
                        blocked: self.block_mode,
                    });
                }
            }
        }

        if let Some(body_bytes) = body {
            if let Ok(body_str) = std::str::from_utf8(body_bytes) {
                if self.check_string(body_str) {
                    return Err(SecurityViolation {
                        threat_type: "XSS".to_string(),
                        threat_level: ThreatLevel::High,
                        description: "XSS attack detected in request body".to_string(),
                        blocked: self.block_mode,
                    });
                }
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "XSS Detector"
    }
}
