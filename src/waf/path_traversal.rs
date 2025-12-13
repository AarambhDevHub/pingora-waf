use super::{SecurityRule, SecurityViolation, ThreatLevel};
use once_cell::sync::Lazy;
use pingora::http::RequestHeader;
use regex::Regex;
use std::collections::HashSet;

/// Path traversal attack patterns
/// Detects attempts to access files outside the intended directory
static PATH_TRAVERSAL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Basic directory traversal
        Regex::new(r"\.\.\/").unwrap(),
        Regex::new(r"\.\.\\").unwrap(),
        Regex::new(r"\.\.%2f").unwrap(),
        Regex::new(r"\.\.%5c").unwrap(),
        // URL encoded variants
        Regex::new(r"(?i)%2e%2e%2f").unwrap(), // ../
        Regex::new(r"(?i)%2e%2e/").unwrap(),   // ../
        Regex::new(r"(?i)%2e%2e%5c").unwrap(), // ..\
        Regex::new(r"(?i)%2e%2e\\").unwrap(),  // ..\
        // Double encoding
        Regex::new(r"(?i)%252e%252e%252f").unwrap(), // ../
        Regex::new(r"(?i)%252e%252e/").unwrap(),     // ../
        // Unicode/overlong encoding
        Regex::new(r"(?i)%c0%ae%c0%ae/").unwrap(),
        Regex::new(r"(?i)%c0%ae%c0%ae%c0%af").unwrap(),
        // Null byte injection (used to bypass extension checks)
        Regex::new(r"%00").unwrap(),
        Regex::new(r"\\x00").unwrap(),
        // Bypass attempts with multiple dots/slashes
        Regex::new(r"\.\.\.\./").unwrap(),
        Regex::new(r"\.\.//").unwrap(),
        Regex::new(r"\.\./\./").unwrap(),
    ]
});

/// Sensitive file paths that should never be accessed
static SENSITIVE_PATHS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Unix sensitive files
        Regex::new(r"(?i)/etc/passwd").unwrap(),
        Regex::new(r"(?i)/etc/shadow").unwrap(),
        Regex::new(r"(?i)/etc/hosts").unwrap(),
        Regex::new(r"(?i)/etc/group").unwrap(),
        Regex::new(r"(?i)/proc/").unwrap(),
        Regex::new(r"(?i)/sys/").unwrap(),
        Regex::new(r"(?i)/var/log/").unwrap(),
        Regex::new(r"(?i)/root/").unwrap(),
        Regex::new(r"(?i)\.ssh/").unwrap(),
        Regex::new(r"(?i)\.bash_history").unwrap(),
        Regex::new(r"(?i)\.env").unwrap(),
        Regex::new(r"(?i)id_rsa").unwrap(),
        Regex::new(r"(?i)id_dsa").unwrap(),
        // Windows sensitive files
        Regex::new(r"(?i)c:\\windows").unwrap(),
        Regex::new(r"(?i)c:\\boot\.ini").unwrap(),
        Regex::new(r"(?i)\\windows\\system32").unwrap(),
        Regex::new(r"(?i)win\.ini").unwrap(),
        Regex::new(r"(?i)system\.ini").unwrap(),
        // Web server configs
        Regex::new(r"(?i)\.htaccess").unwrap(),
        Regex::new(r"(?i)\.htpasswd").unwrap(),
        Regex::new(r"(?i)web\.config").unwrap(),
        Regex::new(r"(?i)nginx\.conf").unwrap(),
        Regex::new(r"(?i)httpd\.conf").unwrap(),
        // Application configs
        Regex::new(r"(?i)config\.php").unwrap(),
        Regex::new(r"(?i)database\.yml").unwrap(),
        Regex::new(r"(?i)settings\.py").unwrap(),
        Regex::new(r"(?i)wp-config\.php").unwrap(),
    ]
});

/// Safe headers that should not be checked for path traversal
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
    set
});

pub struct PathTraversalDetector {
    pub enabled: bool,
    pub block_mode: bool,
}

impl PathTraversalDetector {
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

        // Check for path traversal patterns
        for pattern in PATH_TRAVERSAL_PATTERNS.iter() {
            if pattern.is_match(&decoded) || pattern.is_match(input) {
                return Some(format!("Path traversal pattern: {}", pattern.as_str()));
            }
        }

        // Check for sensitive file paths
        for pattern in SENSITIVE_PATHS.iter() {
            if pattern.is_match(&decoded) || pattern.is_match(input) {
                return Some(format!("Sensitive path access: {}", pattern.as_str()));
            }
        }

        None
    }

    fn is_safe_header(&self, header_name: &str) -> bool {
        SAFE_HEADERS.contains(header_name.to_lowercase().as_str())
    }
}

impl SecurityRule for PathTraversalDetector {
    fn check(&self, request: &RequestHeader, body: Option<&[u8]>) -> Result<(), SecurityViolation> {
        if !self.enabled {
            return Ok(());
        }

        // Check URI
        let uri = request.uri.to_string();
        if let Some(reason) = self.check_string(&uri) {
            return Err(SecurityViolation {
                threat_type: "PATH_TRAVERSAL".to_string(),
                threat_level: ThreatLevel::High,
                description: format!("Path traversal detected in URI: {} - {}", uri, reason),
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
                        threat_type: "PATH_TRAVERSAL".to_string(),
                        threat_level: ThreatLevel::High,
                        description: format!(
                            "Path traversal detected in header {}: {}",
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
                        threat_type: "PATH_TRAVERSAL".to_string(),
                        threat_level: ThreatLevel::High,
                        description: format!("Path traversal detected in request body: {}", reason),
                        blocked: self.block_mode,
                    });
                }
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "Path Traversal Detector"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_request_with_uri(uri: &str) -> RequestHeader {
        RequestHeader::build("GET", uri.as_bytes(), None).unwrap()
    }

    #[test]
    fn test_basic_path_traversal() {
        let detector = PathTraversalDetector::new(true, true);
        let req = create_request_with_uri("/api/../../../etc/passwd");
        let result = detector.check(&req, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().threat_type, "PATH_TRAVERSAL");
    }

    #[test]
    fn test_url_encoded_traversal() {
        let detector = PathTraversalDetector::new(true, true);
        let req = create_request_with_uri("/api/%2e%2e%2f%2e%2e%2fetc/passwd");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_double_encoded_traversal() {
        let detector = PathTraversalDetector::new(true, true);
        let req = create_request_with_uri("/api/%252e%252e%252f");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_windows_path_traversal() {
        let detector = PathTraversalDetector::new(true, true);
        let req = create_request_with_uri("/api/..\\..\\windows\\system32");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_sensitive_file_access() {
        let detector = PathTraversalDetector::new(true, true);
        let req = create_request_with_uri("/api/file?path=/etc/passwd");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_htaccess_access() {
        let detector = PathTraversalDetector::new(true, true);
        let req = create_request_with_uri("/api/.htaccess");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_env_file_access() {
        let detector = PathTraversalDetector::new(true, true);
        let req = create_request_with_uri("/api/.env");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_null_byte_injection() {
        let detector = PathTraversalDetector::new(true, true);
        let req = create_request_with_uri("/api/file.txt%00.jpg");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_normal_request_allowed() {
        let detector = PathTraversalDetector::new(true, true);
        let req = create_request_with_uri("/api/users/123/profile");
        let result = detector.check(&req, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_disabled_detector() {
        let detector = PathTraversalDetector::new(false, true);
        let req = create_request_with_uri("/api/../../../etc/passwd");
        let result = detector.check(&req, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_log_only_mode() {
        let detector = PathTraversalDetector::new(true, false);
        let req = create_request_with_uri("/api/../../../etc/passwd");
        let result = detector.check(&req, None);
        assert!(result.is_err());
        assert!(!result.unwrap_err().blocked);
    }

    #[test]
    fn test_body_path_traversal() {
        let detector = PathTraversalDetector::new(true, true);
        let req = create_request_with_uri("/api/upload");
        let body = b"filename=../../../etc/passwd";
        let result = detector.check(&req, Some(body));
        assert!(result.is_err());
    }

    #[test]
    fn test_bypass_attempt_multiple_dots() {
        let detector = PathTraversalDetector::new(true, true);
        let req = create_request_with_uri("/api/..../etc/passwd");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_ssh_key_access() {
        let detector = PathTraversalDetector::new(true, true);
        let req = create_request_with_uri("/api/file?path=~/.ssh/id_rsa");
        let result = detector.check(&req, None);
        assert!(result.is_err());
    }
}
