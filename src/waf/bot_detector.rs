use super::{SecurityRule, SecurityViolation, ThreatLevel};
use once_cell::sync::Lazy;
use pingora::http::RequestHeader;
use regex::Regex;
use std::collections::HashSet;

/// Known malicious bot User-Agent patterns
/// These are security scanners, scrapers, and spam bots
static BAD_BOT_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Security scanners and vulnerability tools
        Regex::new(r"(?i)\bsqlmap\b").unwrap(),
        Regex::new(r"(?i)\bnikto\b").unwrap(),
        Regex::new(r"(?i)\bnmap\b").unwrap(),
        Regex::new(r"(?i)\bmasscan\b").unwrap(),
        Regex::new(r"(?i)\bmetasploit\b").unwrap(),
        Regex::new(r"(?i)\bburpsuite\b").unwrap(),
        Regex::new(r"(?i)\bacunetix\b").unwrap(),
        Regex::new(r"(?i)\bnessus\b").unwrap(),
        Regex::new(r"(?i)\bowasp\b.*\bzap\b").unwrap(),
        Regex::new(r"(?i)\bdirbuster\b").unwrap(),
        Regex::new(r"(?i)\bgobuster\b").unwrap(),
        Regex::new(r"(?i)\bwpscan\b").unwrap(),
        Regex::new(r"(?i)\bjoomscan\b").unwrap(),
        Regex::new(r"(?i)\bw3af\b").unwrap(),
        Regex::new(r"(?i)\barachni\b").unwrap(),
        Regex::new(r"(?i)\bskipfish\b").unwrap(),
        // Web scrapers
        Regex::new(r"(?i)\bscrapy\b").unwrap(),
        Regex::new(r"(?i)\bwebharvest\b").unwrap(),
        Regex::new(r"(?i)\bhttrack\b").unwrap(),
        Regex::new(r"(?i)\bwebcopier\b").unwrap(),
        Regex::new(r"(?i)\boffline\s*explorer\b").unwrap(),
        Regex::new(r"(?i)\bteleport\s*pro\b").unwrap(),
        Regex::new(r"(?i)\bwebzip\b").unwrap(),
        // Spam bots
        Regex::new(r"(?i)\bsemrush\b").unwrap(),
        Regex::new(r"(?i)\bahrefs\b").unwrap(),
        Regex::new(r"(?i)\bmj12bot\b").unwrap(),
        Regex::new(r"(?i)\bdotbot\b").unwrap(),
        Regex::new(r"(?i)\bseekport\b").unwrap(),
        Regex::new(r"(?i)\bblexbot\b").unwrap(),
        // Generic bad patterns
        Regex::new(r"(?i)\bcrawler\b.*\bbot\b").unwrap(),
        Regex::new(r"(?i)\bspider\b.*\bbot\b").unwrap(),
        Regex::new(r"(?i)\bscan\b").unwrap(),
        Regex::new(r"(?i)\bharvest\b").unwrap(),
        Regex::new(r"(?i)\bextract\b").unwrap(),
        // Library defaults that are often abused
        Regex::new(r"^python-requests").unwrap(),
        Regex::new(r"^python-urllib").unwrap(),
        Regex::new(r"^Java/").unwrap(),
        Regex::new(r"^libwww-perl").unwrap(),
        Regex::new(r"^Go-http-client").unwrap(),
        Regex::new(r"^curl/").unwrap(),
        Regex::new(r"^wget/").unwrap(),
    ]
});

/// Known good bot User-Agent identifiers (exact substrings)
static GOOD_BOT_IDENTIFIERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut set = HashSet::new();
    // Search engine crawlers
    set.insert("googlebot");
    set.insert("bingbot");
    set.insert("slurp"); // Yahoo
    set.insert("duckduckbot");
    set.insert("baiduspider");
    set.insert("yandexbot");
    set.insert("sogou");
    set.insert("exabot");
    set.insert("facebot"); // Facebook
    set.insert("facebookexternalhit");
    set.insert("ia_archiver"); // Alexa
    // Social media
    set.insert("twitterbot");
    set.insert("linkedinbot");
    set.insert("pinterestbot");
    set.insert("slackbot");
    set.insert("telegrambot");
    set.insert("discordbot");
    set.insert("whatsapp");
    // Monitoring and verification
    set.insert("uptimerobot");
    set.insert("pingdom");
    set.insert("statuscake");
    set.insert("site24x7");
    set.insert("gtmetrix");
    // Feed readers
    set.insert("feedly");
    set.insert("feedburner");
    set
});

/// Bot detection result
#[derive(Debug, Clone, PartialEq)]
pub enum BotType {
    /// Known good bot (search engines, social media)
    GoodBot(String),
    /// Known bad bot (scanners, scrapers)
    BadBot(String),
    /// Suspicious bot (missing/empty User-Agent)
    SuspiciousBot(String),
    /// Regular user (no bot detected)
    NotBot,
}

/// Bot detector for identifying malicious and legitimate bots
pub struct BotDetector {
    pub enabled: bool,
    pub block_mode: bool,
    pub allow_known_bots: bool,
    custom_bad_patterns: Vec<Regex>,
    custom_good_identifiers: HashSet<String>,
}

impl BotDetector {
    /// Create a new bot detector
    ///
    /// # Arguments
    /// * `enabled` - Whether bot detection is enabled
    /// * `block_mode` - true = block bad bots, false = log only
    /// * `allow_known_bots` - Allow known good bots (Googlebot, Bingbot, etc.)
    pub fn new(enabled: bool, block_mode: bool, allow_known_bots: bool) -> Self {
        Self {
            enabled,
            block_mode,
            allow_known_bots,
            custom_bad_patterns: Vec::new(),
            custom_good_identifiers: HashSet::new(),
        }
    }

    /// Add a custom bad bot pattern
    pub fn add_bad_bot_pattern(&mut self, pattern: &str) -> Result<(), String> {
        let regex = Regex::new(pattern).map_err(|e| e.to_string())?;
        self.custom_bad_patterns.push(regex);
        Ok(())
    }

    /// Add a custom good bot identifier
    pub fn add_good_bot_identifier(&mut self, identifier: &str) {
        self.custom_good_identifiers
            .insert(identifier.to_lowercase());
    }

    /// Check if User-Agent matches a known good bot
    fn is_good_bot(&self, user_agent: &str) -> Option<String> {
        let ua_lower = user_agent.to_lowercase();

        // Check built-in good bots
        for &identifier in GOOD_BOT_IDENTIFIERS.iter() {
            if ua_lower.contains(identifier) {
                return Some(identifier.to_string());
            }
        }

        // Check custom good bots
        for identifier in &self.custom_good_identifiers {
            if ua_lower.contains(identifier) {
                return Some(identifier.clone());
            }
        }

        None
    }

    /// Check if User-Agent matches a known bad bot
    fn is_bad_bot(&self, user_agent: &str) -> Option<String> {
        // Check built-in bad bot patterns
        for pattern in BAD_BOT_PATTERNS.iter() {
            if pattern.is_match(user_agent) {
                return Some(pattern.to_string());
            }
        }

        // Check custom bad bot patterns
        for pattern in &self.custom_bad_patterns {
            if pattern.is_match(user_agent) {
                return Some(pattern.to_string());
            }
        }

        None
    }

    /// Detect bot type from User-Agent
    pub fn detect_bot(&self, user_agent: Option<&str>) -> BotType {
        match user_agent {
            None => BotType::SuspiciousBot("Missing User-Agent header".to_string()),
            Some(ua) if ua.trim().is_empty() => {
                BotType::SuspiciousBot("Empty User-Agent header".to_string())
            }
            Some(ua) if ua.len() < 10 => {
                BotType::SuspiciousBot(format!("User-Agent too short: {}", ua))
            }
            Some(ua) => {
                // Check for good bot first (allow legitimate crawlers)
                if self.allow_known_bots {
                    if let Some(bot_name) = self.is_good_bot(ua) {
                        return BotType::GoodBot(bot_name);
                    }
                }

                // Check for bad bot
                if let Some(pattern) = self.is_bad_bot(ua) {
                    return BotType::BadBot(pattern);
                }

                BotType::NotBot
            }
        }
    }
}

impl SecurityRule for BotDetector {
    fn check(
        &self,
        request: &RequestHeader,
        _body: Option<&[u8]>,
    ) -> Result<(), SecurityViolation> {
        if !self.enabled {
            return Ok(());
        }

        let user_agent = request
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok());

        match self.detect_bot(user_agent) {
            BotType::GoodBot(_) => Ok(()), // Allow known good bots
            BotType::NotBot => Ok(()),     // Allow regular users
            BotType::BadBot(pattern) => Err(SecurityViolation {
                threat_type: "BAD_BOT".to_string(),
                threat_level: ThreatLevel::High,
                description: format!(
                    "Malicious bot detected - User-Agent matches pattern: {}",
                    pattern
                ),
                blocked: self.block_mode,
            }),
            BotType::SuspiciousBot(reason) => Err(SecurityViolation {
                threat_type: "SUSPICIOUS_BOT".to_string(),
                threat_level: ThreatLevel::Medium,
                description: format!("Suspicious bot activity: {}", reason),
                blocked: self.block_mode,
            }),
        }
    }

    fn name(&self) -> &str {
        "Bot Detector"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_request_with_ua(ua: &str) -> RequestHeader {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("User-Agent", ua).unwrap();
        req
    }

    fn create_request_without_ua() -> RequestHeader {
        RequestHeader::build("GET", b"/", None).unwrap()
    }

    #[test]
    fn test_detect_googlebot() {
        let detector = BotDetector::new(true, true, true);
        let ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
        assert_eq!(
            detector.detect_bot(Some(ua)),
            BotType::GoodBot("googlebot".to_string())
        );
    }

    #[test]
    fn test_detect_bingbot() {
        let detector = BotDetector::new(true, true, true);
        let ua = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)";
        assert_eq!(
            detector.detect_bot(Some(ua)),
            BotType::GoodBot("bingbot".to_string())
        );
    }

    #[test]
    fn test_detect_sqlmap() {
        let detector = BotDetector::new(true, true, true);
        let ua = "sqlmap/1.4.7#stable";
        assert!(matches!(detector.detect_bot(Some(ua)), BotType::BadBot(_)));
    }

    #[test]
    fn test_detect_nikto() {
        let detector = BotDetector::new(true, true, true);
        let ua = "Nikto/2.1.6";
        assert!(matches!(detector.detect_bot(Some(ua)), BotType::BadBot(_)));
    }

    #[test]
    fn test_detect_curl() {
        let detector = BotDetector::new(true, true, true);
        let ua = "curl/7.68.0";
        assert!(matches!(detector.detect_bot(Some(ua)), BotType::BadBot(_)));
    }

    #[test]
    fn test_detect_missing_ua() {
        let detector = BotDetector::new(true, true, true);
        assert!(matches!(
            detector.detect_bot(None),
            BotType::SuspiciousBot(_)
        ));
    }

    #[test]
    fn test_detect_empty_ua() {
        let detector = BotDetector::new(true, true, true);
        assert!(matches!(
            detector.detect_bot(Some("")),
            BotType::SuspiciousBot(_)
        ));
    }

    #[test]
    fn test_detect_short_ua() {
        let detector = BotDetector::new(true, true, true);
        assert!(matches!(
            detector.detect_bot(Some("Bot")),
            BotType::SuspiciousBot(_)
        ));
    }

    #[test]
    fn test_detect_normal_browser() {
        let detector = BotDetector::new(true, true, true);
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        assert_eq!(detector.detect_bot(Some(ua)), BotType::NotBot);
    }

    #[test]
    fn test_security_rule_blocks_bad_bot() {
        let detector = BotDetector::new(true, true, true);
        let req = create_request_with_ua("sqlmap/1.0");
        let result = detector.check(&req, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().threat_type, "BAD_BOT");
    }

    #[test]
    fn test_security_rule_allows_good_bot() {
        let detector = BotDetector::new(true, true, true);
        let req = create_request_with_ua("Googlebot/2.1");
        assert!(detector.check(&req, None).is_ok());
    }

    #[test]
    fn test_security_rule_blocks_missing_ua() {
        let detector = BotDetector::new(true, true, true);
        let req = create_request_without_ua();
        let result = detector.check(&req, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().threat_type, "SUSPICIOUS_BOT");
    }

    #[test]
    fn test_disabled_detector() {
        let detector = BotDetector::new(false, true, true);
        let req = create_request_with_ua("sqlmap/1.0");
        assert!(detector.check(&req, None).is_ok());
    }

    #[test]
    fn test_log_only_mode() {
        let detector = BotDetector::new(true, false, true);
        let req = create_request_with_ua("sqlmap/1.0");
        let result = detector.check(&req, None);
        assert!(result.is_err());
        assert!(!result.unwrap_err().blocked); // Not blocked in log-only mode
    }

    #[test]
    fn test_custom_bad_pattern() {
        let mut detector = BotDetector::new(true, true, true);
        detector.add_bad_bot_pattern(r"(?i)mycustombot").unwrap();
        let ua = "MyCustomBot/1.0";
        assert!(matches!(detector.detect_bot(Some(ua)), BotType::BadBot(_)));
    }

    #[test]
    fn test_custom_good_identifier() {
        let mut detector = BotDetector::new(true, true, true);
        detector.add_good_bot_identifier("mygoodbot");
        let ua = "MyGoodBot/1.0 (Friendly Crawler)";
        assert!(matches!(detector.detect_bot(Some(ua)), BotType::GoodBot(_)));
    }

    #[test]
    fn test_good_bots_disabled() {
        let detector = BotDetector::new(true, true, false); // allow_known_bots = false
        let ua = "Googlebot/2.1";
        // Without allow_known_bots, Googlebot is treated as NotBot (not specifically allowed)
        assert_eq!(detector.detect_bot(Some(ua)), BotType::NotBot);
    }
}
