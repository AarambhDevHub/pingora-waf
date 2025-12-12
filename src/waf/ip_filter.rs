use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::str::FromStr;

use super::{SecurityViolation, ThreatLevel};

/// IP Filter with CIDR notation support
///
/// Supports both individual IPs and CIDR ranges:
/// - Individual IP: "192.168.1.1" (treated as /32 for IPv4, /128 for IPv6)
/// - CIDR range: "192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32"
pub struct IpFilter {
    /// Networks in the whitelist (only these IPs allowed if non-empty)
    pub whitelist: Vec<IpNetwork>,
    /// Networks in the blacklist (these IPs are blocked)
    pub blacklist: Vec<IpNetwork>,
    /// Whether IP filtering is enabled
    pub enabled: bool,
}

impl IpFilter {
    /// Create a new IP filter
    pub fn new(enabled: bool) -> Self {
        Self {
            whitelist: Vec::new(),
            blacklist: Vec::new(),
            enabled,
        }
    }

    /// Add an IP or CIDR range to the whitelist
    ///
    /// # Examples
    /// ```
    /// filter.add_to_whitelist("192.168.1.1");      // Single IP
    /// filter.add_to_whitelist("10.0.0.0/8");       // CIDR range
    /// filter.add_to_whitelist("2001:db8::/32");    // IPv6 CIDR
    /// ```
    pub fn add_to_whitelist(&mut self, ip_or_cidr: &str) -> Result<(), String> {
        let network = self.parse_ip_or_cidr(ip_or_cidr)?;
        self.whitelist.push(network);
        Ok(())
    }

    /// Add an IP or CIDR range to the blacklist
    ///
    /// # Examples
    /// ```
    /// filter.add_to_blacklist("192.168.1.100");    // Single IP
    /// filter.add_to_blacklist("198.51.100.0/24");  // CIDR range
    /// ```
    pub fn add_to_blacklist(&mut self, ip_or_cidr: &str) -> Result<(), String> {
        let network = self.parse_ip_or_cidr(ip_or_cidr)?;
        self.blacklist.push(network);
        Ok(())
    }

    /// Parse an IP address or CIDR notation string into an IpNetwork
    ///
    /// Supports:
    /// - "192.168.1.1" -> 192.168.1.1/32
    /// - "192.168.1.0/24" -> 192.168.1.0/24
    /// - "::1" -> ::1/128
    /// - "2001:db8::/32" -> 2001:db8::/32
    fn parse_ip_or_cidr(&self, input: &str) -> Result<IpNetwork, String> {
        // First try to parse as CIDR notation
        if let Ok(network) = IpNetwork::from_str(input) {
            return Ok(network);
        }

        // If that fails, try to parse as a single IP and convert to /32 or /128
        if let Ok(ip) = IpAddr::from_str(input) {
            match ip {
                IpAddr::V4(v4) => IpNetwork::new(IpAddr::V4(v4), 32).map_err(|e| e.to_string()),
                IpAddr::V6(v6) => IpNetwork::new(IpAddr::V6(v6), 128).map_err(|e| e.to_string()),
            }
        } else {
            Err(format!("Invalid IP address or CIDR notation: {}", input))
        }
    }

    /// Check if an IP address is in the given network list
    fn ip_in_networks(&self, ip: &IpAddr, networks: &[IpNetwork]) -> bool {
        networks.iter().any(|network| network.contains(*ip))
    }

    /// Check if an IP address passes the filter
    ///
    /// Returns Ok(()) if the IP is allowed, Err(SecurityViolation) if blocked
    pub fn check_ip(&self, ip_str: &str) -> Result<(), SecurityViolation> {
        if !self.enabled {
            return Ok(());
        }

        let ip = match IpAddr::from_str(ip_str) {
            Ok(addr) => addr,
            Err(_) => return Ok(()), // Invalid IP format, let it through
        };

        // Check whitelist first - if whitelist is non-empty, IP must be in it
        if !self.whitelist.is_empty() && !self.ip_in_networks(&ip, &self.whitelist) {
            return Err(SecurityViolation {
                threat_type: "IP_NOT_WHITELISTED".to_string(),
                threat_level: ThreatLevel::High,
                description: format!("IP {} not in whitelist", ip),
                blocked: true,
            });
        }

        // Check blacklist - if IP is in any blacklisted network, block it
        if self.ip_in_networks(&ip, &self.blacklist) {
            return Err(SecurityViolation {
                threat_type: "IP_BLACKLISTED".to_string(),
                threat_level: ThreatLevel::Critical,
                description: format!("IP {} is blacklisted", ip),
                blocked: true,
            });
        }

        Ok(())
    }

    /// Get the number of whitelist entries
    pub fn whitelist_count(&self) -> usize {
        self.whitelist.len()
    }

    /// Get the number of blacklist entries  
    pub fn blacklist_count(&self) -> usize {
        self.blacklist.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_ip_whitelist() {
        let mut filter = IpFilter::new(true);
        filter.add_to_whitelist("192.168.1.1").unwrap();

        assert!(filter.check_ip("192.168.1.1").is_ok());
        assert!(filter.check_ip("192.168.1.2").is_err());
    }

    #[test]
    fn test_cidr_whitelist() {
        let mut filter = IpFilter::new(true);
        filter.add_to_whitelist("192.168.1.0/24").unwrap();

        // IPs in range should be allowed
        assert!(filter.check_ip("192.168.1.1").is_ok());
        assert!(filter.check_ip("192.168.1.100").is_ok());
        assert!(filter.check_ip("192.168.1.255").is_ok());

        // IPs outside range should be blocked
        assert!(filter.check_ip("192.168.2.1").is_err());
        assert!(filter.check_ip("10.0.0.1").is_err());
    }

    #[test]
    fn test_cidr_blacklist() {
        let mut filter = IpFilter::new(true);
        filter.add_to_blacklist("10.0.0.0/8").unwrap();

        // IPs in blacklisted range should be blocked
        assert!(filter.check_ip("10.0.0.1").is_err());
        assert!(filter.check_ip("10.255.255.255").is_err());

        // IPs outside range should be allowed
        assert!(filter.check_ip("192.168.1.1").is_ok());
    }

    #[test]
    fn test_single_ip_blacklist() {
        let mut filter = IpFilter::new(true);
        filter.add_to_blacklist("192.168.1.100").unwrap();

        assert!(filter.check_ip("192.168.1.100").is_err());
        assert!(filter.check_ip("192.168.1.101").is_ok());
    }

    #[test]
    fn test_disabled_filter() {
        let mut filter = IpFilter::new(false);
        filter.add_to_blacklist("0.0.0.0/0").unwrap(); // Block everything

        // Should still allow because filter is disabled
        assert!(filter.check_ip("192.168.1.1").is_ok());
    }

    #[test]
    fn test_ipv6_cidr() {
        let mut filter = IpFilter::new(true);
        filter.add_to_whitelist("2001:db8::/32").unwrap();

        assert!(filter.check_ip("2001:db8::1").is_ok());
        assert!(filter.check_ip("2001:db9::1").is_err());
    }

    #[test]
    fn test_mixed_whitelist_blacklist() {
        let mut filter = IpFilter::new(true);
        filter.add_to_whitelist("192.168.0.0/16").unwrap();
        filter.add_to_blacklist("192.168.1.100").unwrap();

        // In whitelist but also in blacklist - blacklist wins
        assert!(filter.check_ip("192.168.1.100").is_err());

        // In whitelist, not in blacklist - allowed
        assert!(filter.check_ip("192.168.1.1").is_ok());

        // Not in whitelist - blocked
        assert!(filter.check_ip("10.0.0.1").is_err());
    }

    #[test]
    fn test_invalid_cidr() {
        let mut filter = IpFilter::new(true);

        assert!(filter.add_to_whitelist("invalid").is_err());
        assert!(filter.add_to_whitelist("192.168.1.0/33").is_err());
    }
}
