use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use super::{SecurityViolation, ThreatLevel};

pub struct IpFilter {
    pub whitelist: HashSet<IpAddr>,
    pub blacklist: HashSet<IpAddr>,
    pub enabled: bool,
}

impl IpFilter {
    pub fn new(enabled: bool) -> Self {
        Self {
            whitelist: HashSet::new(),
            blacklist: HashSet::new(),
            enabled,
        }
    }

    pub fn add_to_whitelist(&mut self, ip: &str) -> Result<(), String> {
        let addr = IpAddr::from_str(ip).map_err(|e| e.to_string())?;
        self.whitelist.insert(addr);
        Ok(())
    }

    pub fn add_to_blacklist(&mut self, ip: &str) -> Result<(), String> {
        let addr = IpAddr::from_str(ip).map_err(|e| e.to_string())?;
        self.blacklist.insert(addr);
        Ok(())
    }

    pub fn check_ip(&self, ip_str: &str) -> Result<(), SecurityViolation> {
        if !self.enabled {
            return Ok(());
        }

        let ip = match IpAddr::from_str(ip_str) {
            Ok(addr) => addr,
            Err(_) => return Ok(()),
        };

        // Check whitelist first
        if !self.whitelist.is_empty() && !self.whitelist.contains(&ip) {
            return Err(SecurityViolation {
                threat_type: "IP_NOT_WHITELISTED".to_string(),
                threat_level: ThreatLevel::High,
                description: format!("IP {} not in whitelist", ip),
                blocked: true,
            });
        }

        // Check blacklist
        if self.blacklist.contains(&ip) {
            return Err(SecurityViolation {
                threat_type: "IP_BLACKLISTED".to_string(),
                threat_level: ThreatLevel::Critical,
                description: format!("IP {} is blacklisted", ip),
                blocked: true,
            });
        }

        Ok(())
    }
}
