use super::{SecurityRule, SecurityViolation};
use pingora::http::RequestHeader;
use std::sync::Arc;

pub struct RuleEngine {
    rules: Vec<Arc<dyn SecurityRule>>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: Arc<dyn SecurityRule>) {
        self.rules.push(rule);
    }

    pub fn evaluate_all(
        &self,
        request: &RequestHeader,
        body: Option<&[u8]>,
    ) -> Vec<SecurityViolation> {
        let mut violations = Vec::new();

        for rule in &self.rules {
            if let Err(violation) = rule.check(request, body) {
                violations.push(violation);
            }
        }

        violations
    }

    pub fn has_blocking_violation(&self, violations: &[SecurityViolation]) -> bool {
        violations.iter().any(|v| v.blocked)
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}
