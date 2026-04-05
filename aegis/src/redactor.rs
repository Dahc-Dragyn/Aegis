use regex::Regex;
use crate::config::RedactionConfig;
use once_cell::sync::Lazy;

use crate::models::RedactionEvent;

/// Privacy Redactor (AU-3 / Privacy Best Practice): Automatically masks sensitive 
/// patterns like IPs and security tokens to reduce exposure of audit data.
pub struct Redactor {
    patterns: Vec<Regex>,
    mask_ips: bool,
}

static IP_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").expect("Invalid IP Regex")
});

static TOKEN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(bearer|token|apikey|secret)[:=]\s*[a-zA-Z0-9\-_./]{8,}").expect("Invalid Token Regex")
});

impl Redactor {
    pub fn new(config: &RedactionConfig) -> Self {
        let mut patterns = Vec::new();
        patterns.push(TOKEN_REGEX.clone());

        for p in &config.patterns {
            if let Ok(re) = Regex::new(p) {
                patterns.push(re);
            }
        }

        Self {
            patterns,
            mask_ips: config.mask_ips,
        }
    }

    /// Performs the privacy redaction pass on a string, returning the sanitized 
    /// text and a manifest of redaction actions (AU-3 / Posture Accountability).
    pub fn redact(&self, input: &str) -> (String, Vec<RedactionEvent>) {
        let mut output = input.to_string();
        let mut redactions = Vec::new();

        // 1. Mask IPs if enabled
        if self.mask_ips {
            let mut ip_count = 0;
            output = IP_REGEX.replace_all(&output, |_: &regex::Captures| {
                ip_count += 1;
                "[REDACTED_IP]"
            }).to_string();
            
            if ip_count > 0 {
                redactions.push(RedactionEvent {
                    reason: "IP Masking".to_string(),
                    count: ip_count,
                });
            }
        }

        // 2. Apply all custom and token redaction patterns
        let mut sensitive_count = 0;
        for re in &self.patterns {
            output = re.replace_all(&output, |caps: &regex::Captures| {
                sensitive_count += 1;
                if caps.len() > 1 {
                    format!("{}: [REDACTED]", &caps[1])
                } else {
                    "[REDACTED_SENSITIVE]".to_string()
                }
            }).to_string();
        }

        if sensitive_count > 0 {
            redactions.push(RedactionEvent {
                reason: "Security Token Masking".to_string(),
                count: sensitive_count,
            });
        }

        (output, redactions)
    }
}
