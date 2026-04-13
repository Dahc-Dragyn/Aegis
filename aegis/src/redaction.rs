use regex::Regex;
use once_cell::sync::Lazy;
use crate::models::RedactionEvent;

/// NIST AU-13 Redaction Engine: Targeting high-risk data exposures while preserving IoCs (IPs/MACs).
static SSN_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());
static CREDIT_CARD_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap());
static API_KEY_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)(?:api[\s_-]?key|secret|token|password|auth[\s_-]?key|access[\s_-]?key)["\s:=]+([a-zA-Z0-9_\-\.]{16,64})"#).unwrap());
static PRIVATE_KEY_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----").unwrap());

pub struct RedactionEngine;

impl RedactionEngine {
    pub fn redact(input: &str) -> (String, Vec<RedactionEvent>) {
        let mut output = input.to_string();
        let mut events = Vec::new();

        // 1. Redact SSNs
        let ssn_matches = SSN_REGEX.find_iter(&output).count();
        if ssn_matches > 0 {
            output = SSN_REGEX.replace_all(&output, "[REDACTED_NIST_AU13_SSN]").into_owned();
            events.push(RedactionEvent { reason: "Social Security Number (PII)".to_string(), count: ssn_matches });
        }

        // 2. Redact Credit Cards (Filtering out Windows SIDs like S-1-5-21...)
        let mut cc_matches = 0;
        let mut final_output = output.clone();
        for mat in CREDIT_CARD_REGEX.find_iter(&output) {
            let matched_str = mat.as_str();
            // Heuristic: If it's part of a SID (contains 'S-1-'), skip redaction
            let start = mat.start();
            let prefix = if start >= 4 { &output[start-4..start] } else { "" };
            
            if !prefix.contains("S-1-") && !matched_str.contains("S-1-") {
                final_output = final_output.replace(matched_str, "[REDACTED_NIST_AU13_CC]");
                cc_matches += 1;
            }
        }
        output = final_output;
        if cc_matches > 0 {
            events.push(RedactionEvent { reason: "Credit Card Data (Financial)".to_string(), count: cc_matches });
        }

        // 3. Redact API Keys / Secrets
        let mut api_matches = 0;
        // Using a loop to avoid redacting the labels themselves
        while let Some(caps) = API_KEY_REGEX.captures(&output) {
            if let Some(mat) = caps.get(1) {
                let range = mat.range();
                output.replace_range(range, "[REDACTED_NIST_AU13_SECRET]");
                api_matches += 1;
            } else { break; }
        }
        if api_matches > 0 {
            events.push(RedactionEvent { reason: "API Key / Secret (NIST AC-3)".to_string(), count: api_matches });
        }

        // 4. Redact Private Keys
        let pk_matches = PRIVATE_KEY_REGEX.find_iter(&output).count();
        if pk_matches > 0 {
            output = PRIVATE_KEY_REGEX.replace_all(&output, "[REDACTED_NIST_AU13_PRIVATE_KEY]").into_owned();
            events.push(RedactionEvent { reason: "Private Key Material (Cryptographic)".to_string(), count: pk_matches });
        }

        (output, events)
    }
}
