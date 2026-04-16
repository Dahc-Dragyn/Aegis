use crate::models::{LogRecord, ParsingQuality};
use crate::parsers::{LogParser, parse_timestamp_robust};
use chrono::Local;
use regex::Regex;
use once_cell::sync::Lazy;
use std::collections::BTreeMap;

pub struct PlainTextParser;

static TIMESTAMP_REGEX: Lazy<Regex> = Lazy::new(|| {
    // Basic regex for common syslog/auth.log timestamp patterns (e.g., Apr 03 09:07:50)
    Regex::new(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}").expect("Invalid RegEx")
});

impl LogParser for PlainTextParser {
    fn format_name(&self) -> &str {
        "plaintext_fallback"
    }

    fn parse(&self, raw: &str) -> LogRecord {
        let trimmed = raw.trim();
        
        // Zero-Drop Fidelity: Every newline is an event (NIST AU-2)
        if trimmed.is_empty() {
             return LogRecord {
                timestamp: Local::now(),
                message: String::new(),
                severity: Some("INFO".to_string()),
                source: Some("local_file".to_string()),
                subject_id: None,
                outcome: Some("Success".to_string()),
                metadata: BTreeMap::new(),
                additional_context: None,
                raw: raw.to_string(),
                unparsed_raw: Some(raw.to_string()),
                original_format: self.format_name().to_string(),
                quality: ParsingQuality::Success,
                incident_id: None,
                redactions: Vec::new(),
                bridge_hash: None,
                chain_hash: None,
                ..Default::default()
            };
        }

        // 1. Best-effort Timestamp Extraction
        let (timestamp, quality) = if let Some(mat) = TIMESTAMP_REGEX.find(trimmed) {
             parse_timestamp_robust(mat.as_str())
        } else {
            (Local::now(), ParsingQuality::PartialTimestamp)
        };

        // 2. Simple severity detection (INFO, ERROR, WARN)
        let severity = if trimmed.to_uppercase().contains("ERROR") || trimmed.to_uppercase().contains("FAIL") {
            Some("ERROR".to_string())
        } else if trimmed.to_uppercase().contains("WARN") {
            Some("WARNING".to_string())
        } else {
            Some("INFO".to_string())
        };

        LogRecord {
            timestamp,
            message: trimmed.to_string(),
            severity,
            source: Some("local_file".to_string()),
            subject_id: None,
            outcome: if quality == ParsingQuality::Degraded { Some("Degraded".to_string()) } else { Some("Success".to_string()) },
            metadata: BTreeMap::new(),
            additional_context: None,
            raw: raw.to_string(),
            unparsed_raw: Some(raw.to_string()), // Preserving for byte-perfect AU-9 audit
            original_format: self.format_name().to_string(),
            quality,
            incident_id: None,
            redactions: Vec::new(),
            bridge_hash: None,
            chain_hash: None,
            ..Default::default()
        }
    }


    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
