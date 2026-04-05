use crate::models::{LogRecord, ParsingQuality};
use crate::parsers::{LogParser, parse_timestamp_robust};
use regex::Regex;
use once_cell::sync::Lazy;

pub struct PlainTextParser;

static TIMESTAMP_REGEX: Lazy<Regex> = Lazy::new(|| {
    // Basic regex for common syslog/auth.log timestamp patterns (e.g., Apr 03 09:07:50)
    Regex::new(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}").expect("Invalid RegEx")
});

impl LogParser for PlainTextParser {
    fn format_name(&self) -> &str {
        "plaintext_fallback"
    }

    fn parse(&self, raw: &str) -> Option<LogRecord> {
        let trimmed = raw.trim();
        if trimmed.is_empty() { return None; }

        // 1. Best-effort Timestamp Extraction
        let (timestamp, quality) = if let Some(mat) = TIMESTAMP_REGEX.find(trimmed) {
             parse_timestamp_robust(mat.as_str())
        } else {
            (chrono::Utc::now(), ParsingQuality::PartialTimestamp)
        };

        // 2. Simple severity detection (INFO, ERROR, WARN)
        let severity = if trimmed.to_uppercase().contains("ERROR") || trimmed.to_uppercase().contains("FAIL") {
            Some("ERROR".to_string())
        } else if trimmed.to_uppercase().contains("WARN") {
            Some("WARNING".to_string())
        } else {
            Some("INFO".to_string())
        };

        Some(LogRecord {
            timestamp,
            message: trimmed.to_string(),
            severity,
            source: Some("local_file".to_string()),
            subject_id: None,
            outcome: None,
            metadata: std::collections::HashMap::new(),
            raw: raw.to_string(),
            original_format: self.format_name().to_string(),
            quality,
            redactions: Vec::new(),
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
