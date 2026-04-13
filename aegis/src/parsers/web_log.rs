use crate::models::{LogRecord, ParsingQuality};
use crate::parsers::{LogParser, parse_timestamp_robust};

use regex::Regex;
use once_cell::sync::Lazy;
use std::collections::BTreeMap;

pub struct WebLogParser;

static COMBINED_LOG_REGEX: Lazy<Regex> = Lazy::new(|| {
    // 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "http://referer.com" "Mozilla/4.0"
    Regex::new(r#"^([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s]+)\s+([^"]+)"\s+(\d+)\s+([^\s]+)(?:\s+"([^"]*)"\s+"([^"]*)")?.*$"#)
        .expect("Invalid Web Log RegEx")
});

impl LogParser for WebLogParser {
    fn format_name(&self) -> &str {
        "web_access"
    }

    fn parse(&self, raw: &str) -> LogRecord {
        let trimmed = raw.trim();
        let mut metadata = BTreeMap::new();

        if let Some(caps) = COMBINED_LOG_REGEX.captures(trimmed) {
            metadata.insert("client_ip".to_string(), caps.get(1).map_or("-", |m| m.as_str()).to_string());
            metadata.insert("http_method".to_string(), caps.get(5).map_or("-", |m| m.as_str()).to_string());
            metadata.insert("http_path".to_string(), caps.get(6).map_or("-", |m| m.as_str()).to_string());
            metadata.insert("http_protocol".to_string(), caps.get(7).map_or("-", |m| m.as_str()).to_string());
            
            let status_code = caps.get(8).map_or("000", |m| m.as_str());
            metadata.insert("http_status".to_string(), status_code.to_string());
            metadata.insert("body_bytes_sent".to_string(), caps.get(9).map_or("0", |m| m.as_str()).to_string());
            
            if let Some(ref_cap) = caps.get(10) {
                metadata.insert("http_referer".to_string(), ref_cap.as_str().to_string());
            }
            if let Some(ua_cap) = caps.get(11) {
                metadata.insert("user_agent".to_string(), ua_cap.as_str().to_string());
            }

            let raw_ts = caps.get(4).map_or("", |m| m.as_str());
            // Web logs often use [10/Oct/2000:13:55:36 -0700] format.
            // parse_timestamp_robust will handle this or fall back.
            let (timestamp, quality) = parse_timestamp_robust(raw_ts);

            return LogRecord {
                timestamp,
                message: format!("{} {} {} -> {}", 
                    metadata.get("http_method").unwrap(),
                    metadata.get("http_path").unwrap(),
                    metadata.get("http_protocol").unwrap(),
                    status_code
                ),
                severity: Some(map_http_status_to_severity(status_code)),
                source: Some("web_log".to_string()),
                metadata,
                raw: raw.to_string(),
                original_format: self.format_name().to_string(),
                quality,
                ..Default::default()
            };
        }

        // Fallback for error logs or non-combined format
        LogRecord {
            message: trimmed.to_string(),
            raw: raw.to_string(),
            original_format: self.format_name().to_string(),
            quality: ParsingQuality::Degraded,
            ..Default::default()
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn map_http_status_to_severity(status: &str) -> String {
    if status.starts_with('5') {
        "ERROR".to_string()
    } else if status.starts_with('4') {
        "WARNING".to_string()
    } else {
        "INFO".to_string()
    }
}
