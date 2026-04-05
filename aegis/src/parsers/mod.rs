use crate::models::{LogRecord, ParsingQuality};
use chrono::{DateTime, Utc, TimeZone};

pub mod json;
pub mod plain;

pub trait LogParser: Send + Sync {
    fn parse(&self, raw: &str) -> Option<LogRecord>;
    fn format_name(&self) -> &str;
    fn as_any(&self) -> &dyn std::any::Any;
}

/// The "Chrono-Chain": Robust best-effort timestamp parsing for NIST accountability.
pub fn parse_timestamp_robust(s: &str) -> (DateTime<Utc>, ParsingQuality) {
    // 1. Try RFC3339 (Standard Cloud JSON format)
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return (dt.with_timezone(&Utc), ParsingQuality::Success);
    }

    // 2. Try ISO8601/RFC2822 variants
    if let Ok(dt) = DateTime::parse_from_rfc2822(s) {
        return (dt.with_timezone(&Utc), ParsingQuality::Success);
    }

    if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ") {
        return (dt.with_timezone(&Utc), ParsingQuality::Success);
    }

    // 4. Try Unix Timestamps (Seconds or Milliseconds)
    if let Ok(ts) = s.parse::<i64>() {
        // Simple heuristic: if it's too large, it's probably milliseconds
        if ts > 10_000_000_000 {
            if let Some(dt) = Utc.timestamp_opt(ts / 1000, (ts % 1000) as u32 * 1_000_000).single() {
                return (dt, ParsingQuality::Success);
            }
        } else {
             if let Some(dt) = Utc.timestamp_opt(ts, 0).single() {
                return (dt, ParsingQuality::Success);
            }
        }
    }

    // 5. Fallback: System Local Time (Audit Warning)
    (Utc::now(), ParsingQuality::PartialTimestamp)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogFormat {
    JsonArray,
    NdJson,
    PlainText,
    Auto,
}

pub struct AutoDetector;

impl AutoDetector {
    pub fn detect(content: &[u8]) -> LogFormat {
        // Handle potential BOM (Byte Order Mark)
        let s = if content.starts_with(&[0xEF, 0xBB, 0xBF]) {
            String::from_utf8_lossy(&content[3..])
        } else {
            String::from_utf8_lossy(content)
        };
        
        let trimmed = s.trim_start();
        if trimmed.starts_with('[') {
            LogFormat::JsonArray
        } else if trimmed.starts_with('{') {
            LogFormat::NdJson
        } else {
            LogFormat::PlainText
        }
    }
}
