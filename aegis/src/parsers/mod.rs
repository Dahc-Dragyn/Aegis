use crate::models::{LogRecord, ParsingQuality};
use chrono::{DateTime, Local, Utc, TimeZone};
use regex::Regex;

pub mod json;
pub mod plain;
pub mod csv;
pub mod evtx;
pub mod ai_proxy;
pub mod pcap;
pub mod syslog;
pub mod web_log;

pub trait LogParser: Send + Sync {
    fn parse(&self, raw: &str) -> LogRecord;
    fn format_name(&self) -> &str;
    fn as_any(&self) -> &dyn std::any::Any;
}

/// The "Chrono-Chain": Robust best-effort timestamp parsing for NIST accountability.
pub fn parse_timestamp_robust(s: &str) -> (DateTime<Local>, ParsingQuality) {
    // 1. Try RFC3339 (Standard Cloud JSON format)
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return (dt.with_timezone(&Local), ParsingQuality::Success);
    }

    // 2. Try ISO8601/RFC2822 variants
    if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return (dt.with_timezone(&Local), ParsingQuality::Success);
    }
    
    // 2b. Try Naive ISO8601 (often used in logs without offset)
    if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        if let Some(dt) = Local.from_local_datetime(&ndt).single() {
            return (dt, ParsingQuality::Success);
        }
    }

    if let Ok(dt) = DateTime::parse_from_rfc2822(s) {
        return (dt.with_timezone(&Local), ParsingQuality::Success);
    }

    if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ") {
        return (dt.with_timezone(&Local), ParsingQuality::Success);
    }

    // 4b. Try Netlogon Legacy Format (MM/DD HH:MM:SS) - Assume current year
    if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(&format!("{}/{}", Local::now().format("%Y"), s), "%Y/%m/%d %H:%M:%S") {
        if let Some(dt) = Local.from_local_datetime(&ndt).single() {
            return (dt, ParsingQuality::Success);
        }
    }

    // 4. Try Unix Timestamps (Seconds or Milliseconds)
    if let Ok(ts) = s.parse::<i64>() {
        // Simple heuristic: if it's too large, it's probably milliseconds
        if ts > 10_000_000_000 {
            if let Some(dt) = Utc.timestamp_opt(ts / 1000, (ts % 1000) as u32 * 1_000_000).single() {
                return (dt.with_timezone(&Local), ParsingQuality::Success);
            }
        } else {
            if let Some(dt) = Utc.timestamp_opt(ts, 0).single() {
                return (dt.with_timezone(&Local), ParsingQuality::Success);
            }
        }
    }

    // 5. Fallback: System Local Time (Audit Warning)
    (Local::now(), ParsingQuality::PartialTimestamp)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogFormat {
    JsonArray,
    NdJson,
    PlainText,
    Csv,
    Evtx,
    AiProxy,
    Pcap,
    Syslog,
    WebLog,
    Elastic,
    Auto,
}

pub struct AutoDetector;

impl AutoDetector {
    pub fn detect(content: &[u8], path: Option<&std::path::Path>) -> LogFormat {
        // 1. Binary Forensic Check (.evtx Magic: ElfFile\0)
        // NIST Hardening: Implement sliding window scan for potentially offset or corrupted headers
        let window_size = std::cmp::min(content.len(), 512);
        if window_size >= 8 {
            for i in 0..(window_size - 7) {
                if &content[i..i+8] == b"ElfFile\0" || &content[i..i+7] == b"ElfChnk" {
                    return LogFormat::Evtx;
                }
                // 1b. Network Magic: PCAP (0xa1b2c3d4) or PCAPNG (0x0A0D0D0A)
                if content[i..i+4] == [0xA1, 0xB2, 0xC3, 0xD4] || content[i..i+4] == [0xD4, 0xC3, 0xB2, 0xA1] {
                     return LogFormat::Pcap;
                }
                if content[i..i+4] == [0x0A, 0x0D, 0x0D, 0x0A] {
                     return LogFormat::Pcap;
                }
            }
        }

        // 2. File Extension Heuristic Fallback (User Directed)
        if let Some(p) = path {
            if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                match ext.to_lowercase().as_str() {
                    "evtx" => return LogFormat::Evtx,
                    "pcap" | "pcapng" => return LogFormat::Pcap,
                    "csv" => return LogFormat::Csv,
                    "syslog" | "auth" => return LogFormat::Syslog,
                    "access" | "error" => return LogFormat::WebLog,
                    "json" | "log" | "txt" => {}, // Defer to content-based check
                    _ => {}
                }
            }
        }

        // 3. String-Based Heuristic (AI RMF 100-1 Prioritization)
        let s = if content.starts_with(&[0xEF, 0xBB, 0xBF]) {
            String::from_utf8_lossy(&content[3..])
        } else {
            String::from_utf8_lossy(content)
        };
        
        let trimmed = s.trim_start();

        // 1. Specialized JSON Heuristics (Highest Priority)
        if trimmed.starts_with('{') {
            let lower = s.to_lowercase();
            if lower.contains("_index") || lower.contains("_source") || lower.contains("agent.type") || lower.contains("textpayload") {
                return LogFormat::Elastic;
            }
            if lower.contains("\"usage\"") || lower.contains("\"security_flags\"") {
                return LogFormat::AiProxy;
            }
        }

        // 2. Syslog & Netlogon Heuristics
        if (s.contains('<') && s.contains('>')) || 
           Regex::new(r"(?m)^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}").unwrap().is_match(&s) ||
           Regex::new(r"(?m)^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}").unwrap().is_match(&s) ||
           Regex::new(r"(?m)^\d{2}/\d{2}\s\d{2}:\d{2}:\d{2}\s\[").unwrap().is_match(&s) {
             return LogFormat::Syslog;
        }

        // 3. Web Access Log Heuristics (Common/Combined)
        if (s.contains("GET /") || s.contains("POST /") || s.contains("PUT /")) && 
           (s.contains("HTTP/1.1") || s.contains("HTTP/1.0") || s.contains("HTTP/2.0")) {
            return LogFormat::WebLog;
        }

        if trimmed.starts_with('[') {
            LogFormat::JsonArray
        } else if trimmed.starts_with('{') {
            LogFormat::NdJson
        } else if s.to_uppercase().contains("LINEID,DATE,TIME") {
            LogFormat::Csv
        } else {
            LogFormat::PlainText
        }
    }
}
