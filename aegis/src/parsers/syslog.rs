use crate::models::{LogRecord, ParsingQuality};
use crate::parsers::{LogParser, parse_timestamp_robust};

use regex::Regex;
use once_cell::sync::Lazy;
use std::collections::BTreeMap;

pub struct SyslogParser;

static RFC5424_REGEX: Lazy<Regex> = Lazy::new(|| {
    // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
    Regex::new(r"^<(\d+)>(\d+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+(?:\[.*\])?\s*(.*)$")
        .expect("Invalid RFC5424 RegEx")
});

static RFC3164_REGEX: Lazy<Regex> = Lazy::new(|| {
    // <PRI>TIMESTAMP HOSTNAME TAG: MSG
    // Example: <34>Oct 11 22:14:15 mymachine su: 'su root' failed
    Regex::new(r"^<(\d+)>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+([^:\s]+):?\s*(.*)$")
        .expect("Invalid RFC3164 RegEx")
});

static BARE_3164_REGEX: Lazy<Regex> = Lazy::new(|| {
    // TIMESTAMP HOSTNAME TAG: MSG (No PRI)
    // Example: Oct 11 22:14:15 mymachine su: 'su root' failed
    Regex::new(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+([^:\s]+):?\s*(.*)$")
        .expect("Invalid Bare 3164 RegEx")
});

static ISO_SYSLOG_REGEX: Lazy<Regex> = Lazy::new(|| {
    // ISO8601 HOSTNAME TAG [PID]: MSG
    // Example: 2026-04-05T00:00:03.839855-07:00 aiyodaserver systemd[1]: ...
    Regex::new(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+([^\s]+)\s+([^:\[\s]+)(?:\[(\d+)\])?:\s*(.*)$")
        .expect("Invalid ISO Syslog RegEx")
});

static NETLOGON_REGEX: Lazy<Regex> = Lazy::new(|| {
    // MM/DD HH:MM:SS [LEVEL] [PID] MSG
    // Example: 09/14 12:33:07 [CRITICAL] [3352] Domain01: NetrServerAuthenticate: Bad password 0
    Regex::new(r"^(\d{2}/\d{2}\s\d{2}:\d{2}:\d{2})\s\[([^\]]+)\]\s(?:\[(\d+)\]\s)?(.*)$")
        .expect("Invalid Netlogon RegEx")
});

impl LogParser for SyslogParser {
    fn format_name(&self) -> &str {
        "syslog"
    }

    fn parse(&self, raw: &str) -> LogRecord {
        let trimmed = raw.trim();
        let mut metadata = BTreeMap::new();
        
        // 1. Try RFC 5424 (Modern)
        if let Some(caps) = RFC5424_REGEX.captures(trimmed) {
            let pri = caps.get(1).map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(0));
            let facility = pri >> 3;
            let severity_num = pri & 7;

            metadata.insert("syslog_priority".to_string(), pri.to_string());
            metadata.insert("syslog_facility".to_string(), facility.to_string());
            metadata.insert("syslog_severity_num".to_string(), severity_num.to_string());
            metadata.insert("hostname".to_string(), caps.get(4).map_or("-", |m| m.as_str()).to_string());
            metadata.insert("app_name".to_string(), caps.get(5).map_or("-", |m| m.as_str()).to_string());
            metadata.insert("proc_id".to_string(), caps.get(6).map_or("-", |m| m.as_str()).to_string());
            metadata.insert("msg_id".to_string(), caps.get(7).map_or("-", |m| m.as_str()).to_string());

            let (timestamp, quality) = parse_timestamp_robust(caps.get(3).map_or("", |m| m.as_str()));
            let message = caps.get(8).map_or("", |m| m.as_str()).to_string();

            return LogRecord {
                timestamp,
                message,
                severity: Some(map_severity(severity_num)),
                source: Some("syslog_rfc5424".to_string()),
                metadata,
                raw: raw.to_string(),
                original_format: self.format_name().to_string(),
                quality,
                ..Default::default()
            };
        }

        // 2. Try RFC 3164 (Legacy/BSD)
        if let Some(caps) = RFC3164_REGEX.captures(trimmed) {
            let pri = caps.get(1).map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(0));
            let severity_num = pri & 7;

            metadata.insert("syslog_priority".to_string(), pri.to_string());
            metadata.insert("hostname".to_string(), caps.get(3).map_or("-", |m| m.as_str()).to_string());
            metadata.insert("tag".to_string(), caps.get(4).map_or("-", |m| m.as_str()).to_string());

            let (timestamp, quality) = parse_timestamp_robust(caps.get(2).map_or("", |m| m.as_str()));
            let message = caps.get(5).map_or("", |m| m.as_str()).to_string();

            return LogRecord {
                timestamp,
                message,
                severity: Some(map_severity(severity_num)),
                source: Some("syslog_rfc3164".to_string()),
                metadata,
                raw: raw.to_string(),
                original_format: self.format_name().to_string(),
                quality,
                ..Default::default()
            };
        }

        // 3. Try Bare RFC 3164 (No PRI)
        if let Some(caps) = BARE_3164_REGEX.captures(trimmed) {
            metadata.insert("hostname".to_string(), caps.get(2).map_or("-", |m| m.as_str()).to_string());
            metadata.insert("tag".to_string(), caps.get(3).map_or("-", |m| m.as_str()).to_string());

            let (timestamp, quality) = parse_timestamp_robust(caps.get(1).map_or("", |m| m.as_str()));
            let message = caps.get(4).map_or("", |m| m.as_str()).to_string();

            return LogRecord {
                timestamp,
                message,
                severity: Some("INFO".to_string()), // Default since no PRI
                source: Some("syslog_bare".to_string()),
                metadata,
                raw: raw.to_string(),
                original_format: self.format_name().to_string(),
                quality,
                ..Default::default()
            };
        }

        // 4. Try ISO Syslog (No PRI)
        if let Some(caps) = ISO_SYSLOG_REGEX.captures(trimmed) {
            metadata.insert("hostname".to_string(), caps.get(2).map_or("-", |m| m.as_str()).to_string());
            metadata.insert("tag".to_string(), caps.get(3).map_or("-", |m| m.as_str()).to_string());
            if let Some(pid) = caps.get(4) {
                metadata.insert("pid".to_string(), pid.as_str().to_string());
            }

            let (timestamp, quality) = parse_timestamp_robust(caps.get(1).map_or("", |m| m.as_str()));
            let message = caps.get(5).map_or("", |m| m.as_str()).to_string();

            return LogRecord {
                timestamp,
                message,
                severity: Some("INFO".to_string()),
                source: Some("syslog_iso".to_string()),
                metadata,
                raw: raw.to_string(),
                original_format: self.format_name().to_string(),
                quality,
                ..Default::default()
            };
        }

        // 5. Try Netlogon Legacy Format
        if let Some(caps) = NETLOGON_REGEX.captures(trimmed) {
            let sev_str = caps.get(2).map_or("INFO", |m| m.as_str()).to_string();
            if let Some(pid) = caps.get(3) {
                metadata.insert("pid".to_string(), pid.as_str().to_string());
            }

            let (timestamp, quality) = parse_timestamp_robust(caps.get(1).map_or("", |m| m.as_str()));
            let message = caps.get(4).map_or("", |m| m.as_str()).to_string();

            return LogRecord {
                timestamp,
                message,
                severity: Some(sev_str.to_uppercase()),
                source: Some("syslog_netlogon".to_string()),
                metadata,
                raw: raw.to_string(),
                original_format: self.format_name().to_string(),
                quality,
                ..Default::default()
            };
        }

        // 5. Fallback: Degraded parsing if it looks like syslog but doesn't match perfectly
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

fn map_severity(syslog_sev: u32) -> String {
    match syslog_sev {
        0..=1 => "CRITICAL".to_string(),
        2..=3 => "ERROR".to_string(),
        4 => "WARNING".to_string(),
        5..=6 => "INFO".to_string(),
        7 => "DEBUG".to_string(),
        _ => "INFO".to_string(),
    }
}
