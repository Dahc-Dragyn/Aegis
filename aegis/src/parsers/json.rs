use crate::models::{LogRecord, ParsingQuality};
use crate::parsers::{LogParser, parse_timestamp_robust};
use crate::config::LogFormatConfig;
use serde_json::Value;
use std::collections::BTreeMap;
use chrono::Local;

pub struct JsonParser {
    config: LogFormatConfig,
    name: String,
}

impl JsonParser {
    pub fn new(config: LogFormatConfig, name: &str) -> Self {
        Self { 
            config,
            name: name.to_string(),
        }
    }

    fn get_nested_value<'a>(&self, val: &'a Value, path: &str) -> Option<&'a Value> {
        let mut current = val;
        for part in path.split('.') {
            current = current.get(part)?;
        }
        Some(current)
    }

    pub fn parse_value(&self, v: Value, raw: &str) -> LogRecord {
        let mut quality = ParsingQuality::Success;
        let mut unparsed_raw = None;

        // 1. Extract Timestamp (Chrono-Chain Robustness)
        let ts_field = self.config.timestamp_field.as_deref().unwrap_or("timestamp");
        let (timestamp, ts_quality) = if let Some(ts_str) = self.get_nested_value(&v, ts_field).and_then(|v| v.as_str()) {
            parse_timestamp_robust(ts_str)
        } else {
            (Local::now(), ParsingQuality::PartialTimestamp)
        };

        if matches!(ts_quality, ParsingQuality::PartialTimestamp) {
            quality = ParsingQuality::PartialTimestamp;
        }

        // 2. Extract Message (No-Pamper Zero-Loss Mapping)
        // NIST Hardening: Priority for forensic context (Process Command Line)
        let msg_fields = ["message", "textPayload", "log", "msg"];
        let mut message = None;
        
        // Elastic/Endpoint Forensic Priority: Use command_line if message is generic
        if let Some(cmd) = self.get_nested_value(&v, "_source.process.command_line").and_then(|v| v.as_str()) {
             message = Some(cmd.to_string());
        }

        if message.is_none() {
            if let Some(field) = &self.config.message_field {
                if let Some(m) = self.get_nested_value(&v, field).and_then(|v| v.as_str()) {
                    message = Some(m.to_string());
                }
            }
        }

        if message.is_none() {
            for f in msg_fields {
                if let Some(m) = self.get_nested_value(&v, f).and_then(|v| v.as_str()) {
                    message = Some(m.to_string());
                    break;
                }
            }
        }

        // NIST Hardening: If we can't find a message, we mark as Degraded but capture the JSON object
        let message = message.unwrap_or_else(|| {
            quality = ParsingQuality::Degraded;
            unparsed_raw = Some(raw.to_string());
            "DEGRADED: No message field found".to_string()
        });

        // 3. Extract Severity
        let sev_fields = ["severity", "level", "logLevel"];
        let mut severity = None;
        if let Some(field) = &self.config.severity_field {
            severity = self.get_nested_value(&v, field).and_then(|v| v.as_str()).map(|s| s.to_string());
        }
        if severity.is_none() {
            for f in sev_fields {
                if let Some(s) = self.get_nested_value(&v, f).and_then(|v| v.as_str()) {
                    severity = Some(s.to_string());
                    break;
                }
            }
        }

        // 4. Populate Metadata (NIST AU-3)
        let mut metadata = BTreeMap::new();
        for (key, path) in &self.config.metadata_map {
            if let Some(val) = self.get_nested_value(&v, path) {
                let clean_val = match val {
                    Value::String(s) => s.clone(),
                    _ => val.to_string(),
                };
                metadata.insert(key.clone(), clean_val);
            }
        }

        // Forensic Mirroring: Ensure extracted message is available as metadata for attribution
        metadata.insert("captured_message".to_string(), message.clone());

        LogRecord {
            timestamp,
            message,
            severity,
            source: Some(self.format_name().to_string()),
            subject_id: None,
            outcome: if quality == ParsingQuality::Degraded { Some("Degraded".to_string()) } else { Some("Success".to_string()) },
            metadata,
            additional_context: Some(v.clone()),
            raw: raw.to_string(),
            unparsed_raw,
            original_format: self.format_name().to_string(),
            quality,
            incident_id: None,
            redactions: Vec::new(),
            bridge_hash: None,
            chain_hash: None,
        }
    }
}

impl LogParser for JsonParser {
    fn format_name(&self) -> &str {
        &self.name
    }

    fn parse(&self, raw: &str) -> LogRecord {
        let trimmed = raw.trim();
        
        // Zero-Drop Fidelity: Every newline is an event (NIST AU-2)
        if trimmed.is_empty() {
             return LogRecord {
                timestamp: Local::now(),
                message: String::new(),
                severity: Some("INFO".to_string()),
                source: Some(self.format_name().to_string()),
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
            };
        }

        let mut stream = serde_json::Deserializer::from_str(trimmed).into_iter::<Value>();
        match stream.next() {
            Some(Ok(v)) => self.parse_value(v, raw),
            _ => {
                // Return Degraded for malformed JSON
                LogRecord {
                    timestamp: Local::now(),
                    message: "DEGRADED: Malformed JSON".to_string(),
                    severity: Some("WARN".to_string()),
                    source: Some(self.format_name().to_string()),
                    subject_id: None,
                    outcome: Some("Degraded".to_string()),
                    metadata: BTreeMap::new(),
                    additional_context: None,
                    raw: raw.to_string(),
                    unparsed_raw: Some(raw.to_string()),
                    original_format: self.format_name().to_string(),
                    quality: ParsingQuality::Degraded,
                    incident_id: None,
                    redactions: Vec::new(),
                    bridge_hash: None,
                    chain_hash: None,
                }
            }
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
