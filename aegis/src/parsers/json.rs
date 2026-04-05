use crate::models::{LogRecord, ParsingQuality};
use crate::parsers::{LogParser, parse_timestamp_robust};
use crate::config::LogFormatConfig;
use serde_json::Value;
use std::collections::HashMap;

pub struct JsonParser {
    config: LogFormatConfig,
}

impl JsonParser {
    pub fn new(config: LogFormatConfig) -> Self {
        Self { config }
    }

    fn get_nested_value<'a>(&self, val: &'a Value, path: &str) -> Option<&'a Value> {
        let mut current = val;
        for part in path.split('.') {
            current = current.get(part)?;
        }
        Some(current)
    }

    pub fn parse_value(&self, v: Value, raw: &str) -> Option<LogRecord> {
        // 1. Extract Timestamp (Chrono-Chain Robustness)
        let ts_field = self.config.timestamp_field.as_deref().unwrap_or("timestamp");
        let (timestamp, quality) = if let Some(ts_str) = self.get_nested_value(&v, ts_field).and_then(|v| v.as_str()) {
            parse_timestamp_robust(ts_str)
        } else {
            (chrono::Utc::now(), ParsingQuality::PartialTimestamp)
        };

        // 2. Extract Message (No-Pamper Zero-Loss Mapping)
        // Check configured field first, then probe for common message fields, then fall back to raw JSON
        let msg_fields = ["message", "textPayload", "log", "msg"];
        let mut message = None;
        
        if let Some(field) = &self.config.message_field {
            if let Some(m) = self.get_nested_value(&v, field).and_then(|v| v.as_str()) {
                message = Some(m.to_string());
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

        // Fallback to the whole object as a string if no text field is found (FORENSIC MODE)
        let message = message.unwrap_or_else(|| v.to_string());

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

        // 4. Extract Source
        let source = self.config.source_field.as_deref()
            .and_then(|path| self.get_nested_value(&v, path))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // 5. Populate Metadata
        let mut metadata = HashMap::new();
        for (key, path) in &self.config.metadata_map {
            if let Some(val) = self.get_nested_value(&v, path) {
                let val_str = match val {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => val.to_string(),
                };
                metadata.insert(key.clone(), val_str);
            }
        }

        // 6. Extract Subject / Identity (AU-3.f)
        let id_fields = ["user", "uid", "principal", "userId", "email"];
        let mut subject_id = None;
        for f in id_fields {
            if let Some(id) = self.get_nested_value(&v, f).and_then(|v| v.as_str()) {
                subject_id = Some(id.to_string());
                break;
            }
        }

        // 7. Extract Outcome (AU-3.e)
        let outcome_fields = ["status", "result", "outcome", "exit_code"];
        let mut outcome = None;
        for f in outcome_fields {
            if let Some(o) = self.get_nested_value(&v, f).and_then(|v| v.as_str()) {
                outcome = Some(o.to_string());
                break;
            }
        }

        Some(LogRecord {
            timestamp,
            message,
            severity,
            source,
            subject_id,
            outcome,
            metadata,
            raw: raw.to_string(),
            original_format: self.format_name().to_string(),
            quality,
            redactions: Vec::new(),
        })
    }
}

impl LogParser for JsonParser {
    fn format_name(&self) -> &str {
        "json_configurable"
    }

    fn parse(&self, raw: &str) -> Option<LogRecord> {
        let v: Value = serde_json::from_str(raw).ok()?;
        self.parse_value(v, raw)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
