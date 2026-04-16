use crate::models::{LogRecord, ParsingQuality};
use crate::parsers::{LogParser, parse_timestamp_robust};
use chrono::{DateTime, Local};
use std::collections::BTreeMap;

/// The Forensic CSV Parser: Engineered for high-fidelity structured audit trails.
pub struct CsvParser;

impl CsvParser {
    pub fn new() -> Self {
        Self
    }

    /// Specialized CBS Log Merger: Joins split Date and Time columns into a single Local timestamp.
    fn merge_cbs_timestamp(&self, date: &str, time: &str) -> (DateTime<Local>, ParsingQuality) {
        let combined = format!("{}T{}", date, time);
        parse_timestamp_robust(&combined)
    }
}

impl Default for CsvParser {
    fn default() -> Self {
        Self::new()
    }
}

impl LogParser for CsvParser {
    fn format_name(&self) -> &str {
        "csv_cbs"
    }

    fn parse(&self, raw: &str) -> LogRecord {
        // 0. Header Guard & Zero-Drop Fidelity (NIST AU-2)
        if raw.trim().is_empty() || raw.starts_with("LineId,Date,Time") {
            return LogRecord {
                timestamp: Local::now(),
                message: if raw.trim().is_empty() { String::new() } else { "CSV_HEADER: Schema Definition".to_string() },
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
                ..Default::default()
            };
        }

        let parts: Vec<String> = raw.split(',').map(|s| s.trim().to_string()).collect();
        let mut quality = ParsingQuality::Success;
        let mut additional_context = None;
        let mut unparsed_raw = None;

        // 1. Forensic Timestamp (AU-3.b) with Degraded Fallback
        let (timestamp, ts_quality) = if parts.len() >= 3 {
            self.merge_cbs_timestamp(&parts[1], &parts[2])
        } else {
            quality = ParsingQuality::Degraded;
            unparsed_raw = Some(raw.to_string());
            (Local::now(), ParsingQuality::PartialTimestamp)
        };

        if matches!(ts_quality, ParsingQuality::PartialTimestamp) && quality != ParsingQuality::Degraded {
            quality = ParsingQuality::PartialTimestamp;
        }

        // 2. Structured Mapping (Target Header: LineId,Date,Time,Level,Component,Content,EventId,EventTemplate)
        let line_id = parts.first().cloned().unwrap_or_default();
        let severity = parts.get(3).cloned();
        let source = parts.get(4).cloned();
        let message = parts.get(5).cloned().unwrap_or_else(|| {
            if parts.len() < 6 {
                quality = ParsingQuality::Degraded;
                unparsed_raw = Some(raw.to_string());
                "DEGRADED: Schema Mismatch".to_string()
            } else {
                "SALVAGED: No content field".to_string()
            }
        });

        // 3. Overflow/Anomaly Capture (NIST AU-2 Catch-all)
        if parts.len() > 8 {
            quality = ParsingQuality::Malformed;
            additional_context = Some(serde_json::to_value(&parts).unwrap_or(serde_json::Value::Null));
        }

        // 4. Metadata Enrichment
        let mut metadata = BTreeMap::new();
        if parts.len() > 6 { metadata.insert("event_id".to_string(), parts[6].clone()); }
        if parts.len() > 7 { metadata.insert("event_template".to_string(), parts[7].clone()); }
        metadata.insert("line_id".to_string(), line_id);

        LogRecord {
            timestamp,
            message,
            severity,
            source,
            subject_id: None,
            outcome: if quality == ParsingQuality::Degraded { Some("Degraded".to_string()) } else { Some("Success".to_string()) },
            metadata,
            additional_context,
            raw: raw.to_string(),
            unparsed_raw,
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
