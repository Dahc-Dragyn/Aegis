use crate::models::{LogRecord, ParsingQuality};
use crate::parsers::{LogParser, parse_timestamp_robust};
use serde_json::Value;
use std::collections::BTreeMap;
use chrono::Local;

/// Splunk BOTS Schema Crosswalk Parser
/// Translates Splunk nested JSON exports into the Aegis LogRecord format.
pub struct SplunkParser;

impl SplunkParser {
    pub fn new() -> Self {
        Self
    }

    fn get_value<'a>(&self, v: &'a Value, key: &str) -> Option<&'a str> {
        v.get(key).and_then(|v| {
            match v {
                Value::String(s) => Some(s.as_str()),
                Value::Number(n) => Some(Box::leak(n.to_string().into_boxed_str())), // Handle numeric fields like EventCode
                _ => None,
            }
        })
    }
}

impl Default for SplunkParser {
    fn default() -> Self {
        Self::new()
    }
}

impl LogParser for SplunkParser {
    fn format_name(&self) -> &str {
        "splunk_bots"
    }

    fn parse(&self, raw: &str) -> LogRecord {
        let trimmed = raw.trim();
        let mut quality = ParsingQuality::Success;
        let unparsed_raw = None;

        // 1. Initial Parse (Matryoshka Unwrap)
        let root: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                return LogRecord {
                    timestamp: Local::now(),
                    message: "DEGRADED: Malformed Splunk JSON".to_string(),
                    severity: Some("WARN".to_string()),
                    source: Some(self.format_name().to_string()),
                    outcome: Some("Degraded".to_string()),
                    raw: raw.to_string(),
                    unparsed_raw: Some(raw.to_string()),
                    original_format: self.format_name().to_string(),
                    quality: ParsingQuality::Degraded,
                    ..Default::default()
                };
            }
        };

        // Drill into {"result": { ... }}
        let result = if let Some(r) = root.get("result") {
            r
        } else {
            // If not wrapped in result, treat the root as the result (Aegis Resilience)
            &root
        };

        // 2. Map _time -> timestamp
        let (timestamp, ts_quality) = if let Some(ts_str) = self.get_value(result, "_time") {
            parse_timestamp_robust(ts_str)
        } else {
            (Local::now(), ParsingQuality::PartialTimestamp)
        };

        if matches!(ts_quality, ParsingQuality::PartialTimestamp) {
            quality = ParsingQuality::PartialTimestamp;
        }

        // 3. Map _raw -> raw and message
        let raw_content = self.get_value(result, "_raw").unwrap_or("");
        let message = if !raw_content.is_empty() {
            raw_content.to_string()
        } else {
            // Fallback: use generic identification
            format!("Splunk Event: {}", self.get_value(result, "sourcetype").unwrap_or("unknown"))
        };

        // 4. Critical Metadata Mapping (NIST/Sysmon Compatibility)
        let mut metadata = BTreeMap::new();
        
        // Identity & Origin
        if let Some(st) = self.get_value(result, "sourcetype") {
            metadata.insert("sourcetype".to_string(), st.to_string());
        }
        if let Some(host) = self.get_value(result, "host") {
            metadata.insert("host".to_string(), host.to_string());
        }

        // Windows/Sysmon Crosswalk
        let mappings = [
            ("EventCode", "EventID"),
            ("CommandLine", "CommandLine"),
            ("Image", "Image"),
            ("ParentImage", "ParentImage"),
            ("ParentCommandLine", "ParentCommandLine"),
            ("User", "User"),
            ("LogName", "LogName"),
            ("SourceName", "SourceName"),
            ("PipeName", "PipeName"),
            ("ShareName", "ShareName"),
            ("TargetFilename", "TargetFilename"),
            ("DestinationIp", "DestinationIp"),
            ("DestinationPort", "DestinationPort"),
        ];

        for (splunk_key, aegis_key) in mappings {
            if let Some(val) = self.get_value(result, splunk_key) {
                metadata.insert(aegis_key.to_string(), val.to_string());
            }
        }

        // 5. Build LogRecord
        LogRecord {
            timestamp,
            message,
            severity: self.get_value(result, "level").or_else(|| self.get_value(result, "severity")).map(|s| s.to_string()),
            source: Some(self.format_name().to_string()),
            subject_id: self.get_value(result, "user").map(|s| s.to_string()),
            outcome: Some("Success".to_string()),
            metadata,
            additional_context: Some(result.clone()),
            raw: raw.to_string(),
            unparsed_raw,
            original_format: self.format_name().to_string(),
            quality,
            ..Default::default()
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_splunk_bots_unwrap() {
        let parser = SplunkParser::new();
        let raw_json = r#"{
            "result": {
                "_time": "2024-04-13T12:00:00Z",
                "_raw": "Process Create: Image=C:\\Windows\\System32\\cmd.exe",
                "EventCode": "1",
                "CommandLine": "whoami /priv",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
            }
        }"#;

        let record = parser.parse(raw_json);
        assert_eq!(record.timestamp.to_rfc3339().contains("2024-04-13"), true);
        assert_eq!(record.message, "Process Create: Image=C:\\Windows\\System32\\cmd.exe");
        assert_eq!(record.metadata.get("EventID").unwrap(), "1");
        assert_eq!(record.metadata.get("CommandLine").unwrap(), "whoami /priv");
        assert_eq!(record.metadata.get("Image").unwrap(), "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(record.metadata.get("sourcetype").unwrap(), "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational");
        assert_eq!(record.source.unwrap(), "splunk_bots");
    }
}
