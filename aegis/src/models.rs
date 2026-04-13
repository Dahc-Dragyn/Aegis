use serde::{Serialize, Deserialize};
use chrono::{DateTime, Local};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, PartialOrd, Default)]
#[repr(i32)]
pub enum ComplianceStatus {
    #[default]
    Pass = 0,
    Fail = 1,
    Observation = 2,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(i32)]
pub enum SeverityLevel {
    #[default]
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ParsingQuality {
    Success,
    PartialTimestamp, // Fallen back to system time 
    Malformed,        // Key fields were missing, but we salvaged the message
    Degraded,         // Schema mismatch, captured raw signal for NIST AU-2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionEvent {
    pub reason: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRecord {
    pub timestamp: DateTime<Local>,
    pub message: String,
    pub severity: Option<String>,
    pub source: Option<String>,
    pub subject_id: Option<String>, // NIST AU-3.f (Identity of subjects)
    pub outcome: Option<String>,    // NIST AU-3.e (Outcome of event)
    pub metadata: BTreeMap<String, String>,
    pub additional_context: Option<serde_json::Value>, // NIST AU-2 (Catch-all for 100% Fidelity)
    pub raw: String,
    pub unparsed_raw: Option<String>, // Explicit Zero-Drop fallback
    pub original_format: String,
    pub quality: ParsingQuality,
    pub incident_id: Option<Uuid>,
    pub redactions: Vec<RedactionEvent>,
    pub bridge_hash: Option<String>, // NIST AU-11 continuity marker
    pub chain_hash: Option<String>, // NIST AU-9 (Rolling Cryptographic Chain)
}

impl Default for LogRecord {
    fn default() -> Self {
        Self {
            timestamp: Local::now(),
            message: String::new(),
            severity: None,
            source: None,
            subject_id: None,
            outcome: None,
            metadata: BTreeMap::new(),
            additional_context: None,
            raw: String::new(),
            unparsed_raw: None,
            original_format: String::new(),
            quality: ParsingQuality::Success,
            incident_id: None,
            redactions: Vec::new(),
            bridge_hash: None,
            chain_hash: None,
        }
    }
}

impl LogRecord {
    pub fn new(message: String, raw: String, format: &str) -> Self {
        Self {
            message,
            raw,
            original_format: format.to_string(),
            ..Default::default()
        }
    }
}
