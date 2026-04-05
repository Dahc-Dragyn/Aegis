use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParsingQuality {
    Success,
    PartialTimestamp, // Fallen back to system time 
    Malformed,        // Key fields were missing, but we salvaged the message
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionEvent {
    pub reason: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRecord {
    pub timestamp: DateTime<Utc>,
    pub message: String,
    pub severity: Option<String>,
    pub source: Option<String>,
    pub subject_id: Option<String>, // NIST AU-3.f (Identity of subjects)
    pub outcome: Option<String>,    // NIST AU-3.e (Outcome of event)
    pub metadata: HashMap<String, String>,
    pub raw: String,
    pub original_format: String,
    pub quality: ParsingQuality,
    pub redactions: Vec<RedactionEvent>,
}

impl LogRecord {
    pub fn new(message: String, raw: String, format: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            message,
            severity: None,
            source: None,
            subject_id: None,
            outcome: None,
            metadata: HashMap::new(),
            raw,
            original_format: format.to_string(),
            quality: ParsingQuality::Success,
            redactions: Vec::new(),
        }
    }
}
