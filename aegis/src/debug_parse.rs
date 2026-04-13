use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, PartialOrd, Default)]
#[repr(i32)]
pub enum ComplianceStatus {
    #[default]
    Pass = 0,
    Fail = 1,
    Observation = 2,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, PartialOrd, Default)]
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
    PartialTimestamp, 
    Malformed,        
    Degraded,         
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionEvent {
    pub reason: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRecord {
    pub timestamp: chrono::DateTime<chrono::Local>,
    pub message: String,
    pub severity: Option<String>,
    pub source: Option<String>,
    pub subject_id: Option<String>, 
    pub outcome: Option<String>,    
    pub metadata: HashMap<String, String>,
    pub additional_context: Option<serde_json::Value>, 
    pub raw: String,
    pub unparsed_raw: Option<String>, 
    pub original_format: String,
    pub quality: ParsingQuality,
    pub incident_id: Option<Uuid>,
    pub redactions: Vec<RedactionEvent>,
    pub chain_hash: Option<String>,
}

fn main() {
    let content = std::fs::read_to_string("aegis.audit.jsonl").unwrap();
    for line in content.lines() {
        if line.trim().is_empty() { continue; }
        match serde_json::from_str::<LogRecord>(line) {
            Ok(_) => println!("OK"),
            Err(e) => println!("ERROR: {}", e),
        }
    }
}
