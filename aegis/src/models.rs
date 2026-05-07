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
    pub parent_process_id: Option<u32>,
    pub parent_process_name: Option<String>,
    pub lineage_chain: Option<String>,
    pub line_id: Option<u32>,
    pub destination_ip: Option<String>,
    pub destination_port: Option<u16>,
    pub protocol: Option<String>,
    pub process_guid: Option<String>,
    pub target_image: Option<String>,
    pub granted_access: Option<String>,
    pub evidence_vault: Option<String>,
    pub log_source: Option<String>,
    pub process_id: Option<u32>,
    pub image: Option<String>,
    pub command_line: Option<String>,
    pub node_id: String, // NIST AU-3: Globally unique source node identifier
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
            parent_process_id: None,
            parent_process_name: None,
            lineage_chain: None,
            line_id: None,
            destination_ip: None,
            destination_port: None,
            protocol: None,
            process_guid: None,
            target_image: None,
            granted_access: None,
            evidence_vault: None,
            log_source: None,
            process_id: None,
            image: None,
            command_line: None,
            node_id: String::from("Standalone"),
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

    pub fn is_high_fidelity(&self) -> bool {
        // 1. Severity check (Literal strings from tactical HUD)
        if let Some(sev) = self.severity.as_deref() {
            let s = sev.to_lowercase();
            if s == "hostile" || s == "critical" || s == "warning" || s == "warn" || s == "error" {
                return true;
            }
        }

        // 2. Event ID check (NIST AU-12: Process Creation is always high-fidelity)
        if let Some(id) = self.metadata.get("EventID") {
            if id == "4688" || id == "1" {
                return true;
            }
        }

        // 3. Keyword heuristic (Heuristic Forensic Strings)
        let msg = self.message.to_lowercase();
        if msg.contains("mimikatz") || 
           msg.contains("lsass") || 
           msg.contains("wmi") || 
           msg.contains("powershell -enc") ||
           msg.contains("suppressed") { // Don't sample out our own noise alerts
            return true;
        }

        false
    }
}
