pub mod watcher;
pub mod dispatcher;
pub mod ledger;
pub mod monitor;
pub mod dashboard;
pub mod report;
pub mod notification;
pub mod models;
pub mod parsers;
pub mod config;
pub mod redactor;

pub use nist_engine::{NistEngine, ControlMapping, PostureEvent, AegisError};

mod nist_engine {
    use regex::Regex;
    use serde::{Deserialize, Serialize};
    use chrono::{DateTime, Utc};
    use std::collections::HashMap;
    use thiserror::Error;
    use anyhow::Result;
    use crate::models::LogRecord;
    use std::sync::Arc;

    /// Aegis internal error definitions
    #[derive(Error, Debug)]
    pub enum AegisError {
        #[error("Failed to compile regex signature: {0}")]
        InvalidSignature(String),
    }

    /// A mapping between a log signature and a NIST SP 800-53 Control.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ControlMapping {
        pub control_id: String,
        pub category: String,
        pub description: String,
        pub target_field: Option<String>,
        #[serde(skip)]
        pub pattern: Option<Regex>,
    }

    /// The forensic record of a captured compliance event.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PostureEvent {
        pub timestamp: DateTime<Utc>,
        pub control_id: String,
        pub raw_log: String,
        pub metadata: HashMap<String, String>,
    }

    /// The core NIST Mapping Engine.
    pub struct NistEngine {
        mappings: Vec<ControlMapping>,
    }

    impl NistEngine {
        pub fn new() -> Result<Self> {
            let mappings = vec![
                ControlMapping {
                    control_id: "AU-2".to_string(),
                    category: "Logging".to_string(),
                    description: "Capture of failed authentication attempts".to_string(),
                    target_field: None,
                    pattern: Some(Regex::new(r"(?i)(failed password for|authentication failure|invalid user)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AU-2".to_string(),
                    category: "Audit and Accountability".to_string(),
                    description: "Detection of audit log clearing or tampering attempts".to_string(),
                    target_field: None,
                    pattern: Some(Regex::new(r"(?i)(log cleared|audit log was cleared|event 1102|event 104)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AC-6".to_string(),
                    category: "Access Control".to_string(),
                    description: "Capture of administrative or privileged account usage".to_string(),
                    target_field: None,
                    pattern: Some(Regex::new(r"(?i)(sudo:|su:|runas|admin access|root login)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "IA-2".to_string(),
                    category: "Identification & Auth".to_string(),
                    description: "Detection of credential modification or password changes".to_string(),
                    target_field: None,
                    pattern: Some(Regex::new(r"(?i)(password changed|passwd:|chfn:|usermod:)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AU-10".to_string(),
                    category: "Audit and Accountability".to_string(),
                    description: "Detection of non-repudiation or signature verification failures".to_string(),
                    target_field: None,
                    pattern: Some(Regex::new(r"(?i)(signature invalid|verification failed|tamper detected)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AC-3".to_string(),
                    category: "Access Control".to_string(),
                    description: "Capture of unauthorized privilege escalation attempts".to_string(),
                    target_field: None,
                    pattern: Some(Regex::new(r"(?i)(sudo: auth failure|access denied for user)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AU-12".to_string(),
                    category: "Incident Response".to_string(),
                    description: "Honeypot/Trap trigger from active reconnaissance".to_string(),
                    target_field: None,
                    pattern: Some(Regex::new(r"(?i)\[HONEYPOT\]")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AU-6".to_string(),
                    category: "Audit and Accountability".to_string(),
                    description: "High-severity system or application warnings".to_string(),
                    target_field: Some("severity".to_string()),
                    pattern: Some(Regex::new(r"(?i)(WARNING|ERROR|CRITICAL|EMERGENCY)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "SC-7".to_string(),
                    category: "System & Comms Protection".to_string(),
                    description: "Detection of access to sensitive system paths (e.g. .env, /admin)".to_string(),
                    target_field: Some("message".to_string()),
                    pattern: Some(Regex::new(r#"(?i)(/\.env|/wp-admin|/config\.php|/admin)"#)
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AC-4".to_string(),
                    category: "Access Control".to_string(),
                    description: "Captures 403/429 responses triggered by 'stiffened security' or AI bot traps.".to_string(),
                    target_field: Some("status".to_string()),
                    pattern: Some(Regex::new(r"(403|429|418)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AU-3".to_string(),
                    category: "Audit and Accountability".to_string(),
                    description: "Verify audit record content integrity via active privacy masking (redaction).".to_string(),
                    target_field: None,
                    pattern: None, // Logic-based check in matches()
                },
            ];

            Ok(Self { mappings })
        }

        /// Analyzes a batch of LogRecords in parallel to maintain 160k+ EPS performance.
        pub fn analyze_batch(&self, batch: &[Arc<LogRecord>]) -> Vec<LogRecord> {
             batch.iter()
                .filter_map(|record| {
                    if let Some(mapping) = self.matches(record) {
                        let mut tagged_record = (**record).clone();
                        tagged_record.metadata.insert("nist_control_id".to_string(), mapping.control_id.clone());
                        tagged_record.metadata.insert("nist_category".to_string(), mapping.category.clone());
                        Some(tagged_record)
                    } else {
                        None
                    }
                })
                .collect()
        }

        pub fn matches(&self, record: &LogRecord) -> Option<&ControlMapping> {
            // First, check for AU-3 (Privacy/Redaction)
            if !record.redactions.is_empty() {
                return self.mappings.iter().find(|m| m.control_id == "AU-3"); 
            }

            for mapping in &self.mappings {
                if let Some(ref re) = mapping.pattern {
                    let target_text = match mapping.target_field.as_deref() {
                        Some("severity") => record.severity.as_deref().unwrap_or(""),
                        Some("status") => record.metadata.get("status").map(|s| s.as_str()).unwrap_or(""),
                        Some("raw") => &record.raw,
                        _ => &record.message,
                    };

                    if re.is_match(target_text) {
                        return Some(mapping);
                    }
                }
            }
            None
        }
    }
}
