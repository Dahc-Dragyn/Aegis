use crate::models::{LogRecord, ParsingQuality};
use crate::parsers::{LogParser, parse_timestamp_robust};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use chrono::Local;

pub struct AiProxyParser;

impl AiProxyParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AiProxyParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AiProxyPayload {
    pub timestamp: Option<String>,
    pub model: Option<String>,
    pub user_id: Option<String>,
    pub usage: Option<AiUsage>,
    pub metadata: Option<AiMetadata>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AiUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AiMetadata {
    pub latency_ms: Option<u64>,
    pub security_flags: Option<BTreeMap<String, serde_json::Value>>,
}

impl LogParser for AiProxyParser {
    fn parse(&self, raw: &str) -> LogRecord {
        match serde_json::from_str::<AiProxyPayload>(raw) {
            Ok(payload) => {
                let (ts, quality) = if let Some(ref t) = payload.timestamp {
                    parse_timestamp_robust(t)
                } else {
                    (Local::now(), ParsingQuality::PartialTimestamp)
                };

                let mut metadata = BTreeMap::new();
                
                // Extract Usage
                if let Some(ref usage) = payload.usage {
                    metadata.insert("prompt_tokens".to_string(), usage.prompt_tokens.to_string());
                    metadata.insert("completion_tokens".to_string(), usage.completion_tokens.to_string());
                    metadata.insert("total_tokens".to_string(), (usage.prompt_tokens + usage.completion_tokens).to_string());
                }

                // Extract Latency & Security Flags
                if let Some(ref meta) = payload.metadata {
                    if let Some(latency) = meta.latency_ms {
                        metadata.insert("latency_ms".to_string(), latency.to_string());
                    }
                    if let Some(ref flags) = meta.security_flags {
                        for (k, v) in flags {
                            metadata.insert(format!("ai_security_{}", k), v.to_string());
                        }
                    }
                }

                LogRecord {
                    timestamp: ts,
                    message: format!("AI Model Interaction: {}", payload.model.as_deref().unwrap_or("unknown")),
                    severity: Some("Info".to_string()),
                    source: payload.model.clone(),
                    subject_id: payload.user_id.clone(),
                    outcome: Some("Computed".to_string()),
                    metadata,
                    additional_context: Some(serde_json::to_value(&payload).unwrap_or(serde_json::Value::Null)),
                    raw: raw.to_string(),
                    unparsed_raw: None,
                    original_format: "ai_proxy".to_string(),
                    quality,
                    incident_id: None,
                    redactions: Vec::new(),
                    bridge_hash: None,
                    chain_hash: None,
                    ..Default::default()
                }
            },
            Err(_) => {
                // NIST AU-2: Hardened Zero-Drop Fallback
                LogRecord {
                    timestamp: Local::now(),
                    message: "DEGRADED: Unrecognized AI Proxy Payload".to_string(),
                    severity: Some("Warning".to_string()),
                    source: Some("ai_proxy_ingestion".to_string()),
                    subject_id: None,
                    outcome: Some("IngestedRaw".to_string()),
                    metadata: BTreeMap::new(),
                    additional_context: None,
                    raw: raw.to_string(),
                    unparsed_raw: Some(raw.to_string()),
                    original_format: "ai_proxy".to_string(),
                    quality: ParsingQuality::Degraded,
                    incident_id: None,
                    redactions: Vec::new(),
                    bridge_hash: None,
                    chain_hash: None,
                    ..Default::default()
                }
            }
        }
    }

    fn format_name(&self) -> &str { "ai_proxy" }

    fn as_any(&self) -> &dyn std::any::Any { self }
}
