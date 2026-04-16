use crate::models::LogRecord;
use crate::parsers::LogParser;
use std::collections::BTreeMap;

/// The Forensic .evtx Parser: Engineered for high-fidelity binary Windows Event Logs.
pub struct EvtxParser;

impl EvtxParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EvtxParser {
    fn default() -> Self {
        Self::new()
    }
}

// Since .evtx records arrive as structured JSON from the crate, we'll map that stream.
impl LogParser for EvtxParser {
    fn format_name(&self) -> &str {
        "evtx_binary"
    }

    fn parse(&self, raw: &str) -> LogRecord {
        use chrono::Local;
        use crate::models::ParsingQuality;

        // Zero-Drop Fidelity: Every newline is an event (NIST AU-2)
        if raw.trim().is_empty() {
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
                ..Default::default()
            };
        }

        // The evtx crate provides an iterator of JSON strings.
        // We parse these and map them to our unified schema.
        let json_val: serde_json::Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(_) => {
                return LogRecord {
                    timestamp: Local::now(),
                    message: "DEGRADED: Malformed EVTX-XML record".to_string(),
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
                    ..Default::default()
                };
            }
        };
        
        let mut quality = ParsingQuality::Success;
        let mut unparsed_raw = None;

        let event = if let Some(e) = json_val.get("Event") {
            e
        } else {
            return LogRecord {
                timestamp: Local::now(),
                message: "DEGRADED: Missing Event root node".to_string(),
                severity: Some("WARN".to_string()),
                source: Some(self.format_name().to_string()),
                subject_id: None,
                outcome: Some("Degraded".to_string()),
                metadata: BTreeMap::new(),
                additional_context: Some(json_val.clone()),
                raw: raw.to_string(),
                unparsed_raw: Some(raw.to_string()),
                original_format: self.format_name().to_string(),
                quality: ParsingQuality::Degraded,
                incident_id: None,
                redactions: Vec::new(),
                bridge_hash: None,
                chain_hash: None,
                ..Default::default()
            };
        };

        let system = if let Some(s) = event.get("System") {
            s
        } else {
            quality = ParsingQuality::Degraded;
            unparsed_raw = Some(raw.to_string());
            // Create a pseudo-system node for later logic
            &json_val 
        };
        
        // 1. Robust EventID Extraction (handles string, number, or object with #text)
        let event_id = match system.get("EventID") {
            Some(id_val) => {
                if let Some(txt) = id_val.get("#text") {
                    if let Some(s) = txt.as_str() { s.to_string() }
                    else if let Some(n) = txt.as_u64() { n.to_string() }
                    else { "000".to_string() }
                } else if let Some(s) = id_val.as_str() { s.to_string() }
                else if let Some(n) = id_val.as_u64() { n.to_string() }
                else { "000".to_string() }
            },
            None => {
                quality = ParsingQuality::Malformed;
                "000".to_string()
            }
        };

        // 2. Robust Attribute Pathing (supports #attributes vs #Attributes)
        let (timestamp, ts_quality) = if let Some(time_created) = system.get("TimeCreated") {
            let timestamp_str = time_created.get("#attributes")
                .or_else(|| time_created.get("#Attributes"))
                .and_then(|a| a.get("SystemTime"))
                .and_then(|s| s.as_str());
            
            if let Some(ts_str) = timestamp_str {
                crate::parsers::parse_timestamp_robust(ts_str)
            } else {
                (Local::now(), ParsingQuality::PartialTimestamp)
            }
        } else {
            (Local::now(), ParsingQuality::PartialTimestamp)
        };
        
        if matches!(ts_quality, ParsingQuality::PartialTimestamp) && quality != ParsingQuality::Degraded {
            quality = ParsingQuality::PartialTimestamp;
        }
        
        let mut metadata = BTreeMap::new();
        metadata.insert("EventID".to_string(), event_id.clone());
        
        if let Some(comp) = system.get("Computer").and_then(|c| c.as_str()) {
            metadata.insert("computer".to_string(), comp.to_string());
        }
        
        if let Some(chan) = system.get("Channel").and_then(|c| c.as_str()) {
            metadata.insert("channel".to_string(), chan.to_string());
        }

        // 3. Robust Message Extraction and Metadata Population
        let message = if let Some(event_data) = event.get("EventData") {
            let mut fields = Vec::new();

            // Case A: Data is an array (Standard Windows/Sysmon XML-to-JSON)
            if let Some(data_node) = event_data.get("Data") {
                if let Some(arr) = data_node.as_array() {
                    for item in arr {
                        let name = item.get("@Name").or_else(|| item.get("Name")).and_then(|v| v.as_str());
                        let value = item.get("#text").or_else(|| item.get("Value")).and_then(|v| {
                            v.as_str().map(|s| s.to_string())
                             .or_else(|| v.as_u64().map(|n| n.to_string()))
                        }).or_else(|| item.as_str().map(|s| s.to_string()));

                        if let (Some(n), Some(v)) = (name, value) {
                            metadata.insert(n.to_string(), v.clone());
                            fields.push(format!("{}: {}", n, v));
                        } else if let Some(s) = item.as_str() {
                            fields.push(s.to_string());
                        }
                    }
                } else if let Some(s) = data_node.as_str() {
                    fields.push(s.to_string());
                }
            } 
            
            // Case B: EventData is a flat object (Sysmon JSON optimization)
            if let Some(obj) = event_data.as_object() {
                for (k, v) in obj {
                    if k == "Data" { continue; } // Already handled
                    let val = v.as_str().map(|s| s.to_string())
                        .unwrap_or_else(|| v.to_string().replace("\"", ""));
                    metadata.insert(k.clone(), val.clone());
                    fields.push(format!("{}: {}", k, val));
                }
            }

            if fields.is_empty() { "No EventData mapped".to_string() }
            else { fields.join(" | ") }
        } else {
            "No EventData available".to_string()
        };

        // Provider Casing check
        let provider = system.get("Provider")
            .and_then(|p| p.get("#attributes").or_else(|| p.get("#Attributes")))
            .and_then(|a| a.get("Name"))
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());

        LogRecord {
            timestamp,
            message: format!("[EventID {}] {}", event_id, message),
            severity: Some("INFO".to_string()), 
            source: provider,
            subject_id: None, 
            outcome: if quality == ParsingQuality::Degraded { Some("Degraded".to_string()) } else { Some("Success".to_string()) },
            metadata: metadata.clone(),
            additional_context: Some(json_val),
            raw: raw.to_string(),
            unparsed_raw,
            original_format: self.format_name().to_string(),
            quality,
            incident_id: None,
            redactions: Vec::new(),
            bridge_hash: None,
            chain_hash: None,
            parent_process_id: metadata.get("ParentProcessId")
                .or_else(|| metadata.get("parent_process_id"))
                .and_then(|id| {
                    if id.starts_with("0x") {
                        u32::from_str_radix(&id[2..], 16).ok()
                    } else {
                        id.parse::<u32>().ok()
                    }
                }),
            parent_process_name: metadata.get("ParentImage")
                .or_else(|| metadata.get("ParentProcessName"))
                .or_else(|| metadata.get("parent_image"))
                .cloned(),
            ..Default::default()
        }
    }



    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
