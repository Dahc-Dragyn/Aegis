    /// Resiliently extracts critical telemetry and payloads from raw forensic logs. (NIST AU-8/AU-12)
    fn extract_telemetry(&self, event: &PostureEvent) -> (String, String, String, String, String) {
        let raw = &event.raw_log;
        let v: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
        
        let metadata_payload = event.metadata.get("forensic_payload").map(|s| s.to_string());

        // --- 1. JSON Path (EVTX/JSON) ---
        if !v.is_null() {
            let event_kv = v.get("Event").unwrap_or(&v);
            let system = event_kv.get("System").unwrap_or(event_kv);

            // 1. EventID
            let eid = system.get("EventID")
                .and_then(|id| {
                    id.as_str().map(|s| s.to_string())
                    .or_else(|| id.as_u64().map(|n| n.to_string()))
                    .or_else(|| id.get("#text").and_then(|t| t.as_str()).map(|s| s.to_string()))
                })
                .unwrap_or_else(|| "N/A".to_string());

            // 2. Timestamp (NIST AU-8 Alignment)
            let time = system.get("TimeCreated")
                .and_then(|tc| tc.get("SystemTime").or_else(|| tc.get("@SystemTime")))
                .and_then(|t| t.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| event.timestamp.to_rfc3339());

            // 3. ProcessID
            let pid = system.get("Execution")
                .and_then(|e| e.get("ProcessID").or_else(|| e.get("@ProcessID")))
                .and_then(|p| p.as_str().map(|s| s.to_string()).or_else(|| p.as_u64().map(|n| n.to_string())))
                .unwrap_or_else(|| event.metadata.get("process_id").cloned().unwrap_or_else(|| "N/A".to_string()));

            // 4. EventRecordID (NIST AU-12 Witnesses)
            let rid = system.get("EventRecordID")
                .and_then(|r| r.as_u64().map(|n| n.to_string()).or_else(|| r.as_str().map(|s| s.to_string())))
                .unwrap_or_else(|| event.metadata.get("line_id").cloned().unwrap_or_else(|| "N/A".to_string()));

            // 5. Payload (ISSO directive: Prioritize ScriptBlockText and IP telemetry)
            let payload = metadata_payload.unwrap_or_else(|| {
                event_kv.get("EventData").and_then(|ed| {
                    // Start of extraction chain (Hardened order)
                    let p = ed.get("ScriptBlockText")
                        .or_else(|| ed.get("CommandLine"))
                        .or_else(|| ed.get("PipeName"))
                        .or_else(|| ed.get("TargetObject"))
                        .or_else(|| ed.get("Details"))
                        .or_else(|| ed.get("ImageLoaded"))
                        .or_else(|| ed.get("SourceImage"))
                        .or_else(|| ed.get("TargetImage"))
                        .or_else(|| ed.get("Image"))
                        .or_else(|| ed.get("IpAddress")) // Exact case for native 4624/RDP
                        .or_else(|| ed.get("ClientIP"))
                        .or_else(|| ed.get("NewProcessName"))
                        .or_else(|| ed.get("ProcessName"))
                        .and_then(|val| val.as_str().map(|s| s.to_string()));

                    p.or_else(|| {
                        // Fallback scanner for generic <Data> structures (RdpCoreTS / Sysmon)
                        ed.get("Data").and_then(|d| {
                            if let Some(arr) = d.as_array() {
                                arr.iter().find_map(|v| {
                                    v.as_str().or_else(|| v.get("#text").and_then(|t| t.as_str()))
                                        .and_then(|s| {
                                            if s.contains("TCP") || s.contains("UDP") || s.contains("RDP-Tcp") || s.contains(":\\") || s.to_lowercase().contains(".dit") || s.contains("127.0.0.1") || s.contains("::1") {
                                                Some(s.to_string())
                                            } else {
                                                None
                                            }
                                        })
                                })
                            } else {
                                d.as_str().or_else(|| d.get("#text").and_then(|t| t.as_str()))
                                    .and_then(|s| {
                                        if s.contains("TCP") || s.contains("UDP") || s.contains("RDP-Tcp") || s.contains(":\\") || s.to_lowercase().contains(".dit") || s.contains("127.0.0.1") || s.contains("::1") {
                                            Some(s.to_string())
                                        } else {
                                            None
                                        }
                                    })
                            }
                        })
                    })
                })
                .or_else(|| {
                    // Deep String Scan: Final safety net for raw logs
                    let lower_raw = raw.to_lowercase();
                    if lower_raw.contains("tcp") || lower_raw.contains("udp") || lower_raw.contains("rdp-tcp") || raw.contains(":\\") || lower_raw.contains(".dit") || raw.contains("127.0.0.1") {
                        if let Some(pos) = lower_raw.find("tcp")
                            .or(lower_raw.find("udp"))
                            .or(lower_raw.find("rdp-tcp"))
                            .or(raw.find(":\\"))
                            .or(lower_raw.find(".dit"))
                            .or(raw.find("127.0.0.1")) 
                        {
                            let start = pos.saturating_sub(10);
                            let end = (pos + 45).min(raw.len());
                            Some(format!("...{}...", &raw[start..end].replace('"', "").replace("\\\\", "\\")))
                        } else {
                            Some("Forensic Path/Link Detected (Raw)".to_string())
                        }
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "N/A".to_string())
            });

            return (eid, time, pid, rid, payload);
        }

        // --- 2. PostureEvent Path (Fallback for CSV/Plain) ---
        let eid = event.metadata.get("event_id").cloned().unwrap_or_else(|| "N/A".to_string());
        let time = event.timestamp.to_rfc3339();
        let pid = event.metadata.get("process_id").cloned().unwrap_or_else(|| "N/A".to_string());
        let rid = event.metadata.get("line_id").cloned().unwrap_or_else(|| "N/A".to_string());
        
        // For CSV, try to extract content from raw (CBS: LineId,Date,Time,Level,Component,Content,...)
        let payload = if raw.contains(',') {
            let parts: Vec<&str> = raw.split(',').collect();
            parts.get(5).map(|s| s.trim().to_string()).unwrap_or_else(|| "N/A".to_string())
        } else {
            "N/A".to_string()
        };

        (eid, time, pid, rid, payload)
    }
