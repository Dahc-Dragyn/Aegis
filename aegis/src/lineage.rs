use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;
use chrono::{DateTime, Local};
use crate::models::{LogRecord, SeverityLevel};

#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub pid: u32,
    pub image: String,
    pub command_line: Option<String>,
    pub timestamp: DateTime<Local>,
    pub log_source: Option<String>,
    pub hashes: Option<String>, // NIST enrichment (Sysmon)
}

#[derive(Debug, Clone)]
pub struct LineageAnomaly {
    pub parent_pid: u32,
    pub parent_image: String,
    pub child_pid: u32,
    pub child_image: String,
    pub child_cmd: Option<String>,
    pub timestamp: DateTime<Local>,
    pub severity: SeverityLevel,
    pub description: String,
}

pub struct LineageGraph {
    graph: DiGraph<ProcessNode, ()>,
    // Maps ProcessId to NodeIndex.
    // NOTE: PID reuse is handled by always taking the most recent node for a PID.
    pid_map: HashMap<u32, NodeIndex>,
    orphan_root: NodeIndex,
    pub correlation_count: u64, // Cross-Vector Fusion Metric
    fuzzy_match_window_ms: i64,
}

impl LineageGraph {
    pub fn new() -> Self {
        let mut graph = DiGraph::new();
        let orphan_root = graph.add_node(ProcessNode {
            pid: 0,
            image: "Unknown/Pre-existing Parent".to_string(),
            command_line: None,
            timestamp: Local::now(),
            log_source: None,
            hashes: None,
        });

        Self {
            graph,
            pid_map: HashMap::new(),
            orphan_root,
            correlation_count: 0,
            fuzzy_match_window_ms: 500, // Default 500ms jitter window
        }
    }

    pub fn set_fuzzy_window(&mut self, window_ms: i64) {
        self.fuzzy_match_window_ms = window_ms;
    }

    pub fn add_record(&mut self, record: &LogRecord) {
        // We only track process creation events (EventID 1 for Sysmon, 4688 for Security)
        let event_id = record.metadata.get("EventID").cloned().unwrap_or_default();
        if event_id != "1" && event_id != "4688" {
            return;
        }

        let pid = record.process_id.unwrap_or(0);
        if pid == 0 { return; }

        let ppid = record.parent_process_id.unwrap_or(0);
        let image = record.image.clone().unwrap_or_else(|| "Unknown".to_string());
        let cmd = record.command_line.clone();
        let hashes = record.metadata.get("Hashes").cloned();

        // --- PHASE 3: FUZZY MATCH FUSION ENGINE ---
        // Check if we already have a node for this PID within the temporal window
        if let Some(&existing_idx) = self.pid_map.get(&pid) {
            let existing_node = &mut self.graph[existing_idx];
            
            // Fuzzy Match Criteria: Same PID, Same Image (Partial), and within Window
            let time_diff = (record.timestamp - existing_node.timestamp).num_milliseconds().abs();
            
            // Normalize image paths for comparison (Field laptops might have case diffs)
            let is_same_image = image.to_lowercase().ends_with(&existing_node.image.to_lowercase()) 
                                || existing_node.image.to_lowercase().ends_with(&image.to_lowercase());

            if time_diff <= self.fuzzy_match_window_ms && is_same_image {
                // FUSION DETECTED: Enrich existing node with missing metadata
                if existing_node.command_line.is_none() && cmd.is_some() {
                    existing_node.command_line = cmd;
                }
                if existing_node.hashes.is_none() && hashes.is_some() {
                    existing_node.hashes = hashes;
                }
                // Append source for forensic attribution
                if let Some(src) = &record.log_source {
                    if let Some(existing_src) = &existing_node.log_source {
                        if !existing_src.contains(src) {
                            existing_node.log_source = Some(format!("{}, {}", existing_src, src));
                        }
                    } else {
                        existing_node.log_source = Some(src.clone());
                    }
                }
                
                self.correlation_count += 1;
                return; // Exit without adding a duplicate node
            }
        }

        let node = ProcessNode {
            pid,
            image: image.clone(),
            command_line: cmd,
            timestamp: record.timestamp,
            log_source: record.log_source.clone(),
            hashes,
        };

        let node_idx = self.graph.add_node(node);
        
        // Link to parent
        if ppid != 0 {
            if let Some(&parent_idx) = self.pid_map.get(&ppid) {
                self.graph.add_edge(parent_idx, node_idx, ());
            } else if let Some(parent_image) = &record.parent_process_name {
                // PHASE 2: PARENT PLACEHOLDER (NIST AU-12 Continuity)
                // Create a placeholder node for the parent process if it wasn't seen in the current forensic window.
                let parent_node = ProcessNode {
                    pid: ppid,
                    image: parent_image.clone(),
                    command_line: None,
                    timestamp: record.timestamp, // Approximate
                    log_source: Some("PRE-EXISTING (Reconstructed)".to_string()),
                    hashes: None,
                };
                let parent_idx = self.graph.add_node(parent_node);
                self.pid_map.insert(ppid, parent_idx);
                self.graph.add_edge(parent_idx, node_idx, ());
            } else {
                // Orphan Guardrail: Link to virtual root
                self.graph.add_edge(self.orphan_root, node_idx, ());
            }
        } else {
            // No parent info, link to root
            self.graph.add_edge(self.orphan_root, node_idx, ());
        }

        // Update PID map (overwrite for PID reuse)
        self.pid_map.insert(pid, node_idx);
    }

    pub fn detect_anomalies(&self) -> Vec<LineageAnomaly> {
        let mut anomalies = Vec::new();
        
        // Iterate through all edges to inspect parent-child relationships
        for edge in self.graph.edge_indices() {
            let (parent_idx, child_idx) = self.graph.edge_endpoints(edge).unwrap();
            let parent = &self.graph[parent_idx];
            let child = &self.graph[child_idx];
            
            let parent_img = parent.image.to_lowercase();
            let child_img = child.image.to_lowercase();
            
            // Heuristic 1: Living off the Land (LotL) / Living off the Binary (LotB) Spawns
            let hostile_spawners = [
                "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", 
                "acrord32.exe", "notepad.exe", "spoolsv.exe", "msdt.exe",
                "certutil.exe", "bash.exe", "wsl.exe"
            ];
            let shells = [
                "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", 
                "cscript.exe", "mshta.exe", "bitsadmin.exe", "scrcons.exe",
                "schtasks.exe", "regsvr32.exe"
            ];

            if hostile_spawners.iter().any(|&s| parent_img.contains(s)) &&
               shells.iter().any(|&s| child_img.contains(s)) {
                
                let severity = if parent_img.contains("winword.exe") || parent_img.contains("excel.exe") || parent_img.contains("msdt.exe") {
                    SeverityLevel::Critical
                } else {
                    SeverityLevel::High
                };

                anomalies.push(LineageAnomaly {
                    parent_pid: parent.pid,
                    parent_image: parent.image.clone(),
                    child_pid: child.pid,
                    child_image: child.image.clone(),
                    child_cmd: child.command_line.clone(),
                    timestamp: child.timestamp,
                    severity,
                    description: format!(
                        "LotL Anomaly: {} spawned suspicious shell {}",
                        parent.image, child.image
                    ),
                });
            }

            // Heuristic 2: System Process Anomalies
            if parent_img.contains("spoolsv.exe") && (child_img.contains("cmd.exe") || child_img.contains("powershell.exe")) {
                anomalies.push(LineageAnomaly {
                    parent_pid: parent.pid,
                    parent_image: parent.image.clone(),
                    child_pid: child.pid,
                    child_image: child.image.clone(),
                    child_cmd: child.command_line.clone(),
                    timestamp: child.timestamp,
                    severity: SeverityLevel::Critical,
                    description: "SYSTEM Anomaly: Print Spooler spawned a shell (Possible PrintNightmare/Exploit)".to_string(),
                });
            }

            if parent_img.contains("svchost.exe") && child_img.contains("cmd.exe") {
                anomalies.push(LineageAnomaly {
                    parent_pid: parent.pid,
                    parent_image: parent.image.clone(),
                    child_pid: child.pid,
                    child_image: child.image.clone(),
                    child_cmd: child.command_line.clone(),
                    timestamp: child.timestamp,
                    severity: SeverityLevel::High,
                    description: "System Service Anomaly: svchost.exe spawned cmd.exe".to_string(),
                });
            }

            // Heuristic 3: Common User-Shell spawners (Explorer is normal, but worth watching if it's not a common shell)
            if parent_img.contains("explorer.exe") && (child_img.contains("whoami.exe") || child_img.contains("nltest.exe") || child_img.contains("net.exe")) {
                anomalies.push(LineageAnomaly {
                    parent_pid: parent.pid,
                    parent_image: parent.image.clone(),
                    child_pid: child.pid,
                    child_image: child.image.clone(),
                    child_cmd: child.command_line.clone(),
                    timestamp: child.timestamp,
                    severity: SeverityLevel::Medium,
                    description: format!("Suspicious Reconnaissance: Explorer spawned {}", child.image),
                });
            }
        }
        
        anomalies
    }
}
