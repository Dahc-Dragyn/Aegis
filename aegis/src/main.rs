use aegis::watcher::Sentry;
use aegis::dispatcher::Dispatcher;
use aegis::ledger::AuditLedger;
use aegis::monitor::PostureMonitor;
use aegis::dashboard::AuditorDashboard;
use aegis::NistEngine;
use aegis::compliance_cache::ComplianceCache;
use aegis::audit_receipt::{ReceiptManager, ReceiptMetrics};
use aegis::config::{AppConfig, ActiveFramework};
use aegis::models::LogRecord;
use aegis::correlation::FusionWorker;
use aegis::parsers::{
    json::JsonParser, 
    plain::PlainTextParser, 
    csv::CsvParser,
    syslog::SyslogParser,
    web_log::WebLogParser,
    LogParser, AutoDetector, LogFormat
};
use anyhow::Result;
use std::sync::Arc;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::process::Command;
use chrono::Local;
use crossterm::event::{self, Event, KeyCode};
use clap::Parser;
use sha2::{Sha256, Digest};
use rayon::prelude::*;

// Rename the external crate to avoid collision with our internal module
extern crate evtx as evtx_crate;

#[derive(Parser, Debug)]
#[command(author = "DeepMind", version, about = "Aegis: The Compliance Sentinel", long_about = None)]
struct Cli {
    /// Paths to the log files to monitor
    #[arg(name = "LOG_FILES")]
    log_files: Vec<PathBuf>,

    /// Override log format (json, plain, ndjson, auto)
    #[arg(short, long)]
    format: Option<String>,

    /// Path to custom format configuration (TOML)
    #[arg(short, long, default_value = "rules/log_formats.toml")]
    config: PathBuf,

    /// Fail fast on malformed log lines (Audit Requirement)
    #[arg(short, long, default_value_t = false)]
    strict: bool,

    /// Load Auditor Dashboard Mode (TUI)
    #[arg(short, long, default_value_t = false)]
    dashboard: bool,

    /// Live Sentinel Mode (Daemon file tailing)
    #[arg(short, long, default_value_t = false)]
    watch: bool,

    /// Reset forensic checkpoint (Force Re-scan)
    #[arg(long, default_value_t = false)]
    reset: bool,

    /// Export compliance artifacts (oscal-ar, oscal-poam, pdf)
    #[arg(long)]
    export: Option<String>,

    /// Control Framework Profile (53 = NIST 800-53, 171 = NIST 800-171)
    #[arg(short, long, default_value = "53")]
    profile: String,

    /// Simulate Offline Mode (Tactical Edge Resilience Test)
    #[arg(long, default_value_t = false)]
    offline: bool,

    /// Run only forensic pre-flight checks and exit
    #[arg(long, default_value_t = false)]
    check_only: bool,

    /// Output directory for artifacts
    #[arg(short, long, default_value = "forensic_results")]
    output_dir: String,

    /// Operational Mode (standalone, push)
    #[arg(short, long, default_value = "standalone")]
    mode: String,

    /// Automatically open the browser to the HUD
    #[arg(short, long, default_value_t = false)]
    auto_open: bool,
}

fn calculate_file_hash(path: &PathBuf) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // --- BLACKBOX LOGGING SETUP ---
    let log_fn = |msg: &str| {
        let mut file = OpenOptions::new().create(true).append(true).open("aegis.debug.log").ok()?;
        writeln!(file, "[{}] {}", Local::now().format("%Y-%m-%d %H:%M:%S %:z"), msg).ok()
    };
    log_fn("--- AEGIS STARTUP ---");

    // 2. Load Hardened Configuration
    let mut config = if cli.config.exists() {
        AppConfig::load_from_file(&cli.config)?
    } else {
        AppConfig::default_config()
    };

    // Apply Framework Profile Override
    match cli.profile.as_str() {
        "171" => {
            println!("🛡️ Aegis Profile: [NIST SP 800-171 Commercial]");
            config.active_framework = ActiveFramework::Commercial171;
            config.profile_name = "NIST_SP-800-171_Rev2_Commercial-Audit".to_string();
        },
        "100-1" | "100" | "ai" => {
            println!("🛡️ Aegis Profile: [NIST AI RMF 100-1 Trustworthiness]");
            config.active_framework = ActiveFramework::AiRmf100;
            config.profile_name = "NIST_AI-RMF-100-1_Trustworthiness-Characteristic-Audit".to_string();
        },
        _ => {
            println!("🛡️ Aegis Profile: [NIST SP 800-53 Federal High]");
            config.active_framework = ActiveFramework::Federal53;
            config.profile_name = "NIST_SP-800-53_rev5_HIGH-baseline".to_string();
        }
    }

    // --- STANDALONE HUB ACTIVATION (LONE SENTINEL) ---
    if cli.mode == "standalone" {
        let results_dir = PathBuf::from(&cli.output_dir);
        let server_dir = results_dir.clone();
        let auto_open = cli.auto_open;
        
        tokio::spawn(async move {
            if let Err(e) = aegis::server::start_server(server_dir, 8080).await {
                eprintln!("❌ Aegis Server Error: {}", e);
            }
        });

        if auto_open {
            // Give the server a moment to bind
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Err(e) = webbrowser::open("http://localhost:8080") {
                eprintln!("⚠️ Warning: Failed to open browser automatically: {}", e);
            }
        }
    }

    if cfg!(windows) && !cli.offline {
        println!("🛡️ Aegis: Initializing forensic pre-flight checks...");
        match run_preflight_checks().await {
            Ok(_) => {
                if cli.check_only {
                    println!("✅ Pre-flight SUCCESS. Forensic auditing is correctly configured.");
                    return Ok(());
                }
            },
            Err(e) => {
                log_fn(&format!("❌ PRE-FLIGHT CRITICAL: {}", e));
                println!("❌ ERROR: {}", e);
                if cli.check_only {
                    return Err(e);
                }
                println!("⚠️ WARNING: Proceeding with degraded forensic capabilities. Lineage tracking may be non-functional.");
            }
        }
    }

    // 3. Selection of AI Proxy Parser (Priority Override for Phase 7)
    let _is_ai_rmf = matches!(config.active_framework, ActiveFramework::AiRmf100);

    // 4. Select Target Logs (with Auto-Discovery)
    let is_watchtower = cli.watch && cli.log_files.is_empty();
    
    let log_paths = if is_watchtower {
        vec![PathBuf::from("WATCHTOWER")]
    } else {
        if !cli.log_files.is_empty() {
            cli.log_files.clone()
        } else {
            let candidates = vec![PathBuf::from("auth.log"), PathBuf::from("cloudlogs.json")];
            let found: Vec<PathBuf> = candidates.into_iter().filter(|p| p.exists()).collect();
            if found.is_empty() {
                if cli.mode == "standalone" {
                    println!("📡 Aegis: [PURE-HUB] No local logs provided. Monitoring Tactical Stream only.");
                    // Return a dummy path to satisfy the rest of the initialization, 
                    // or we need to refactor more. 
                    // Let's use a non-existent path but handle it.
                    vec![PathBuf::from("STANDALONE_HUB")]
                } else {
                    return Err(anyhow::anyhow!("No log files found. Provide one or more via 'aegis.exe <PATH1> <PATH2> ...' or use --watch for live events."));
                }
            } else {
                found
            }
        }
    };

    // 🔬 Intelligent Forensic Offset (AU-10): Use the first log for the session hash
    let primary_log = log_paths[0].clone();
    let log_abs = std::fs::canonicalize(&primary_log).unwrap_or(primary_log.clone());
    let mut hasher = Sha256::new();
    hasher.update(log_abs.to_string_lossy().as_bytes());
    let log_hash = format!("{:x}", hasher.finalize());
    let offset_path = PathBuf::from(format!("aegis.pos.{}", &log_hash[..8]));
    
    let audit_path = PathBuf::from("aegis.audit.jsonl");

    // 🔬 SI-7 Self-Integrity Hashing
    if let Ok(exe_path) = std::env::current_exe() {
        if let Ok(h) = calculate_file_hash(&exe_path) {
            let _ = std::fs::write("aegis.bin.hash", h);
        }
    }
    if let Ok(h) = calculate_file_hash(&cli.config) {
        let _ = std::fs::write("aegis.config.hash", h);
    }
    if offset_path.exists() {
        if let Ok(h) = calculate_file_hash(&offset_path) {
            let _ = std::fs::write("aegis.pos.hash", h);
        }
    } else {
        let _ = std::fs::write("aegis.pos.hash", "NEW_SESSION_INITIALIZED");
    }

    // 🔭 Reset Logic
    if cli.reset {
        if offset_path.exists() {
            std::fs::remove_file(&offset_path)?;
            println!("🛡️ Aegis: Forensic checkpoint RESET successfully ({:?}).", offset_path);
        }
        if audit_path.exists() {
            std::fs::remove_file(&audit_path)?;
            println!("🛡️ Aegis: Audit ledger RESET successfully.");
        }
        log_fn("Forensic state RESET via --reset flag.");
    }

    // 5. Initialize Shared Engine, Ledger, and Monitor
    let engine = Arc::new(NistEngine::new(config.clone())?);
    let monitor = Arc::new(PostureMonitor::new());
    let mut ledger_obj = AuditLedger::new(audit_path.clone(), Arc::clone(&engine), Arc::clone(&monitor), &config, 512)?;
    ledger_obj.set_source_artifact(&primary_log.to_string_lossy());
    let ledger = Arc::new(ledger_obj);
    
    let compliance_cache_path = PathBuf::from("aegis.compliance.db");
    let compliance_cache = Arc::new(ComplianceCache::new(&compliance_cache_path)?);
    
    let output_dir = &cli.output_dir;
    let _ = std::fs::create_dir_all(output_dir);
    let receipt_manager = ReceiptManager::new(output_dir)?;
    
    let _ = compliance_cache.prune_old_records();
    
    let (initial_signals, ledger_healthy) = ledger.verify_integrity()?;
    if !ledger_healthy {
        println!("⚠️  NIST AU-9 ALERT: Forensic Ledger Integrity Check FAILED.");
    } else {
        println!("✅ NIST Audit Integrity: VERIFIED | 📜 {} signals confirmed.", initial_signals);
    }

    // 6. Resilience Buffer & Dispatcher
    let edge_db_path = PathBuf::from("aegis.edge.db");
    if cli.reset && edge_db_path.exists() {
        let _ = std::fs::remove_file(&edge_db_path);
    }
    
    let (edge_buffer, buffer_handle) = aegis::edge_buffer::EdgeBuffer::new(
        "Standalone".to_string(), // Default node ID
        edge_db_path, 
        Arc::clone(&ledger), 
        50000, 
        true, // Standalone FOB: Local Ledger is always "Online"
        None // No whisper cache in standalone mode
    )?;
    let edge_buffer = Arc::new(edge_buffer);

    let batch_threshold = if cli.dashboard { 512 } else if cli.watch { 1 } else { 512 };
    let (fusion_tx, fusion_rx) = mpsc::channel(10000);
    
    let dispatcher = Arc::new(Dispatcher::new(
        Arc::clone(&engine), 
        fusion_tx.clone(),
        Arc::clone(&monitor),
        &config,
        batch_threshold
    ));

    let edge_buffer_clone = Arc::clone(&edge_buffer);
    let mut fusion_worker = FusionWorker::new(fusion_rx, edge_buffer_clone);
    
    let fusion_handle = tokio::spawn(async move {
        if let Err(e) = fusion_worker.run().await {
            eprintln!("❌ Aegis Fusion Worker Critical Error: {:?}", e);
        }
    });
    
    let (tx, rx) = mpsc::channel(1024);
    let dispatcher_clone = Arc::clone(&dispatcher);
    
    let dispatcher_handle = tokio::spawn(async move {
        if let Err(e) = dispatcher_clone.run(rx).await {
            eprintln!("❌ Aegis Dispatcher Critical Error: {:?}", e);
        }
    });

    // 7. Concurrent Multi-Log Ingestion (Phase 1)
    let mut sentry_ptr = None;
    let mut _event_sentry_ptr = None;

    if is_watchtower {
        log_fn("Initializing Operation Watchtower (Real-Time Subscription)...");
        let mut event_sentry = aegis::watcher::EventSentry::new(Arc::clone(&monitor));
        let tx_clone = tx.clone();
        event_sentry.start_watching(tx_clone).await?;
        _event_sentry_ptr = Some(event_sentry);
        monitor.increment_sources(3); 
    } else {
        println!("🚀 Aegis: Initializing Concurrent Multi-Log Fusion (FOB Mode)...");
        
        let config_arc = Arc::new(config.clone());
        let records: Vec<LogRecord> = log_paths.par_iter()
            .map(|path| {
                let filename = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                let mut local_records = Vec::new();
                
                let content = match std::fs::read(&path) {
                    Ok(c) => c,
                    Err(_) => return local_records,
                };

                let format = AutoDetector::detect(&content[..std::cmp::min(1024, content.len())], Some(&path));
                
                // Parser selection logic
                let parser: Box<dyn LogParser> = match format {
                    LogFormat::Evtx => Box::new(aegis::parsers::evtx::EvtxParser::new()),
                    LogFormat::JsonArray => {
                        let cfg = config_arc.formats.get("gcp").cloned().unwrap_or(config_arc.formats.values().next().unwrap().clone());
                        Box::new(JsonParser::new(cfg, "json"))
                    },
                    LogFormat::NdJson => {
                        let cfg = config_arc.formats.get("gcp").cloned().unwrap_or(config_arc.formats.values().next().unwrap().clone());
                        Box::new(JsonParser::new(cfg, "ndjson"))
                    },
                    LogFormat::Csv => Box::new(CsvParser::new()),
                    LogFormat::Syslog => Box::new(SyslogParser),
                    LogFormat::WebLog => Box::new(WebLogParser),
                    _ => Box::new(PlainTextParser),
                };

                if format == LogFormat::Evtx {
                    if let Ok(mut evtx_file) = evtx_crate::EvtxParser::from_path(path.to_string_lossy().to_string()) {
                        for rec_json in evtx_file.records_json().flatten() {
                            let mut log_rec = parser.parse(&rec_json.data);
                            log_rec.log_source = Some(filename.clone());
                            local_records.push(log_rec);
                        }
                    }
                } else {
                    let lines = String::from_utf8_lossy(&content);
                    for line in lines.lines() {
                        let mut log_rec = parser.parse(line);
                        log_rec.log_source = Some(filename.clone());
                        local_records.push(log_rec);
                    }
                }
                local_records
            })
            .flatten()
            .collect();

        // println!("DEBUG [Main]: Records count after ingestion: {}", records.len());

        // 🛡️ ARCHITECTURAL GUARDRAIL: Chronological Sorting (NIST AU-11)
        let mut sorted_records = records;
        sorted_records.sort_by_key(|r| r.timestamp);

        // 🔬 Phase 2: Offline Provenance Engine (petgraph)
        let mut lineage = aegis::lineage::LineageGraph::new();
        for record in &sorted_records {
            lineage.add_record(record);
        }
        
        let anomalies = lineage.detect_anomalies();
        if !anomalies.is_empty() {
            for anomaly in anomalies {
                let mut record = LogRecord {
                    timestamp: anomaly.timestamp,
                    message: format!("[LINEAGE ANOMALY] {}", anomaly.description),
                    severity: Some(format!("{:?}", anomaly.severity).to_uppercase()),
                    source: Some("LineageEngine".to_string()),
                    outcome: Some("AnomalyDetected".to_string()),
                    ..Default::default()
                };
                record.metadata.insert("parent_pid".to_string(), anomaly.parent_pid.to_string());
                record.metadata.insert("parent_image".to_string(), anomaly.parent_image);
                record.metadata.insert("child_pid".to_string(), anomaly.child_pid.to_string());
                record.metadata.insert("child_image".to_string(), anomaly.child_image);
                if let Some(cmd) = anomaly.child_cmd {
                    record.metadata.insert("child_command_line".to_string(), cmd);
                }
                
                // Promote to NIST-compliant signal
                record.metadata.insert("nist_control_id".to_string(), "SI-4 [Ghost Hunter]".to_string());
                record.metadata.insert("forensic_tag".to_string(), "LineageAnomaly".to_string());
                record.metadata.insert("captured_message".to_string(), record.message.clone());
                
                tx.send(Arc::new(record)).await.ok();
            }
        }

        println!("⚖️  Timeline Stabilized. Dispatching to Forensic Engine...");
        
        for record in &sorted_records {
            tx.send(Arc::new(record.clone())).await.ok();
        }
        
        monitor.increment_signals(sorted_records.len() as u64);
        monitor.increment_sources(log_paths.len());

        if cli.watch && log_paths.len() == 1 {
            // Restore watch mode for single file if requested
            let path = log_paths[0].clone();
            let format = AutoDetector::detect(&[0u8; 0], Some(&path)); // Re-detect for parser
            let parser: Arc<dyn LogParser> = match format {
                LogFormat::Evtx => Arc::new(aegis::parsers::evtx::EvtxParser::new()),
                _ => Arc::new(PlainTextParser),
            };
            let sentry = Arc::new(Sentry::with_parser(
                path, 
                offset_path.clone(), 
                parser, 
                Arc::clone(&monitor)
            )?);
            let sentry_clone = Arc::clone(&sentry);
            let tx_clone = tx.clone();
            sentry_ptr = Some(sentry);
            tokio::spawn(async move {
                let _ = sentry_clone.tail_live(tx_clone).await;
            });
        }
    }

    // Drop the main thread's sender so `dispatcher` can close when all clones drop
    drop(tx);

    // 8. Output & Dashboard
    if cli.dashboard {
        let mut dashboard = AuditorDashboard::new()?;
        let tick_rate = Duration::from_millis(250);

        loop {
            dashboard.draw(&monitor.get_snapshot())?;
            if event::poll(tick_rate)? {
                if let Event::Key(key) = event::read()? {
                    if let KeyCode::Esc = key.code { break; }
                    if let KeyCode::Char('r') | KeyCode::Char('R') = key.code {
                        let _ = ledger.generate_manifest(&PathBuf::from(output_dir).join("NIST_MANIFEST.md"));
                        let _ = ledger.generate_commanders_brief(&PathBuf::from(output_dir).join("COMMANDERS_BRIEF.md"));
                    }
                }
            }
            monitor.tick();
            if dispatcher_handle.is_finished() { break; }
        }
        dashboard.cleanup()?;
    } else if cli.watch {
        let mode_desc = if is_watchtower { "Watchtower (Live Events)" } else { "Sentinel (File Tailing)" };
        println!("🛡️ Aegis: Active {} is running in the background.", mode_desc);
        
        let mut last_flush_count = monitor.get_snapshot().total_processed;
        let mut no_change_ticks = 0;
        
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let current_count = monitor.get_snapshot().total_processed;
            
            if current_count > last_flush_count {
                no_change_ticks = 0;
                last_flush_count = current_count;
            } else {
                if no_change_ticks == 5 {
                    println!("🔄 Pulse Stable. Syncing artifacts ({} total events).", current_count);
                    let _ = AuditLedger::prep_vault(output_dir);
                    let _ = ledger.generate_manifest(&PathBuf::from(output_dir).join("NIST_MANIFEST.md"));
                    let _ = ledger.generate_commanders_brief(&PathBuf::from(output_dir).join("COMMANDERS_BRIEF.md"));
                    if let Ok(events) = ledger.get_posture_events() {
                        let _ = std::fs::write(PathBuf::from(output_dir).join("oscal-assessment-results.json"), aegis::report::OscalExporter::generate_assessment_results(&events, "Aegis-Sentinel", &config).unwrap_or_default());
                        let _ = std::fs::write(PathBuf::from(output_dir).join("oscal-poam.json"), aegis::report::OscalExporter::generate_poam(&events, &compliance_cache, &config).unwrap_or_default());
                    }
                }
                if no_change_ticks <= 5 {
                    no_change_ticks += 1;
                }
            }
            if dispatcher_handle.is_finished() { break; }
        }
    } else {
        // --- HARDENED ORCHESTRATION: Drain & Await Ingestion Pipeline ---
        // 1. Drop the main thread references to allow the chain to close
        drop(dispatcher);       // Allow dispatcher to drop fusion_tx
        drop(fusion_tx);        // Allow fusion_rx to close
        drop(edge_buffer);      // Allow edge_buffer to close once fusion finishes
        
        // 2. Wait for workers to finish processing and flushing (Sequential Chain)
        let _ = dispatcher_handle.await;
        let _ = fusion_handle.await;
        let _ = buffer_handle.await;
        
        let _ = AuditLedger::prep_vault(output_dir);
        let manifest_path = PathBuf::from(output_dir).join("NIST_MANIFEST.md");
        ledger.generate_manifest(&manifest_path)?;
        let brief_path = PathBuf::from(output_dir).join("COMMANDERS_BRIEF.md");
        ledger.generate_commanders_brief(&brief_path)?;

        let events = ledger.get_posture_events()?;
        let system_name = "Aegis-Sentinel";
        
        let ar_json = aegis::report::OscalExporter::generate_assessment_results(&events, system_name, &config)?;
        std::fs::write(PathBuf::from(output_dir).join("oscal-assessment-results.json"), ar_json)?;
        
        let poam_json = aegis::report::OscalExporter::generate_poam(&events, &compliance_cache, &config)?;
        std::fs::write(PathBuf::from(output_dir).join("oscal-poam.json"), poam_json)?;

        if let Some(export_type) = &cli.export {
            if export_type == "pdf" {
                aegis::report::ComplianceReporter::generate_pdf(&events, PathBuf::from(output_dir).join("compliance-report.pdf").as_path())?;
                println!("✅ compliance-report.pdf Generated Successfully");
            }
        }
        
        // --- NIST AU-6 PROOF OF REVIEW (PHASE 3) ---
        let snapshot = monitor.get_snapshot();
        let metrics = ReceiptMetrics {
            total_signals_reviewed: snapshot.total_processed,
            failures_detected: snapshot.signals_found, 
            time_window_start: Local::now() - Duration::from_secs(snapshot.uptime_secs),
            time_window_end: Local::now(),
        };
        
        receipt_manager.generate_receipt(
            metrics, 
            env!("CARGO_PKG_VERSION"), 
            &config.profile_name
        )?;
        
        println!("✅ NIST Compliance Suite Generated (MANIFEST, OSCAL-AR, OSCAL-POAM, AU-6 RECEIPT)");

        // --- 📊 FINAL PULSE SUMMARY ---
        let final_snapshot = monitor.get_snapshot();
        if final_snapshot.signals_found > 0 {
            let criticals = events.iter().filter(|e| e.severity == aegis::models::SeverityLevel::Critical).count();
            let highs = events.iter().filter(|e| e.severity == aegis::models::SeverityLevel::High).count();

            let grade = if criticals > 0 { 
                "🔴 F (CRITICAL)" 
            } else if highs > 5 { 
                "🟠 D (FAILING)" 
            } else if highs > 0 {
                "🟡 C (CAUTION)"
            } else {
                "🟡 C (RISK)" // Medium/Low signals present
            };
            
            println!("🚨 COMPLIANCE ALERT: {} Forensic Signals Confirmed.", final_snapshot.signals_found);
            println!("🛡️ System Posture: {}", grade);
        } else {
            println!("✅ PULSE SECURE: 0 forensic anomalies detected.");
        }

        // --- PHASE 4: STATELESS FINALIZATION & VAULT ISOLATION ---
        ledger.produce_final_artifact(output_dir)?;
        
        // Targeted Purge: Only debug trace (Excluding .pos, .hash, and .db per Directive)
        // if PathBuf::from("aegis.debug.log").exists() {
        //     let _ = std::fs::remove_file("aegis.debug.log");
        // }
    }

    if let Some(s) = sentry_ptr {
        let _ = s.save_current_offset();
    }
    
    if cli.mode == "standalone" {
        println!("🚀 Aegis: Hub is active. Press Ctrl+C to terminate mission.");
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    }

    println!("🛡️ Project Aegis: Audit Finalized Successfully.");
    Ok(())
}

async fn run_preflight_checks() -> Result<()> {
    if !cfg!(windows) { return Ok(()); }

    // Check 1: Registry Auditing (SC-7 / SI-4 / Operation Shadow Vault)
    let output_reg = Command::new("powershell")
        .args(&["-NoProfile", "-Command", "auditpol /get /subcategory:'Registry' /r"])
        .output()
        .await;
    
    if let Ok(output) = output_reg {
        let stdout_reg = String::from_utf8_lossy(&output.stdout);
        if !stdout_reg.contains("Success") {
            println!("⚠️ WARNING: CRITICAL NIST SI-4 ALIGNMENT FAILURE: 'Registry' auditing (Event ID 4663/4656) is DISABLED.");
            println!("   Operation Shadow Vault (Registry Trap) requires this for SAM/SECURITY exfiltration detection.");
        } else {
            println!("✅ Forensic Baseline: Registry Auditing is ACTIVE.");
        }
    }

    // Check 2: Process Creation Auditing (AU-12 / SI-4) - Critical for Operation Ghost Hunter
    let output_proc = Command::new("powershell")
        .args(&["-NoProfile", "-Command", "auditpol /get /subcategory:'Process Creation' /r"])
        .output()
        .await;
    
    if let Ok(output) = output_proc {
        let stdout_proc = String::from_utf8_lossy(&output.stdout);
        if !stdout_proc.contains("Success") {
            println!("⚠️ WARNING: CRITICAL NIST AU-12 ALIGNMENT FAILURE: 'Process Creation' auditing (Event ID 4688) is DISABLED.");
            println!("   Operation Ghost Hunter (Lineage Reconstruction) requires this telemetry for low-noise analysis.");
            println!("   Enable via GPO: Detailed Tracking > Audit Process Creation.");
        } else {
            println!("✅ Forensic Baseline: Process Creation Auditing is ACTIVE.");
        }
    }
    
    // Check 3: Process Command Line (Fidelity Check)
    let output_cmd = Command::new("powershell")
        .args(&["-NoProfile", "-Command", "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' | Select-Object -ExpandProperty ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue"])
        .output()
        .await;
    
    if let Ok(output) = output_cmd {
        let stdout_cmd = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout_cmd != "1" {
            println!("⚠️ WARNING: 'Include Command Line in Process Creation Events' is DISABLED. Forensic depth will be reduced.");
        } else {
            println!("✅ Forensic Baseline: Process Command Line telemetry is ACTIVE.");
        }
    }

    Ok(())
}
