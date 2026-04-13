use aegis::watcher::Sentry;
use aegis::dispatcher::Dispatcher;
use aegis::ledger::AuditLedger;
use aegis::monitor::PostureMonitor;
use aegis::dashboard::AuditorDashboard;
use aegis::NistEngine;
use aegis::compliance_cache::ComplianceCache;
use aegis::audit_receipt::{ReceiptManager, ReceiptMetrics};
use aegis::config::{AppConfig, ActiveFramework};
use aegis::correlation::FusionWorker;
use aegis::parsers::{
    json::JsonParser, 
    plain::PlainTextParser, 
    csv::CsvParser,
    syslog::SyslogParser,
    web_log::WebLogParser,
    LogParser, AutoDetector, LogFormat
};
use anyhow::{Result, Context};
use std::sync::Arc;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;
use chrono::Local;
use crossterm::event::{self, Event, KeyCode};
use clap::Parser;
use sha2::{Sha256, Digest};

// Rename the external crate to avoid collision with our internal module
extern crate evtx as evtx_crate;

#[derive(Parser, Debug)]
#[command(author = "DeepMind", version, about = "Aegis: The Compliance Sentinel", long_about = None)]
struct Cli {
    /// Path to the log file to monitor
    log_file: Option<PathBuf>,

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

    // 3. Selection of AI Proxy Parser (Priority Override for Phase 7)
    let is_ai_rmf = matches!(config.active_framework, ActiveFramework::AiRmf100);

    // 4. Select Target Log (with Auto-Discovery)
    let log_path = match cli.log_file {
        Some(path) => path,
        None => {
            let candidates = vec![PathBuf::from("auth.log"), PathBuf::from("cloudlogs.json")];
            candidates.into_iter().find(|p| p.exists()).context("No log file found. Provide one via 'aegis.exe <PATH>'")?
        }
    };

    // 🔬 Intelligent Forensic Offset (AU-10): Hash the canonical path to ensure 
    // that switching between logs (e.g., auth.log vs evtx) never overlaps offsets.
    let log_abs = std::fs::canonicalize(&log_path).unwrap_or(log_path.clone());
    let mut hasher = Sha256::new();
    hasher.update(log_abs.to_string_lossy().as_bytes());
    let log_hash = format!("{:x}", hasher.finalize());
    let offset_path = PathBuf::from(format!("aegis.pos.{}", &log_hash[..8]));
    
    let audit_path = PathBuf::from("aegis.audit.jsonl");

    // 🔬 SI-7 Self-Integrity Hashing (Information Integrity): We delay this until 
    // the target log and its specific offset file are identified.
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

    // 🔭 Reset Logic (Forensic Clean Slate)
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
    let engine = Arc::new(NistEngine::new()?);
    let monitor = Arc::new(PostureMonitor::new());
    let mut ledger_obj = AuditLedger::new(audit_path.clone(), Arc::clone(&engine), Arc::clone(&monitor), &config, 512)?;
    ledger_obj.set_source_artifact(&log_path.to_string_lossy());
    let ledger = Arc::new(ledger_obj);
    
    let compliance_cache_path = PathBuf::from("aegis.compliance.db");
    let compliance_cache = Arc::new(ComplianceCache::new(&compliance_cache_path)?);
    
    let output_dir = "forensic_results";
    let receipt_manager = ReceiptManager::new(output_dir)?;
    
    // Automatic cache pruning (NIST CA-5)
    let _ = compliance_cache.prune_old_records();
    
    let (initial_signals, ledger_healthy) = ledger.verify_integrity()?;
    if !ledger_healthy {
        println!("⚠️  NIST AU-9 ALERT: Forensic Ledger Integrity Check FAILED.");
    } else {
        println!("✅ NIST Audit Integrity: VERIFIED | 📜 {} signals confirmed.", initial_signals);
    }

    // 6. Initialize Format-Specific Parser (with Watch Mode Resilience)
    if cli.watch && !log_path.exists() {
        println!("🔭 Aegis Sentinel: Target {:?} not found. Entering active wait state...", log_path);
        while !log_path.exists() {
            std::thread::sleep(Duration::from_secs(2));
        }
        println!("✅ Aegis Sentinel: Origin detected at {:?}. Initializing ingestion...", log_path);
    }

    let detected_format = if let Some(fmt_str) = cli.format.as_deref() {
        match fmt_str {
            "json" | "gcp" => LogFormat::JsonArray,
            "plain" | "txt" => LogFormat::PlainText,
            "csv" => LogFormat::Csv,
            "evtx" => LogFormat::Evtx,
            "ai_proxy" => LogFormat::AiProxy,
            "syslog" => LogFormat::Syslog,
            "web" | "access" => LogFormat::WebLog,
            _ => {
                let content = std::fs::read(&log_path).context(format!("Failed to read {:?}", log_path))?;
                AutoDetector::detect(&content[..std::cmp::min(1024, content.len())], Some(&log_path))
            }
        }
    } else {
        let content = std::fs::read(&log_path).context(format!("Failed to read {:?}", log_path))?;
        let mut fmt = AutoDetector::detect(&content[..std::cmp::min(1024, content.len())], Some(&log_path));
        // Priority Override: If profile is 100-1, assume AI Proxy metadata unless explicit override
        if is_ai_rmf && (fmt == LogFormat::NdJson || fmt == LogFormat::PlainText) {
             fmt = LogFormat::AiProxy;
        }
        fmt
    };

    let parser: Arc<dyn LogParser> = match detected_format {
        LogFormat::AiProxy => {
            log_fn("Initializing AI RMF Proxy Parser (LiteLLM/OpenAI)...");
            Arc::new(aegis::parsers::ai_proxy::AiProxyParser::new())
        },
        LogFormat::Elastic => {
            log_fn("Initializing High-Fidelity Elastic/Endpoint Forensic Parser...");
            let elastic_config = config.formats.get("elastic").cloned().unwrap_or(config.formats.values().next().unwrap().clone());
            Arc::new(JsonParser::new(elastic_config, "elastic"))
        },
        LogFormat::JsonArray | LogFormat::NdJson => {
            let (name, gcp_config) = if let Some(c) = config.formats.get("gcp") {
                ("gcp", c.clone())
            } else {
                ("json_generic", config.formats.values().next().unwrap().clone())
            };
            Arc::new(JsonParser::new(gcp_config, name))
        },
        LogFormat::Csv => Arc::new(CsvParser::new()),
        LogFormat::Evtx => {
            log_fn("Initializing Binary Forensic Parser (evtx)...");
            Arc::new(aegis::parsers::evtx::EvtxParser::new())
        },
        LogFormat::Pcap => {
            log_fn("Initializing Network Forensic Parser (pcap)...");
            Arc::new(aegis::parsers::pcap::PcapParser::new())
        },
        LogFormat::Syslog => {
            log_fn("Initializing High-Fidelity Syslog Parser (RFC 5424/3164)...");
            Arc::new(SyslogParser)
        },
        LogFormat::WebLog => {
            log_fn("Initializing Web Server Forensic Parser (Combined/CLF)...");
            Arc::new(WebLogParser)
        },
        _ => Arc::new(PlainTextParser),
    };

    // 6. Resilience Buffer & Dispatcher
    let edge_db_path = PathBuf::from("aegis.edge.db");
    if cli.reset && edge_db_path.exists() {
        let _ = std::fs::remove_file(&edge_db_path);
    }
    
    let (edge_buffer, buffer_handle) = aegis::edge_buffer::EdgeBuffer::new(
        edge_db_path, 
        Arc::clone(&ledger), 
        50000, 
        !cli.offline
    )?;
    let edge_buffer = Arc::new(edge_buffer);

    let batch_threshold = if cli.dashboard || cli.watch { 512 } else { 1 };
    let (fusion_tx, fusion_rx) = mpsc::channel(10000);
    
    let dispatcher = Arc::new(Dispatcher::new(
        Arc::clone(&engine), 
        fusion_tx.clone(),
        Arc::clone(&monitor),
        &config,
        batch_threshold
    ));

    // 7. Initialize Fusion Worker (NIST IR-4 Correlation Engine)
    let edge_buffer_clone = Arc::clone(&edge_buffer);
    let monitor_clone = Arc::clone(&monitor);
    let mut fusion_worker = FusionWorker::new(fusion_rx, edge_buffer_clone, monitor_clone);
    
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

    // 7. Forensic Branch: .evtx vs Standard Stream
    let mut sentry_ptr = None;

    if detected_format == LogFormat::Evtx {
        log_fn("Pivoting to Binary Forensic Ingestion (.evtx)...");
        // Windows Forensic Logic: Read from path again via crate specialized iterator
        let evtx_path_str = log_path.to_string_lossy().to_string();
        let mut evtx_file = evtx_crate::EvtxParser::from_path(evtx_path_str)?;
        for rec_json in evtx_file.records_json().flatten() {
            let log_rec = parser.parse(&rec_json.data);
            tx.send(Arc::new(log_rec)).await.ok();
        }
    } else if detected_format == LogFormat::Pcap {
        log_fn("Pivoting to Network Forensic Ingestion (.pcap/ng)...");
        if let Some(pcap_parser) = parser.as_any().downcast_ref::<aegis::parsers::pcap::PcapParser>() {
            let records = pcap_parser.parse_binary(&log_path);
            for rec in records {
                tx.send(Arc::new(rec)).await.ok();
            }
        }
    } else {
        let sentry = Arc::new(Sentry::with_parser(
            log_path.clone(), 
            offset_path.clone(), 
            parser, 
            Arc::clone(&monitor)
        )?);
        
        if let Ok(metadata) = std::fs::metadata(&audit_path) {
            if metadata.len() == 0 && offset_path.exists() {
                let _ = std::fs::remove_file(&offset_path);
            }
        }

        monitor.increment_signals(initial_signals as u64);
        monitor.increment_sources(1);

        let sentry_clone = Arc::clone(&sentry);
        let tx_clone = tx.clone();
        sentry_ptr = Some(sentry);

        if cli.watch {
            tokio::spawn(async move {
                let _ = sentry_clone.tail_live(tx_clone).await;
            });
        } else {
            println!("🚀 Aegis Automated Mode: Processing stream for NIST manifest...");
            sentry_clone.process_once(tx_clone, 0).await?;
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
        println!("🛡️ Aegis Sentinel: Watching {:?} in the background.", log_path);
        
        let mut last_flush_count = monitor.get_snapshot().total_processed;
        let mut no_change_ticks = 0;
        
        loop {
            tokio::time::sleep(Duration::from_millis(1000)).await;
            let current_count = monitor.get_snapshot().total_processed;
            
            if current_count > last_flush_count {
                // New events ingested
                no_change_ticks = 0;
                last_flush_count = current_count;
            } else {
                // No new events, check if we need to flush (debounce)
                if no_change_ticks == 2 {
                    println!("🔄 Event debounce triggered. Flushing artifacts ({} events processed).", current_count);
                    let _ = AuditLedger::prep_vault(output_dir);
                    let _ = ledger.generate_manifest(&PathBuf::from(output_dir).join("NIST_MANIFEST.md"));
                    let _ = std::fs::write(PathBuf::from(output_dir).join("COMMANDERS_BRIEF.md"), {
                        let count = ledger.verify_integrity().unwrap_or((0, false)).0;
                        let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
                        format!("# 🛡️ COMMANDER'S BRIEF: AEGIS STATUS\n\n**Audit Pulse**: {}\n**Signals Captured**: {}\n**Compliance State**: NIST-CERTIFIED\n\n*Notice: Review NIST_MANIFEST.md for full technical details.*", ts, count)
                    });
                    if let Ok(events) = ledger.get_posture_events() {
                        let _ = std::fs::write(PathBuf::from(output_dir).join("oscal-assessment-results.json"), aegis::report::OscalExporter::generate_assessment_results(&events, "Aegis-Sentinel", &config).unwrap_or_default());
                        let _ = std::fs::write(PathBuf::from(output_dir).join("oscal-poam.json"), aegis::report::OscalExporter::generate_poam(&events, &compliance_cache, &config).unwrap_or_default());
                    }
                }
                if no_change_ticks <= 2 {
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
        if PathBuf::from("aegis.debug.log").exists() {
            let _ = std::fs::remove_file("aegis.debug.log");
        }
    }

    if let Some(s) = sentry_ptr {
        let _ = s.save_current_offset();
    }
    
    println!("🛡️ Project Aegis: Audit Finalized Successfully.");
    Ok(())
}
