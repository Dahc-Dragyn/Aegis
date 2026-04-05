use aegis::watcher::Sentry;
use aegis::dispatcher::Dispatcher;
use aegis::ledger::AuditLedger;
use aegis::monitor::PostureMonitor;
use aegis::dashboard::AuditorDashboard;
use aegis::NistEngine;
use aegis::config::AppConfig;
use aegis::parsers::{json::JsonParser, plain::PlainTextParser, LogParser};
use anyhow::{Result, Context};
use std::sync::Arc;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;
use chrono::Utc;
use crossterm::event::{self, Event, KeyCode};
use clap::Parser;

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

    /// Generate NIST_MANIFEST.md and exit automatically (Automated Mode)
    #[arg(short, long, default_value_t = false)]
    report: bool,

    /// Reset forensic checkpoint (Force Re-scan)
    #[arg(long, default_value_t = false)]
    reset: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // --- BLACKBOX LOGGING SETUP ---
    let log_fn = |msg: &str| {
        let mut file = OpenOptions::new().create(true).append(true).open("aegis.debug.log").ok()?;
        writeln!(file, "[{}] {}", Utc::now(), msg).ok()
    };
    log_fn("--- AEGIS STARTUP ---");

    // 1. Reset Logic
    if cli.reset {
        let pos_file = PathBuf::from("aegis.pos");
        if pos_file.exists() {
            std::fs::remove_file(&pos_file)?;
            log_fn("Forensic checkpoint RESET via --reset flag.");
            println!("🛡️ Aegis: Forensic checkpoint RESET successfully.");
        }
    }

    let _desktop_path = dirs_next::desktop_dir().unwrap_or_else(|| PathBuf::from("."));

    // 2. Load Hardened Configuration
    let config = if cli.config.exists() {
        AppConfig::load_from_file(&cli.config)?
    } else {
        AppConfig::default_config()
    };

    // 2. Select Target Log (with Auto-Discovery)
    let log_path = match cli.log_file {
        Some(path) => path,
        None => {
            // Check for common files if not provided
            let candidates = vec![PathBuf::from("auth.log"), PathBuf::from("cloudlogs.json")];
            candidates.into_iter().find(|p| p.exists()).context("No log file found. Provide one via 'aegis.exe <PATH>'")?
        }
    };

    let offset_path = PathBuf::from("aegis.pos");
    let audit_path = PathBuf::from("aegis.audit.jsonl");

    // 3. Initialize Shared Engine, Ledger, and Monitor
    let engine = Arc::new(NistEngine::new()?);
    let monitor = Arc::new(PostureMonitor::new());
    let ledger = Arc::new(AuditLedger::new(audit_path.clone(), Arc::clone(&engine), Arc::clone(&monitor), &config, 512)?);
    
    // --- FORENSIC INTEGRITY & CATCH-UP CHECK ---
    let (initial_signals, ledger_healthy) = ledger.verify_integrity()?;
    if !ledger_healthy {
        println!("⚠️  NIST AU-9 ALERT: Forensic Ledger Integrity Check FAILED.");
        println!("📦 Integrity state: CORRUPT (Non-standard JSON detected in ledger)");
    } else {
        println!("✅ NIST Audit Integrity: VERIFIED | 📜 {} signals confirmed.", initial_signals);
    }

    // --- FORENSIC DIAGNOSTIC CHECK ---
    if offset_path.exists() {
        if let Ok(offset_str) = std::fs::read_to_string(&offset_path) {
            if let Ok(offset) = offset_str.trim().parse::<u64>() {
                if let Ok(metadata) = std::fs::metadata(&log_path) {
                    if offset >= metadata.len() {
                        println!("📑 Log Pulse: '{:?}' is already fully audited.", log_path);
                        println!("💡 To re-scan, use: aegis.exe --reset");
                    }
                }
            }
        }
    }

    // 4. Initialize Format-Specific Parser
    let parser: Arc<dyn LogParser> = match cli.format.as_deref() {
        Some("json") | Some("gcp") => {
            let gcp_config = config.formats.get("gcp").cloned().unwrap_or(config.formats.values().next().unwrap().clone());
            Arc::new(JsonParser::new(gcp_config))
        },
        Some("plain") => Arc::new(PlainTextParser),
        _ => {
             // Default to auto-detecting the first one in config if it looks like JSON
             let gcp_config = config.formats.get("gcp").cloned().unwrap_or(config.formats.values().next().cloned().unwrap());
             Arc::new(JsonParser::new(gcp_config))
        }
    };

    // 5. Wire the High-Performance Pipeline
    let batch_threshold = if cli.report { 1 } else { 512 };
    let dispatcher = Arc::new(Dispatcher::new(
        Arc::clone(&engine), 
        Arc::clone(&ledger), 
        Arc::clone(&monitor),
        &config,
        batch_threshold
    ));
    
    let sentry = Arc::new(Sentry::with_parser(
        log_path.clone(), 
        offset_path.clone(), 
        parser, 
        Arc::clone(&monitor)
    )?);
    monitor.increment_signals(initial_signals);
    monitor.increment_sources(1);
    
    let (tx, rx) = mpsc::channel(1024);

    let sentry_clone = Arc::clone(&sentry);
    let dispatcher_clone = Arc::clone(&dispatcher);
    
    // --- FORCED REPLAY LOGIC: If ledger is empty, reset offset ---
    if let Ok(metadata) = std::fs::metadata(&audit_path) {
        if metadata.len() == 0 && offset_path.exists() {
            log_fn("Audit ledger is empty. Forcing full log re-scan...");
            let _ = std::fs::remove_file(&offset_path);
        }
    }

    log_fn(&format!("Sentry Path: {:?}", log_path));
    log_fn(&format!("Report Mode: {}", cli.report));

    // ALWAYS spawn Dispatcher to avoid channel blockage
    let dispatcher_handle = tokio::spawn(async move {
        log_fn("Dispatcher thread started.");
        if let Err(e) = dispatcher_clone.run(rx).await {
            log_fn(&format!("❌ DISPATCHER CRITICAL: {:?}", e));
            eprintln!("❌ Aegis Dispatcher Critical Error: {:?}", e);
        }
        log_fn("Dispatcher thread finished.");
    });

    if cli.report {
        log_fn("Entering Report Mode...");
        println!("🚀 Aegis Automated Mode: Processing stream for NIST manifest...");
        let stats = sentry_clone.process_once(tx.clone(), 0).await?;
        log_fn(&format!("Inbound stream processing completed (offset: {})", stats));
        
        // Give dispatcher a moment to flush batches
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        let manifest_path = PathBuf::from("NIST_MANIFEST.md");
        ledger.generate_manifest(&manifest_path)?;
        println!("✅ NIST_MANIFEST.md Generated Successfully (Automated Mode)");
    } else {
        log_fn("Entering Interactive Mode (TUI)...");
        let sentry_handle = tokio::spawn(async move {
            log_fn("Sentry thread started.");
            if let Err(e) = sentry_clone.tail(tx).await {
                log_fn(&format!("❌ SENTRY CRITICAL: {:?}", e));
                eprintln!("❌ Aegis Sentry Critical Error: {:?}", e);
            }
            log_fn("Sentry thread finished.");
        });

        log_fn("Initializing AuditorDashboard...");
        let mut dashboard = AuditorDashboard::new()?;
        log_fn("AuditorDashboard active. Entering main loop.");
        let mut last_tick = std::time::Instant::now();
        let tick_rate = Duration::from_millis(250);

        loop {
            let snapshot = monitor.get_snapshot();
            dashboard.draw(&snapshot)?;

            if event::poll(tick_rate)? {
                if let Event::Key(key) = event::read()? {
                    if let KeyCode::Esc = key.code {
                        break;
                    }
                    if let KeyCode::Char('r') | KeyCode::Char('R') = key.code {
                        let manifest_path = PathBuf::from("NIST_MANIFEST.md");
                        if let Err(e) = ledger.generate_manifest(&manifest_path) {
                            monitor.set_status(format!("ERROR: Report failed: {:?}", e));
                        } else {
                            monitor.set_status("NIST_MANIFEST.md Generated Successfully".to_string());
                        }
                    }
                }
            }

            if last_tick.elapsed() >= tick_rate {
                monitor.tick();
                last_tick = std::time::Instant::now();
            }

            // CRITICAL: Exit if a core thread crashes
            if sentry_handle.is_finished() || dispatcher_handle.is_finished() {
                 let status = if sentry_handle.is_finished() { "WATCHER_EXIT" } else { "DISPATCHER_EXIT" };
                 monitor.set_status(format!("CRITICAL: Thread exited ({})", status));
                 tokio::time::sleep(Duration::from_millis(100)).await;
                 break;
            }
        }
        dashboard.cleanup()?;
        
        // --- FORENSIC EXIT ANALYSIS ---
        if sentry_handle.is_finished() {
            if let Err(e) = sentry_handle.await {
                eprintln!("❌ Aegis Sentry PANIC captured: {:?}", e);
            }
        }
        if dispatcher_handle.is_finished() {
            if let Err(e) = dispatcher_handle.await {
                eprintln!("❌ Aegis Dispatcher PANIC captured: {:?}", e);
            }
        }
    }
    let _ = sentry.save_current_offset();
    println!("🛡️ Project Aegis: Audit Finalized Successfully.");
    Ok(())
}
