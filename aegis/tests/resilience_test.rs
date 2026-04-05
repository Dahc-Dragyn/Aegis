use aegis::watcher::Sentry;
use aegis::dispatcher::Dispatcher;
use aegis::ledger::AuditLedger;
use aegis::monitor::PostureMonitor;
use aegis::NistEngine;
use aegis::config::AppConfig;
use std::sync::Arc;
use tokio::sync::mpsc;
use std::fs::OpenOptions;
use std::io::{Write};
use std::time::Duration;
use tempfile::tempdir;

#[tokio::test]
async fn test_log_rotation_resilience() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    let offset_path = dir.path().join("aegis.pos");
    let audit_path = dir.path().join("aegis.audit.jsonl");

    // 1. Initialize System with Default Config
    let config = AppConfig::default_config();
    let engine = Arc::new(NistEngine::new().unwrap());
    let monitor = Arc::new(PostureMonitor::new());
    let ledger = Arc::new(AuditLedger::new(audit_path.clone(), Arc::clone(&engine), Arc::clone(&monitor), &config, 1).unwrap());
    let (tx, rx) = mpsc::channel(100);
    
    // Hardened Dispatcher (using batch size 1 for instant feedback in resilience tests)
    let dispatcher = Dispatcher::new(
        Arc::clone(&engine), 
        Arc::clone(&ledger), 
        Arc::clone(&monitor),
        &config,
        1
    );
    
    // Hardened Sentry (using PlainTextParser for log-injection tests)
    let parser = Arc::new(aegis::parsers::plain::PlainTextParser);
    let monitor = Arc::new(PostureMonitor::new());
    let sentry = Sentry::with_parser(
        log_path.clone(), 
        offset_path.clone(), 
        parser, 
        monitor
    ).expect("Failed to create sentry");
    let d_handle = tokio::spawn(async move { let _ = dispatcher.run(rx).await; });
    let s_handle = tokio::spawn(async move { let _ = sentry.tail(tx).await; });

    // 2. WAIT FOR SENTRY TO INITIALIZE
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // 3. Inject Log (Should be captured)
    {
        let mut file = OpenOptions::new().create(true).append(true).open(&log_path).unwrap();
        writeln!(file, "2026-04-03T12:00:00Z auth_service sudo: auth failure for user admin from 192.168.1.100").unwrap();
        file.flush().unwrap();
    } 

    tokio::time::sleep(Duration::from_millis(2000)).await;
    assert_eq!(monitor.get_snapshot().signals_found, 1, "Initial signal failed to register");

    // 4. ROTATE LOG (Delete and Recreate - Changes Creation Time)
    println!("🔄 Rotating log file...");
    std::fs::remove_file(&log_path).unwrap();
    
    // Rotation Visibility Gap (Essential for Windows OS detection)
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // 5. NEW WRITE AFTER ROTATION
    {
        let mut file = OpenOptions::new().create(true).append(true).open(&log_path).unwrap();
        writeln!(file, "2026-04-03T12:05:00Z auth_service sudo: auth failure for user admin from 10.0.0.5").unwrap();
        file.flush().unwrap();
    } 

    // Wait for Sentry to detect new file after rotation
    tokio::time::sleep(Duration::from_millis(3000)).await;

    let snapshot = monitor.get_snapshot();
    println!("📊 Resilience Test Results:");
    println!("   - Total Processed: {}", snapshot.total_processed);
    println!("   - Capture State:  {}", if snapshot.signals_found == 2 { "PASSED" } else { "FAILED" });

    assert_eq!(snapshot.signals_found, 2, "Aegis failed to recover after log rotation");

    d_handle.abort();
    s_handle.abort();
}
