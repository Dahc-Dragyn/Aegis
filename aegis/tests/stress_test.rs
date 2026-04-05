use aegis::watcher::Sentry;
use aegis::dispatcher::Dispatcher;
use aegis::ledger::AuditLedger;
use aegis::monitor::PostureMonitor;
use aegis::NistEngine;
use aegis::config::AppConfig;
use std::sync::Arc;
use tokio::sync::mpsc;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::Instant;
use tempfile::tempdir;

#[tokio::test]
async fn test_100k_compliance_burst() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    let offset_path = dir.path().join("aegis.pos");
    let audit_path = dir.path().join("aegis.audit.jsonl");

    // 1. Initialize System with Default Config (Enabled for Federal Stress)
    let mut config = AppConfig::default_config();
    config.redaction.enabled = true;
    config.redaction.mask_ips = true;
    
    let engine = Arc::new(NistEngine::new().unwrap());
    let monitor = Arc::new(PostureMonitor::new());
    let ledger = Arc::new(AuditLedger::new(audit_path.clone(), Arc::clone(&engine), Arc::clone(&monitor), &config, 512).unwrap());
    
    // Hardened Dispatcher (using batch size 512 for stress)
    let dispatcher = Dispatcher::new(
        Arc::clone(&engine), 
        Arc::clone(&ledger), 
        Arc::clone(&monitor),
        &config,
        512
    );
    
    // Hardened Sentry (using PlainTextParser for log-injection tests)
    let parser = Arc::new(aegis::parsers::plain::PlainTextParser);
    let monitor = Arc::new(PostureMonitor::new());
    let sentry = Arc::new(Sentry::with_parser(
        log_path.clone(), 
        offset_path.clone(), 
        parser, 
        monitor
    ).expect("Failed to create sentry"));
    
    // Achievement: Use a massive channel (2x volume) to eliminate backpressure
    let (tx, rx) = mpsc::channel(200000); 

    // 2. Spawn Dispatcher (Will end when tx is dropped)
    let dispatcher_handle = tokio::spawn(async move {
        let _ = dispatcher.run(rx).await;
    });

    // 3. The 100,000 Line Burst Injector (LFA v3 Hardened)
    println!("🚀 Starting 100,000 line burst...");
    let start = Instant::now();
    {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap();

        for i in 0..100_000 {
            // Mix 10% NIST hits (10,000 total matches expected)
            if i % 10 == 0 {
                // Signature: "sudo: auth failure" (LFA v3 Standard)
                writeln!(file, "2026-04-04T12:00:00Z auth_service sudo: auth failure for user admin from 192.168.1.100").unwrap();
            } else {
                writeln!(file, "2026-04-04T12:00:00Z noise_service periodic log line {}", i).unwrap();
            }
        }
        file.flush().unwrap();
    }
    let injection_duration = start.elapsed();
    println!("✅ Injection complete in {:?}", injection_duration);

    // 4. Force Capture (One-Shot Sweep)
    // Achievement: By calling process_once directly and letting the handle drop, 
    // we ensure the tx channel CLOSES, triggering a Final Flush in the dispatcher.
    {
        sentry.process_once(tx, 0).await.unwrap();
    } // tx is dropped here

    // 5. Wait for Dispatcher to finish the Final Flush
    dispatcher_handle.await.unwrap();

    let total_duration = start.elapsed();
    let snapshot = monitor.get_snapshot();
    
    // Reliability Check: Verify Audit Ledger
    let audit_content = std::fs::read_to_string(&audit_path).unwrap();
    let audit_count = audit_content.trim().lines().count();

    println!("📊 Stress Test Results:");
    println!("   - Total Processed:   {}", snapshot.total_processed);
    let signals = snapshot.signals_found;
    println!("   - Signals Found:     {}", signals);
    println!("   - Ledger Records:    {}", audit_count);
    println!("   - Total Duration:    {:?}", total_duration);
    
    let eps = (snapshot.total_processed as f64) / total_duration.as_secs_f64();
    println!("   - Effective EPS:     {:.2}", eps);

    assert_eq!(snapshot.total_processed, 100_000, "Should process all 100k lines");
    // Achievement: With Final Flush and massive channel, we expect EXACTLY 10,000 signals.
    assert_eq!(signals, 10_000, "Should capture exactly 10,000 compliance events");
    assert_eq!(audit_count, 10_000, "Should record exactly 10,000 compliance events in the ledger");
}
