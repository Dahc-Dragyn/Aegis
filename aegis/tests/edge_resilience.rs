use aegis::edge_buffer::{EdgeBuffer};
use aegis::ledger::AuditLedger;
use aegis::monitor::PostureMonitor;
use aegis::config::AppConfig;
use aegis::NistEngine;
use aegis::models::{LogRecord, ParsingQuality};
use std::sync::Arc;

use chrono::Utc;
use tempfile::tempdir;

#[tokio::test]
async fn test_edge_resilience_spillover() {
    let dir = tempdir().unwrap();
    let edge_db_path = dir.path().join("aegis.edge.db");
    let audit_path = dir.path().join("aegis.audit.jsonl");

    let engine = Arc::new(NistEngine::new(AppConfig::default_config()).unwrap());
    let monitor = Arc::new(PostureMonitor::new());
    let config = AppConfig::default_config();
    let ledger = Arc::new(AuditLedger::new(audit_path.clone(), Arc::clone(&engine), Arc::clone(&monitor), &config, 1).unwrap());

    // 1. Initialize EdgeBuffer in OFFLINE mode
    let (buffer, _handle) = EdgeBuffer::new(edge_db_path.clone(), Arc::clone(&ledger), 100, false).unwrap();
    let buffer = Arc::new(buffer);

    // 2. Push records (should spill to disk)
    let record = LogRecord {
        timestamp: chrono::Local::now(),
        message: "Test Breach Signal".to_string(),
        severity: Some("CRITICAL".to_string()),
        source: None,
        subject_id: None,
        outcome: None,
        metadata: std::collections::BTreeMap::new(),
        additional_context: None,
        raw: "raw".to_string(),
        unparsed_raw: None,
        original_format: "test".to_string(),
        quality: ParsingQuality::Success,
        ..Default::default()
    };

    buffer.push(Arc::new(record.clone())).await.unwrap();
    
    // Give worker a moment to process spillover
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // 3. Verify ledger is EMPTY (because offline)
    {
        let content = std::fs::read_to_string(&audit_path).unwrap_or_default();
        assert!(content.is_empty(), "Audit ledger should be empty during blackout");
    }

    // 4. Go ONLINE
    buffer.status.set_online(true);
    
    // Trigger another push to wake up the worker/reconciler
    buffer.push(Arc::new(record.clone())).await.unwrap();

    // Give worker time to reconcile
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // 5. Verify records are now in the ledger
    {
        let content = std::fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
        assert!(lines.len() >= 2, "Expected at least 2 records after reconciliation");
        println!("✅ Edge Resilience Test Passed: {} signals synchronized.", lines.len());
    }
}
