use aegis::edge_buffer::{EdgeBuffer, AuditReceipt};
use aegis::ledger::AuditLedger;
use aegis::models::LogRecord;
use aegis::NistEngine;
use aegis::monitor::PostureMonitor;
use aegis::config::AppConfig;
use std::sync::Arc;
use std::path::PathBuf;
use tokio::sync::broadcast;
use chrono::Local;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("--- AEGIS SWARM TACTICAL SIMULATOR (Hydra's Reach) ---");

    // Cleanup previous runs
    let _ = std::fs::remove_file("ledger_alpha.jsonl");
    let _ = std::fs::remove_file("edge_alpha.db");
    let _ = std::fs::remove_file("ledger_beta.jsonl");
    let _ = std::fs::remove_file("edge_beta.db");

    // 1. Establish the "Airwaves" (P2P Correlation Cache)
    let (whisper_tx, mut whisper_rx) = broadcast::channel::<AuditReceipt>(100);

    // 2. Common engine resources (using shared configs for simulation)
    let config = AppConfig::default_config();
    let engine = Arc::new(NistEngine::new(config.clone())?);
    let monitor = Arc::new(PostureMonitor::new());

    // 3. Spin up Node Alpha
    let ledger_alpha = Arc::new(AuditLedger::new(
        PathBuf::from("ledger_alpha.jsonl"),
        Arc::clone(&engine),
        Arc::clone(&monitor),
        &config,
        512,
    )?);
    let (alpha_buffer, _alpha_handle) = EdgeBuffer::new(
        "Alpha".to_string(),
        PathBuf::from("edge_alpha.db"),
        ledger_alpha,
        50000,
        true, // Online
        Some(whisper_tx.clone()),
    )?;
    let alpha_buffer = Arc::new(alpha_buffer);

    // 4. Spin up Node Beta
    let ledger_beta = Arc::new(AuditLedger::new(
        PathBuf::from("ledger_beta.jsonl"),
        Arc::clone(&engine),
        Arc::clone(&monitor),
        &config,
        512,
    )?);
    let (beta_buffer, _beta_handle) = EdgeBuffer::new(
        "Beta".to_string(),
        PathBuf::from("edge_beta.db"),
        ledger_beta,
        50000,
        true, // Online
        Some(whisper_tx.clone()),
    )?;
    let beta_buffer = Arc::new(beta_buffer);

    // Monitor whispers
    tokio::spawn(async move {
        while let Ok(receipt) = whisper_rx.recv().await {
            println!("📡 [AIRWAVES] Intercepted Whisper from Node [{}]: Hash={}", receipt.node_id, receipt.chain_hash);
        }
    });

    println!("✅ Swarm Topology Established. Nodes: Alpha, Beta.");

    // --- The "Ghost Pivot" Kill-Chain ---
    println!("🔥 Initiating Ghost Pivot Sequence...");
    
    // Step 1: Compromise Alpha (Mimikatz)
    let mimikatz = Arc::new(LogRecord {
        timestamp: Local::now(),
        message: "Mimikatz LSASS Dump Detected".to_string(),
        severity: Some("CRITICAL".to_string()),
        node_id: "Alpha".to_string(),
        command_line: Some("sekurlsa::logonpasswords".to_string()),
        ..Default::default()
    });
    alpha_buffer.push(mimikatz).await?;

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Step 2: Sever Alpha's connection to simulate adversary covering tracks
    println!("🧨 Adversary severs Node Alpha's primary connection...");
    alpha_buffer.status.set_online(false);

    // Step 3: WMI Pivot (Occurs while offline, triggering whisper)
    let wmi = Arc::new(LogRecord {
        timestamp: Local::now(),
        message: "WMI Lateral Movement to Beta".to_string(),
        severity: Some("HIGH".to_string()),
        node_id: "Alpha".to_string(),
        command_line: Some("wmic /node:Beta process call create".to_string()),
        ..Default::default()
    });
    alpha_buffer.push(wmi).await?;

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Step 4: Burn Alpha (Node destroyed)
    println!("🧨 Burning Node Alpha (Simulating Physical/Total Crash)...");

    // Step 5: Beta detects the inbound
    let inbound = Arc::new(LogRecord {
        timestamp: Local::now(),
        message: "Inbound WMI Execution".to_string(),
        severity: Some("HIGH".to_string()),
        node_id: "Beta".to_string(),
        source: Some("Alpha".to_string()),
        ..Default::default()
    });
    beta_buffer.push(inbound).await?;

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Step 6: Restore Alpha (Time-Travel Reconciliation)
    println!("🔄 Restoring Node Alpha...");
    alpha_buffer.status.set_online(true);
    // Push a dummy record to force flush/reconcile, since buffer worker checks backlog on flush
    let dummy = Arc::new(LogRecord {
        timestamp: Local::now(),
        message: "System Restore".to_string(),
        node_id: "Alpha".to_string(),
        ..Default::default()
    });
    alpha_buffer.push(dummy).await?;

    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

    println!("🏁 Ghost Pivot Simulation Complete.");
    
    // Exiting cleanly releases the redb locks
    std::process::exit(0);
}
