use aegis::edge_buffer::{EdgeBuffer, AuditReceipt};
use aegis::ledger::AuditLedger;
use aegis::models::LogRecord;
use std::sync::Arc;
use std::path::PathBuf;
use tokio::sync::broadcast;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- AEGIS OPERATION: SIGNAL SILENCE (SNR Stress Test) ---");
    
    let config = aegis::config::AppConfig::default_config();
    let engine = Arc::new(aegis::NistEngine::new(config.clone())?);
    let monitor = Arc::new(aegis::monitor::PostureMonitor::new());
    let audit_path = PathBuf::from("forensic_results/snr_stress_test.jsonl");
    if audit_path.exists() {
        let _ = std::fs::remove_file(&audit_path);
    }
    
    // Ensure artifacts directory exists
    if !audit_path.parent().unwrap().exists() {
        std::fs::create_dir_all(audit_path.parent().unwrap())?;
    }

    let ledger = Arc::new(AuditLedger::new(
        audit_path,
        Arc::clone(&engine),
        Arc::clone(&monitor),
        &config,
        512,
        false, // offline_mode
    )?);
    
    let (whisper_tx, _) = broadcast::channel::<AuditReceipt>(1000);

    // Initialize Swarm Nodes
    let (node_alpha, _h1) = EdgeBuffer::new(
        "Alpha".to_string(),
        PathBuf::from("edge_alpha_snr.db"),
        Arc::clone(&ledger),
        100000,
        true,
        Some(whisper_tx.clone()),
    )?;

    let (node_beta, _h2) = EdgeBuffer::new(
        "Beta".to_string(),
        PathBuf::from("edge_beta_snr.db"),
        Arc::clone(&ledger),
        100000,
        true,
        Some(whisper_tx.clone()),
    )?;

    println!("🛡️ Swarm Online. Initiating Log Tsunami on Node Alpha...");

    // 1. THE TSUNAMI (Node Alpha)
    // We'll push 50,000 neutral events as fast as possible
    let tsunami_handle = tokio::spawn(async move {
        for i in 0..100000 {
            let mut record = LogRecord::default();
            record.node_id = "Alpha".to_string();
            record.severity = Some("neutral".to_string());
            record.message = format!("cmd.exe /c dir C:\\Windows\\System32\\{:05}", i);
            let _ = node_alpha.push(Arc::new(record)).await;
            
            // Force it to take at least 2 seconds
            if i % 100 == 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(2)).await;
            }
        }
        println!("🌊 Tsunami Source (Node Alpha) has finished injection.");
    });

    // 2. THE NEEDLE (Node Beta)
    // Surgical Mimikatz execution amidst the chaos
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    println!("🔥 Adversary executing surgical Mimikatz on Node Beta...");
    
    let mut mimi = LogRecord::default();
    mimi.node_id = "Beta".to_string();
    mimi.severity = Some("hostile".to_string());
    mimi.message = "mimikatz.exe sekurlsa::logonpasswords".to_string();
    mimi.metadata.insert("EventID".to_string(), "1".to_string());
    node_beta.push(Arc::new(mimi)).await?;

    // Wait for tsunami to finish
    tsunami_handle.await?;
    
    // Allow buffer to flush
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    println!("\n--- SNR STRESS TEST RESULTS ---");
    let logs = ledger.get_records();
    
    let hostile_count = logs.iter().filter(|l| l.severity.as_deref() == Some("hostile")).count();
    let noise_alerts = logs.iter().filter(|l| l.message.contains("NOISE DETECTED")).count();
    let total_logs = logs.len();

    println!("✅ Mimikatz (High-Fidelity) Signals: {}", hostile_count);
    println!("✅ Noise Suppression Alerts: {}", noise_alerts);
    println!("📊 Total Logs Ingested: {} (Sampled from 100,000+)", total_logs);

    if hostile_count > 0 && noise_alerts > 0 {
        println!("\n🏁 OPERATION SIGNAL SILENCE: PHASE 1 SUCCESS.");
    } else {
        println!("\n❌ OPERATION SIGNAL SILENCE: FAILURE - Signals lost in noise.");
    }

    Ok(())
}
