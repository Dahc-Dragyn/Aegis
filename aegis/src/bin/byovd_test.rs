use aegis::ledger::AuditLedger;
use aegis::models::LogRecord;
use std::sync::Arc;
use std::path::PathBuf;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- AEGIS OPERATION: RING 0 (BYOVD Validation) ---");
    
    let config = aegis::config::AppConfig::default_config();
    let engine = Arc::new(aegis::NistEngine::new(config.clone())?);
    let monitor = Arc::new(aegis::monitor::PostureMonitor::new());
    let audit_path = PathBuf::from("forensic_results/byovd_validation.jsonl");
    if audit_path.exists() {
        let _ = std::fs::remove_file(&audit_path);
    }
    
    if !audit_path.parent().unwrap().exists() {
        std::fs::create_dir_all(audit_path.parent().unwrap())?;
    }

    let ledger = Arc::new(AuditLedger::new(
        audit_path,
        Arc::clone(&engine),
        Arc::clone(&monitor),
        &config,
        100,
        false,
    )?);

    println!("Injecting BYOVD Threat Vectors...");

    // 1. Sysmon Event ID 6 (Driver Load) from \Temp\
    let mut driver_load = LogRecord::default();
    driver_load.message = "Sysmon Driver Load: C:\\Windows\\Temp\\gdrv.sys".to_string();
    driver_load.metadata.insert("EventID".to_string(), "6".to_string());
    driver_load.metadata.insert("ImageLoaded".to_string(), "C:\\Windows\\Temp\\gdrv.sys".to_string());
    if let Some(analyzed) = engine.analyze_record(Arc::new(driver_load))? {
        ledger.record(&analyzed)?;
    }

    // 2. Service Creation (7045) from \Users\Public\
    let mut svc_creation = LogRecord::default();
    svc_creation.message = "Service Installed: Capcom".to_string();
    svc_creation.metadata.insert("EventID".to_string(), "7045".to_string());
    svc_creation.metadata.insert("ImagePath".to_string(), "C:\\Users\\Public\\Capcom.sys".to_string());
    if let Some(analyzed) = engine.analyze_record(Arc::new(svc_creation))? {
        ledger.record(&analyzed)?;
    }

    // 3. Legitimate Service (Normal path)
    let mut normal_svc = LogRecord::default();
    normal_svc.message = "Service Installed: WinDefend".to_string();
    normal_svc.metadata.insert("EventID".to_string(), "7045".to_string());
    normal_svc.metadata.insert("ImagePath".to_string(), "C:\\Windows\\System32\\drivers\\wd\\wdboot.sys".to_string());
    if let Some(analyzed) = engine.analyze_record(Arc::new(normal_svc))? {
        ledger.record(&analyzed)?;
    } else {
        // Still record the raw log if no heuristic hit, though byovd_test only cares about hits
        let mut raw = LogRecord::default();
        raw.message = "Service Installed: WinDefend".to_string();
        raw.metadata.insert("EventID".to_string(), "7045".to_string());
        raw.metadata.insert("ImagePath".to_string(), "C:\\Windows\\System32\\drivers\\wd\\wdboot.sys".to_string());
        ledger.record(&raw)?;
    }

    println!("Validating Structural Invariants...");
    
    let logs = ledger.get_records();
    let kernel_invaders = logs.iter().filter(|l| l.metadata.get("forensic_tag").map(|s| s.as_str()) == Some("KernelInvader")).collect::<Vec<_>>();

    println!("\nDetection Report:");
    for log in &kernel_invaders {
        println!("  [!] Detected: {}", log.message);
        println!("      Mapped Control: {}", log.metadata.get("nist_control_id").unwrap_or(&"Unknown".to_string()));
    }

    if kernel_invaders.len() == 2 {
        println!("\n☢️ BYOVD VALIDATION SUCCESS: Structural Invariants verified.");
    } else {
        println!("\n❌ BYOVD VALIDATION FAILURE: Expected 2 detections, found {}.", kernel_invaders.len());
    }

    Ok(())
}
