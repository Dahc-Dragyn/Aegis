use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use serde_json::Value;
use chrono::Local;
use regex::Regex;

struct TestResult {
    filename: String,
    success: bool,
    actual_title: String,
    expected_title: String,
    mermaid_map: String,
    actions: String,
    error_log: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let binary_path = base_dir.parent().unwrap().join("target").join("debug").join("aegis.exe");
    let log_root = base_dir.join("tests").join("Violation_logs").join("attack_evtx_logs");
    let baseline_path = base_dir.join("tests").join("golden_baselines.json");
    let output_dir = base_dir.join("forensic_qa");
    
    if !output_dir.exists() {
        fs::create_dir_all(&output_dir)?;
    }

    println!("🎨 Aegis QA: Initializing Forensic Quality Audit...");
    
    let baseline_data = fs::read_to_string(&baseline_path)?;
    let baselines: Value = serde_json::from_str(&baseline_data)?;
    let baseline_map = baselines.as_object().ok_or_else(|| anyhow::anyhow!("Malformed baselines"))?;
    
    let mut results = Vec::new();

    for (filename, expectations) in baseline_map {
        print!("🔬 Auditing {}... ", filename);
        let log_file_path = log_root.join(filename);
        
        let mut error_msg = None;
        let mut actual_title = String::from("UNKNOWN");
        let mut mermaid_map = String::from("```mermaid\ngraph TD\n  N/A\n```");
        let mut actions = String::from("N/A");
        
        let run_status = Command::new(&binary_path)
            .args(&[
                log_file_path.to_str().unwrap(),
                "--reset",
                "--profile", "53"
            ])
            .output();

        match run_status {
            Ok(output) if output.status.success() => {
                let brief_path = base_dir.join("artifacts").join("COMMANDERS_BRIEF.md");
                let brief_content = fs::read_to_string(&brief_path).unwrap_or_default();
                
                // Extract Title
                let title_re = Regex::new(r"\{'☢️ (.*?)'\}").unwrap();
                actual_title = title_re.captures(&brief_content)
                    .map(|c| c[1].to_string())
                    .unwrap_or_else(|| "No human title found".to_string());
                
                // Extract Mermaid
                let mermaid_re = Regex::new(r"(?s)```mermaid(.*?)```").unwrap();
                mermaid_map = mermaid_re.find(&brief_content)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_else(|| "No map found".to_string());
                
                // Extract Actions
                let actions_re = Regex::new(r"(?s)## 🛡️ What You Need To Do(.*?)(?:---|<details>)").unwrap();
                actions = actions_re.captures(&brief_content)
                    .map(|c| c[1].trim().to_string())
                    .unwrap_or_else(|| "No actions found".to_string());
                
                let expected = expectations["expected_title"].as_str().unwrap_or("");
                if !brief_content.contains(expected) {
                    error_msg = Some(format!("Title mismatch: Expected '{}'", expected));
                }
            },
            Ok(output) => {
                error_msg = Some(String::from_utf8_lossy(&output.stderr).to_string());
            },
            Err(e) => {
                error_msg = Some(e.to_string());
            }
        }

        results.push(TestResult {
            filename: filename.clone(),
            success: error_msg.is_none(),
            actual_title,
            expected_title: expectations["expected_title"].as_str().unwrap_or("").to_string(),
            mermaid_map,
            actions,
            error_log: error_msg,
        });
        
        if results.last().unwrap().success {
            println!("✅");
        } else {
            println!("❌");
        }
    }

    generate_dashboard(&output_dir.join("FORENSIC_QA_DASHBOARD.md"), results)?;
    
    println!("\n✨ QA Audit Complete. Report generated at forensic_qa/FORENSIC_QA_DASHBOARD.md");
    Ok(())
}

fn generate_dashboard(path: &Path, results: Vec<TestResult>) -> anyhow::Result<()> {
    let mut md = String::from("# 🧪 Aegis Forensic Quality Dashboard\n\n");
    md.push_str(&format!("**Audit Pulse**: {}\n\n", Local::now().to_rfc2822()));
    
    let pass_count = results.iter().filter(|r| r.success).count();
    let total = results.len();
    md.push_str(&format!("## 📊 Global Score: {}% ({}/{})\n\n", (pass_count * 100 / total), pass_count, total));

    md.push_str("## 🎞️ Attack Chain Gallery\n\n");
    for res in &results {
        md.push_str(&format!("### 🎯 {}\n", res.filename));
        md.push_str(&format!("**Status**: {}\n\n", if res.success { "🟢 PASS" } else { "🔴 FAIL" }));
        md.push_str(&res.mermaid_map);
        md.push_str("\n\n---\n");
    }

    md.push_str("\n## 🏛️ Comparison Vault (Regresson Check)\n\n");
    md.push_str("| Dataset | Golden Title | Engine Output | Containment Quality |\n");
    md.push_str("|:---|:---|:---|:---|\n");
    for res in &results {
        md.push_str(&format!(
            "| {} | **{}** | {} | {} |\n",
            res.filename,
            res.expected_title,
            if res.success { format!("✅ {}", res.actual_title) } else { format!("❌ {}", res.actual_title) },
            res.actions.replace("\n", " ").chars().take(50).collect::<String>() + "..."
        ));
    }

    if results.iter().any(|r| !r.success) {
        md.push_str("\n## 🚩 Failure Logs\n\n");
        for res in results.iter().filter(|r| !r.success) {
            md.push_str(&format!("### ❌ {}\n", res.filename));
            md.push_str(&format!("```text\n{}\n```\n", res.error_log.as_deref().unwrap_or("Unknown Error")));
        }
    }

    fs::write(path, md)?;
    Ok(())
}
