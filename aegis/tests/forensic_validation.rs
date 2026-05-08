use std::fs;
use std::path::PathBuf;
use std::process::Command;
use serde_json::Value;
use rayon::prelude::*;
use regex::Regex;

#[test]
fn test_forensic_human_readability_regression() {
    let binary_path = env!("CARGO_BIN_EXE_aegis");
    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let log_root = base_dir.join("tests").join("Violation_logs").join("attack_evtx_logs");
    let baseline_path = base_dir.join("tests").join("golden_baselines.json");
    
    let baseline_data = fs::read_to_string(&baseline_path).expect("Failed to read golden_baselines.json");
    let baselines: Value = serde_json::from_str(&baseline_data).expect("Malformed golden_baselines.json");
    
    let baseline_map = baselines.as_object().expect("Baselines should be a JSON object");
    
    // Collect entries into a vector for Rayon parallel iteration
    let entries: Vec<(&String, &Value)> = baseline_map.iter().collect();
    
    entries.into_par_iter().for_each(|(filename, expectations)| {
        let log_file_path = log_root.join(filename);
        if !log_file_path.exists() {
            panic!("Baseline log file not found: {:?}", log_file_path);
        }
        
        // Create a unique temporary directory for each run to avoid redb locking conflicts
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let temp_path = temp_dir.path();
        
        // Execute Aegis on the log file in the temp directory
        let output = Command::new(binary_path)
            .args(&[
                log_file_path.to_str().expect("Valid UTF-8 path"),
                "--reset",
                "--profile", "53"
            ])
            .current_dir(temp_path)
            .output()
            .expect("Failed to execute Aegis binary");
            
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("Aegis failed to process {}: \n{}", filename, stderr);
        }
        
        // Load the generated Commander's Brief from the temp directory
        let brief_path = temp_path.join("artifacts").join("COMMANDERS_BRIEF.md");
        let brief_content = fs::read_to_string(&brief_path)
            .expect("Aegis did not generate COMMANDERS_BRIEF.md");
            
        // 1. Title/Header Jargon Check
        let header_re = Regex::new(r"(?m)^#.*").unwrap();
        for cap in header_re.captures_iter(&brief_content) {
            let header = &cap[0];
            // Fail if technical jargon is used in headers
            if header.contains("NIST") || header.contains("CVE-") || header.contains("AU-") || header.contains("SI-") {
                panic!("JARGON DETECTED in primary header for {}: \"{}\". NIST/CVE identifiers must be relegated to the appendix.", filename, header);
            }
        }
        
        // 2. Expected Human Title Check
        let expected_title = expectations["expected_title"].as_str().expect("baseline missing expected_title");
        assert!(
            brief_content.contains(expected_title),
            "REPORT FAILURE for {}: Could not find expected human title \"{}\" in result.",
            filename, expected_title
        );
        
        // 3. Containment Verbs Check
        if let Some(required_verbs) = expectations["required_verbs"].as_array() {
            let action_section = brief_content.split("## 🛡️ What You Need To Do")
                .nth(1)
                .expect("Missing 'What You Need To Do' section")
                .split("<details>")
                .next()
                .expect("Malformed actions section");
                
            let mut match_count = 0;
            for verb in required_verbs {
                let verb_str: &str = verb.as_str().expect("verb must be string");
                if action_section.to_lowercase().contains(&verb_str.to_lowercase()) {
                    match_count += 1;
                }
            }
            
            assert!(
                match_count >= 2,
                "CONTAINMENT FAILURE for {}: Found only {}/2 required action keywords. Expected from: {:?}. Found in: \n{}",
                filename, match_count, required_verbs, action_section
            );
        }
        
        println!("✅ Passed: {}", filename);
    });
}
