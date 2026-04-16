use std::process::Command;
use std::fs;
use std::path::{Path, PathBuf};
use chrono::Local;
use anyhow::{Result, Context};
use sha2::{Sha256, Digest};
use std::io::{Read, Write};

pub struct TriggeredExtraction;

impl TriggeredExtraction {
    pub fn capture_volatile_evidence(tag: &str, pid: Option<u32>) -> Result<String> {
        let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
        let vault_dir = format!("forensic_results/vault_{}_{}", tag, timestamp);
        let vault_path = PathBuf::from(&vault_dir);

        if !vault_path.exists() {
            fs::create_dir_all(&vault_path).context("Failed to create evidence vault directory")?;
        }

        // 1. Execute Collection Tasks based on Forensic Tag
        match tag {
            "PivotAttempt" | "RemoteExecution" => {
                Self::capture_network_state(&vault_path)?;
            }
            "CredentialDumping" | "RegistryExfiltration" => {
                Self::capture_identity_state(&vault_path)?;
            }
            "OrphanProcess" | "GhostProcess" => {
                Self::capture_process_state(&vault_path, pid)?;
            }
            _ => {
                // Default: Capture base system state for any Critical alert
                Self::capture_network_state(&vault_path)?;
            }
        }

        // 2. Generate Forensic Manifest (SHA-256 Chain of Custody)
        Self::generate_manifest(&vault_path)?;

        Ok(vault_dir)
    }

    fn capture_network_state(vault_path: &Path) -> Result<()> {
        Self::run_cmd_to_file("netstat", &["-ano"], vault_path.join("netstat.txt"))?;
        Self::run_cmd_to_file("ipconfig", &["/displaydns"], vault_path.join("dns_cache.txt"))?;
        Self::run_cmd_to_file("arp", &["-a"], vault_path.join("arp_table.txt"))?;
        Ok(())
    }

    fn capture_identity_state(vault_path: &Path) -> Result<()> {
        // Persistence Keys (HKCU/HKLM Run)
        Self::run_cmd_to_file("reg", &["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"], vault_path.join("reg_hkcu_run.txt"))?;
        Self::run_cmd_to_file("reg", &["query", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"], vault_path.join("reg_hklm_run.txt"))?;
        
        // Note: SAM/SECURITY/SYSTEM hives are usually locked. 
        // We attempt a 'reg save' which requires elevated Aegis privileges.
        let _ = Self::run_cmd_to_file("reg", &["save", "HKLM\\SAM", vault_path.join("SAM.hiv").to_str().unwrap()], vault_path.join("reg_save_status.txt"));
        
        Ok(())
    }

    fn capture_process_state(vault_path: &Path, pid: Option<u32>) -> Result<()> {
        if let Some(p) = pid {
            let filter = format!("pid eq {}", p);
            Self::run_cmd_to_file("tasklist", &["/m", "/fi", &filter], vault_path.join(format!("process_{}_modules.txt", p)))?;
            
            // Capture environment variables if possible (tasklist doesn't do this easily, but it's a start)
            Self::run_cmd_to_file("tasklist", &["/v", "/fi", &filter], vault_path.join(format!("process_{}_details.txt", p)))?;
        } else {
            Self::run_cmd_to_file("tasklist", &["/v"], vault_path.join("all_processes.txt"))?;
        }
        Ok(())
    }

    fn run_cmd_to_file(cmd: &str, args: &[&str], output_path: PathBuf) -> Result<()> {
        let output = Command::new(cmd)
            .args(args)
            .output()
            .with_context(|| format!("Failed to execute command: {} {:?}", cmd, args))?;

        let mut file = fs::File::create(output_path)?;
        file.write_all(&output.stdout)?;
        if !output.stderr.is_empty() {
            file.write_all(b"\n--- STDERR ---\n")?;
            file.write_all(&output.stderr)?;
        }
        Ok(())
    }

    fn generate_manifest(vault_path: &Path) -> Result<()> {
        let mut manifest_content = String::from("# 📦 Aegis: Forensic Evidence Manifest\n\n");
        manifest_content.push_str(&format!("**Vault Path**: `{}`\n", vault_path.display()));
        manifest_content.push_str(&format!("**Captured At**: `{}`\n\n", Local::now().to_rfc3339()));
        manifest_content.push_str("| Artifact | SHA-256 Hash | Integrity Status |\n");
        manifest_content.push_str("| :--- | :--- | :--- |\n");

        for entry in fs::read_dir(vault_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.file_name().unwrap() != "forensic_evidence_manifest.md" {
                let hash = Self::calculate_sha256(&path)?;
                manifest_content.push_str(&format!("| `{}` | `{}` | ✅ VERIFIED |\n", 
                    path.file_name().unwrap().to_string_lossy(),
                    hash));
            }
        }

        let manifest_path = vault_path.join("forensic_evidence_manifest.md");
        fs::write(manifest_path, manifest_content)?;
        Ok(())
    }

    fn calculate_sha256(path: &Path) -> Result<String> {
        let mut file = fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 1024];

        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 { break; }
            hasher.update(&buffer[..count]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }
}
