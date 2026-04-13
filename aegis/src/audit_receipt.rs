use serde::{Serialize, Deserialize};
use chrono::{DateTime, Local};
use sha2::{Sha256, Digest};
use anyhow::{Result, Context};
use std::fs::{OpenOptions, create_dir_all};
use std::io::{Write, BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReceiptMetrics {
    pub total_signals_reviewed: u64,
    pub failures_detected: u64,
    pub time_window_start: DateTime<Local>,
    pub time_window_end: DateTime<Local>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CryptographicSeal {
    pub algorithm: String,
    pub payload_hash: String,
    pub previous_receipt_hash: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditReceipt {
    pub artifact_type: String,
    pub timestamp_generated: DateTime<Local>,
    pub aegis_version: String,
    pub ruleset_applied: String,
    pub metrics: ReceiptMetrics,
    pub cryptographic_seal: CryptographicSeal,
}

pub struct ReceiptManager {
    ledger_path: PathBuf,
}

impl ReceiptManager {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self> {
        let receipts_dir = base_dir.as_ref().join("receipts");
        if !receipts_dir.exists() {
            create_dir_all(&receipts_dir).context("Failed to create receipts directory")?;
        }
        
        Ok(Self {
            ledger_path: receipts_dir.join("aegis_receipts.jsonl"),
        })
    }

    pub fn generate_receipt(
        &self,
        metrics: ReceiptMetrics,
        version: &str,
        profile_name: &str,
    ) -> Result<AuditReceipt> {
        let now = Local::now();
        let prev_hash = self.get_last_receipt_hash()?;

        // 1. Prepare Payload (everything but the seal)
        #[derive(Serialize)]
        struct Payload<'a> {
            artifact_type: &'a str,
            timestamp_generated: DateTime<Local>,
            aegis_version: &'a str,
            ruleset_applied: &'a str,
            metrics: &'a ReceiptMetrics,
        }

        let payload = Payload {
            artifact_type: "NIST_AU-6_PROOF_OF_REVIEW",
            timestamp_generated: now,
            aegis_version: version,
            ruleset_applied: profile_name,
            metrics: &metrics,
        };

        // 2. Hash Payload (Deterministic signing)
        let payload_json = serde_json::to_string(&payload)?;
        let mut hasher = Sha256::new();
        hasher.update(payload_json.as_bytes());
        let payload_hash = format!("{:x}", hasher.finalize());

        // 3. Construct Final Receipt
        let receipt = AuditReceipt {
            artifact_type: payload.artifact_type.to_string(),
            timestamp_generated: payload.timestamp_generated,
            aegis_version: payload.aegis_version.to_string(),
            ruleset_applied: payload.ruleset_applied.to_string(),
            metrics,
            cryptographic_seal: CryptographicSeal {
                algorithm: "SHA-256".to_string(),
                payload_hash,
                previous_receipt_hash: prev_hash,
            },
        };

        // 4. Atomic Append to Ledger (Ensuring Directory Existence)
        if let Some(parent) = self.ledger_path.parent() {
            if !parent.exists() {
                create_dir_all(parent).context("Failed to recreate receipts directory after purge")?;
            }
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.ledger_path)
            .context("Failed to open audit ledger")?;

        let receipt_json = serde_json::to_string(&receipt)?;
        writeln!(file, "{}", receipt_json).context("Failed to write receipt to ledger")?;

        Ok(receipt)
    }

    fn get_last_receipt_hash(&self) -> Result<String> {
        if !self.ledger_path.exists() {
            return Ok("0".repeat(64));
        }

        let file = OpenOptions::new().read(true).open(&self.ledger_path)?;
        let reader = BufReader::new(file);
        
        let last_line = reader.lines().last();
        
        match last_line {
            Some(Ok(line)) => {
                let last_receipt: AuditReceipt = serde_json::from_str(&line)
                    .context("Corrupt audit ledger detected: failed to parse last receipt")?;
                Ok(last_receipt.cryptographic_seal.payload_hash)
            },
            _ => Ok("0".repeat(64)),
        }
    }
}
