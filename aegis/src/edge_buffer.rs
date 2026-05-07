use crate::models::LogRecord;
use crate::ledger::AuditLedger;
use redb::{Database, TableDefinition, ReadableTable};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use anyhow::{Context, Result};
use sha2::{Sha256, Digest};
use std::path::PathBuf;

const RECORDS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("records");
const METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");

/// Connectivity status for the edge node.
pub struct ConnectivityStatus {
    pub is_online: AtomicBool,
}

impl ConnectivityStatus {
    pub fn new(initial: bool) -> Self {
        Self { is_online: AtomicBool::new(initial) }
    }
    pub fn set_online(&self, state: bool) {
        self.is_online.store(state, Ordering::SeqCst);
    }
    pub fn is_online(&self) -> bool {
        self.is_online.load(Ordering::SeqCst)
    }
}

/// A cryptographic receipt broadcasted to peers before a record is committed locally.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditReceipt {
    pub node_id: String,
    pub chain_hash: String,
    pub timestamp: chrono::DateTime<chrono::Local>,
}

pub struct EdgeBuffer {
    tx: mpsc::Sender<Arc<LogRecord>>,
    pub status: Arc<ConnectivityStatus>,
    pub node_id: String,
}

impl EdgeBuffer {
    pub fn new(
        node_id: String,
        db_path: PathBuf,
        ledger: Arc<AuditLedger>,
        capacity: usize,
        initial_online: bool,
        whisper_tx: Option<tokio::sync::broadcast::Sender<AuditReceipt>>,
    ) -> Result<(Self, tokio::task::JoinHandle<()>)> {
        let (tx, rx) = mpsc::channel(capacity);
        let status = Arc::new(ConnectivityStatus::new(initial_online));
        let status_clone = Arc::clone(&status);
        let node_id_clone = node_id.clone();

        // Initialize redb
        let db = Database::builder()
            .create(db_path)
            .context("Failed to initialize redb edge database")?;

        // Start background worker
        let handle = tokio::spawn(async move {
            let mut worker = BufferWorker::new(node_id_clone, db, rx, ledger, status_clone, whisper_tx);
            if let Err(e) = worker.run().await {
                eprintln!("❌ Aegis EdgeBuffer Worker Failure: {:?}", e);
            }
        });

        Ok((Self { tx, status, node_id }, handle))
    }

    pub async fn push(&self, record: Arc<LogRecord>) -> Result<()> {
        self.tx.send(record).await.context("EdgeBuffer channel closed")
    }

    pub async fn push_batch(&self, records: Vec<LogRecord>) -> Result<()> {
        for record in records {
            self.tx.send(Arc::new(record)).await.context("EdgeBuffer channel closed during batch")?;
        }
        Ok(())
    }
}

struct BufferWorker {
    node_id: String,
    db: Database,
    rx: mpsc::Receiver<Arc<LogRecord>>,
    ledger: Arc<AuditLedger>,
    status: Arc<ConnectivityStatus>,
    whisper_tx: Option<tokio::sync::broadcast::Sender<AuditReceipt>>,
    last_hash: Vec<u8>,
    next_id: u64,
    // SNR Stress Test Fields
    velocity_count: usize,
    velocity_start: std::time::Instant,
    current_velocity: usize,
    sampling_mode: bool,
    sampling_cooldown: std::time::Instant,
    suppressed_count: usize,
}

impl BufferWorker {
    fn new(node_id: String, db: Database, rx: mpsc::Receiver<Arc<LogRecord>>, ledger: Arc<AuditLedger>, status: Arc<ConnectivityStatus>, whisper_tx: Option<tokio::sync::broadcast::Sender<AuditReceipt>>) -> Self {
        // Recover last state if it exists
        let (last_hash, next_id) = {
            let read_txn = db.begin_read().expect("Failed to begin read transaction");
            
            let last_hash = if let Ok(table) = read_txn.open_table(METADATA_TABLE) {
                table.get("last_hash").ok().flatten()
                    .map(|v| v.value().to_vec())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            
            let next_id = if let Ok(table) = read_txn.open_table(RECORDS_TABLE) {
                table.iter().ok()
                    .and_then(|mut it| it.next_back())
                    .and_then(|r| r.ok())
                    .map(|(k, _)| k.value() + 1)
                    .unwrap_or(0)
            } else {
                0
            };
            
            (last_hash, next_id)
        };

        Self { 
            node_id, db, rx, ledger, status, whisper_tx, last_hash, next_id,
            velocity_count: 0,
            velocity_start: std::time::Instant::now(),
            current_velocity: 0,
            sampling_mode: false,
            sampling_cooldown: std::time::Instant::now(),
            suppressed_count: 0,
        }
    }
    async fn run(&mut self) -> Result<()> {
        println!("🛡️ Aegis: Tactical Edge Resilience Buffer ACTIVE.");
        let mut batch = Vec::new();
        let mut last_flush = std::time::Instant::now();

        loop {
            tokio::select! {
                biased;
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                    if !batch.is_empty() && last_flush.elapsed().as_millis() > 100 {
                        self.flush_batch(&mut batch).await?;
                        last_flush = std::time::Instant::now();
                    }
                }
                record = self.rx.recv() => {
                    if let Some(record) = record {
                        self.velocity_count += 1;
                        
                        // Periodic Velocity Update (Every 100ms)
                        if self.velocity_start.elapsed().as_millis() >= 100 {
                            self.current_velocity = self.velocity_count * 10;
                            self.velocity_count = 0;
                            self.velocity_start = std::time::Instant::now();

                            if self.current_velocity > 1000 {
                                if !self.sampling_mode {
                                    println!("⚠️ Aegis: SNR Threshold Exceeded ({} eps). Engaging Sampling Mode.", self.current_velocity);
                                }
                                self.sampling_mode = true;
                                self.sampling_cooldown = std::time::Instant::now() + std::time::Duration::from_secs(10);
                            } else if self.sampling_mode && std::time::Instant::now() > self.sampling_cooldown {
                                println!("✅ Aegis: Signal Noise Stabilized. Returning to Full Fidelity.");
                                self.sampling_mode = false;
                            }
                        }

                        if self.sampling_mode && !record.is_high_fidelity() {
                            self.suppressed_count += 1;
                            if self.suppressed_count % 100 != 0 {
                                continue;
                            }
                        }

                        batch.push((*record).clone());
                        if batch.len() >= 500 {
                            self.flush_batch(&mut batch).await?;
                            last_flush = std::time::Instant::now();
                        }
                    } else {
                        self.flush_batch(&mut batch).await?;
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    async fn flush_batch(&mut self, batch: &mut Vec<LogRecord>) -> Result<()> {
        // [SIGNAL SILENCE] Inject Noise Suppression Summary
        if self.suppressed_count > 0 {
            let mut summary = LogRecord::default();
            summary.node_id = self.node_id.clone();
            summary.severity = Some("warning".to_string());
            summary.message = format!("[!] NOISE DETECTED: {} decoy events suppressed", self.suppressed_count);
            summary.metadata.insert("details".to_string(), format!("SNR Stress Test: Sampling active due to velocity of {} eps", self.current_velocity));
            batch.push(summary);
            self.suppressed_count = 0;
        }

        if batch.is_empty() { 
            // If empty but online, check for backlog anyway
            if self.status.is_online() && self.has_backlog().unwrap_or(false) {
                self.reconcile().await?;
            }
            return Ok(()); 
        }
        let count = batch.len();
        let records = std::mem::take(batch);
        println!("💾 Aegis: Node [{}] flushing batch of {} records to ledger...", self.node_id, count);
        
        if self.status.is_online() {
            // Forward
            self.ledger.log_batch(&records)?;
            
            // Check for backlog to reconcile
            if self.has_backlog().unwrap_or(false) {
                self.reconcile().await?;
            }
        } else {
            for rec in records {
                self.spill_to_disk(Arc::new(rec))?;
            }
        }
        Ok(())
    }

    fn has_backlog(&self) -> Result<bool> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(RECORDS_TABLE) {
            Ok(t) => t,
            Err(_) => return Ok(false), // If table doesn't exist, no backlog
        };
        Ok(!table.is_empty()?)
    }

    fn spill_to_disk(&mut self, record: Arc<LogRecord>) -> Result<()> {
        let serialized = bincode::serialize(&*record)?;
        
        // Local Cryptographic Chaining
        let mut hasher = Sha256::new();
        hasher.update(&self.last_hash);
        hasher.update(&serialized);
        let hash_result = hasher.finalize();
        let current_hash = hash_result.to_vec();

        // [HYDRA'S REACH] P2P Whisper Cache Broadcast
        if let Some(tx) = &self.whisper_tx {
            let receipt = AuditReceipt {
                node_id: self.node_id.clone(),
                chain_hash: format!("{:x}", hash_result),
                timestamp: chrono::Local::now(),
            };
            // Send receipt. We ignore the error if there are no active receivers.
            let _ = tx.send(receipt);
        }

        // Atomic write to redb
        let write_txn = self.db.begin_write()?;
        {
            let mut records = write_txn.open_table(RECORDS_TABLE)?;
            records.insert(self.next_id, serialized.as_slice())?;
            
            let mut meta = write_txn.open_table(METADATA_TABLE)?;
            meta.insert("last_hash", current_hash.as_slice())?;
        }
        write_txn.commit()?;

        self.last_hash = current_hash;
        self.next_id += 1;
        
        Ok(())
    }

    async fn reconcile(&mut self) -> Result<()> {
        println!("🔄 Aegis: Network Restored. Reconciling offline ledger...");
        
        let mut records_to_send = Vec::new();
        
        {
            let read_txn = self.db.begin_read()?;
            let table = match read_txn.open_table(RECORDS_TABLE) {
                Ok(t) => t,
                Err(_) => return Ok(()), // Nothing to reconcile
            };
            
            for result in table.iter()? {
                let (_, value) = result?;
                let record: LogRecord = bincode::deserialize::<LogRecord>(value.value())?;
                records_to_send.push(record);
            }
        }

        if !records_to_send.is_empty() {
            // Forward in one verified batch
            self.ledger.log_batch(&records_to_send)?;
            
            // Clear cache
            let write_txn = self.db.begin_write()?;
            {
                let mut records = write_txn.open_table(RECORDS_TABLE)?;
                // redb doesn't have truncate, so we drain or drop
                // For simplicity here, we delete keys
                for i in 0..self.next_id {
                    records.remove(i)?;
                }
                
                let mut meta = write_txn.open_table(METADATA_TABLE)?;
                meta.remove("last_hash")?;
            }
            write_txn.commit()?;
            
            self.last_hash = Vec::new();
            self.next_id = 0;
            println!("✅ Aegis: Edge synchronization complete.");
        }
        
        Ok(())
    }
}
