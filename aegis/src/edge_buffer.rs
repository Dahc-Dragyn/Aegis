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
    is_online: AtomicBool,
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

pub struct EdgeBuffer {
    tx: mpsc::Sender<Arc<LogRecord>>,
    pub status: Arc<ConnectivityStatus>,
}

impl EdgeBuffer {
    pub fn new(
        db_path: PathBuf,
        ledger: Arc<AuditLedger>,
        capacity: usize,
        initial_online: bool,
    ) -> Result<(Self, tokio::task::JoinHandle<()>)> {
        let (tx, rx) = mpsc::channel(capacity);
        let status = Arc::new(ConnectivityStatus::new(initial_online));
        let status_clone = Arc::clone(&status);

        // Initialize redb
        let db = Database::builder()
            .create(db_path)
            .context("Failed to initialize redb edge database")?;

        // Start background worker
        let handle = tokio::spawn(async move {
            let mut worker = BufferWorker::new(db, rx, ledger, status_clone);
            if let Err(e) = worker.run().await {
                eprintln!("❌ Aegis EdgeBuffer Worker Failure: {:?}", e);
            }
        });

        Ok((Self { tx, status }, handle))
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
    db: Database,
    rx: mpsc::Receiver<Arc<LogRecord>>,
    ledger: Arc<AuditLedger>,
    status: Arc<ConnectivityStatus>,
    last_hash: Vec<u8>,
    next_id: u64,
}

impl BufferWorker {
    fn new(db: Database, rx: mpsc::Receiver<Arc<LogRecord>>, ledger: Arc<AuditLedger>, status: Arc<ConnectivityStatus>) -> Self {
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

        Self { db, rx, ledger, status, last_hash, next_id }
    }

    async fn run(&mut self) -> Result<()> {
        println!("🛡️ Aegis: Tactical Edge Resilience Buffer ACTIVE.");
        
        while let Some(record) = self.rx.recv().await {
            if self.status.is_online() {
                // Check if we have cached data to flush first
                match self.has_backlog() {
                    Ok(true) => self.reconcile().await?,
                    Ok(false) => {},
                    Err(_) => {}, // Table likely doesn't exist yet, which is fine
                }
                
                // Normal live forwarding
                self.ledger.log_batch(vec![(*record).clone()])?;
            } else {
                // Spillover Mode: Persistence & Chaining
                self.spill_to_disk(record)?;
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
        let current_hash = hasher.finalize().to_vec();

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
            self.ledger.log_batch(records_to_send)?;
            
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
