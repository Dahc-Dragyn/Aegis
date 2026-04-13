use redb::{Database, TableDefinition, ReadableTable};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Local, Duration};
use anyhow::{Result, Context};
use std::path::Path;
use uuid::Uuid;

const CACHE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("failure_cache");

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CachedFailure {
    pub uuid: Uuid,
    pub control_id: String,
    pub system_id: String,
    pub entry_timestamp: DateTime<Local>,
    pub last_seen: DateTime<Local>,
    pub occurrence_count: usize,
    pub evidence_hash: String,
}

pub struct ComplianceCache {
    db: Database,
}

impl ComplianceCache {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = Database::builder()
            .create(path)
            .context("Failed to initialize redb compliance cache")?;
        
        // Ensure table exists
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(CACHE_TABLE)?;
        }
        write_txn.commit()?;

        Ok(Self { db })
    }

    /// Attempts to deduplicate a failure. 
    /// Returns Some(CachedFailure) if an active one was updated, or None if it's a new occurrence.
    pub fn deduplicate(&self, system_id: &str, control_id: &str, _log_hash: &str) -> Result<Option<CachedFailure>> {
        let key = format!("{}:{}", system_id, control_id);
        let now = Local::now();
        let window = Duration::hours(4);

        let write_txn = self.db.begin_write()?;
        let mut result = None;

        {
            let mut table = write_txn.open_table(CACHE_TABLE)?;
            let mut existing_failure = None;

            if let Some(guard) = table.get(key.as_str())? {
                existing_failure = Some(bincode::deserialize::<CachedFailure>(guard.value())?);
            }

            if let Some(mut failure) = existing_failure {
                // 4-hour Deduplication Window check
                if now - failure.entry_timestamp < window {
                    failure.last_seen = now;
                    failure.occurrence_count += 1;
                    
                    let serialized = bincode::serialize(&failure)?;
                    table.insert(key.as_str(), serialized.as_slice())?;
                    result = Some(failure);
                } else {
                    table.remove(key.as_str())?;
                }
            }
        }
        write_txn.commit()?;

        Ok(result)
    }

    pub fn insert_failure(&self, failure: CachedFailure) -> Result<()> {
        let key = format!("{}:{}", failure.system_id, failure.control_id);
        let serialized = bincode::serialize(&failure)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(CACHE_TABLE)?;
            table.insert(key.as_str(), serialized.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn prune_old_records(&self) -> Result<usize> {
        let now = Local::now();
        let window = Duration::hours(4);
        let mut pruned = 0;

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(CACHE_TABLE)?;
            let mut keys_to_remove = Vec::new();

            for entry in table.iter()? {
                let (key, value) = entry.context("Failed to read failure cache entry")?;
                let failure: CachedFailure = bincode::deserialize(value.value())?;
                if now - failure.entry_timestamp > window {
                    keys_to_remove.push(key.value().to_string());
                }
            }

            for key in keys_to_remove {
                table.remove(key.as_str())?;
                pruned += 1;
            }
        }
        write_txn.commit()?;
        Ok(pruned)
    }

    pub fn get_active_failures(&self) -> Result<Vec<CachedFailure>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(CACHE_TABLE)?;
        let mut failures = Vec::new();

        for entry in table.iter()? {
            let (_, value) = entry.context("Failed to read failure cache entry")?;
            let failure: CachedFailure = bincode::deserialize(value.value())?;
            failures.push(failure);
        }

        Ok(failures)
    }
}
