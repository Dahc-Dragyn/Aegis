use crate::models::LogRecord;
use crate::monitor::PostureMonitor;
use tokio::sync::mpsc;
use uuid::Uuid;
use moka::future::Cache;
use std::time::Duration;
use std::sync::Arc;
use anyhow::{Result, Context};

use dashmap::DashMap;

/// The Cross-Vector Correlation Fusion Engine (NIST IR-4).
pub struct FusionWorker {
    rx: mpsc::Receiver<Arc<LogRecord>>,
    edge_buffer_tx: Arc<crate::edge_buffer::EdgeBuffer>,
    monitor: Arc<PostureMonitor>,
    /// Thread-safe synchronous cache for O(1) correlation
    cache: Arc<DashMap<String, Uuid>>,
}

impl FusionWorker {
    pub fn new(
        rx: mpsc::Receiver<Arc<LogRecord>>, 
        edge_buffer_tx: Arc<crate::edge_buffer::EdgeBuffer>,
        monitor: Arc<PostureMonitor>
    ) -> Self {
        Self { 
            rx, 
            edge_buffer_tx, 
            monitor, 
            cache: Arc::new(DashMap::new()) 
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        println!("🛰️ Aegis: Cross-Vector Correlation Fusion Engine ACTIVE.");
        
        while let Some(record) = self.rx.recv().await {
            let mut record_val = (*record).clone();
            let system_id = self.extract_system_id(&record_val);
            
            // NIST IR-4: Atomic Fusion matching
            let incident_id = self.cache.entry(system_id).or_insert_with(Uuid::new_v4);
            record_val.incident_id = Some(*incident_id);

            // Forward to EdgeBuffer (Non-Blocking)
            self.edge_buffer_tx.push(Arc::new(record_val)).await?;
        }

        Ok(())
    }

    fn extract_system_id(&self, record: &LogRecord) -> String {
        record.metadata.get("computer")
            .or_else(|| record.metadata.get("host"))
            .or_else(|| record.metadata.get("source_ip"))
            .cloned()
            .unwrap_or_else(|| "unidentified-system".to_string())
    }
}
