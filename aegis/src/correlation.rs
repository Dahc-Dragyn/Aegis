use crate::models::LogRecord;
use crate::monitor::PostureMonitor;
use tokio::sync::mpsc;
use uuid::Uuid;
use moka::future::Cache;
use std::time::Duration;
use std::sync::Arc;
use anyhow::{Result, Context};

/// The Cross-Vector Correlation Fusion Engine (NIST IR-4).
/// 
/// Correlates disparate high-severity signals into unified "Incidents" based on 
/// temporal proximity and System ID boundaries.
pub struct FusionWorker {
    rx: mpsc::Receiver<Arc<LogRecord>>,
    edge_buffer_tx: Arc<crate::edge_buffer::EdgeBuffer>,
    monitor: Arc<PostureMonitor>,
    /// Cache stores SystemID -> IncidentID with 10s TTL
    cache: Cache<String, Uuid>,
}

impl FusionWorker {
    pub fn new(
        rx: mpsc::Receiver<Arc<LogRecord>>, 
        edge_buffer_tx: Arc<crate::edge_buffer::EdgeBuffer>,
        monitor: Arc<PostureMonitor>
    ) -> Self {
        let cache = Cache::builder()
            .time_to_live(Duration::from_secs(10))
            .build();
        
        Self { rx, edge_buffer_tx, monitor, cache }
    }

    /// Primary execution loop for the Fusion Worker.
    pub async fn run(&mut self) -> Result<()> {
        println!("🛰️ Aegis: Cross-Vector Correlation Fusion Engine ACTIVE.");
        
        while let Some(record) = self.rx.recv().await {
            let mut record_val = (*record).clone();
            
            // Extract NIST metadata for severity evaluation
            let nist_control = record_val.metadata.get("nist_control_id");
            
            if let Some(id) = nist_control {
                // NIST IR-4 Heuristic: Only fuse and count if it's a security finding.
                // We exclude AU-2 (Audit Records) and AU-3 (Content of Audit Records) 
                // from the finding count to ensure Pulsar parity.
                if id != "AU-2" && id != "AU-3" {
                    let system_id = self.extract_system_id(&record_val);
                    
                    if let Some(existing_uuid) = self.cache.get(&system_id).await {
                        record_val.incident_id = Some(existing_uuid);
                    } else {
                        let new_incident_id = Uuid::new_v4();
                        self.cache.insert(system_id, new_incident_id).await;
                        record_val.incident_id = Some(new_incident_id);
                    }
                    
                    // Update monitor stats only for matched actionable signals
                    self.monitor.increment_signals(1);
                }
            }

            // Forward to EdgeBuffer for persistence (Non-Blocking)
            self.edge_buffer_tx.push(Arc::new(record_val)).await.context("EdgeBuffer persistence failed")?;
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
