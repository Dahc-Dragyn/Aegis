use crate::ledger::AuditLedger;
use crate::monitor::PostureMonitor;
use crate::NistEngine;
use crate::models::LogRecord;
use crate::redactor::Redactor;
use crate::config::AppConfig;
use std::sync::Arc;
use tokio::sync::mpsc;
use anyhow::Result;

pub struct Dispatcher {
    engine: Arc<NistEngine>,
    ledger: Arc<AuditLedger>,
    monitor: Arc<PostureMonitor>,
    redactor: Arc<Redactor>,
    batch_threshold: usize,
}

impl Dispatcher {
    pub fn new(
        engine: Arc<NistEngine>,
        ledger: Arc<AuditLedger>,
        monitor: Arc<PostureMonitor>,
        config: &AppConfig,
        batch_threshold: usize,
    ) -> Self {
        let redactor = Arc::new(Redactor::new(&config.redaction));
        Self {
            engine,
            ledger,
            monitor,
            redactor,
            batch_threshold,
        }
    }

    pub async fn run(&self, mut rx: mpsc::Receiver<Arc<LogRecord>>) -> Result<()> {
        let mut batch = Vec::new();

        while let Some(record) = rx.recv().await {
            // 1. Account for Parsing Quality (success vs partial vs skipped)
            self.monitor.record_quality(&record.quality);

            // 2. Privacy Redaction Pass (AU-3 / Privacy Best Practice)
            let mut record_val = (*record).clone();
            
            // Redact main message
            let (sanitized_msg, msg_redactions) = self.redactor.redact(&record_val.message);
            record_val.message = sanitized_msg;
            record_val.redactions.extend(msg_redactions);
            
            // Redact metadata values and aggregate events
            for value in record_val.metadata.values_mut() {
                let (sanitized_val, val_redactions) = self.redactor.redact(value);
                *value = sanitized_val;
                
                // Aggregate counts for same reason rather than just extending
                for new_event in val_redactions {
                    if let Some(existing) = record_val.redactions.iter_mut().find(|e| e.reason == new_event.reason) {
                        existing.count += new_event.count;
                    } else {
                        record_val.redactions.push(new_event);
                    }
                }
            }

            let record = Arc::new(record_val);
            batch.push(record);

            if batch.len() >= self.batch_threshold {
                self.process_batch(&mut batch).await?;
            }
        }

        // Final flush
        if !batch.is_empty() {
            self.process_batch(&mut batch).await?;
        }

        Ok(())
    }

    async fn process_batch(&self, batch: &mut Vec<Arc<LogRecord>>) -> Result<()> {
        let engine = Arc::clone(&self.engine);
        let ledger = Arc::clone(&self.ledger);
        let monitor = Arc::clone(&self.monitor);
        
        let batch_to_process = std::mem::take(batch);

        // Heavy lifting NIST analysis in parallel (Hardened Await for Persistence)
        tokio::task::spawn_blocking(move || {
            let signals = engine.analyze_batch(&batch_to_process);
            let signal_count = signals.len() as u64;
            
            if signal_count > 0 {
                monitor.increment_signals(signal_count);
                if let Err(e) = ledger.log_batch(signals) {
                    eprintln!("❌ Failed to write to audit ledger: {:?}", e);
                }
            }
        }).await?;

        Ok(())
    }
}
