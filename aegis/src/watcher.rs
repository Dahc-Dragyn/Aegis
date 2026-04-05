use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use std::os::windows::fs::MetadataExt;
use std::collections::HashMap;
use chrono::Utc;

use crate::models::{LogRecord, ParsingQuality};
use crate::parsers::{LogParser};

pub struct Sentry {
    path: PathBuf,
    offset_path: PathBuf,
    parser: Arc<dyn LogParser>,
    monitor: Arc<crate::monitor::PostureMonitor>,
    last_creation_time: std::sync::Mutex<u64>,
}

impl Sentry {
    pub fn with_parser(path: PathBuf, offset_path: PathBuf, parser: Arc<dyn LogParser>, monitor: Arc<crate::monitor::PostureMonitor>) -> Result<Self> {
        let creation_time = std::fs::metadata(&path).map(|m| m.creation_time()).unwrap_or(0);
        Ok(Self { 
            path, 
            offset_path, 
            parser,
            monitor,
            last_creation_time: std::sync::Mutex::new(creation_time),
        })
    }

    pub async fn tail(&self, tx: mpsc::Sender<Arc<LogRecord>>) -> Result<()> {
        let mut last_size = self.load_offset();
        println!("🔍 Aegis Sentry: Starting tail mode on {:?} (Initial offset: {})", self.path, last_size);
        
        let mut first_pass = true;

        loop {
            match self.process_once(tx.clone(), last_size).await {
                Ok(new_size) => {
                    if first_pass {
                        self.monitor.mark_caught_up();
                        first_pass = false;
                    }
                    last_size = new_size;
                },
                Err(e) => {
                    println!("⚠️ Aegis Sentry Loop Error: {:?}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    pub async fn process_once(&self, tx: mpsc::Sender<Arc<LogRecord>>, last_size: u64) -> Result<u64> {
        let metadata = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(last_size),
            Err(e) => return Err(e).context("Failed to check log metadata"),
        };
        
        let current_size = metadata.len();
        let current_creation = metadata.creation_time();

        // 1. Detect Log Rotation via Stable Creation Time (AU-3 Compliance)
        let rotated = {
            let mut guard = self.last_creation_time.lock().unwrap();
            let old = *guard;
            *guard = current_creation;
            old != 0 && old != current_creation
        };

        if rotated || current_size < last_size {
            // Truncation or Rotation detected!
            return self.process_from_start(tx).await;
        }

        if current_size > last_size {
            let file = File::open(&self.path)?;
            let mut reader = BufReader::new(file);
            reader.seek(SeekFrom::Start(last_size))?;

            let is_gz = self.path.extension().is_some_and(|ext| ext == "gz");
            if is_gz {
                let decoder = GzDecoder::new(reader.into_inner());
                let reader = BufReader::new(decoder);
                self.process_lines(reader, &tx).await?;
            } else {
                self.process_lines(reader, &tx).await?;
            }

            self.save_offset(current_size)?;
            Ok(current_size)
        } else {
            Ok(last_size)
        }
    }

    async fn process_from_start(&self, tx: mpsc::Sender<Arc<LogRecord>>) -> Result<u64> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        self.process_lines(reader, &tx).await?;
        let metadata = std::fs::metadata(&self.path)?;
        let new_offset = metadata.len();
        self.save_offset(new_offset)?;
        Ok(new_offset)
    }

    async fn process_lines<R: BufRead>(&self, mut reader: R, tx: &mpsc::Sender<Arc<LogRecord>>) -> Result<()> {
        let format = {
            let peek_buf = reader.fill_buf()?;
            let f = crate::parsers::AutoDetector::detect(peek_buf);
            println!("📑 Aegis Ingestion: Detected format [{:?}] for stream", f);
            f
        };
        
        let mut count = 0;

        match format {
            crate::parsers::LogFormat::JsonArray | crate::parsers::LogFormat::NdJson => {
                let stream = serde_json::Deserializer::from_reader(reader).into_iter::<serde_json::Value>();
                for value in stream.flatten() {
                    let values = if let Some(arr) = value.as_array() { arr.clone() } else { vec![value] };
                    for val in values {
                        let record = if let Some(json_parser) = self.parser.as_any().downcast_ref::<crate::parsers::json::JsonParser>() {
                            json_parser.parse_value(val, "streamed_json")
                        } else {
                            self.parser.parse(&val.to_string())
                        };
                        if let Some(r) = record {
                            count += 1;
                            tx.send(Arc::new(r)).await?;
                        }
                    }
                }
                println!("✅ Aegis Ingestion: Streamed through {} signals", count);
            }
            _ => {
                for content in reader.lines().map_while(Result::ok) {
                    count += 1;
                    if let Some(record) = self.parser.parse(&content) {
                        tx.send(Arc::new(record)).await?;
                    } else {
                        tx.send(Arc::new(LogRecord {
                            timestamp: Utc::now(),
                            message: "Malformed line skipped".to_string(),
                            severity: Some("WARN".to_string()),
                            source: Some("sentry_watcher".to_string()),
                            subject_id: None,
                            outcome: Some("Failure".to_string()),
                            metadata: HashMap::new(),
                            raw: content,
                            original_format: self.parser.format_name().to_string(),
                            quality: ParsingQuality::Malformed,
                            redactions: Vec::new(),
                        })).await?;
                    }
                }
                println!("✅ Aegis Ingestion: Streamed through {} lines as PlainText", count);
            }
        }
        Ok(())
    }

    fn load_offset(&self) -> u64 {
        std::fs::read_to_string(&self.offset_path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    fn save_offset(&self, offset: u64) -> Result<()> {
        std::fs::write(&self.offset_path, offset.to_string())?;
        Ok(())
    }

    pub fn save_current_offset(&self) -> Result<()> {
        let metadata = std::fs::metadata(&self.path)?;
        self.save_offset(metadata.len())
    }
}
