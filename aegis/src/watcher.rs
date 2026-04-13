use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use futures::stream::StreamExt;
use linemux::MuxedLines;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::windows::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::models::LogRecord;
use crate::parsers::LogParser;

pub struct Sentry {
    path: PathBuf,
    offset_path: PathBuf,
    parser: Arc<dyn LogParser>,
    monitor: Arc<crate::monitor::PostureMonitor>,
    last_creation_time: std::sync::Mutex<u64>,
}

impl Sentry {
    pub fn with_parser(
        path: PathBuf,
        offset_path: PathBuf,
        parser: Arc<dyn LogParser>,
        monitor: Arc<crate::monitor::PostureMonitor>,
    ) -> Result<Self> {
        let creation_time = std::fs::metadata(&path)
            .map(|m| m.creation_time())
            .unwrap_or(0);
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
        println!(
            "🔍 Aegis Sentry: Starting tail mode on {:?} (Initial offset: {})",
            self.path, last_size
        );

        let mut first_pass = true;

        loop {
            match self.process_once(tx.clone(), last_size).await {
                Ok(new_size) => {
                    if first_pass {
                        self.monitor.mark_caught_up();
                        first_pass = false;
                    }
                    last_size = new_size;
                }
                Err(e) => {
                    println!("⚠️ Aegis Sentry Loop Error: {:?}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    pub async fn tail_live(&self, tx: mpsc::Sender<Arc<LogRecord>>) -> Result<()> {
        let last_size = self.load_offset();
        println!(
            "🔭 Aegis Live Sentinel: Attaching linemux core to {:?} (Initial offset: {})",
            self.path, last_size
        );

        let _ = self
            .process_once(tx.clone(), last_size)
            .await;
        self.monitor.mark_caught_up();

        let mut mux = MuxedLines::new()?;
        mux.add_file(&self.path).await?;

        while let Some(Ok(line_event)) = mux.next().await {
            let line_str = line_event.line();

            let record = self.parser.parse(line_str);
            let _ = tx.send(Arc::new(record)).await;

            if let Ok(m) = std::fs::metadata(&self.path) {
                let _ = self.save_offset(m.len());
            }
        }

        Ok(())
    }

    pub async fn process_once(
        &self,
        tx: mpsc::Sender<Arc<LogRecord>>,
        last_size: u64,
    ) -> Result<u64> {
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

    async fn process_lines<R: BufRead>(
        &self,
        mut reader: R,
        tx: &mpsc::Sender<Arc<LogRecord>>,
    ) -> Result<()> {
        let mut count = 0;
        let format_name = self.parser.format_name().to_string();

        // 🛡️ NIST AU-9 Integrity: We stream line-by-line using read_line to preserve
        // trailing newlines (\n, \r\n). This ensures the unparsed_raw field matches
        // the source file byte-for-byte, resulting in valid forensic hashes.

        // Check for JSON Buffer Need:
        // 1. JSON Array: Always buffer whole thing.
        // 2. Specialized Pretty-JSON (Elastic/GCP): Buffer if it looks like a single object header.
        let (is_json_array, is_json_object) = if let Ok(n) = reader.fill_buf() {
            let first_char = n.iter().find(|&&b| !b.is_ascii_whitespace());
            (
                first_char.map(|&b| b == b'[').unwrap_or(false),
                first_char.map(|&b| b == b'{').unwrap_or(false),
            )
        } else {
            (false, false)
        };

        let needs_whole_buffer = is_json_array
            || (is_json_object
                && (format_name == "elastic"
                    || format_name == "gcp"
                    || format_name == "json_generic"));

        if needs_whole_buffer {
            let mut content = String::new();
            reader.read_to_string(&mut content)?;

            if is_json_array {
                if let Some(json_parser) = self
                    .parser
                    .as_any()
                    .downcast_ref::<crate::parsers::json::JsonParser>()
                {
                    let values: Vec<serde_json::Value> =
                        serde_json::from_str(&content).unwrap_or_default();
                    for val in values {
                        count += 1;
                        let r = json_parser.parse_value(val.clone(), &val.to_string());
                        tx.send(Arc::new(r)).await?;
                    }
                } else {
                    count += 1;
                    let record = self.parser.parse(&content);
                    tx.send(Arc::new(record)).await?;
                }
            } else {
                // Single Pretty-Printed Object (Elastic/GCP)
                count += 1;
                let record = self.parser.parse(&content);
                tx.send(Arc::new(record)).await?;
            }
        } else {
            // Standard Streaming Path: Plaintext, CSV, or NDJSON (Line-based)
            let mut line = String::new();
            while reader.read_line(&mut line)? > 0 {
                count += 1;
                let record = self.parser.parse(&line);
                tx.send(Arc::new(record)).await?;
                line.clear();
            }
        }

        println!(
            "✅ Aegis Ingestion: Streamed through {} signals as {}",
            count, format_name
        );
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
