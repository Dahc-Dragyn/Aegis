use crate::config::Watch;
use anyhow::{Context, Result};
use std::io::SeekFrom;
use std::path::PathBuf;
use tokio::fs::{self, File};
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc;
use notify::{Watcher, RecommendedWatcher, RecursiveMode, Event};

pub struct LogMatch {
    pub _file: PathBuf, // Reserved for detailed reporting
    pub content: String,
}

pub struct Monitor {
    watch: Watch,
    tx: mpsc::Sender<LogMatch>,
    pos_file: PathBuf,
}

impl Monitor {
    pub fn new(watch: Watch, tx: mpsc::Sender<LogMatch>) -> Self {
        let pos_file = watch.path.with_extension("sentinel_pos");
        Self { watch, tx, pos_file }
    }

    pub async fn run(self) -> Result<()> {
        let path = self.watch.path.clone();
        println!("- Sentinel 🛡️ Monitoring: {:?}", path);

        let file = self.open_and_seek().await?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();

        // Setup Watcher
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(1);
        let mut watcher = RecommendedWatcher::new(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                if event.kind.is_modify() || event.kind.is_create() || event.kind.is_remove() {
                    let _ = event_tx.blocking_send(event.kind);
                }
            }
        }, notify::Config::default())?;

        watcher.watch(&path, RecursiveMode::NonRecursive)?;

        loop {
            // Initial read / catch up on every loop iteration to be safe
            while reader.read_line(&mut line).await? > 0 {
                let content = line.trim().to_string();
                if !content.is_empty() {
                    self.tx.send(LogMatch {
                        _file: path.clone(),
                        content,
                    }).await?;
                }
                line.clear();
                
                // Update Checkpoint
                let pos = reader.get_mut().stream_position().await?;
                let _ = fs::write(&self.pos_file, pos.to_string()).await;
            }

            tokio::select! {
                Some(kind) = event_rx.recv() => {
                    if kind.is_remove() {
                        println!("- Log Rotation Detected! Attempting re-subscription for {:?}", path);
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        // Re-open file
                        if let Ok(new_file) = File::open(&path).await {
                            reader = BufReader::new(new_file);
                        }
                    }
                    // Loop continues, triggering the 'while reader.read_line' above
                }
            }
        }
    }

    async fn open_and_seek(&self) -> Result<File> {
        let mut file = File::open(&self.watch.path).await
            .with_context(|| format!("Failed to open log: {:?}", self.watch.path))?;

        if let Ok(pos_str) = fs::read_to_string(&self.pos_file).await {
            if let Ok(pos) = pos_str.trim().parse::<u64>() {
                println!("- Resuming {:?} from byte {}", self.watch.path, pos);
                file.seek(SeekFrom::Start(pos)).await?;
                return Ok(file);
            }
        }

        // Default to end
        file.seek(SeekFrom::End(0)).await?;
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Watch;
    use tempfile::tempdir;
    use tokio::time::{self, Duration};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_monitor_detects_appends() -> Result<()> {
        let dir = tempdir()?;
        let log_path = dir.path().join("test.log");
        fs::write(&log_path, "").await?;

        let watch = Watch {
            path: log_path.clone(),
            _json: false,
        };

        let (tx, mut rx) = mpsc::channel(100);
        let monitor = Monitor::new(watch, tx);

        // Spawn monitor
        let _monitor_handle = tokio::spawn(async move {
            let _ = monitor.run().await;
        });

        // Wait for watcher to initialize properly
        time::sleep(Duration::from_millis(500)).await;

        // Write to log
        {
            let mut file = fs::OpenOptions::new().append(true).open(&log_path).await?;
            use tokio::io::AsyncWriteExt;
            file.write_all(b"ERROR: System overheating\n").await?;
            file.flush().await?;
        }

        // Check if monitor sent the match
        let msg = time::timeout(Duration::from_secs(5), rx.recv()).await
            .context("Monitor timed out waiting for append")?
            .context("Channel closed")?;

        assert_eq!(msg.content, "ERROR: System overheating");

        Ok(())
    }
}
