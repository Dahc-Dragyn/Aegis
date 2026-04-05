mod config;
mod monitor;
mod dispatcher;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tokio::fs;
use crate::config::Config;
use crate::monitor::Monitor;
use crate::dispatcher::Dispatcher;

#[derive(Parser, Debug)]
#[command(author, version, about = "Sentinel 🛡️: Async Concurrent Log Monitor")]
struct Args {
    #[arg(short, long, default_value = "sentinel.toml")]
    config: PathBuf,

    #[arg(short, long)]
    poll: bool, // Support fallback polling

    /// Auto-approve destructive actions (bypass safety gate)
    #[arg(short = 'y', long)]
    pub auto_approve: bool,
}

fn main() -> Result<()> {
    // Initialize Ryzen 3600X optimized runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(12)
        .enable_all()
        .build()?;

    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let args = Args::parse();
    println!("Sentinel 🛡️ Initializing on Ryzen 3600X (12 Threads)...");

    // Load Config
    let config_content = fs::read_to_string(&args.config).await
        .with_context(|| format!("Failed to read config: {:?}", args.config))?;
    let config: Config = toml::from_str(&config_content)?;

    // Setup Dispatcher
    let (tx, rx) = tokio::sync::mpsc::channel(100);
    let dispatcher = Dispatcher::new(config.clone(), args.auto_approve)?;

    // Spawn Dispatcher Task
    let _dispatcher_handle = tokio::spawn(async move {
        if let Err(e) = dispatcher.run(rx).await {
            eprintln!("Dispatcher error: {}", e);
        }
    });

    // Spawn Monitor Tasks
    for watch in config.watches {
        let monitor = Monitor::new(watch, tx.clone());
        tokio::spawn(async move {
            if let Err(e) = monitor.run().await {
                eprintln!("Monitor error: {}", e);
            }
        });
    }

    println!("Sentinel 🛡️ Operational. Press Ctrl+C to terminate.");
    tokio::signal::ctrl_c().await?;
    println!("Sentinel 🛡️ Shutting down gracefully.");

    Ok(())
}
