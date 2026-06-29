pub mod brain;
pub mod memory;
pub mod publisher;
pub mod scout;

use tokio_cron_scheduler::{Job, JobScheduler};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Load local environment configurations
    if let Err(e) = dotenvy::dotenv() {
        eprintln!("Warning: failed to load .env file: {}", e);
    }

    println!("ForgeControl Daemon Initialized");

    // DRY-FIRE TEST: Execute a pipeline run immediately
    println!("--- INITIATING DRY-FIRE TEST ---");
    crate::scout::run_vta_pipeline().await;
    println!("--- DRY-FIRE TEST COMPLETE ---");

    let sched = JobScheduler::new().await?;

    sched.add(
        Job::new_async("0 0 0/6 * * *", |_uuid, _l| {
            Box::pin(async move {
                crate::scout::run_vta_pipeline().await;
            })
        })?,
    ).await?;

    sched.add(
        Job::new_async("0 0 12 * * FRI", |_uuid, _l| {
            Box::pin(async move {
                crate::publisher::generate_weekly_digest().await;
            })
        })?,
    ).await?;

    sched.start().await?;

    // Await Ctrl+C signal to prevent main from exiting
    tokio::signal::ctrl_c().await?;
    println!("ForgeControl Daemon terminating...");

    Ok(())
}
