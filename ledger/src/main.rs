use clap::{Parser, Subcommand};
use anyhow::Result;
use std::path::PathBuf;
use ledger::{Ledger, InventoryItem, Board, WoodType, Measure};

#[derive(Parser)]
#[command(name = "ledger")]
#[command(about = "The Woodshop Foreman's Ledger: Persistence & Inventory", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a new board to the inventory
    Add {
        #[arg(short, long)]
        species: String,
        #[arg(short, long)]
        length: f64,
        #[arg(short, long)]
        width: f64,
        #[arg(short, long)]
        thickness: f64,
    },
    /// List all items in the inventory
    List,
    /// Search by minimum volume (Parallel processing for large inventories)
    Search {
        #[arg(short, long)]
        volume: f64,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let path = PathBuf::from("ledger.json");

    // Phase 1: Load or Initialize
    let mut ledger = Ledger::load(path.clone()).unwrap_or_else(|_| Ledger::new());

    match cli.command {
        Commands::Add { species, length, width, thickness } => {
            let wood_type = match species.to_lowercase().as_str() {
                "oak" => WoodType::Oak,
                "walnut" => WoodType::Walnut,
                "pine" => WoodType::Pine,
                _ => anyhow::bail!("Unsupported species: {}. (Oak, Walnut, Pine allowed)", species),
            };

            let item = InventoryItem::Board(Board {
                species: wood_type,
                length,
                width,
                thickness,
            });

            ledger.items.push(item);
            println!("✅ Added new {:?} board ({}m x {}m x {}m)", wood_type, length, width, thickness);
        }
        Commands::List => {
            println!("📋 Shop Inventory:");
            for (i, item) in ledger.items.iter().enumerate() {
                println!("  [{}] - {:?} (Volume: {:.4}m³)", i + 1, item, item.volume());
            }
        }
        Commands::Search { volume } => {
            println!("🔍 Searching for items >= {:.4}m³...", volume);
            let results = ledger.search(volume);
            for item in results {
                println!("  🌟 Match: {:?} (Volume: {:.4}m³)", item, item.volume());
            }
        }
    }

    // Phase 2: Atomic Save
    ledger.save(path)?;
    
    Ok(())
}
