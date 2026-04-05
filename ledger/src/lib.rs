use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
use rayon::prelude::*;

/// Custom error types for the Ledger system.
#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("IO failure: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization failure: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Inventory state error: {0}")]
    State(String),
}

/// The basic unit of measurement in the woodshop.
pub trait Measure {
    const DENSITY: f64;
    fn volume(&self) -> f64;
    fn is_suitable_for_finish(&self) -> bool;
}

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum WoodType {
    Oak,
    Walnut,
    Pine,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Board {
    pub species: WoodType,
    pub length: f64,
    pub width: f64,
    pub thickness: f64,
}

impl Measure for Board {
    const DENSITY: f64 = 700.0;
    fn volume(&self) -> f64 {
        self.length * self.width * self.thickness
    }
    fn is_suitable_for_finish(&self) -> bool {
        matches!(self.species, WoodType::Oak | WoodType::Walnut)
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Sheet {
    pub material: WoodType,
    pub length: f64,
    pub width: f64,
}

impl Measure for Sheet {
    const DENSITY: f64 = 550.0;
    fn volume(&self) -> f64 {
        self.length * self.width * 0.019
    }
    fn is_suitable_for_finish(&self) -> bool {
        self.material == WoodType::Walnut
    }
}

/// A wrapper for different inventory items.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum InventoryItem {
    Board(Board),
    Sheet(Sheet),
}

impl Measure for InventoryItem {
    const DENSITY: f64 = 0.0; // Placeholder for polymorphic dispatch
    fn volume(&self) -> f64 {
        match self {
            InventoryItem::Board(b) => b.volume(),
            InventoryItem::Sheet(s) => s.volume(),
        }
    }
    fn is_suitable_for_finish(&self) -> bool {
        match self {
            InventoryItem::Board(b) => b.is_suitable_for_finish(),
            InventoryItem::Sheet(s) => s.is_suitable_for_finish(),
        }
    }
}

/// The Foreman's Ledger: Manages persistence and search.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Ledger {
    pub items: Vec<InventoryItem>,
}


impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomic Save Strategy: Write to .tmp then rename.
    pub fn save(&self, path: PathBuf) -> Result<(), LedgerError> {
        let mut tmp_path = path.clone();
        tmp_path.set_extension("tmp");

        // 1. Serialize to string
        let data = serde_json::to_string_pretty(self)?;

        // 2. Write to temporary file
        fs::write(&tmp_path, data)?;

        // 3. Atomic rename (Standard OS guarantee for data integrity)
        fs::rename(tmp_path, path)?;

        Ok(())
    }

    /// Load the ledger from a file.
    pub fn load(path: PathBuf) -> Result<Self, LedgerError> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let data = fs::read_to_string(path)?;
        let ledger: Self = serde_json::from_str(&data)?;
        Ok(ledger)
    }

    /// High-performance search optimized for Ryzen 3600X.
    /// Switches to Rayon parallelism if items > 1000.
    pub fn search(&self, min_volume: f64) -> Vec<&InventoryItem> {
        if self.items.len() > 1000 {
            self.items.par_iter()
                .filter(|i| i.volume() >= min_volume)
                .collect()
        } else {
            self.items.iter()
                .filter(|i| i.volume() >= min_volume)
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_vortex_persistence_integrity() -> Result<(), LedgerError> {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_path_buf();

        let mut ledger = Ledger::new();
        ledger.items.push(InventoryItem::Board(Board {
            species: WoodType::Walnut,
            length: 10.0,
            width: 1.0,
            thickness: 1.0,
        }));

        // Phase 2: Save, clear, and reload
        ledger.save(path.clone())?;
        
        let loaded = Ledger::load(path)?;
        assert_eq!(loaded.items.len(), 1);
        
        if let InventoryItem::Board(b) = &loaded.items[0] {
            assert_eq!(b.species, WoodType::Walnut);
        } else {
            panic!("Wrong item type loaded!");
        }

        Ok(())
    }
}
