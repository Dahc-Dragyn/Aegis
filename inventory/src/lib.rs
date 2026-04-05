//! # The Master Craftsman’s Inventory 🪵
//! 
//! An advanced Rust laboratory project demonstrating the technical "joints" of 
//! Zero-Cost Abstractions, Manual Iterators, and Move Semantics.

/// The basic unit of measurement in the woodshop.
/// 
/// Every piece of inventory must have a volume and metadata about its species.
pub trait Measure {
    /// Standard density of the species (kg/m^3).
    const DENSITY: f64;

    /// Calculate the total volume in cubic meters.
    fn volume(&self) -> f64;

    /// Determine if the texture and grain are suitable for high-end finishing.
    fn is_suitable_for_finish(&self) -> bool {
        self.volume() > 0.0
    }
}

/// Wood species available in the shop.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum WoodType {
    Oak,
    Walnut,
    Pine,
}

/// A solid board from a specific wood species.
#[derive(Debug, PartialEq)]
pub struct Board {
    pub species: WoodType,
    pub length: f64,
    pub width: f64,
    pub thickness: f64,
}

impl Measure for Board {
    const DENSITY: f64 = 700.0; // Default for hardwood

    fn volume(&self) -> f64 {
        self.length * self.width * self.thickness
    }

    fn is_suitable_for_finish(&self) -> bool {
        match self.species {
            WoodType::Oak | WoodType::Walnut => true,
            WoodType::Pine => false, // Pine is the "scrap" wood
        }
    }
}

/// A sheet of plywood.
#[derive(Debug, PartialEq)]
pub struct Sheet {
    pub material: WoodType,
    pub length: f64,
    pub width: f64,
}

impl Measure for Sheet {
    const DENSITY: f64 = 550.0; // Plywood is less dense

    fn volume(&self) -> f64 {
        self.length * self.width * 0.019 // Standard 3/4" thickness
    }

    fn is_suitable_for_finish(&self) -> bool {
        self.material == WoodType::Walnut // Only walnut veneer plywood is finish-grade
    }
}

/// A generic storage container for inventory.
pub struct StorageBin<T> {
    items: Vec<T>,
}

impl<T> StorageBin<T> {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn add(&mut self, item: T) {
        self.items.push(item);
    }
}

impl<T> Default for StorageBin<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// The Manual Iterator (The Dovetail Joint).
/// 
/// We do not wrap `items.iter()` here. We manually track the index pointer 
/// and tie the iterator's lifetime to the `StorageBin` container.
pub struct StorageBinIter<'a, T> {
    container: &'a [T],
    index: usize,
}

impl<'a, T> Iterator for StorageBinIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.container.len() {
            let item = &self.container[self.index];
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }
}

// Tie the StorageBin's reference to the manual Iterator
impl<'a, T> IntoIterator for &'a StorageBin<T> {
    type Item = &'a T;
    type IntoIter = StorageBinIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        StorageBinIter {
            container: &self.items,
            index: 0,
        }
    }
}

/// Lifetime Mastery: Returning a reference to the best match.
/// 
/// 'a connects the input inventory to the output reference, 
/// telling the compiler these references "live together."
pub fn find_best_match<'a, T: Measure>(inventory: &'a StorageBin<T>, criteria: f64) -> Option<&'a T> {
    let mut best: Option<&'a T> = None;
    let mut min_diff = f64::MAX;

    for item in inventory {
        let diff = (item.volume() - criteria).abs();
        if diff < min_diff {
            min_diff = diff;
            best = Some(item);
        }
    }

    best
}

/// Ownership Challenge: Consuming a board to create two new ones.
/// 
/// Once split, the original `board` is "dead" (moved).
pub fn split_board(board: Board, cut_length: f64) -> (Board, Board) {
    if cut_length >= board.length {
        panic!("Cannot cut longer than the board!");
    }

    let b1 = Board {
        length: cut_length,
        ..board // Note: We use struct update syntax which consumes the original
    };

    let b2 = Board {
        species: b1.species, // Copy species back
        length: board.length - cut_length,
        width: b1.width,
        thickness: b1.thickness,
    };

    (b1, b2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vortex_manual_iterator() {
        let mut bin = StorageBin::new();
        // Add 5 boards (Gate 2: Nextest requirement)
        for i in 0..5 {
            bin.add(Board {
                species: WoodType::Oak,
                length: (i + 1) as f64,
                width: 1.0,
                thickness: 1.0,
            });
        }

        // Use the manual iterator
        let mut count = 0;
        for board in &bin {
            count += 1;
            println!("🛠️ Measuring Board (volume: {})", board.volume());
        }

        assert_eq!(count, 5);
    }

    #[test]
    fn test_lifetime_matching() {
        let mut bin = StorageBin::new();
        bin.add(Board { species: WoodType::Pine, length: 10.0, width: 1.0, thickness: 1.0 });
        bin.add(Board { species: WoodType::Oak, length: 50.0, width: 1.0, thickness: 1.0 });

        let match_ref = find_best_match(&bin, 45.0);
        assert!(match_ref.is_some());
        assert_eq!(match_ref.unwrap().length, 50.0);
    }

    #[test]
    fn test_ownership_transfer() {
        let b = Board { species: WoodType::Walnut, length: 100.0, width: 1.0, thickness: 1.0 };
        let (s1, s2) = split_board(b, 30.0);
        
        // println!("{:?}", b); // Would trigger compiler error: USE AFTER MOVE
        assert_eq!(s1.length, 30.0);
        assert_eq!(s2.length, 70.0);
    }
}
