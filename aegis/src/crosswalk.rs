use std::collections::HashSet;
use crate::config::ActiveFramework;

/// NIST SP 800-171 Requirement representation for SPRS scoring.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Requirement171 {
    pub id: &'static str,
    pub weight: i32,
    pub description: &'static str,
}

/// The Commercial Compliance Crosswalk: Translates 800-53 controls to 800-171 requirements.
pub struct NistCrosswalk;

impl NistCrosswalk {
    /// Maps a NIST 800-53 Control ID to its corresponding 800-171 Requirement.
    pub fn translate(control_id: &str) -> Option<Requirement171> {
        match control_id {
            "AU-2" => Some(Requirement171 { id: "3.3.1", weight: 5, description: "Create and retain system audit logs and records" }),
            "AU-9" => Some(Requirement171 { id: "3.3.2", weight: 5, description: "Protect audit information and tools from unauthorized access" }),
            "CM-5" => Some(Requirement171 { id: "3.4.1", weight: 3, description: "Establish and maintain baseline configurations" }),
            "SC-7" => Some(Requirement171 { id: "3.13.1", weight: 3, description: "Monitor, control, and protect organizational communications" }),
            "SI-4" => Some(Requirement171 { id: "3.14.3", weight: 1, description: "Monitor the information system and its surroundings" }),
            "AC-6" => Some(Requirement171 { id: "3.1.5", weight: 3, description: "Employ the principle of least privilege" }),
            "IA-2" => Some(Requirement171 { id: "3.5.3", weight: 3, description: "Use multi-factor authentication for network access" }),
            "AU-10" => Some(Requirement171 { id: "3.3.3", weight: 3, description: "Review and update system audit logs and records" }),
            "AU-6" => Some(Requirement171 { id: "3.3.3", weight: 3, description: "Review and update system audit logs and records" }),
            "AC-4" => Some(Requirement171 { id: "3.1.1", weight: 5, description: "Limit information system access to authorized users" }),
            _ => None, // controls with no direct commercial crosswalk or pure federal availability controls
        }
    }
}

/// Supplier Performance Risk System (SPRS) Scoring Engine.
pub struct SprsCalculator {
    base_score: i32,
    failed_requirements: HashSet<Requirement171>,
}

impl Default for SprsCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl SprsCalculator {
    pub fn new() -> Self {
        Self {
            base_score: 110,
            failed_requirements: HashSet::new(),
        }
    }

    /// Records a failed control. Deduplication is handled via HashSet.
    pub fn record_failure(&mut self, control_id: &str) {
        if let Some(req) = NistCrosswalk::translate(control_id) {
            self.failed_requirements.insert(req);
        }
    }

    /// Calculates the final SPRS score.
    pub fn calculate_score(&self) -> i32 {
        let deductions: i32 = self.failed_requirements.iter().map(|r| r.weight).sum();
        self.base_score - deductions
    }

    pub fn get_failed_requirements(&self) -> &HashSet<Requirement171> {
        &self.failed_requirements
    }
}

/// Zero-Overhead Factory: Only instantiates the crosswalk/calculator if framework is Commercial.
pub fn initialize_crosswalk(framework: &ActiveFramework) -> Option<SprsCalculator> {
    if let ActiveFramework::Commercial171 = framework {
        Some(SprsCalculator::new())
    } else {
        None
    }
}
