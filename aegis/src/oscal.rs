use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Local};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct OscalAssessmentResults {
    pub assessment_results: AssessmentResults,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AssessmentResults {
    pub uuid: Uuid,
    pub metadata: Metadata,
    pub results: Vec<ResultEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Metadata {
    pub title: String,
    pub last_modified: DateTime<Local>,
    pub version: String,
    pub oscal_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ResultEntry {
    pub uuid: Uuid,
    pub title: String,
    pub description: String,
    pub start: DateTime<Local>,
    pub observations: Vec<Observation>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Observation {
    pub uuid: Uuid,
    pub description: String,
    pub methods: Vec<String>,
    pub occurrence_count: usize,
    pub sample_evidence: Vec<String>,
    pub relevant_evidence: Vec<Evidence>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Evidence {
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Finding {
    pub uuid: Uuid,
    pub title: String,
    pub description: String,
    pub occurrence_count: usize,
    pub incident_id: Option<Uuid>,
    pub target: FindingTarget,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FindingTarget {
    pub target_id: String,
    pub status: FindingStatus,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FindingStatus {
    pub state: String, // e.g., "satisfied", "not-satisfied"
}

// --- PoAM MODELS ---

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct OscalPoam {
    pub plan_of_action_and_milestones: Poam,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Poam {
    pub uuid: Uuid,
    pub metadata: Metadata,
    pub poam_items: Vec<PoamItem>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PoamItem {
    pub uuid: Uuid,
    pub incident_id: Option<Uuid>,
    pub title: String,
    pub description: String,
    pub status: String,
    pub occurrence_count: usize,
    pub entry_timestamp: DateTime<Local>,
    pub last_seen: DateTime<Local>,
    pub impacted_system: String,
    pub evidence_hash: String,
    pub remediation_remarks: String,
    pub correlated_events: Vec<Uuid>,
}
