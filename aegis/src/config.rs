use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use anyhow::{Result, Context};

#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
pub enum ActiveFramework {
    #[default]
    Federal53,
    Commercial171,
    AiRmf100,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub formats: HashMap<String, LogFormatConfig>,
    #[serde(default)]
    pub redaction: RedactionConfig,
    #[serde(default = "default_sensor_id")]
    pub sensor_id: String,
    #[serde(default = "default_profile_name")]
    pub profile_name: String,
    #[serde(default)]
    pub active_framework: ActiveFramework,
    #[serde(default)]
    pub ai_rmf: AiRmfConfig,
    #[serde(default)]
    pub authorized_baseline_services: Vec<String>,
}

fn default_profile_name() -> String {
    "NIST_SP-800-53_rev5_HIGH-baseline".to_string()
}

fn default_sensor_id() -> String {
    "aegis.edge-node.01".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogFormatConfig {
    pub timestamp_field: Option<String>,
    pub message_field: Option<String>,
    pub severity_field: Option<String>,
    pub source_field: Option<String>,
    #[serde(default)]
    pub metadata_map: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AiRmfConfig {
    #[serde(default = "default_toxicity_threshold")]
    pub toxicity_threshold: f64,
    #[serde(default = "default_latency_threshold")]
    pub latency_threshold_ms: u64,
}

impl Default for AiRmfConfig {
    fn default() -> Self {
        Self {
            toxicity_threshold: default_toxicity_threshold(),
            latency_threshold_ms: default_latency_threshold(),
        }
    }
}

fn default_toxicity_threshold() -> f64 { 0.85 }
fn default_latency_threshold() -> u64 { 5000 }

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RedactionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mask_ips: bool,
    #[serde(default)]
    pub patterns: Vec<String>, // Custom regex patterns for redaction
}

impl AppConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .context("Failed to read log_formats.toml")?;
        let mut config: AppConfig = toml::from_str(&content)
            .context("Failed to parse log_formats.toml")?;

        // Day-2 SOC Baseline Tuning: Proactively load aegis_baseline.json if it exists
        if let Ok(baseline_content) = std::fs::read_to_string("aegis_baseline.json") {
            if let Ok(baseline) = serde_json::from_str::<serde_json::Value>(&baseline_content) {
                if let Some(services) = baseline.get("authorized_services").and_then(|v| v.as_array()) {
                    for service in services {
                        if let Some(s) = service.as_str() {
                            if !config.authorized_baseline_services.contains(&s.to_string()) {
                                config.authorized_baseline_services.push(s.to_string());
                            }
                        }
                    }
                }
            }
        }

        Ok(config)
    }

    pub fn default_config() -> Self {
        let mut formats = HashMap::new();
        // Default GCP Cloud Run Mapping
        formats.insert("gcp".to_string(), LogFormatConfig {
            timestamp_field: Some("timestamp".to_string()),
            message_field: Some("textPayload".to_string()),
            severity_field: Some("severity".to_string()),
            source_field: Some("resource.type".to_string()),
            metadata_map: {
                let mut m = HashMap::new();
                m.insert("status".to_string(), "httpRequest.status".to_string());
                m.insert("ip".to_string(), "httpRequest.remoteIp".to_string());
                m.insert("ParentProcessId".to_string(), "parent_process_id".to_string());
                m.insert("ParentImage".to_string(), "parent_image".to_string());
                m.insert("ProcessId".to_string(), "process_id".to_string());
                m.insert("NewProcessName".to_string(), "image_name".to_string());
                m
            },
        });

        // 2. High-Fidelity Elastic/Endpoint/Beats Mapping
        formats.insert("elastic".to_string(), LogFormatConfig {
            timestamp_field: Some("_source.@timestamp".to_string()),
            message_field: Some("_source.message".to_string()),
            severity_field: Some("_source.log.level".to_string()),
            source_field: Some("_source.event.dataset".to_string()),
            metadata_map: {
                let mut m = HashMap::new();
                m.insert("hostname".to_string(), "_source.host.hostname".to_string());
                m.insert("cmd".to_string(), "_source.process.command_line".to_string());
                m.insert("user".to_string(), "_source.user.name".to_string());
                m.insert("action".to_string(), "_source.event.action".to_string());
                m.insert("ParentProcessId".to_string(), "_source.process.ppid".to_string());
                m.insert("ParentImage".to_string(), "_source.process.parent.executable".to_string());
                m.insert("ProcessId".to_string(), "_source.process.pid".to_string());
                m.insert("NewProcessName".to_string(), "_source.process.executable".to_string());
                m
            },
        });

        Self {
            formats,
            redaction: RedactionConfig::default(),
            sensor_id: default_sensor_id(),
            profile_name: default_profile_name(),
            active_framework: ActiveFramework::Federal53,
            ai_rmf: AiRmfConfig::default(),
            authorized_baseline_services: vec![
                "RtkAudioUniversalService".to_string(),
                "GameSDK Service".to_string(),
                "RulesEngine".to_string(),
                "AsusUpdateHelper.msi".to_string(),
                "UAPSDKAddOn-x86.msi".to_string(),
                "Windows Subsystem for Linux".to_string(),
            ],
        }
    }
}
