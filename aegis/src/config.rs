use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use anyhow::{Result, Context};

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub formats: HashMap<String, LogFormatConfig>,
    #[serde(default)]
    pub redaction: RedactionConfig,
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
        let config: AppConfig = toml::from_str(&content)
            .context("Failed to parse log_formats.toml")?;
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
                m
            },
        });
        
        Self {
            formats,
            redaction: RedactionConfig::default(),
        }
    }
}
