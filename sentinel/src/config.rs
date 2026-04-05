use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub watches: Vec<Watch>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub pattern: String,
    pub action: String,
    #[serde(default)]
    pub script: Option<String>,
    #[serde(default = "default_cooldown")]
    pub cooldown: String,
    #[serde(default)]
    pub destructive: bool, // Required manual confirmation if true
}

#[derive(Deserialize, Debug, Clone)]
pub struct Watch {
    pub path: PathBuf,
    #[serde(default)]
    pub _json: bool, // Reserved for Phase 2
}

fn default_cooldown() -> String {
    "10s".to_string()
}
