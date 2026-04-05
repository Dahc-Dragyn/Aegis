use crate::config::{Config, Rule};
use crate::monitor::LogMatch;
use anyhow::{Context, Result};
use notify_rust::Notification;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

pub struct Dispatcher {
    compiled_rules: Vec<(Rule, Arc<Regex>)>,
    history: HashMap<String, Instant>, // rule.name -> last_triggered
    force: bool,                      // --auto-approve
}

impl Dispatcher {
    pub fn new(config: Config, force: bool) -> Result<Self> {
        let compiled_rules = config.rules.iter().map(|rule| {
            let re = Regex::new(&rule.pattern)
                .with_context(|| format!("Invalid regex: {}", rule.pattern))?;
            Ok((rule.clone(), Arc::new(re)))
        }).collect::<Result<Vec<_>>>()?;

        Ok(Self {
            compiled_rules,
            history: HashMap::new(),
            force,
        })
    }

    pub async fn run(mut self, mut rx: mpsc::Receiver<LogMatch>) -> Result<()> {
        println!("- Dispatcher 📡 Ready for Ryzen 3600X parallel matching.");

        while let Some(msg) = rx.recv().await {
            // Match against rules first (immutable)
            let matches: Vec<Rule> = self.compiled_rules.iter()
                .filter(|(_, re)| re.is_match(&msg.content))
                .map(|(rule, _)| rule.clone())
                .collect();

            // Trigger acts (mutable)
            for rule in matches {
                if self.should_trigger(&rule) {
                    self.trigger(&rule, &msg.content).await?;
                }
            }
        }
        Ok(())
    }

    fn should_trigger(&mut self, rule: &Rule) -> bool {
        let now = Instant::now();
        let cooldown = self.parse_duration(&rule.cooldown);

        if let Some(last) = self.history.get(&rule.name) {
            if now.duration_since(*last) < cooldown {
                return false; // Debounce
            }
        }

        self.history.insert(rule.name.clone(), now);
        true
    }

    async fn trigger(&self, rule: &Rule, content: &str) -> Result<()> {
        println!("🔥 Match! [{}]: {}", rule.name, content);

        if rule.action == "notify" {
            let _ = Notification::new()
                .summary(&format!("Sentinel: {}", rule.name))
                .body(content)
                .timeout(Duration::from_secs(5))
                .show();
        }

        if let Some(script) = &rule.script {
            if rule.destructive && !self.force {
                println!("\n⚠️  DESTRUCTIVE ACTION DETECTED: [{}]", rule.name);
                println!("👉 Action: Execute script '{}'", script);
                println!("👉 Confirm execution? (y/N): ");
                
                use tokio::io::{AsyncBufReadExt, BufReader, stdin};
                let mut reader = BufReader::new(stdin());
                let mut input = String::new();
                let _ = reader.read_line(&mut input).await;
                
                if !input.to_lowercase().trim().starts_with('y') {
                    println!("❌ Action aborted by user.\n");
                    return Ok(());
                }
            }

            println!("🚀 Executing self-healing script: {}", script);
            let mut cmd = Command::new("powershell");
            cmd.arg("-Command").arg(script);
            let _ = cmd.spawn(); // Fire and forget reboot scripts
        }

        Ok(())
    }

    fn parse_duration(&self, s: &str) -> Duration {
        let s = s.trim();
        if let Some(stripped) = s.strip_suffix('s') {
            Duration::from_secs(stripped.parse().unwrap_or(10))
        } else if let Some(stripped) = s.strip_suffix('m') {
            Duration::from_secs(stripped.parse::<u64>().unwrap_or(1) * 60)
        } else {
            Duration::from_secs(10)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Rule};

    #[tokio::test]
    async fn test_dispatcher_debounce_logic() -> Result<()> {
        let rule = Rule {
            name: "Test Debounce".to_string(),
            pattern: "ERROR".to_string(),
            action: "notify".to_string(),
            script: None,
            cooldown: "10s".to_string(),
            destructive: false,
        };

        let config = Config {
            rules: vec![rule.clone()],
            watches: vec![],
        };

        let mut dispatcher = Dispatcher::new(config, false)?;
        
        // First trigger
        assert!(dispatcher.should_trigger(&rule));
        // Immediate second trigger should fail (cooldown)
        assert!(!dispatcher.should_trigger(&rule));
        
        Ok(())
    }

    #[tokio::test]
    async fn test_dispatcher_destructive_check_logic() -> Result<()> {
        let rule = Rule {
            name: "Destructive Action".to_string(),
            pattern: "REBOOT".to_string(),
            action: "notify".to_string(),
            script: Some("echo rebooting".to_string()),
            cooldown: "10s".to_string(),
            destructive: true,
        };

        let config = Config {
            rules: vec![rule.clone()],
            watches: vec![],
        };

        // If force is true, it should proceed (we can't easily wait for stdin in a test, 
        // but we can verify the 'force' flag logic pathway).
        let dispatcher = Dispatcher::new(config, true)?;
        // This won't prompt and will return Ok(())
        dispatcher.trigger(&rule, "REBOOT DETECTED").await?;
        
        Ok(())
    }
}
