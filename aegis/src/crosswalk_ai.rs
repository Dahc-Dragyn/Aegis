use crate::config::{ActiveFramework, AiRmfConfig};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AiRmfPillar {
    SecureResilient,
    PrivacyEnhanced,
    FairHarmManaged,
    ValidReliable,
}

impl AiRmfPillar {
    pub fn as_str(&self) -> &'static str {
        match self {
            AiRmfPillar::SecureResilient => "Secure & Resilient",
            AiRmfPillar::PrivacyEnhanced => "Privacy-Enhanced",
            AiRmfPillar::FairHarmManaged => "Fair / Harmful Bias Managed",
            AiRmfPillar::ValidReliable => "Valid & Reliable",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AiRmfPillar::SecureResilient => "Protection against prompt injections, jailbreaks, and adversarial attacks.",
            AiRmfPillar::PrivacyEnhanced => "Ensuring PII and sensitive data are not leaked in prompts or completions.",
            AiRmfPillar::FairHarmManaged => "Auditing for toxicity, hate speech, and harmful biases in AI outputs.",
            AiRmfPillar::ValidReliable => "Monitoring for performance anomalies and model integrity issues.",
        }
    }
}

pub struct AiRmfCrosswalk;

impl AiRmfCrosswalk {
    pub fn evaluate(metadata: &std::collections::BTreeMap<String, String>, config: &AiRmfConfig) -> Vec<AiRmfPillar> {
        let mut violations = Vec::new();

        // 1. Secure & Resilient (Prompt Injection)
        if metadata.get("ai_security_prompt_injection_detected").and_then(|v| v.parse::<bool>().ok()).unwrap_or(false) {
            violations.push(AiRmfPillar::SecureResilient);
        }

        // 2. Privacy-Enhanced (PII Leak)
        // Check if ai_security_pii_detected exists and is not "[]" or empty
        if let Some(pii) = metadata.get("ai_security_pii_detected") {
            if pii != "[]" && pii != "null" && !pii.is_empty() {
                violations.push(AiRmfPillar::PrivacyEnhanced);
            }
        }

        // 3. Fair (Toxicity)
        if let Some(toxicity) = metadata.get("ai_security_toxicity_score").and_then(|v| v.parse::<f64>().ok()) {
            if toxicity >= config.toxicity_threshold {
                violations.push(AiRmfPillar::FairHarmManaged);
            }
        }

        // 4. Valid & Reliable (Latency)
        if let Some(latency) = metadata.get("latency_ms").and_then(|v| v.parse::<u64>().ok()) {
            if latency >= config.latency_threshold_ms {
                violations.push(AiRmfPillar::ValidReliable);
            }
        }

        violations
    }
}

pub struct AiPostureCalculator {
    pub config: AiRmfConfig,
    pub failed_pillars: HashSet<AiRmfPillar>,
}

impl AiPostureCalculator {
    pub fn new(config: AiRmfConfig) -> Self {
        Self {
            config,
            failed_pillars: HashSet::new(),
        }
    }

    pub fn record_violation(&mut self, pillar: AiRmfPillar) {
        self.failed_pillars.insert(pillar);
    }
}

pub fn initialize_ai_crosswalk(framework: &ActiveFramework, config: &AiRmfConfig) -> Option<AiPostureCalculator> {
    if let ActiveFramework::AiRmf100 = framework {
        Some(AiPostureCalculator::new(config.clone()))
    } else {
        None
    }
}
