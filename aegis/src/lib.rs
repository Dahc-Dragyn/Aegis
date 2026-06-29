pub mod watcher;
pub mod dispatcher;
pub mod ledger;
pub mod monitor;
pub mod dashboard;
pub mod report;
pub mod notification;
pub mod models;
pub mod parsers;
pub mod config;
pub mod redactor;
pub mod oscal;
pub mod edge_buffer;
pub mod compliance_cache;
pub mod audit_receipt;
pub mod correlation;
pub mod lineage;
pub mod crosswalk;
pub mod crosswalk_ai;
pub mod redaction;
pub mod extraction;
pub mod server;

pub use nist_engine::{NistEngine, ControlMapping, PostureEvent, AegisError};

mod nist_engine {
    
    use regex::Regex;
    use serde::{Deserialize, Serialize};
    use chrono::{DateTime, Local};
    use std::collections::BTreeMap;
    use dashmap::DashMap;
    use uuid::Uuid;
    use thiserror::Error;
    use anyhow::Result;
    use crate::models::LogRecord;
    use crate::config::AppConfig;
    
    use std::sync::Arc;
    

    #[derive(Error, Debug)]
    pub enum AegisError {
        #[error("Failed to compile regex signature: {0}")]
        InvalidSignature(String),
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct ControlMapping {
        pub control_id: String,
        pub category: String,
        pub description: String,
        pub human_title: String,
        pub human_action: String,
        pub long_description: String,
        pub remediation: String,
        pub target_field: Option<String>,
        pub default_status: crate::models::ComplianceStatus,
        pub severity: crate::models::SeverityLevel,
        pub pattern_str: Option<String>,
        pub adversary_profile: Option<String>,
        pub tactical_intent: Option<String>,
        pub attack_mechanism: Option<String>,
        #[serde(skip)]
        pub pattern: Option<Regex>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PostureEvent {
        pub timestamp: DateTime<Local>,
        pub control_id: String,
        pub status: crate::models::ComplianceStatus,
        pub severity: crate::models::SeverityLevel,
        pub description: String,
        pub human_title: String,
        pub human_action: String,
        pub long_description: String,
        pub remediation: String,
        pub adversary_profile: String,
        pub tactical_intent: String,
        pub attack_mechanism: String,
        pub raw_log: String,
        pub metadata: BTreeMap<String, String>,
        pub incident_id: Option<Uuid>,
    }

    #[derive(Debug, Clone)]
    pub enum WmiState {
        Filter,
        Consumer,
    }

    pub struct NistEngine {
        pub(crate) mappings: Vec<ControlMapping>,
        wmi_buffer: DashMap<String, WmiState>,
        signal_counts: DashMap<String, (u64, DateTime<Local>)>,
        process_tree: DashMap<u32, (String, Option<u32>, Option<String>)>, // Pid -> (ImageName, ParentPid, ProcessGuid)
        config: crate::config::AppConfig,
    }

    impl NistEngine {
        pub fn new(config: crate::config::AppConfig) -> Result<Self> {
            let mut mappings = vec![
                ControlMapping {
                    control_id: "SI-4 [Ghost Hunter]".to_string(),
                    category: "System and Information Integrity".to_string(),
                    description: "Operation Ghost Hunter: Lineage-based parent-child anomaly detection".to_string(),
                    human_title: "Suspicious Process Lineage Detected".to_string(),
                    human_action: "Isolate host and investigate the process tree for malicious activity.".to_string(),
                    long_description: "Detection of anomalous parent-child relationships, such as Office applications spawning shells or system utilities spawning unusual binaries.".to_string(),
                    remediation: "Investigate suspicious process parent-child relationship. Office app spawning shells is a high-fidelity indicator of exploit/macro execution.".to_string(),
                    adversary_profile: Some("Hostile Lineage (LotL/LotB)".to_string()),
                    tactical_intent: Some("Execution of malicious code via trusted parent processes.".to_string()),
                    attack_mechanism: Some("Parent-Child Anomaly (LotL/LotB)".to_string()),
                    target_field: Some("message".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Critical,
                    pattern_str: Some(r"\[LINEAGE ANOMALY\]".to_string()),
                    pattern: Some(Regex::new(r"\[LINEAGE ANOMALY\]").unwrap()),
                },
                ControlMapping {
                    control_id: "SC-7 [C2 Exfiltration]".to_string(),
                    category: "System & Comms Protection".to_string(),
                    description: "Command and Control / Data Exfiltration".to_string(),
                    human_title: "Anomalous Network Data Outbound".to_string(),
                    human_action: "Large amounts of data are being sent from your computer to an unknown location. This often indicates an active security breach or data theft.".to_string(),
                    long_description: "Detection of massive data exfiltration via HTTP POST bodies. This pattern, characterized by high-entropy encoded payloads in single parameters, is a definitive signature of backdoor C2 beaconing.".to_string(),
                    remediation: "Immediately isolate the host. Extract the 'Host:' header from the forensic evidence to identify the C2/DGA domain. Blacklist the domain at the perimeter firewall/DNS sinkhole. Perform full forensic audit of the exfiltrated payload.".to_string(),
                    adversary_profile: Some("Unknown (C2 Beaconing)".to_string()),
                    tactical_intent: Some("Establish Command and Control channel and exfiltrate data.".to_string()),
                    attack_mechanism: Some("High-entropy network payloads.".to_string()),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Critical,
                    pattern_str: Some(r"(?is)txt=.{500,}".to_string()),
                    pattern: Some(Regex::new(r"(?is)txt=.{500,}")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
            ];

            // Try to load from external file
            let rules_path = "intel/nist_mappings.json";
            if std::path::Path::new(rules_path).exists() {
                if let Ok(content) = std::fs::read_to_string(rules_path) {
                    if let Ok(mut loaded_mappings) = serde_json::from_str::<Vec<ControlMapping>>(&content) {
                        for mapping in &mut loaded_mappings {
                            if let Some(ref p_str) = mapping.pattern_str {
                                if let Ok(re) = Regex::new(p_str) {
                                    mapping.pattern = Some(re);
                                }
                            }
                        }
                        mappings.extend(loaded_mappings);
                    }
                }
            }

            mappings.extend(vec![
                ControlMapping {
                    control_id: "AC-3 [Cloud Identity Expansion]".to_string(),
                    category: "Access Enforcement".to_string(),
                    description: "Azure AD: Service Principal Privilege Escalation / Role Assignment".to_string(),
                    human_title: "Identity Permission Theft".to_string(),
                    human_action: "Check your Azure/Office 365 permissions and revoke any unauthorized 'Service Principal' role assignments.".to_string(),
                    long_description: "Detection of app role assignments to service principals. Targeted role assignment (e.g., Mail.Read.All) is a critical precursor to O365 data exfiltration and domain dominance.".to_string(),
                    remediation: "Audit the Service Principal for over-privileged Graph permissions. Immediately revoke unauthorized AppRole assignments. Review sign-in logs for the affected Service Principal ID.".to_string(),
                    adversary_profile: Some("Unknown (Cloud Identity Hijack)".to_string()),
                    tactical_intent: Some("Gain unauthorized access to identity infrastructure.".to_string()),
                    attack_mechanism: Some("Azure AD Service Principal role assignment.".to_string()),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::High,
                    pattern_str: Some(r#"(?i)"Operation":\s*"Add app role assignment to service principal.""#.to_string()),
                    pattern: Some(Regex::new(r#"(?i)"Operation":\s*"Add app role assignment to service principal.""#)
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AU-10 [Cloud Forensic Extension]".to_string(),
                    category: "Audit and Accountability".to_string(),
                    description: "O365: MFA Tampering / Unauthorized Mailbox Permission Change".to_string(),
                    human_title: "Email & Security Tampering".to_string(),
                    human_action: "Change your main user password and re-enable Multi-Factor Authentication (MFA) for the affected account immediately.".to_string(),
                    long_description: "Detection of O365 mailbox permission changes (Add-MailboxPermission) or MFA disabling operations. These represent attempts to gain persistent access to executive communications or bypass identity security controls.".to_string(),
                    remediation: "Verify user identity via out-of-band communication. Rollback mailbox permission changes. Immediately enforce MFA re-enrollment for the affected account.".to_string(),
                    adversary_profile: Some("Unknown (O365 Tampering)".to_string()),
                    tactical_intent: Some("Gain access to executive communications by tampering with mail permissions.".to_string()),
                    attack_mechanism: Some("MFA disabling or mailbox permission modification.".to_string()),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Critical,
                    pattern_str: Some(r#"(?i)"Operation":\s*"(Add-MailboxPermission|Disable-Mfa|Set-Mailbox)""#.to_string()),
                    pattern: Some(Regex::new(r#"(?i)"Operation":\s*"(Add-MailboxPermission|Disable-Mfa|Set-Mailbox)""#)
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "SI-4 [Windows Integrity]".to_string(),
                    category: "System & Info Integrity".to_string(),
                    description: "Windows Forensic: System Integrity / Active Exploit".to_string(),
                    human_title: "Critical System Takeover Attempt".to_string(),
                    human_action: "1. Disconnect your computer from the internet immediately. 2. Run Windows Update as soon as you reconnect securely. 3. Change your main Windows/Admin password.".to_string(),
                    long_description: "Detection of system manifest corruption, execution of discovery tools, or highly definitive protocol-level exploit markers.".to_string(),
                    remediation: "Immediately isolate host and freeze network segment. Run 'dism /online /cleanup-image /restorehealth' for manifest corruption.".to_string(),
                    adversary_profile: Some("Unknown (Windows Exploitation)".to_string()),
                    tactical_intent: Some("Compromise system integrity via exploit or baseline deviation.".to_string()),
                    attack_mechanism: Some("Generic system exploit marker.".to_string()),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Critical,
                    pattern_str: Some(r#"(?i)CBS_E_MANIFEST_INVALID_ITEM|0x800f080d|EventID 2004|Resource-Exhaustion-Detector|0x80042100|netstat\s+-ano|ipconfig\s+/all|\bnmap\b|\bnc\s+-|\bncat\b|\bexploit\b|ZAM64|BYOV|CVE-2021-21551|doppel|proc_doppel|doppelgang|ntds\.dit|ntdsutil|herpaderp|scriptblocklogging|transcription|powershell.*policies|System\.Management\.Automation|psinject|\[Net\.ServicePointManager\]|\$env:temp|DownloadFile|Invoke-WebRequest|IWR|javascript:|mshtml,RunHTMLApplication|mshta.*\.hta|mshta.*(http|https)|user shell folders.*startup|mscfile\\shell\\open\\command|ms-settings\\shell\\open\\command|eventvwr\.exe|bitsadmin|start-bitstransfer|openvpn|BITS-Client|-s EventLog|wevtutil(\.exe)?\s+cl|clear-eventlog|cmstp(\.exe)?.*(/au|/ni|/s|\.inf|\.ini)|timestomp|Set-ItemProperty.*CreationTime|(\\[a-z0-9_]{15,}\.exe)|(\\AppData\\Local\\Temp\\[a-z0-9_]+\.exe)|promptforcredential|getnetworkcredential|validatecredentials|Suspicious_C2_Tunnel|DNS_TXT_C2_Tunneling|DNS-TXT|SMBGhost|CVE-2020-0796|ZeroLogon|CVE-2020-1472|NetrServerAuthenticate: Bad password 0|NetrServerAuthenticate returns Success|PetitPotam|MS-EFSR|EFS_RPC|CVE-2021-36942|byt3bl33d3r|Event Log Crash|Defense Evasion|/etc/shadow|authorized_keys|crontab\\s+-e|systemctl\\s+stop|(\.env|config\.php|wp-admin|phpinfo)|TCC\.db|PipeName"#.to_string()),
                    pattern: Some(Regex::new(r#"(?i)CBS_E_MANIFEST_INVALID_ITEM|0x800f080d|EventID 2004|Resource-Exhaustion-Detector|0x80042100|netstat\s+-ano|ipconfig\s+/all|\bnmap\b|\bnc\s+-|\bncat\b|\bexploit\b|ZAM64|BYOV|CVE-2021-21551|doppel|proc_doppel|doppelgang|ntds\.dit|ntdsutil|herpaderp|scriptblocklogging|transcription|powershell.*policies|System\.Management\.Automation|psinject|\[Net\.ServicePointManager\]|\$env:temp|DownloadFile|Invoke-WebRequest|IWR|javascript:|mshtml,RunHTMLApplication|mshta.*\.hta|mshta.*(http|https)|user shell folders.*startup|mscfile\\shell\\open\\command|ms-settings\\shell\\open\\command|eventvwr\.exe|bitsadmin|start-bitstransfer|openvpn|BITS-Client|-s EventLog|wevtutil(\.exe)?\s+cl|clear-eventlog|cmstp(\.exe)?.*(/au|/ni|/s|\.inf|\.ini)|timestomp|Set-ItemProperty.*CreationTime|(\\[a-z0-9_]{15,}\.exe)|(\\AppData\\Local\\Temp\\[a-z0-9_]+\.exe)|promptforcredential|getnetworkcredential|validatecredentials|Suspicious_C2_Tunnel|DNS_TXT_C2_Tunneling|DNS-TXT|SMBGhost|CVE-2020-0796|ZeroLogon|CVE-2020-1472|NetrServerAuthenticate: Bad password 0|NetrServerAuthenticate returns Success|PetitPotam|MS-EFSR|EFS_RPC|CVE-2021-36942|byt3bl33d3r|Event Log Crash|Defense Evasion|/etc/shadow|authorized_keys|crontab\\s+-e|systemctl\\s+stop|(\.env|config\.php|wp-admin|phpinfo)|TCC\.db|PipeName"#)
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AC-3 [Identity Infrastructure]".to_string(),
                    category: "Access Enforcement".to_string(),
                    description: "Windows Forensic: AD Certificate Services (AD CS) Request / Abuse".to_string(),
                    human_title: "Identity System Abuse".to_string(),
                    human_action: "A core identity certificates system was accessed or tampered with.".to_string(),
                    long_description: "Audit of Active Directory Certificate Services (AD CS) requests (4886) and approvals (4887).".to_string(),
                    remediation: "Verify the requested Template and Subject Alternative Name (SAN).".to_string(),
                    adversary_profile: Some("Unknown (Identity Infrastructure)".to_string()),
                    tactical_intent: Some("Abuse Active Directory Certificate Services.".to_string()),
                    attack_mechanism: Some("AD CS Certificate request/abuse.".to_string()),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Medium,
                    pattern_str: Some(r"(?i)EventID.*?488(6|7)".to_string()),
                    pattern: Some(Regex::new(r"(?i)EventID.*?488(6|7)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AU-9".to_string(),
                    category: "Audit and Accountability".to_string(),
                    description: "Detection of audit log clearing or service tampering".to_string(),
                    human_title: "Security Log Tampering".to_string(),
                    human_action: "Your security logs were just cleared.".to_string(),
                    long_description: "Clearing audit logs or stopping the logging service is a high-severity indicator of anti-forensic activity.".to_string(),
                    remediation: "Investigate why the log service was stopped or cleared.".to_string(),
                    adversary_profile: Some("Unknown (Anti-Forensic Actor)".to_string()),
                    tactical_intent: Some("Cover tracks by deleting forensic evidence.".to_string()),
                    attack_mechanism: Some("Audit log clearing or service tampering.".to_string()),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Critical,
                    pattern_str: Some(r"(?i)(log cleared|audit log was cleared|EventID.*?1102|EventID.*?104|systemctl stop (rsyslog|auditd)|net stop (eventlog|sysmon)|kill -9.*(rsyslog|auditd|eventlog))".to_string()),
                    pattern: Some(Regex::new(r"(?i)(log cleared|audit log was cleared|EventID.*?1102|EventID.*?104|systemctl stop (rsyslog|auditd)|net stop (eventlog|sysmon)|kill -9.*(rsyslog|auditd|eventlog))")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AU-12".to_string(),
                    category: "Incident Response".to_string(),
                    description: "Honeypot/Trap trigger from active reconnaissance".to_string(),
                    human_title: "Security Tripwire Triggered".to_string(),
                    human_action: "An automated threat or actor touched a security 'trap'.".to_string(),
                    long_description: "Access to 'honeypot' resources is a reliable indicator of malicious intent.".to_string(),
                    remediation: "Initiate full Incident Response (IR) for the host.".to_string(),
                    adversary_profile: Some("Unknown (Honeypot Trigger)".to_string()),
                    tactical_intent: Some("Unauthorized discovery or reconnaissance.".to_string()),
                    attack_mechanism: Some("Access to trap/honeypot resource.".to_string()),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Critical,
                    pattern_str: Some(r"(?i)\[HONEYPOT\]".to_string()),
                    pattern: Some(Regex::new(r"(?i)\[HONEYPOT\]")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AC-3 [Credential Access]".to_string(),
                    category: "Access Enforcement".to_string(),
                    description: "NIST AC-3: Explicit OS Credential Access".to_string(),
                    human_title: "Security Credential Theft".to_string(),
                    human_action: "Someone tried to steal your saved passwords.".to_string(),
                    long_description: "Detection of explicit offensive tooling (Mimikatz, Procdump, etc.).".to_string(),
                    remediation: "Assume all local and domain credentials cached on this system are compromised.".to_string(),
                    adversary_profile: Some("Unknown (Credential Harvester)".to_string()),
                    tactical_intent: Some("Harvest administrative credentials to facilitate domain-wide escalation.".to_string()),
                    attack_mechanism: Some("Credential extraction via Mimikatz/Procdump.".to_string()),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Critical,
                    pattern_str: Some(r"(?i)\b(mimikatz|mimidrv|procdump|pypykatz|ppldump|LsarSetSecret|AS-REQ|Kerbrute)\b|comsvcs\.dll.*?MiniDump|rdp-tcp|psexesvc|wmiprvse|lsarpc|samr|DCSync|krbtgt|DRSUAPI|MachineAccount Password|Policy\\Secrets|TGS-REQ|sname=krbtgt|RC4-HMAC|EType 23".to_string()),
                    pattern: Some(Regex::new(r"(?i)\b(mimikatz|mimidrv|procdump|pypykatz|ppldump|LsarSetSecret|AS-REQ|Kerbrute)\b|comsvcs\.dll.*?MiniDump|rdp-tcp|psexesvc|wmiprvse|lsarpc|samr|DCSync|krbtgt|DRSUAPI|MachineAccount Password|Policy\\Secrets|TGS-REQ|sname=krbtgt|RC4-HMAC|EType 23")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "CM-3 [Scheduled Task Manipulation]".to_string(),
                    category: "Configuration Management".to_string(),
                    description: "NIST CM-3: Unauthorized persistence via Scheduled Task creation/modification".to_string(),
                    human_title: "☢️ Hidden Scheduled Task Created".to_string(),
                    human_action: "A hidden task was created to run programs automatically.".to_string(),
                    long_description: "Audit of schtasks.exe activity and Event IDs 4698 (Task Created) / 4702 (Task Updated).".to_string(),
                    remediation: "Immediately delete the suspicious task: 'schtasks /delete /tn \"TASK_NAME\" /f'.".to_string(),
                    adversary_profile: Some("Unknown (Persistence Actor)".to_string()),
                    tactical_intent: Some("Maintain long-term access via automated task execution.".to_string()),
                    attack_mechanism: Some("Unauthorized Scheduled Task creation.".to_string()),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::High,
                    pattern_str: Some(r"(?i)(schtasks(\.exe)?\s+/create|EventID.*?469(8)|EventID.*?4702).*?\\(AppData\\Local\\Temp|Windows\\Temp|Public)".to_string()),
                    pattern: Some(Regex::new(r"(?i)(schtasks(\.exe)?\s+/create|EventID.*?469(8)|EventID.*?4702).*?\\(AppData\\Local\\Temp|Windows\\Temp|Public)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "SC-7 [Registry Persistence]".to_string(),
                    category: "System & Comms Protection".to_string(),
                    description: "NIST SC-7: Registry 'Run' key hijack for automatic startup".to_string(),
                    human_title: "☢️ Automatic Startup Hijack Attempt".to_string(),
                    human_action: "An attacker tried to hide a program in your system's 'Automatic Startup' list.".to_string(),
                    long_description: "Detection of modifications to high-value auto-run keys via EventID 4657.".to_string(),
                    remediation: "Audit the registry key using 'reg query'.".to_string(),
                    adversary_profile: Some("Unknown (Persistence Actor)".to_string()),
                    tactical_intent: Some("Establish persistence via registry auto-run hijacking.".to_string()),
                    attack_mechanism: Some("Registry 'Run' key modification.".to_string()),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::High,
                    pattern_str: Some(r"(?i)(reg\s+add.*\\(CurrentVersion\\(Run|RunOnce)|Winlogon\\Shell|Image\s+File\s+Execution\s+Options)|EventID.*?4657).*?(cmd\.exe\s+/c|powershell\s+-enc|\\Temp\\|\\AppData\\)".to_string()),
                    pattern: Some(Regex::new(r"(?i)(reg\s+add.*\\(CurrentVersion\\(Run|RunOnce)|Winlogon\\Shell|Image\s+File\s+Execution\s+Options)|EventID.*?4657).*?(cmd\.exe\s+/c|powershell\s+-enc|\\Temp\\|\\AppData\\)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "SI-4 [WMI Persistence]".to_string(),
                    category: "System & Info Integrity".to_string(),
                    description: "NIST SI-4: WMI Permanent Event Consumer establishment".to_string(),
                    human_title: "☢️ WMI Persistence Script Detected".to_string(),
                    human_action: "A stealthy WMI script was set up to run in the background.".to_string(),
                    long_description: "Detection of WMI Filter-to-Consumer bindings (Event IDs 5857/5858).".to_string(),
                    remediation: "List WMI consumers and remove unauthorized ones.".to_string(),
                    adversary_profile: Some("Unknown (Stealth Persistence Actor)".to_string()),
                    tactical_intent: Some("Establish stealthy persistence via WMI event filters.".to_string()),
                    attack_mechanism: Some("WMI Permanent Event Consumer establishment.".to_string()),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::High,
                    pattern_str: Some(r"(?i)EventID.*?585(7|8)".to_string()),
                    pattern: Some(Regex::new(r"(?i)EventID.*?585(7|8)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "SI-4 [Mirror Test]".to_string(),
                    category: "System & Info Integrity".to_string(),
                    description: "NIST SI-4: Process Hollowing / Stealth Detection (Mirror Test)".to_string(),
                    human_title: "☢️ Stealth Process Hijack Unmasked".to_string(),
                    human_action: "A standard Windows program is behaving like a virus.".to_string(),
                    long_description: "Detection of signature-mismatch or behaviorally inconsistent common processes.".to_string(),
                    remediation: "Isolate the host from the network. Capture a memory dump.".to_string(),
                    adversary_profile: Some("Unknown (Stealth Process Actor)".to_string()),
                    tactical_intent: Some("Bypass process monitoring via hollowing or masquerading.".to_string()),
                    attack_mechanism: Some("Mirror Test / Process Hollowing signature.".to_string()),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Critical,
                    pattern_str: Some(r"(?i)(ProcessHollowing|MirrorTestFail|mimic__aegis|EventID.*?wevtutil.*?cl|clear-eventlog)".to_string()),
                    pattern: Some(Regex::new(r"(?i)(ProcessHollowing|MirrorTestFail|mimic__aegis|EventID.*?wevtutil.*?cl|clear-eventlog)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AU-3".to_string(),
                    category: "Audit and Accountability".to_string(),
                    description: "Verify audit record content integrity via active privacy masking (redaction).".to_string(),
                    human_title: "Privacy System Active".to_string(),
                    human_action: "Aegis is protecting your private data.".to_string(),
                    long_description: "Audit records should be redacted of PII/PHI.".to_string(),
                    remediation: "No action required.".to_string(),
                    adversary_profile: Some("Aegis Privacy Engine".to_string()),
                    tactical_intent: Some("Protect PII/PHI via automated redaction.".to_string()),
                    attack_mechanism: Some("Baseline security audit.".to_string()),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Pass,
                    severity: crate::models::SeverityLevel::Low,
                    pattern_str: None,
                    pattern: None,
                },
            ]);

            Ok(Self { 
                mappings, 
                wmi_buffer: DashMap::new(), 
                signal_counts: DashMap::new(),
                process_tree: DashMap::new(),
                config,
            })
        }

        pub fn get_lineage_chain(&self, pid: u32, depth: usize) -> String {
            if depth > 10 { return "... (depth limit)".to_string(); }
            if let Some(entry) = self.process_tree.get(&pid) {
                let (name, parent_pid, _) = entry.value();
                let name_os = std::ffi::OsStr::new(name);
                let basename = std::path::Path::new(name_os).file_name().and_then(|f: &std::ffi::OsStr| f.to_str()).unwrap_or(name);
                if let Some(ppid) = parent_pid {
                    let parent_chain = self.get_lineage_chain(*ppid, depth + 1);
                    if parent_chain.is_empty() {
                        basename.to_string()
                    } else {
                        format!("{} -> {}", parent_chain, basename)
                    }
                } else {
                    basename.to_string()
                }
            } else {
                String::new()
            }
        }

        pub fn prune_tree(&self) {
            // Simple pruning: If tree exceeds 5000 entries, clear it to prevent leak
            // In a production version, we would check for active PIDs or lifecycle events
            let count = self.process_tree.len();
            if count > 5000 {
                println!("🧹 Aegis Maintenance: Pruning process tree (Count: {})", count);
                self.process_tree.clear();
            }
        }

    pub fn analyze_batch(&self, batch: &[Arc<LogRecord>], _config: &AppConfig) -> Vec<LogRecord> {
        if batch.len() > 100 { self.prune_tree(); } // Occasional pruning

        batch.iter()
            .filter_map(|record| {
                match self.analyze_record(record.clone()) {
                    Ok(Some(finding)) => Some(finding),
                    _ => None,
                }
            })
            .collect()
    }

    pub fn analyze_record(&self, record: Arc<LogRecord>) -> Result<Option<LogRecord>> {
        use chrono::Local;
        use crate::extraction::TriggeredExtraction;

        let mut tagged_record = (*record).clone();

        if let Some(ref source) = tagged_record.log_source {
            tagged_record.metadata.insert("log_source".to_string(), source.clone());
        }
        
        match &self.config.active_framework {
            crate::config::ActiveFramework::AiRmf100 => {
                let violations = crate::crosswalk_ai::AiRmfCrosswalk::evaluate(&tagged_record.metadata, &self.config.ai_rmf);
                if !violations.is_empty() {
                    let primary = &violations[0];
                    tagged_record.metadata.insert("airmf_pillar".to_string(), primary.as_str().to_string());
                    tagged_record.metadata.insert("airmf_description".to_string(), primary.description().to_string());
                    tagged_record.severity = Some("High".to_string());
                    return Ok(Some(tagged_record));
                }
                Ok(None)
            },
            _ => {
                // 1. Populate/Refresh Process Tree
                let current_pid = record.metadata.get("ProcessId")
                    .or_else(|| record.metadata.get("process_id"))
                    .or_else(|| record.metadata.get("CallerProcessId"))
                    .or_else(|| record.metadata.get("ClientProcessId"))
                    .and_then(|id| {
                        if id.starts_with("0x") { u32::from_str_radix(&id[2..], 16).ok() }
                        else { id.parse::<u32>().ok() }
                    });
                
                let current_image = record.metadata.get("NewProcessName")
                    .or_else(|| record.metadata.get("process_name"))
                    .or_else(|| record.metadata.get("Image"))
                    .or_else(|| record.metadata.get("CallerProcessName"))
                    .cloned();

                let current_guid = record.metadata.get("ProcessGuid").cloned();
                if let (Some(pid), Some(image)) = (current_pid, current_image.clone()) {
                    self.process_tree.insert(pid, (image, record.parent_process_id, current_guid.clone()));
                    tagged_record.process_guid = current_guid;
                }

                // Network Telemetry Extraction (Iron Sights)
                let dest_ip = record.metadata.get("DestinationIp")
                    .or_else(|| record.metadata.get("dest_ip"))
                    .or_else(|| record.metadata.get("dest"))
                    .or_else(|| record.metadata.get("DestinationAddress"))
                    .cloned();
                let dest_port = record.metadata.get("DestinationPort")
                    .or_else(|| record.metadata.get("dest_port"))
                    .and_then(|p| p.parse::<u16>().ok());
                let protocol = record.metadata.get("Protocol")
                    .or_else(|| record.metadata.get("protocol"))
                    .cloned();

                let target_image = record.metadata.get("TargetImage")
                    .or_else(|| record.metadata.get("TargetImageName"))
                    .cloned();
                
                let granted_access = record.metadata.get("GrantedAccess")
                    .cloned();

                let relative_target = record.metadata.get("RelativeTargetName")
                    .or_else(|| record.metadata.get("ObjectName"))
                    .cloned();

                tagged_record.target_image = target_image.clone();
                tagged_record.granted_access = granted_access.clone();
                if let Some(ref ti) = target_image { tagged_record.metadata.insert("target_image".to_string(), ti.clone()); }
                if let Some(ref ga) = granted_access { tagged_record.metadata.insert("granted_access".to_string(), ga.clone()); }
                if let Some(ref rt) = relative_target { tagged_record.metadata.insert("relative_target".to_string(), rt.clone()); }

                if dest_ip.is_some() {
                    tagged_record.destination_ip = dest_ip.clone();
                    tagged_record.destination_port = dest_port;
                    tagged_record.protocol = protocol.clone();
                    
                    if let Some(ref ip) = dest_ip { tagged_record.metadata.insert("destination_ip".to_string(), ip.clone()); }
                    if let Some(p) = dest_port { tagged_record.metadata.insert("destination_port".to_string(), p.to_string()); }
                    if let Some(ref pr) = protocol { tagged_record.metadata.insert("protocol".to_string(), pr.clone()); }

                    // High-Fidelity Matching via ProcessGuid (Anti-PID-Reuse)
                    if let (Some(pid), Some(ref ev_guid)) = (current_pid, tagged_record.process_guid.as_ref()) {
                        if let Some(entry) = self.process_tree.get(&pid) {
                            let (_, _, tree_guid) = entry.value();
                            if let Some(t_guid) = tree_guid {
                                if t_guid != *ev_guid {
                                    tagged_record.outcome = Some("PidReuseMismatch".to_string());
                                }
                            }
                        }
                    }
                }

                self.correlate_wmi(&mut tagged_record);

                // 4. Lineage-Aware Heuristics (Operation Ghost Hunter)
                let chain = if let Some(pid) = current_pid {
                    self.get_lineage_chain(pid, 0)
                } else { String::new() };

                if !chain.is_empty() {
                    tagged_record.lineage_chain = Some(chain.clone());
                    tagged_record.metadata.insert("lineage_chain".to_string(), chain.clone());
                }

                let nist_match = self.matches(&tagged_record);
                let mut final_severity = nist_match.as_ref().map(|(m, _)| m.severity).unwrap_or(crate::models::SeverityLevel::Info);
                
                if let Some((ref mapping, ref match_str)) = nist_match {
                    tagged_record.metadata.insert("nist_control_id".to_string(), mapping.control_id.clone());
                    tagged_record.metadata.insert("nist_category".to_string(), mapping.category.clone());
                    tagged_record.metadata.insert("forensic_payload".to_string(), match_str.clone());
                    
                    let signal_key = format!("{}:{}", mapping.control_id, match_str);
                    let now = Local::now();
                    {
                        let mut entry = self.signal_counts.entry(signal_key.clone()).or_insert((0, now));
                        let (count, start_time) = entry.value_mut();
                        if now.signed_duration_since(*start_time).num_minutes() > 10 {
                            *count = 1;
                            *start_time = now;
                        } else {
                            *count += 1;
                        }
                    }
                }

                let cmd_lower = tagged_record.message.to_lowercase();
                let raw_lower = tagged_record.raw.to_lowercase();
                
                let current_image_lower = current_image.as_ref().map(|s| s.to_lowercase()).unwrap_or_default();
                
                if cmd_lower.contains("aegis") && (raw_lower.contains("kill") || raw_lower.contains("stop") || raw_lower.contains("delete")) {
                    final_severity = crate::models::SeverityLevel::Critical;
                    tagged_record.message = format!("☢️ CRITICAL: DIRECT ATTACK ON FORENSIC SENTINEL! Attempt to terminate/tamper with Aegis detected.");
                    tagged_record.outcome = Some("SelfProtectionTrigger".to_string());
                }

                let is_orphan = current_pid.is_some() && chain.split("->").count() <= 1 && record.parent_process_id.is_some();
                let is_verified_origin = chain.to_lowercase().contains("services.exe") 
                    || chain.to_lowercase().contains("update") 
                    || chain.to_lowercase().contains("orchestrator")
                    || chain.to_lowercase().contains("tiworker.exe")
                    || chain.to_lowercase().contains("explorer.exe")
                    || chain.to_lowercase().contains("winlogon.exe")
                    || chain.to_lowercase().contains("smss.exe");

                let mut is_trusted_lineage = is_verified_origin;
                // If we have a parent name but no chain, check if parent name is known-good
                if !is_trusted_lineage {
                    if let Some(parent_name) = record.metadata.get("ParentProcessName")
                        .or_else(|| record.metadata.get("parent_process_name")) {
                        let pn_lower = parent_name.to_lowercase();
                        if pn_lower.contains("services.exe") || pn_lower.contains("explorer.exe") || pn_lower.contains("wininit.exe") {
                            is_trusted_lineage = true;
                        }
                    }
                }

                let mut heuristic_hit = false;

                // --- 🛡️ DCSYNC HEURISTIC: Atomic TTP Detection [Event 4662] ---
                let event_id = record.metadata.get("EventID").or_else(|| record.metadata.get("event_id")).cloned().unwrap_or_default();
                if event_id == "4662" {
                    let properties = record.metadata.get("Properties").cloned().unwrap_or_default();
                    let access_mask = record.metadata.get("AccessMask").cloned().unwrap_or_default();
                    
                    // GUIDs: DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
                    let is_dcsync_guid = properties.contains("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") || 
                                         properties.contains("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");
                    
                    // Access Mask 0x100 = Control Access
                    if is_dcsync_guid && (access_mask == "0x100" || access_mask == "256") {
                        let subject_name = record.metadata.get("SubjectUserName").cloned().unwrap_or_else(|| "Unknown".to_string());
                        
                        // Non-DC Attribution Filter: DCs usually end in $
                        if !subject_name.ends_with('$') {
                            final_severity = crate::models::SeverityLevel::Critical;
                            let dcsync_msg = format!("☢️ RED ALERT: DCSYNC ATTACK DETECTED! Non-DC account '{}' is requesting sensitive directory replication (DS-Replication-Get-Changes). Possible Domain Dominance event.", subject_name);
                            tagged_record.message = dcsync_msg.clone();
                            tagged_record.metadata.insert("forensic_tag".to_string(), "DCSyncAttack".to_string());
                            tagged_record.metadata.insert("captured_message".to_string(), dcsync_msg);
                            tagged_record.metadata.insert("nist_control_id".to_string(), "SI-4 [DCSync Detector]".to_string());
                            heuristic_hit = true;
                        } else {
                            // Even if it's a machine account, if it's suspicious, we flag it as High
                            final_severity = crate::models::SeverityLevel::High;
                            tagged_record.metadata.insert("nist_control_id".to_string(), "SI-4 [Replication Audit]".to_string());
                        }
                    }
                }

                // --- 🛡️ PASS-THE-HASH HEURISTIC: T1550.002 [Event 4624 / Logon Type 9] ---
                if event_id == "4624" {
                    let logon_type = record.metadata.get("LogonType").cloned().unwrap_or_default();
                    let auth_package = record.metadata.get("AuthenticationPackageName").cloned().unwrap_or_default().to_lowercase();
                    let logon_process = record.metadata.get("LogonProcessName").cloned().unwrap_or_default().to_lowercase();
                    
                    if logon_type == "9" && (auth_package.contains("negotiate") || logon_process.contains("seclogo")) {
                        final_severity = crate::models::SeverityLevel::Critical;
                        let pth_msg = format!("☢️ CRITICAL: PASS-THE-HASH ATTACK DETECTED! Anomalous Logon Type 9 (NewCredentials) via '{}' process. Possible Mimikatz PtH token injection.", logon_process);
                        tagged_record.message = pth_msg.clone();
                        tagged_record.metadata.insert("forensic_tag".to_string(), "PassTheHash".to_string());
                        tagged_record.metadata.insert("captured_message".to_string(), pth_msg);
                        tagged_record.metadata.insert("nist_control_id".to_string(), "AC-3 [Identity Thief]".to_string());
                        heuristic_hit = true;
                    }
                }

                // --- 🛡️ KERNEL INVADER HEURISTIC: BYOVD Prevention [SI-4] ---
                // Monitoring Service Creation (7045/4697) and Driver Load (Sysmon 6)
                if event_id == "7045" || event_id == "4697" || event_id == "6" {
                    let image_path = if event_id == "6" {
                        record.metadata.get("ImageLoaded").cloned().unwrap_or_default().to_lowercase()
                    } else {
                        record.metadata.get("ImagePath").cloned().unwrap_or_default().to_lowercase()
                    };

                    if !image_path.is_empty() {
                        let is_malicious_path = image_path.contains("\\temp\\") || 
                                               image_path.contains("\\users\\") || 
                                               image_path.contains("\\programdata\\") || 
                                               image_path.contains("\\perflogs\\") ||
                                               image_path.contains("\\appdata\\");

                        if is_malicious_path && image_path.ends_with(".sys") {
                            final_severity = crate::models::SeverityLevel::Critical;
                            let kernel_msg = format!("☢️ CRITICAL: KERNEL INTEGRITY VIOLATION! Malicious driver load detected from non-standard directory: '{}'. Possible BYOVD attack.", image_path);
                            tagged_record.message = kernel_msg.clone();
                            tagged_record.metadata.insert("forensic_tag".to_string(), "KernelInvader".to_string());
                            tagged_record.metadata.insert("captured_message".to_string(), kernel_msg);
                            tagged_record.metadata.insert("nist_control_id".to_string(), "SI-4 [Kernel Integrity Violation]".to_string());
                            heuristic_hit = true;
                        }
                    }
                }

                // --- 🛡️ ZERO-TRUST PROXY ENFORCEMENT: LOLBAS / Signed Binary Abuse [T1218] ---

                let is_shell_or_proxy = current_image_lower.contains("cmd.exe") ||
                                       current_image_lower.contains("powershell.exe") ||
                                       current_image_lower.contains("pwsh.exe") ||
                                       current_image_lower.contains("rundll32.exe") || 
                                       current_image_lower.contains("regsvr32.exe") || 
                                       current_image_lower.contains("msiexec.exe") ||
                                       current_image_lower.contains("certutil.exe") ||
                                       raw_lower.contains("rundll32.exe") ||
                                       raw_lower.contains("regsvr32.exe") ||
                                       raw_lower.contains("msiexec.exe") ||
                                       raw_lower.contains("certutil.exe");
                
                if is_shell_or_proxy {
                    // Lineage Invariant: Shells/Proxies spawned from unknown/orphaned/untrusted lineage are CRITICAL
                    if is_orphan && !is_trusted_lineage {
                        final_severity = crate::models::SeverityLevel::Critical;
                        let lineage_msg = format!("☢️ CRITICAL: LINEAGE INVARIANT VIOLATION! {} spawned from an untrusted or unknown parent (Orphan). Possible T1218 or T1059.", current_image_lower);
                        tagged_record.message = lineage_msg.clone();
                        tagged_record.metadata.insert("forensic_tag".to_string(), "LineageViolation".to_string());
                        tagged_record.metadata.insert("captured_message".to_string(), lineage_msg);
                        tagged_record.metadata.insert("nist_control_id".to_string(), "SI-4 [Ghost Hunter]".to_string());
                        heuristic_hit = true;
                    }
                }

                let is_proxy_bin = is_shell_or_proxy && (current_image_lower.contains("rundll32") || current_image_lower.contains("regsvr32") || current_image_lower.contains("msiexec") || current_image_lower.contains("certutil"));
                
                if is_proxy_bin {
                    let mut proxy_hit = false;
                    let mut proxy_msg = String::new();
                    
                    let forbidden_exports = ["minidump", "control_rundll", "fileprotocolhandler", "#24", "openurl", "shell_run", "runas"];
                    let whitelist = ["printui.dll", "sysdm.cpl", "advpack.dll", "setupapi.dll", "appresolver.dll"];

                    let is_forbidden = forbidden_exports.iter().any(|e| raw_lower.contains(e));
                    let is_whitelisted = whitelist.iter().any(|w| raw_lower.contains(w));
                    
                    // Geography Filter: Check for non-standard path loading (outside System32/Program Files/SysWOW64)
                    let has_outside_path = (raw_lower.contains(":\\") || raw_lower.contains("\\\\")) && 
                                           !(raw_lower.contains("system32") || raw_lower.contains("program files") || raw_lower.contains("syswow64"));

                    if is_forbidden {
                        proxy_hit = true;
                        final_severity = crate::models::SeverityLevel::Critical;
                        proxy_msg = format!("☢️ CRITICAL: WEAPONIZED PROXY EXECUTION! Forbidden export detected in {} context. Automatic Red Alert.", current_image_lower);
                    } else if has_outside_path {
                        proxy_hit = true;
                        final_severity = crate::models::SeverityLevel::High;
                        proxy_msg = format!("☢️ HIGH: ZERO-TRUST VIOLATION! {} is loading a binary from a non-standard/unprotected directory. Escalating for forensic review.", current_image_lower);
                    } else if !is_whitelisted {
                        proxy_hit = true;
                        final_severity = crate::models::SeverityLevel::Medium;
                        proxy_msg = format!("🟡 WARNING: UNKNOWN PROXY EXECUTION! {} is running with a non-whitelisted module. Zero-Trust policy enforcement applied.", current_image_lower);
                    }

                    if proxy_hit {
                        tagged_record.message = proxy_msg.clone();
                        tagged_record.metadata.insert("forensic_tag".to_string(), "ProxyExecution".to_string());
                        tagged_record.metadata.insert("captured_message".to_string(), proxy_msg);
                        tagged_record.metadata.insert("nist_control_id".to_string(), "SI-4 [Zero-Trust Proxy]".to_string());
                        heuristic_hit = true;
                    }
                }

                // --- 🧬 COM HIJACKING HEURISTIC: T1546.015 [Registry Persistence] ---
                if (raw_lower.contains("inprocserver32") || raw_lower.contains("localserver32")) && 
                   (raw_lower.contains("software\\classes\\clsid") || raw_lower.contains("hkcu")) {
                    
                    let has_outside_path = (raw_lower.contains(":\\") || raw_lower.contains("\\\\")) && 
                                           !(raw_lower.contains("system32") || raw_lower.contains("program files") || raw_lower.contains("syswow64"));
                    
                    if has_outside_path {
                        final_severity = crate::models::SeverityLevel::Critical;
                        let com_msg = format!("☢️ CRITICAL: COM HIJACKING DETECTED! Registry persistence established via InprocServer32/LocalServer32 pointing to a non-system path. Possible T1546.015.");
                        tagged_record.message = com_msg.clone();
                        tagged_record.metadata.insert("forensic_tag".to_string(), "COMHijacking".to_string());
                        tagged_record.metadata.insert("captured_message".to_string(), com_msg);
                        tagged_record.metadata.insert("nist_control_id".to_string(), "SI-4 [Persistence Trap]".to_string());
                        heuristic_hit = true;
                    }
                }

                if is_orphan && (final_severity >= crate::models::SeverityLevel::High || nist_match.is_none()) && !heuristic_hit {
                    if tagged_record.destination_ip.is_some() {
                        final_severity = crate::models::SeverityLevel::Critical;
                        let pivot_msg = format!("☢️ CRITICAL: PIVOT ATTEMPT DETECTED! Orphan process {} is initiating network traffic to {}:{}.", 
                            current_image.as_ref().unwrap_or(&"Unknown".to_string()),
                            tagged_record.destination_ip.as_ref().unwrap(),
                            tagged_record.destination_port.unwrap_or(0));
                        tagged_record.message = pivot_msg.clone();
                        tagged_record.metadata.insert("forensic_tag".to_string(), "PivotAttempt".to_string());
                        tagged_record.metadata.insert("captured_message".to_string(), pivot_msg);
                        tagged_record.metadata.insert("nist_control_id".to_string(), "SI-4 [Iron Sights]".to_string());
                        heuristic_hit = true;
                    } else if nist_match.is_some() {
                        final_severity = crate::models::SeverityLevel::Critical;
                        let orphan_msg = format!("☢️ CRITICAL: ORPHAN PROCESS DETECTED! No verifiable parent lineage for high-privilege activity. Possible Process Hollowing.");
                        tagged_record.message = orphan_msg.clone();
                        tagged_record.metadata.insert("forensic_tag".to_string(), "OrphanProcess".to_string());
                        tagged_record.metadata.insert("captured_message".to_string(), orphan_msg);
                        tagged_record.metadata.insert("nist_control_id".to_string(), "SI-4 [Ghost Hunter]".to_string());
                        heuristic_hit = true;
                    }
                } else {
                    // Note: Heuristics for LSASS, Registry, and LOLBAS have been externalized to intel/nist_mappings.json
                    // to eliminate the 'Whack-a-Mole' recompilation cycle.
                }

                // 6. Operation Black Box: Point-of-Detection Extraction Trigger
                if final_severity == crate::models::SeverityLevel::Critical {
                    let tag = tagged_record.metadata.get("forensic_tag").map(|s| s.as_str()).unwrap_or("CriticalIncident");
                    let pid = current_pid;
                    
                    if let Ok(vault_path) = TriggeredExtraction::capture_volatile_evidence(tag, pid) {
                        tagged_record.evidence_vault = Some(vault_path.clone());
                        tagged_record.metadata.insert("evidence_vault".to_string(), vault_path);
                    }
                }

                // 7. Verified Origin Suppression (NIST AU-12 Low-Noise)
                if is_verified_origin && !heuristic_hit && nist_match.is_none() {
                    if final_severity >= crate::models::SeverityLevel::High {
                        final_severity = crate::models::SeverityLevel::Info;
                        tagged_record.outcome = Some("VerifiedOrigin".to_string());
                        tagged_record.message = format!("[Lineage Verified] System maintenance/install activity confirmed: {}", chain);
                    }
                }

                // 8. High-Volume Noise Suppression (Anti-Flood)
                // Only suppress if it's NOT a heuristic hit and NOT already Critical
                if !heuristic_hit && final_severity < crate::models::SeverityLevel::Critical {
                    if let Some((_, match_str)) = nist_match.as_ref() {
                        let mapping = &nist_match.as_ref().unwrap().0;
                        let signal_key = format!("{}:{}", mapping.control_id, match_str);
                        if let Some(entry) = self.signal_counts.get(&signal_key) {
                            let (count, _) = entry.value();
                            if *count > 500 {
                                final_severity = crate::models::SeverityLevel::Medium;
                                tagged_record.outcome = Some("HighVolumeNoise".to_string());
                                tagged_record.metadata.insert("noise_suppression".to_string(), "true".to_string());
                            }
                        }
                    }
                }

                if nist_match.is_some() || heuristic_hit || tagged_record.outcome.is_some() {
                    // Fill in defaults for heuristics if missing nist info
                    if tagged_record.metadata.get("nist_control_id").is_none() {
                        tagged_record.metadata.insert("nist_control_id".to_string(), "SI-4 [Windows Integrity]".to_string());
                        tagged_record.metadata.insert("nist_category".to_string(), "System and Information Integrity".to_string());
                    }
                    
                    // Ensure message is synced for the report
                    if tagged_record.metadata.get("captured_message").is_none() {
                        tagged_record.metadata.insert("captured_message".to_string(), tagged_record.message.clone());
                    }
                    
                    tagged_record.severity = Some(format!("{:?}", final_severity));
                    Ok(Some(tagged_record))
                } else {
                    Ok(None)
                }
            }
        }
    }

        pub fn correlate_wmi(&self, record: &mut LogRecord) {
            let event_id = record.metadata.get("EventID")
                .or_else(|| record.metadata.get("event_id"))
                .cloned()
                .unwrap_or_default();
            
            match event_id.as_str() {
                "19" => {
                    if let Some(name) = record.metadata.get("Name").or_else(|| record.metadata.get("name")) {
                        self.wmi_buffer.insert(format!("filter:{}", name.to_lowercase()), WmiState::Filter);
                    }
                },
                "20" => {
                    if let Some(name) = record.metadata.get("Name").or_else(|| record.metadata.get("name")) {
                        self.wmi_buffer.insert(format!("consumer:{}", name.to_lowercase()), WmiState::Consumer);
                    }
                },
                "21" | "5857" | "5858" => {
                    let consumer = record.metadata.get("Consumer").or_else(|| record.metadata.get("consumer")).cloned().unwrap_or_default().to_lowercase();
                    let filter = record.metadata.get("Filter").or_else(|| record.metadata.get("filter")).cloned().unwrap_or_default().to_lowercase();
                    
                    if self.wmi_buffer.contains_key(&format!("consumer:{}", consumer)) && self.wmi_buffer.contains_key(&format!("filter:{}", filter)) {
                        record.severity = Some("Critical".to_string());
                        record.message = format!("☢️ CRITICAL: Multi-Event WMI Persistence Chain Correlated! Consumer: {}, Filter: {}", consumer, filter);
                        record.metadata.insert("correlation_type".to_string(), "WMI_Persistence_Binding_FULL".to_string());
                        record.metadata.insert("nist_control_id".to_string(), "SI-4".to_string());
                    }
                },
                _ => {}
            }
        }

        pub fn matches(&self, record: &LogRecord) -> Option<(&ControlMapping, String)> {
            if let Some(tagged_id) = record.metadata.get("nist_control_id") {
                if record.metadata.contains_key("correlation_type") {
                    if let Some(mapping) = self.mappings.iter().find(|m| m.control_id == *tagged_id) {
                        return Some((mapping, "Stateful Correlation".to_string()));
                    }
                }
            }

            for mapping in &self.mappings {
                if mapping.control_id == "AU-3" { continue; }
                if let Some(ref re) = mapping.pattern {
                    let target_text = match mapping.target_field.as_deref() {
                        Some("raw") => &record.raw,
                        _ => &record.message,
                    };
                    if let Some(m) = re.find(target_text) {
                        return Some((mapping, m.as_str().to_string()));
                    }
                }
            }

            if !record.redactions.is_empty() {
                return self.mappings.iter().find(|m| m.control_id == "AU-3").map(|m| (m, "Privacy Redaction".to_string()));
            }

            None
        }

        pub fn lookup_control(&self, control_id: &str) -> Option<&ControlMapping> {
            self.mappings.iter().find(|m| m.control_id == control_id || m.control_id.starts_with(control_id))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::models::LogRecord;

        #[test]
        fn test_ghost_hunter_verified_origin() {
            let config = AppConfig::default_config();
            let engine = NistEngine::new(config.clone()).unwrap();
            
            // 1. Simulate Parent: UpdateOrchestrator (PID 1000)
            let mut parent_record = LogRecord {
                message: "Process Created: UpdateOrchestrator.exe".to_string(),
                ..Default::default()
            };
            parent_record.metadata.insert("ProcessId".to_string(), "1000".to_string());
            parent_record.metadata.insert("NewProcessName".to_string(), "C:\\Windows\\System32\\UpdateOrchestrator.exe".to_string());
            
            // 2. Simulate Child: wevtutil.exe (PID 2000) spawned by 1000
            let mut child_record = LogRecord {
                message: "wevtutil.exe cl Security".to_string(),
                parent_process_id: Some(1000),
                ..Default::default()
            };
            child_record.metadata.insert("ProcessId".to_string(), "2000".to_string());
            child_record.metadata.insert("NewProcessName".to_string(), "wevtutil.exe".to_string());
            child_record.raw = "wevtutil.exe cl Security".to_string();
            
            let batch = vec![Arc::new(parent_record), Arc::new(child_record)];
            let results = engine.analyze_batch(&batch, &config);
            
            // The child record (wevtutil) should be suppressed to INFO because its origin is verified
            let result_child = results.iter().find(|r| r.metadata.get("ProcessId").map(|s| s.as_str()) == Some("2000")).unwrap();
            assert_eq!(result_child.severity.as_ref().unwrap(), "Info");
            assert!(result_child.outcome.as_ref().unwrap().contains("VerifiedOrigin"));
        }

        #[test]
        fn test_ghost_hunter_orphan_escalation() {
            let config = AppConfig::default_config();
            let engine = NistEngine::new(config.clone()).unwrap();
            
            // Simulate an Orphan: mimikatz.exe (PID 3000) with a parent PID that DOES NOT EXIST in our tree
            let mut orphan_record = LogRecord {
                message: "mimikatz.exe privilege::debug".to_string(),
                parent_process_id: Some(9999), // Non-existent parent
                ..Default::default()
            };
            orphan_record.metadata.insert("ProcessId".to_string(), "3000".to_string());
            orphan_record.metadata.insert("NewProcessName".to_string(), "mimikatz.exe".to_string());
            orphan_record.raw = "mimikatz.exe privilege::debug".to_string();
            
            let batch = vec![Arc::new(orphan_record)];
            let results = engine.analyze_batch(&batch, &config);
            
            let result_orphan = results.get(0).unwrap();
            // Should be escalated to Critical because it's an orphan malicious-looking process
            assert_eq!(result_orphan.severity.as_ref().unwrap(), "Critical");
            assert!(result_orphan.message.contains("ORPHAN PROCESS"));
        }

        #[test]
        fn test_pass_the_hash_detection() {
            let config = AppConfig::default_config();
            let engine = NistEngine::new(config.clone()).unwrap();
            
            // Simulate Event 4624, Logon Type 9, seclogo process
            let mut pth_record = LogRecord {
                message: "An account was successfully logged on.".to_string(),
                ..Default::default()
            };
            pth_record.metadata.insert("EventID".to_string(), "4624".to_string());
            pth_record.metadata.insert("LogonType".to_string(), "9".to_string());
            pth_record.metadata.insert("LogonProcessName".to_string(), "seclogo".to_string());
            pth_record.metadata.insert("AuthenticationPackageName".to_string(), "Negotiate".to_string());
            
            let batch = vec![Arc::new(pth_record)];
            let results = engine.analyze_batch(&batch, &config);
            
            let result_pth = results.get(0).unwrap();
            assert_eq!(result_pth.severity.as_ref().unwrap(), "Critical");
            assert!(result_pth.message.contains("PASS-THE-HASH"));
            assert!(result_pth.metadata.get("forensic_tag").unwrap() == "PassTheHash");
        }
    }
}
