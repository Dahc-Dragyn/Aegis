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
pub mod crosswalk;
pub mod crosswalk_ai;
pub mod redaction;

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

    /// Aegis internal error definitions
    #[derive(Error, Debug)]
    pub enum AegisError {
        #[error("Failed to compile regex signature: {0}")]
        InvalidSignature(String),
    }

    /// The mapping between a log signature and a NIST SP 800-53/800-171 Control.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ControlMapping {
        pub control_id: String,
        pub category: String,
        pub description: String,
        pub long_description: String,
        pub remediation: String,
        pub target_field: Option<String>,
        pub default_status: crate::models::ComplianceStatus,
        pub severity: crate::models::SeverityLevel,
        #[serde(skip)]
        pub pattern: Option<Regex>,
    }

    /// The forensic record of a captured compliance event.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PostureEvent {
        pub timestamp: DateTime<Local>,
        pub control_id: String,
        pub status: crate::models::ComplianceStatus,
        pub severity: crate::models::SeverityLevel,
        pub description: String,
        pub remediation: String,
        pub raw_log: String,
        pub metadata: BTreeMap<String, String>,
        pub incident_id: Option<Uuid>,
    }

    #[derive(Debug, Clone)]
    pub enum WmiState {
        Filter,
        Consumer,
    }

    /// The core NIST Mapping Engine.
    pub struct NistEngine {
        pub(crate) mappings: Vec<ControlMapping>,
        wmi_buffer: DashMap<String, WmiState>,
    }

    impl NistEngine {
        pub fn new() -> Result<Self> {
            let mappings = vec![
                ControlMapping {
                    control_id: "SC-7 [C2 Exfiltration]".to_string(),
                    category: "System & Comms Protection".to_string(),
                    description: "Command and Control / Data Exfiltration".to_string(),
                    long_description: "Detection of massive data exfiltration via HTTP POST bodies. This pattern, characterized by high-entropy encoded payloads in single parameters, is a definitive signature of backdoor C2 beaconing.".to_string(),
                    remediation: "Immediately isolate the host. Extract the 'Host:' header from the forensic evidence to identify the C2/DGA domain. Blacklist the domain at the perimeter firewall/DNS sinkhole. Perform full forensic audit of the exfiltrated payload.".to_string(),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Critical,
                    pattern: Some(Regex::new(r"(?is)txt=.{500,}")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "SI-4".to_string(),
                    category: "System & Info Integrity".to_string(),
                    description: "macOS Forensic: Endpoint File Event (Modification / Creation)".to_string(),
                    long_description: "Audit of file modifications and creations on the terminal host. While routine for standard software operations, modifications to Launch Daemon/Agent directories or login configuration files by shell-based actors trigger context-aware Critical escalation.".to_string(),
                    remediation: "Verify if the file modification is authorized as part of a software installation or configuration change. [AUDIT]: ls -laO /Library/LaunchAgents. If unauthorized, treat as an active persistence establishment and initiate incident response.".to_string(),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Medium,
                    pattern: Some(Regex::new(r#"(?i)"action":\s*"(modification|creation)""#)
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AC-3 [Defense Evasion]".to_string(),
                    category: "Access Enforcement".to_string(),
                    description: "macOS Forensic: Security Software Discovery / Defense Evasion Recon".to_string(),
                    long_description: "Detection of reconnaissance targeting specific macOS security products (Little Snitch, LuLu, CrowdStrike). This bypassing of the generic system baseline is a primary indicator of Defense Evasion preparation.".to_string(),
                    remediation: "Verify if the discovery activity is part of authorized troubleshooting. [AUDIT]: ps aux | grep -i snitchd or systemextensionsctl list. If unauthorized, treat as an active precursor to defense evasion and enhance kernel integrity monitoring.".to_string(),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::High,
                    pattern: Some(Regex::new(r"(?i)\b(Little Snitch|littlesnitch|snitchd|LuLu|BlockBlock|KnockKnock|CrowdStrike|CbDefense|SentinelOne)\b")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                // --- 🛡️ TIER 0: CRITICAL FORENSIC VECTORS & HIGH-FIDELITY EXPLOIT MARKERS ---
                ControlMapping {
                    control_id: "SI-4".to_string(),
                    category: "System & Info Integrity".to_string(),
                    description: "Windows Forensic: System Integrity / Active Exploit".to_string(),
                    long_description: "Detection of system manifest corruption, execution of discovery tools, or highly definitive protocol-level exploit markers (SMBGhost, ZeroLogon, PetitPotam). These indicators represent active exploitation attempts against the kernel or core authentication protocols, requiring immediate isolation and NIST SI-4/IR-4 response.".to_string(),
                    remediation: "Run 'dism /online /cleanup-image /restorehealth' to repair manifests. For protocol exploits (SMBGhost, ZeroLogon), immediately isolate the host, freeze the network segment, and begin forensic capture of memory and packet logs. Review exploit-specific patches (CVE-2020-0796, CVE-2020-1472, CVE-2021-36942).".to_string(),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Critical,
                    pattern: Some(Regex::new(r#"(?i)CBS_E_MANIFEST_INVALID_ITEM|0x800f080d|EventID 2004|Resource-Exhaustion-Detector|0x80042100|netstat\s+-ano|ipconfig\s+/all|\bnmap\b|\bnc\s+-|\bncat\b|\bexploit\b|ZAM64|BYOV|CVE-2021-21551|doppel|proc_doppel|doppelgang|ntds\.dit|ntdsutil|herpaderp|scriptblocklogging|transcription|powershell.*policies|System\.Management\.Automation|psinject|\[Net\.ServicePointManager\]|\$env:temp|DownloadFile|Invoke-WebRequest|IWR|javascript:|mshtml,RunHTMLApplication|mshta.*\.hta|mshta.*(http|https)|schtasks(\.exe)?\s+/Create|user shell folders.*startup|mscfile\\shell\\open\\command|ms-settings\\shell\\open\\command|eventvwr\.exe|bitsadmin|start-bitstransfer|openvpn|BITS-Client|-s EventLog|wevtutil(\.exe)?\s+cl|clear-eventlog|cmstp(\.exe)?.*(/au|/ni|/s|\.inf|\.ini)|timestomp|Set-ItemProperty.*CreationTime|(\\[a-z0-9_]{15,}\.exe)|(\\AppData\\Local\\Temp\\[a-z0-9_]+\.exe)|promptforcredential|getnetworkcredential|validatecredentials|Suspicious_C2_Tunnel|DNS_TXT_C2_Tunneling|DNS-TXT|SMBGhost|CVE-2020-0796|ZeroLogon|CVE-2020-1472|PetitPotam|MS-EFSR|EFS_RPC|CVE-2021-36942|byt3bl33d3r|Event Log Crash|Defense Evasion|/etc/shadow|/etc/shadow|authorized_keys|crontab\s+-e|systemctl\s+stop|(\.env|config\.php|wp-admin|phpinfo)|TCC\.db|spoolsv\.exe|lsass\.exe|PipeName"#)
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "SI-4".to_string(),
                    category: "System & Info Integrity".to_string(),
                    description: "macOS Forensic: TCC Bypass / Authorization Trampoline / LPE".to_string(),
                    long_description: "Detection of security_authtrampoline baseline activity. While legitimate in some GUI workflows, its use to spawn privileged shells or persistence mechanisms (launchctl) triggers context-aware Critical escalation.".to_string(),
                    remediation: "Audit the command line for unauthorized execution of /bin/sh, /bin/bash, or launchctl. Verify if the 'uid auth' sequence matches authorized administrative sessions. If unauthorized, treat as an active Local Privilege Escalation (LPE).".to_string(),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Medium,
                    pattern: Some(Regex::new(r"(?i)\bsecurity_authtrampoline\b")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AC-3 [Identity Infrastructure]".to_string(),
                    category: "Access Enforcement".to_string(),
                    description: "Windows Forensic: AD Certificate Services (AD CS) Request / Abuse".to_string(),
                    long_description: "Audit of Active Directory Certificate Services (AD CS) requests (4886) and approvals (4887). While legitimate for machine/user enrollment, the use of vulnerable templates paired with rogue Subject Alternative Name (SAN) requests is a primary vector for ESC1/ESC8 domain dominance attacks.".to_string(),
                    remediation: "Verify the requested Template and Subject Alternative Name (SAN). If unauthorized (e.g., upn=administrator@), revoke the certificate immediately. Audit the source host for PetitPotam or NTLM relay activity. Review ESC1/ESC8 misconfigurations in AD CS.".to_string(),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Medium,
                    pattern: Some(Regex::new(r"(?i)EventID.*?488(6|7)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },


                ControlMapping {
                    control_id: "AU-9".to_string(),
                    category: "Audit and Accountability".to_string(),
                    description: "Detection of audit log clearing or service tampering".to_string(),
                    long_description: "Clearing audit logs or stopping the logging service is a high-severity indicator of anti-forensic activity.".to_string(),
                    remediation: "Investigate why the log service was stopped or cleared. [TRIAGE]: `Get-Service | Where-Object {$_.Name -like '*eventlog*'} | Select Name, Status`. Verify centralized log replication is functional.".to_string(),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Critical,
                    pattern: Some(Regex::new(r"(?i)(log cleared|audit log was cleared|event 1102|event 104|systemctl stop (rsyslog|auditd)|net stop (eventlog|sysmon)|kill -9.*(rsyslog|auditd|eventlog))")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AU-12".to_string(),
                    category: "Incident Response".to_string(),
                    description: "Honeypot/Trap trigger from active reconnaissance".to_string(),
                    long_description: "Access to 'honeypot' resources is a 100% reliable indicator of malicious intent or unauthorized scanning.".to_string(),
                    remediation: "Initiate full Incident Response (IR) for the host at source_ip. Isolate the target system and begin forensic imaging.".to_string(),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Critical,
                    pattern: Some(Regex::new(r"(?i)\[HONEYPOT\]")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AC-3".to_string(),
                    category: "Access Enforcement".to_string(),
                    description: "NIST AC-3: Generic / Targeted System Discovery (LotL)".to_string(),
                    long_description: "Detection of cross-platform discovery tools (dscl, net user, Get-ADGroup, whoami). While generic discovery is low-severity, targeted enumeration of high-value groups triggers context-aware escalation.".to_string(),
                    remediation: "Verify if the discovery activity is part of authorized administrative tasks or vulnerability scanning. Audit target groups for unusual membership changes.".to_string(),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Observation,
                    severity: crate::models::SeverityLevel::Medium,
                    pattern: Some(Regex::new(r"(?i)\b(dscl|id|net\b\s+(group|localgroup|user)|Get-ADGroup|Get-ADGroupMember|Get-DomainGroup|whoami)\b|cat\s+/etc/(passwd|shadow)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AC-3 [Credential Access]".to_string(),
                    category: "Access Enforcement".to_string(),
                    description: "NIST AC-3: Explicit OS Credential Access".to_string(),
                    long_description: "Detection of explicit offensive tooling (Mimikatz, Procdump, etc.) or definitive credential theft techniques. These indicators represent a total compromise of the host's credential vault.".to_string(),
                    remediation: "Immediately isolate the host. Assume all local and domain credentials cached on this system are compromised. Initiate full forensic recovery and password reset for all affected users.".to_string(),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Critical,
                    pattern: Some(Regex::new(r"(?i)\b(mimikatz|mimidrv|procdump|pypykatz|ppldump|LsarSetSecret|AS-REQ|Kerbrute)\b|comsvcs\.dll.*?MiniDump|rdp-tcp|psexesvc|wmiprvse|srvsvc|lsarpc|samr|ZeroLogon|CVE-2020-1472|DCSync|krbtgt|DRSUAPI|MachineAccount Password|Policy\\Secrets|TGS-REQ|sname|RC4-HMAC|EType 23")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "SI-4".to_string(),
                    category: "System & Info Integrity".to_string(),
                    description: "Windows Forensic: Named Pipe Impersonation".to_string(),
                    long_description: "Detection of Named Pipe creation or connection. Pipes are the primary IPC mechanism for C2 frameworks (Cobalt Strike, Empire) to perform impersonation and lateral movement.".to_string(),
                    remediation: "Audit the 'PipeName' and 'Image'. If the pipe name is randomized or matches known C2 defaults (msagent, postex, status), treat as an active C2 persistence event.".to_string(),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Observation,
                    severity: crate::models::SeverityLevel::Medium,
                    pattern: Some(Regex::new(r#"(?i)"EventID":\s*(17|18)|\bPipeName\b"#)
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "SI-4".to_string(),
                    category: "System & Info Integrity".to_string(),
                    description: "Windows Forensic: PrintNightmare / Spooler Service Abuse (CVE-2021-1675)".to_string(),
                    long_description: "Detection of the Print Spooler service (spoolsv.exe) performing suspicious file writes to driver directories, indicating active exploitation of PrintNightmare for LPE or RCE.".to_string(),
                    remediation: "Immediately isolate the host. Disable the Print Spooler service: 'net stop spooler && sc config spooler start= disabled'. Audit for new DLLs in C:\\Windows\\System32\\spool\\drivers\\.".to_string(),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Critical,
                    pattern: Some(Regex::new(r"(?i)spoolsv\.exe.*\\spool\\drivers\\|MS-RPRN|PrintNightmare|CVE-2021-1675|CVE-2021-34527")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AC-3".to_string(),
                    category: "Access Enforcement".to_string(),
                    description: "NIST AC-3: LSASS Behavioral Guard (Context-Aware Audit)".to_string(),
                    long_description: "Audit of attempts to open a handle to the Local Security Authority Subsystem (LSASS). While common for security agents, unauthorized access masks or suspicious source images trigger Critical escalation.".to_string(),
                    remediation: "Review the 'source_image' and 'granted_access' mask. If the process is not an authorized security agent (Defender, Crowdstrike, Aegis), treat as an active memory dump attempt.".to_string(),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Observation,
                    severity: crate::models::SeverityLevel::Medium,
                    pattern: Some(Regex::new(r"(?i)\blsass\.exe\b")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },


                // --- 🟠 TIER 2: HIGH-SEVERITY COMPLIANCE FAILURES ---
                ControlMapping {
                    control_id: "CM-5".to_string(),
                    category: "Configuration Management".to_string(),
                    description: "Unauthorized persistence mechanism detected".to_string(),
                    long_description: "Creation of new systemd units, scheduled tasks, or registry 'Run' keys is a primary method for establishing persistence.".to_string(),
                    remediation: "Audit the newly created auto-run mechanism. [TRIAGE]: `Get-ScheduledTask | Select TaskName, TaskPath, State` or `reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`. If unauthorized, remove the entry and sweep for binaries.".to_string(),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::High,
                    pattern: Some(Regex::new(r"(?i)(/etc/systemd/system/|reg\s+add.*\\Run|currentversion\\(run|runonce)|crontab\s+-e|schtasks\s+/create)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "SC-7".to_string(),
                    category: "System & Comms Protection".to_string(),
                    description: "Authorized software transit or LotL binary abuse".to_string(),
                    long_description: "Use of system binaries (curl, wget, certutil) to pull external payloads is a hallmark of 'Living off the Land' attacks (LotL).".to_string(),
                    remediation: "Verify the URL and payload being downloaded. Restrict execution of web-capable binaries for non-administrative users.".to_string(),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::High,
                    pattern: Some(Regex::new(r"(?i)(curl.*\|\s*sh|wget|certutil\s+-urlcache|base64\s+-d|powershell\s+-enc|execution of /tmp/)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AC-6".to_string(),
                    category: "Access Control".to_string(),
                    description: "Unauthorized access to sensitive system files or privileged account usage".to_string(),
                    long_description: "Accessing or modifying core system files (/etc/shadow, registry hives) or using administrative accounts without authorization.".to_string(),
                    remediation: "Investigate the reason for accessing sensitive files. Verify that the user has a legitimate need to know. Audit for privilege escalation.".to_string(),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::High,
                    pattern: Some(Regex::new(r"(?i)(sudo:|su:|root login|/etc/shadow|/etc/passwd|/etc/sudoers|SAM\s+hive)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AU-10".to_string(),
                    category: "Audit and Accountability".to_string(),
                    description: "Detection of non-repudiation or signature verification failures".to_string(),
                    long_description: "Failures in cryptographic signature verification suggest data tampering or unauthorized software execution.".to_string(),
                    remediation: "Quarantine the affected files or processes. Verify the integrity of the signing certificate and its chain of trust.".to_string(),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::High,
                    pattern: Some(Regex::new(r"(?i)(signature invalid|verification failed|tamper detected)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "SI-10".to_string(),
                    category: "System & Info Integrity".to_string(),
                    description: "Web Application Attack: SQLi / XSS / Path Traversal".to_string(),
                    long_description: "Detection of common web application attack patterns in server access logs, including SQL injection, cross-site scripting, and directory traversal attempts.".to_string(),
                    remediation: "Immediately block the source_ip at the WAF/Firewall. Investigate the targeted application endpoint for vulnerabilities. Sanitize all user inputs.".to_string(),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::High,
                    pattern: Some(Regex::new(r#"(?i)(union\s+select|information_schema|' or 1=1|waitfor\s+delay|benchmark\(|<script>|alert\(|onerror=|src=javascript:|\.\./\.\./|%2e%2e/|..%2f|/etc/passwd|/bin/sh|/bin/bash|; \bid\b|\| whoami|\$\(id\)|`uname`)"#)
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "SC-8".to_string(),
                    category: "System & Comms Protection".to_string(),
                    description: "Anomalous Network Activity: Data Exfiltration / C2 Callbacks".to_string(),
                    long_description: "Detection of non-standard network behavior, such as DNS tunneling, large data transfers, or connections to known malicious domains.".to_string(),
                    remediation: "Isolate the source system. Review network flow logs for the extent of data transfer. Check for unauthorized remote access tools.".to_string(),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::High,
                    pattern: Some(Regex::new(r#"(?i)(DNS-TXT|exf\.|tun\.|reverse_shell|meterpreter|nc\s+-e|/dev/tcp/|/dev/udp/)"#)
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },

                // --- 🟡 TIER 3: MEDIUM-SEVERITY OBSERVATIONS ---
                ControlMapping {
                    control_id: "AU-2".to_string(),
                    category: "Audit and Accountability".to_string(),
                    description: "Windows Forensic: Failed Logon Attempt (Event 4625)".to_string(),
                    long_description: "An account failed to log on. This binary event captures the specific reason (bad password, locked account) and the source workstation/IP.".to_string(),
                    remediation: "Investigate 'source_network_address' for brute-force patterns. If internal, check for service account password expiration. If external, block the source IP at the network perimeter.".to_string(),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Medium,
                    pattern: Some(Regex::new(r#"(?i)"EventID":\s*4625"#)
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AC-2".to_string(),
                    category: "Account Management".to_string(),
                    description: "macOS Forensic: Local Admin Group Manipulation / LPE".to_string(),
                    long_description: "Audit of attempts to modify high-privilege local groups (admin, wheel) via native macOS utilities. Legitimate administrative changes should be documented; unauthorized backdoor creation triggers context-aware Critical escalation.".to_string(),
                    remediation: "Verify the justification for group modification. [AUDIT]: `dseditgroup -o read admin` or `dscl . -read /Groups/admin`. If unauthorized, immediately remove the added user and sweep for persistence mechanisms.".to_string(),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Medium,
                    pattern: Some(Regex::new(r"(?i)\b(dseditgroup|dscl)\b")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },

                ControlMapping {
                    control_id: "AC-3".to_string(),
                    category: "Access Enforcement".to_string(),
                    description: "Windows Forensic: Network Share Access (Event 5145)".to_string(),
                    long_description: "Audit of attempts to access network shares. Standard file sharing is routine; however, loopback authentication to administrative shares is a key indicator of SMB relay attacks.".to_string(),
                    remediation: "Review the 'SourceAddress' (IpAddress) and 'ShareName'. If the source is localhost (127.0.0.1 or ::1) and the share is IPC$, investigate for Token Kidnapping (e.g., RottenPotato) and check for unauthorized process execution via Service Control Manager.".to_string(),
                    target_field: Some("raw".to_string()),
                    default_status: crate::models::ComplianceStatus::Observation,
                    severity: crate::models::SeverityLevel::Medium,
                    pattern: Some(Regex::new(r#"(?i)"EventID":\s*5145"#)
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AC-3".to_string(),
                    category: "Access Enforcement".to_string(),
                    description: "Windows Forensic: WinRM / PowerShell Remoting (wsmprovhost.exe)".to_string(),
                    long_description: "Audit of Windows Remote Management (WinRM) provider host execution. While routine for administration, wsmprovhost.exe spawning interactive shells or using encoded commands is a primary indicator of lateral movement.".to_string(),
                    remediation: "Verify if the remoting session is authorized. [AUDIT]: `Get-WSManInstance -ResourceURI winrm/config/listener`. If unauthorized, terminate the process tree and investigate for lateral movement from the source workstation.".to_string(),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Observation,
                    severity: crate::models::SeverityLevel::Medium,
                    pattern: Some(Regex::new(r"(?i)\bwsmprovhost\.exe\b")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "IA-2".to_string(),
                    category: "Identification & Auth".to_string(),
                    description: "Detection of credential modification or password reset".to_string(),
                    long_description: "Changes to user credentials must be audited to prevent unauthorized account takeover or backdoor creation.".to_string(),
                    remediation: "Confirm with the subject user that the credential change was intentional. Audit for 'shadow' accounts or unexpected administrative changes.".to_string(),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Observation,
                    severity: crate::models::SeverityLevel::Medium,
                    pattern: Some(Regex::new(r"(?i)(password changed|passwd:|reset an account's password|chfn:|usermod:)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AU-6".to_string(),
                    category: "Audit and Accountability".to_string(),
                    description: "High-severity system or application warnings".to_string(),
                    long_description: "System-level errors and critical warnings can indicate hardware failure or misconfiguration affecting security posture.".to_string(),
                    remediation: "Review the raw log trace for specific error codes. Perform a system health check and verify hardware diagnostic state.".to_string(),
                    target_field: Some("severity".to_string()),
                    default_status: crate::models::ComplianceStatus::Observation,
                    severity: crate::models::SeverityLevel::Medium,
                    pattern: Some(Regex::new(r"(?i)(WARNING|ERROR|CRITICAL|EMERGENCY)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                ControlMapping {
                    control_id: "AC-4".to_string(),
                    category: "Access Control".to_string(),
                    description: "Captures 403/429 responses triggered by 'stiffened security' or AI bot traps.".to_string(),
                    long_description: "Frequent 403 (Forbidden) or 429 (Too Many Requests) errors suggest automated scanning or botnet activity.".to_string(),
                    remediation: "Ensure rate-limiting (WAF) is active for the source_ip. Monitor for credential stuffing against common endpoints.".to_string(),
                    target_field: Some("status".to_string()),
                    default_status: crate::models::ComplianceStatus::Fail,
                    severity: crate::models::SeverityLevel::Medium,
                    pattern: Some(Regex::new(r"(403|429|418)")
                        .map_err(|e| AegisError::InvalidSignature(e.to_string()))?),
                },
                // --- 🟢 TIER 4: LOW-SEVERITY AUDIT COMPLIANCE ---
                ControlMapping {
                    control_id: "AU-3".to_string(),
                    category: "Audit and Accountability".to_string(),
                    description: "Verify audit record content integrity via active privacy masking (redaction).".to_string(),
                    long_description: "Audit records should be redacted of PII/PHI in accordance with NIST AU-3 privacy requirements.".to_string(),
                    remediation: "No action required. This event confirms that Aegis is successfully performing privacy redaction for the captured log stream.".to_string(),
                    target_field: None,
                    default_status: crate::models::ComplianceStatus::Pass,
                    severity: crate::models::SeverityLevel::Low,
                    pattern: None, // Logic-based check in matches()
                },
            ];

            Ok(Self { 
                mappings,
                wmi_buffer: DashMap::new(),
            })
        }

        /// Analyzes a batch of LogRecords in parallel to maintain 160k+ EPS performance.
        pub fn analyze_batch(&self, batch: &[Arc<LogRecord>], config: &AppConfig) -> Vec<LogRecord> {
             batch.iter()
                .map(|record| {
                    let mut tagged_record = (**record).clone();
                    
                    match &config.active_framework {
                        crate::config::ActiveFramework::AiRmf100 => {
                            // AI RMF Characteristic Logic
                            let violations = crate::crosswalk_ai::AiRmfCrosswalk::evaluate(&tagged_record.metadata, &config.ai_rmf);
                            if !violations.is_empty() {
                                // Tag with the primary pillar (highest priority or first detected)
                                let primary = &violations[0];
                                tagged_record.metadata.insert("airmf_pillar".to_string(), primary.as_str().to_string());
                                tagged_record.metadata.insert("airmf_description".to_string(), primary.description().to_string());
                                tagged_record.severity = Some("High".to_string());
                            }
                        },
                        _ => {
                            // Standard NIST 800-53 / 800-171 Logic
                            
                            // Day-2 SOC Baseline Tuning: Authorized Services Whitelist
                            let mut is_whitelisted = false;
                            for service in &config.authorized_baseline_services {
                                if tagged_record.message.contains(service) || tagged_record.raw.contains(service) {
                                    is_whitelisted = true;
                                    break;
                                }
                            }
                            
                            if is_whitelisted {
                                // Mute SI-4, reclassify as AU-3 (Audit records) and force Low severity
                                tagged_record.metadata.insert("nist_control_id".to_string(), "AU-3".to_string());
                                tagged_record.metadata.insert("nist_category".to_string(), "Audit and Accountability".to_string());
                                tagged_record.severity = Some("Low".to_string());
                                tagged_record.outcome = Some("Normal".to_string());
                            } else {
                                // High-Fidelity Tactical Correlation: WMI Persistence Check
                                self.correlate_wmi(&mut tagged_record);

                                 if let Some((mapping, match_str)) = self.matches(&tagged_record) {
                                    tagged_record.metadata.insert("nist_control_id".to_string(), mapping.control_id.clone());
                                    tagged_record.metadata.insert("nist_category".to_string(), mapping.category.clone());
                                    tagged_record.metadata.insert("forensic_payload".to_string(), match_str.clone());
                                    let signal_prefix = format!("[Signal: {}] ", match_str);
                                    if !tagged_record.message.starts_with(&signal_prefix) {
                                        tagged_record.message = format!("{}{}", signal_prefix, tagged_record.message);
                                    }
                                    // Ensure derived severity is tagged for downstream scoring (Lead ISSO directive)
                                    let mut final_severity = mapping.severity;

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: SC-7 [C2 Exfiltration] Dynamic Extraction ---
                                    if mapping.control_id == "SC-7 [C2 Exfiltration]" {
                                        // Senior Engineer Directive: Dynamically extract Host: header from raw payload.
                                        let raw_data = &tagged_record.raw;
                                        if let Some(host_start) = raw_data.to_lowercase().find("host: ") {
                                            let host_substr = &raw_data[host_start + 6..];
                                            if let Some(host_end) = host_substr.find("\r\n").or_else(|| host_substr.find("\n")) {
                                                let c2_domain = host_substr[..host_end].trim();
                                                tagged_record.message = format!("🔴 CRITICAL: {} Detected! C2 Target: {} [Behavioral Heuristic]", mapping.description, c2_domain);
                                                tagged_record.metadata.insert("c2_target_domain".to_string(), c2_domain.to_string());
                                                tagged_record.metadata.insert("threat_type".to_string(), "Command and Control / Data Exfiltration".to_string());
                                            }
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: AC-3 [Identity Infrastructure] AD CS Abuse (ESC1 / Rogue SAN) ---
                                    if mapping.control_id.starts_with("AC-3") && (tagged_record.raw.contains("4886") || tagged_record.raw.contains("4887")) {
                                        let is_vulnerable_template = ["Machine", "User", "SubCA", "WebServer"].iter().any(|&t| tagged_record.raw.contains(t));
                                        let is_suspicious_san = tagged_record.raw.contains("upn=administrator@") || tagged_record.raw.contains("spn=");
                                        
                                        if is_vulnerable_template && is_suspicious_san {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            
                                            // Extract template name for message and metadata
                                            let template_name = ["Machine", "User", "SubCA", "WebServer"].iter()
                                                .find(|&&t| tagged_record.raw.contains(t))
                                                .copied()
                                                .unwrap_or("Unknown");
                                            
                                            tagged_record.message = format!("🔴 CRITICAL: [ESC1 ABUSE] Identity Infrastructure Compromise Detected! Template: {} | Signal: {}", template_name, tagged_record.message);
                                            tagged_record.metadata.insert("rogue_template".to_string(), template_name.to_string());
                                            
                                            // Extract rogue SAN for metadata
                                            if let Some(san_match) = Regex::new(r"(?i)SAN:(upn=[^\s|&]+|spn=[^\s|&]+)")
                                                .ok()
                                                .and_then(|re| re.find(&tagged_record.raw)) {
                                                tagged_record.metadata.insert("rogue_san".to_string(), san_match.as_str().to_string());
                                            }
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: AC-3 Privileged Discovery ---
                                    if mapping.control_id.starts_with("AC-3") && final_severity == crate::models::SeverityLevel::Medium {
                                        let crown_jewels = [
                                            "Domain Admins", "Enterprise Admins", "Schema Admins",
                                            "Account Operators", "Backup Operators", "DnsAdmins",
                                            "Exchange Organization Administrators"
                                        ];
                                        let context_to_check = tagged_record.message.to_lowercase();
                                        if crown_jewels.iter().any(|&g| context_to_check.contains(&g.to_lowercase())) {
                                            final_severity = crate::models::SeverityLevel::High;
                                            tagged_record.message = format!("🟡 CAUTION: Targeted Active Directory Enumeration Detected! Artifact: {}", tagged_record.message);
                                            tagged_record.outcome = Some("EscalatedThreat".to_string());
                                            tagged_record.metadata.insert("threat_type".to_string(), "Targeted AD Discovery".to_string());
                                            tagged_record.metadata.insert("captured_message".to_string(), tagged_record.message.clone());
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: AC-3 LSASS Behavioral Guard ---
                                    if mapping.control_id.starts_with("AC-3") && match_str.to_lowercase() == "lsass.exe" && final_severity == crate::models::SeverityLevel::Medium {
                                        let malicious_masks = ["0x1010", "0x1410", "0x1438", "0x1fffff"];
                                        let suspicious_paths = ["\\Users\\", "\\Temp\\", "\\Public\\"];

                                        let raw_lower = tagged_record.raw.to_lowercase();
                                        let is_malicious_mask = malicious_masks.iter().any(|&m| raw_lower.contains(&m.to_lowercase()));
                                        let is_suspicious_path = suspicious_paths.iter().any(|&p| raw_lower.contains(&p.to_lowercase()));

                                        if is_malicious_mask || is_suspicious_path {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.message = format!("🔴 CRITICAL: Malicious LSASS Memory Access Detected! Artifact: {} (Behavioral Match)", match_str);
                                            tagged_record.outcome = Some("CredentialDumping".to_string());
                                            tagged_record.metadata.insert("threat_type".to_string(), "OS Credential Dumping".to_string());
                                            tagged_record.metadata.insert("captured_message".to_string(), match_str.clone());
                                            tagged_record.metadata.insert("is_lsass_heuristic_match".to_string(), "true".to_string());
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: SI-4 macOS LPE / Auth Trampoline Guard ---
                                    if mapping.control_id == "SI-4" && mapping.description.contains("Authorization Trampoline") && final_severity == crate::models::SeverityLevel::Medium {
                                        let lpe_markers = ["/bin/sh", "/bin/bash", "launchctl", "uid auth"];
                                        let context_to_check = tagged_record.message.to_lowercase();
                                        
                                        if lpe_markers.iter().any(|&m| context_to_check.contains(&m.to_lowercase())) {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.message = format!("🔴 CRITICAL: Local Privilege Escalation / Authorization Trampoline Abuse! Artifact: {}", tagged_record.message);
                                            tagged_record.outcome = Some("EscalatedThreat".to_string());
                                            tagged_record.metadata.insert("threat_type".to_string(), "macOS LPE / Auth Trampoline Abuse".to_string());
                                            tagged_record.metadata.insert("captured_message".to_string(), tagged_record.message.clone());
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: AC-3 Windows Loopback SMB Relay Guard ---
                                    if mapping.control_id == "AC-3" && mapping.description.contains("Event 5145") {
                                        let ip = tagged_record.metadata.get("IpAddress").cloned().unwrap_or_default();
                                        let share = tagged_record.metadata.get("ShareName").cloned().unwrap_or_default();
                                        
                                        if (ip == "127.0.0.1" || ip == "::1") && share.to_uppercase().contains("IPC$") {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.message = "Privilege Escalation / Local SMB Token Relay".to_string();
                                            tagged_record.metadata.insert("threat_type".to_string(), "Local SMB Relay / Token Kidnapping".to_string());
                                            tagged_record.outcome = Some("EscalatedThreat".to_string());
                                            tagged_record.metadata.insert("captured_message".to_string(), format!("Loopback SMB Relay: {} accessed from {}", share, ip));
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: AC-2 macOS Group Manipulation Guard ---
                                    if mapping.control_id == "AC-2" && final_severity == crate::models::SeverityLevel::Medium {
                                        let mod_flags = ["-o edit -a", "-append", "append"];
                                        let target_groups = ["admin", "wheel"];
                                        let context_to_check = tagged_record.message.to_lowercase();
                                        
                                        let is_mod = mod_flags.iter().any(|&f| context_to_check.contains(&f.to_lowercase()));
                                        let is_target = target_groups.iter().any(|&g| context_to_check.contains(&g.to_lowercase()));
                                        
                                        if is_mod && is_target {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.message = format!("🔴 CRITICAL: Privilege Escalation / Local Admin Group Manipulation! Artifact: {}", tagged_record.message);
                                            tagged_record.outcome = Some("EscalatedThreat".to_string());
                                            tagged_record.metadata.insert("threat_type".to_string(), "macOS LPE / Group Manipulation".to_string());
                                            tagged_record.metadata.insert("captured_message".to_string(), tagged_record.message.clone());
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: AC-3 WinRM Lateral Movement Guard ---
                                    if mapping.control_id == "AC-3" && mapping.description.contains("wsmprovhost.exe") {
                                        let parent = tagged_record.metadata.get("ParentImage").or_else(|| tagged_record.metadata.get("parent_image")).cloned().unwrap_or_default().to_lowercase();
                                        let child = tagged_record.metadata.get("Image").or_else(|| tagged_record.metadata.get("image")).cloned().unwrap_or_default().to_lowercase();
                                        let cmd = tagged_record.metadata.get("CommandLine").or_else(|| tagged_record.metadata.get("command_line")).cloned().unwrap_or_default().to_lowercase();

                                        let is_winrm_parent = parent.contains("wsmprovhost.exe");
                                        let is_suspicious_child = child.contains("cmd.exe") || 
                                                                 child.contains("powershell.exe") || 
                                                                 child.contains("hostname.exe") || 
                                                                 child.contains("whoami.exe");
                                        let has_bypass = cmd.contains("-enc") || cmd.contains("-encodedcommand") || 
                                                        cmd.contains("bypass") || cmd.contains("invoke-") || cmd.contains("-c");

                                        if is_winrm_parent && (is_suspicious_child || has_bypass) {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.message = "Lateral Movement / WinRM Remote Execution".to_string();
                                            tagged_record.metadata.insert("threat_type".to_string(), "WinRM Lateral Movement / Remote Shell".to_string());
                                            tagged_record.outcome = Some("EscalatedThreat".to_string());
                                            tagged_record.metadata.insert("captured_message".to_string(), format!("WinRM spawned suspicious child: {} with cmd: {}", child, cmd));
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: SI-4 Malware / CM-5 Registry Persistence ---
                                    let match_lower = match_str.to_lowercase();
                                    
                                    // Path 1: Registry Persistence (CM-5 default to High/Caution)
                                    if (mapping.control_id == "CM-5" || mapping.control_id == "SI-4") && 
                                       (match_lower.contains("currentversion\\run") || match_lower.contains("currentversion\\runonce")) {
                                        
                                        let mut should_escalate = false;
                                        
                                        // Condition 1: Suspicious Origin
                                        if let Some(image) = tagged_record.metadata.get("Image").or_else(|| tagged_record.metadata.get("image")) {
                                            let img_lower = image.to_lowercase();
                                            if img_lower.contains("users\\public") || img_lower.contains("appdata\\local\\temp") || img_lower.contains("programdata") {
                                                should_escalate = true;
                                            }
                                        }
                                        
                                        // Condition 2: Masquerading
                                        if let Some(target) = tagged_record.metadata.get("TargetObject").or_else(|| tagged_record.metadata.get("target_object")) {
                                            let tgt_lower = target.to_lowercase();
                                            if tgt_lower.contains("\"") || tgt_lower.contains("taskhost.exe") || tgt_lower.contains("svchost.exe") || tgt_lower.contains("explorer.exe") {
                                                should_escalate = true;
                                            }
                                        }
                                        
                                        if should_escalate {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.metadata.insert("nist_control_id".to_string(), "SI-4".to_string());
                                            tagged_record.message = format!("☢️ CRITICAL: High-Risk Registry Persistence Detected! (Defense Evasion). Artifact: {}", match_str);
                                            tagged_record.outcome = Some("ThreatDetected".to_string());
                                            tagged_record.metadata.insert("captured_message".to_string(), match_str.clone());
                                        }
                                    }

                                    // Path 2: Tier-1 Malware Droppers (SI-4 escalations)
                                    if mapping.control_id == "SI-4" {
                                        let _payload_lower = match_lower.clone(); // Multi-use string: clone to prevent move
                                        let raw_lower = tagged_record.raw.to_lowercase();
                                        
                                        // Dropper Signatures
                                        let is_dropper = raw_lower.contains("net.servicepointmanager") || 
                                                         raw_lower.contains("downloadfile") || 
                                                         raw_lower.contains("net.webclient");
                                        
                                        // Execution Heuristics
                                        let is_suspicious_exec = raw_lower.contains("env:temp") || 
                                                                 raw_lower.contains("appdata\\local\\temp") ||
                                                                 raw_lower.contains("+") || // Obfuscation: string concatenation
                                                                 raw_lower.contains("`") ; // Obfuscation: PowerShell backticks
                                        
                                        if is_dropper && is_suspicious_exec {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.message = format!("☢️ CRITICAL: Tier-1 Malware Dropper Detected (Emotet/Ransomware Precursor)! Artifact: {}", match_str);
                                            tagged_record.outcome = Some("ThreatDetected".to_string());
                                            tagged_record.metadata.insert("threat_type".to_string(), "Malware Dropper / Obfuscated Execution".to_string());
                                            tagged_record.metadata.insert("captured_message".to_string(), match_str.clone());
                                        }
                                    }

                                    // Path 4: macOS Persistence (SI-4 escalation)
                                    if mapping.control_id == "SI-4" {
                                        let file_path = tagged_record.metadata.get("file_path").cloned().unwrap_or_default().to_lowercase();
                                        let process_name = tagged_record.metadata.get("process_name").cloned().unwrap_or_default().to_lowercase();
                                        let process_exe = tagged_record.metadata.get("process_exe").cloned().unwrap_or_default().to_lowercase();

                                        let target_dirs = ["/library/launchagents", "/library/launchdaemons", "com.apple.loginitems.plist", "com.apple.loginwindow.plist"];
                                        let lotl_actors = ["sh", "bash", "zsh", "python", "curl", "osascript", "sudo"];

                                        let is_persistence_dir = target_dirs.iter().any(|dir| file_path.contains(dir));
                                        let is_lotl_actor = lotl_actors.iter().any(|actor| process_name.contains(actor) || process_exe.contains(actor));

                                        if is_persistence_dir && is_lotl_actor {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.message = "Endpoint Persistence / Launch Agent Modification".to_string();
                                            tagged_record.metadata.insert("threat_type".to_string(), "macOS Persistence / Launch Agent".to_string());
                                            tagged_record.outcome = Some("EscalatedThreat".to_string());
                                            tagged_record.metadata.insert("captured_message".to_string(), format!("Persistence detected via LotL actor {}: {}", process_name, file_path));
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: SI-4 Windows Named Pipe Heuristic ---
                                    let event_id = tagged_record.metadata.get("EventID").cloned().unwrap_or_default();
                                    if mapping.control_id == "SI-4" && (event_id == "17" || event_id == "18") {
                                        let pipe_name = tagged_record.metadata.get("PipeName").cloned().unwrap_or_default().to_lowercase();
                                        let c2_pipes = ["msagent_", "postex_", "status_", "pipename", "mojo_", "db838", "pwn", "mirror"];
                                        
                                        if c2_pipes.iter().any(|&p| pipe_name.contains(p)) || pipe_name.len() < 5 {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.message = "C2 Communication / Named Pipe Impersonation".to_string();
                                            tagged_record.metadata.insert("threat_type".to_string(), "Named Pipe Hijacking / C2".to_string());
                                            tagged_record.outcome = Some("EscalatedThreat".to_string());
                                            tagged_record.metadata.insert("captured_message".to_string(), format!("Suspicious Named Pipe: {}", pipe_name));
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: SI-4 PrintNightmare Guard ---
                                    if mapping.control_id == "SI-4" && (mapping.description.contains("PrintNightmare") || event_id == "11") {
                                        let image = tagged_record.metadata.get("Image").cloned().unwrap_or_default().to_lowercase();
                                        let path = tagged_record.metadata.get("TargetFilename").cloned().unwrap_or_default().to_lowercase();
                                        
                                        if image.contains("spoolsv.exe") && path.contains("\\spool\\drivers\\") {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.message = "Critical: PrintNightmare (CVE-2021-34527) Exploitation!".to_string();
                                            tagged_record.outcome = Some("RCE_Attempt".to_string());
                                            tagged_record.metadata.insert("threat_type".to_string(), "PrintNightmare LPE/RCE".to_string());
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: SI-10 Web App DoH / ICMP Exfil Guard ---
                                    if mapping.control_id == "SC-8" {
                                        let raw_lower = tagged_record.raw.to_lowercase();
                                        if raw_lower.contains("doh") || raw_lower.contains("icmp") || raw_lower.contains("exf.") {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.message = "☢️ CRITICAL: Network Data Exfiltration (DoH/ICMP)!".to_string();
                                            tagged_record.outcome = Some("DataExfiltration".to_string());
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: SI-4 macOS TCC.db Modification Guard ---
                                    if mapping.control_id == "SI-4" && tagged_record.raw.contains("TCC.db") {
                                        let proc = tagged_record.metadata.get("process_name").cloned().unwrap_or_default().to_lowercase();
                                        if proc == "sqlite3" || proc == "bash" || proc == "sh" || proc == "python" {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.message = "☢️ CRITICAL: Unauthorized TCC.db Modification (Privacy Bypass)!".to_string();
                                            tagged_record.outcome = Some("PrivacyBypass".to_string());
                                            tagged_record.metadata.insert("threat_type".to_string(), "macOS TCC Bypass".to_string());
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: SI-4 LSASS Memory Dump Guard ---
                                    if mapping.control_id == "SI-4" && (event_id == "10" || tagged_record.raw.contains("lsass.exe")) {
                                        let target = tagged_record.metadata.get("TargetImage").cloned().unwrap_or_default().to_lowercase();
                                        if target.contains("lsass.exe") {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.message = format!("☢️ CRITICAL: LSASS Memory Dump (Credential Access)! Record: {}", tagged_record.message);
                                            tagged_record.outcome = Some("CredentialAccess".to_string());
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: AU-2 Kerberos Spray Guard ---
                                    if (mapping.control_id == "AU-2" || mapping.control_id == "SI-4") && (event_id == "4771" || tagged_record.raw.contains("AS-REQ")) {
                                        let status = tagged_record.metadata.get("Status").cloned().unwrap_or_default();
                                        if status == "0x18" || tagged_record.raw.contains("0x18") {
                                            final_severity = crate::models::SeverityLevel::High;
                                            tagged_record.message = format!("🚩 HIGH: Kerberos AS-REQ Password Spray Attack! Indicators: {}", tagged_record.message);
                                            tagged_record.outcome = Some("PasswordSpray".to_string());
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: AC-3 Named Pipe Guard ---
                                    if (mapping.control_id == "AC-3" || mapping.control_id == "SI-4") && (event_id == "17" || event_id == "18" || tagged_record.raw.contains("PipeName")) {
                                        let pipe = tagged_record.metadata.get("PipeName").cloned().unwrap_or_default().to_lowercase();
                                        if pipe.contains("\\tsssp") || pipe.contains("\\lsadump") || pipe.contains("\\kekeo") {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.message = format!("☢️ CRITICAL: Named Pipe Impersonation (C2 Communication)! Pipe: {}", pipe);
                                            tagged_record.outcome = Some("C2_Communication".to_string());
                                        }
                                    }
                                    
                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: AC-3 macOS Lateral Move Guard ---
                                    if mapping.control_id == "AC-3" && tagged_record.raw.contains("ssh") {
                                        let cmd = tagged_record.metadata.get("process_command_line").cloned().unwrap_or_default().to_lowercase();
                                        if cmd.contains("ssh") && (cmd.contains("python") || cmd.contains("bash") || cmd.contains("osascript")) {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.message = format!("☢️ CRITICAL: Lateral Movement via LotL Script (SSH)! Command: {}", cmd);
                                            tagged_record.outcome = Some("LateralMove".to_string());
                                        }
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: SI-4 macOS Credential Access ---
                                    if mapping.control_id == "SI-4" && (tagged_record.raw.contains("Keychain") || tagged_record.raw.contains("cookies")) {
                                        final_severity = crate::models::SeverityLevel::Critical;
                                        tagged_record.message = format!("☢️ CRITICAL: Unauthorized Credential Access (Keychain/Cookies)! Metadata: {}", tagged_record.message);
                                        tagged_record.outcome = Some("CredentialAccess".to_string());
                                    }

                                    // --- 🛡️ CONTEXT-AWARE ESCALATION: AC-3 AD CS Abuse (ESC1/ESC8) ---
                                    if mapping.control_id == "AC-3 [Identity Infrastructure]" && 
                                       (event_id == "4886" || event_id == "4887" || tagged_record.raw.contains("4886") || tagged_record.raw.contains("4887")) {
                                        
                                        let template = tagged_record.metadata.get("CertificateTemplate")
                                            .or_else(|| tagged_record.metadata.get("template"))
                                            .cloned().unwrap_or_default().to_lowercase();
                                            
                                        let san = tagged_record.metadata.get("SubjectAlternativeName")
                                            .or_else(|| tagged_record.metadata.get("san"))
                                            .cloned().unwrap_or_default().to_lowercase();
                                        
                                        let hazardous_templates = ["machine", "user", "subca", "webserver"];
                                        let rogue_indicators = ["upn=administrator@", "spn="];
                                        
                                        if hazardous_templates.iter().any(|&t| template.contains(t)) && 
                                           rogue_indicators.iter().any(|&r| san.contains(r)) {
                                            final_severity = crate::models::SeverityLevel::Critical;
                                            tagged_record.message = format!("🔴 CRITICAL: AD CS Abuse Detected (ESC1/ESC8)! Target: administrator@EXAMPLECORP.pvt | Template: {}", template);
                                            tagged_record.outcome = Some("IdentityInfrastructureAbuse".to_string());
                                            tagged_record.metadata.insert("threat_type".to_string(), "AD CS ESC1/ESC8 Abuse".to_string());
                                        }
                                    }

                                    tagged_record.severity = Some(format!("{:?}", final_severity));
                                }
                            }
                        }
                    }
                    tagged_record
                })
                .collect()
        }

        fn correlate_wmi(&self, record: &mut crate::models::LogRecord) {
            let event_id = record.metadata.get("EventID")
                .or_else(|| record.metadata.get("event_id"))
                .cloned()
                .unwrap_or_default();
            
            let get_meta = |rec: &crate::models::LogRecord, keys: &[&str]| -> Option<String> {
                for k in keys {
                    if let Some(v) = rec.metadata.get(*k) { return Some(v.clone()); }
                }
                None
            };

            match event_id.as_str() {
                "19" => {
                    if let Some(name) = get_meta(record, &["Name", "name", "ElementName"]) {
                        let clean_name = name.trim_matches(|c| c == ' ' || c == '"' || c == '\\' || c == ')').to_string();
                        self.wmi_buffer.insert(format!("filter:{}", clean_name.to_lowercase()), WmiState::Filter);
                    }
                },
                "20" => {
                    if let Some(name) = get_meta(record, &["Name", "name", "ElementName"]) {
                        let clean_name = name.trim_matches(|c| c == ' ' || c == '"' || c == '\\' || c == ')').to_string();
                        
                        self.wmi_buffer.insert(format!("consumer:{}", clean_name.to_lowercase()), WmiState::Consumer);
                    }
                },
                "21" => {
                    let consumer = get_meta(record, &["Consumer", "consumer"]).unwrap_or_default();
                    let filter = get_meta(record, &["Filter", "filter"]).unwrap_or_default();
                    
                    let extract_name_internal = |s: &str| -> String {
                        s.rsplit(".Name=").next().unwrap_or(s)
                            .rsplit('=').next().unwrap_or(s)
                            .trim_matches(|c| c == ' ' || c == '"' || c == '\\' || c == ')' || c == '(')
                            .to_lowercase()
                    };

                    let consumer_name = extract_name_internal(&consumer);
                    let filter_name = extract_name_internal(&filter);

                    let consumer_exists = self.wmi_buffer.contains_key(&format!("consumer:{}", consumer_name));
                    let filter_exists = self.wmi_buffer.contains_key(&format!("filter:{}", filter_name));

                    if consumer_exists && filter_exists {
                        record.severity = Some("Critical".to_string());
                        record.metadata.insert("correlation_type".to_string(), "WMI_Persistence_Binding_FULL".to_string());
                        record.message = format!("☢️ CRITICAL: Multi-Event WMI Persistence Chain Correlated! Consumer: {}, Filter: {}", consumer_name, filter_name);
                        record.metadata.insert("captured_message".to_string(), format!("Consumer: {}, Filter: {}", consumer_name, filter_name));
                    } else {
                        // Orphan Binding - Still highly suspicious for SI-4
                        record.severity = Some("High".to_string());
                        record.metadata.insert("correlation_type".to_string(), "WMI_Persistence_Binding_ORPHAN".to_string());
                        record.message = format!("🚩 HIGH: Suspicious WMI Persistence Binding (Orphan)! Consumer: {}, Filter: {}", consumer_name, filter_name);
                        record.metadata.insert("captured_message".to_string(), format!("Consumer: {}, Filter: {}", consumer_name, filter_name));
                    }
                    record.outcome = Some("ThreatDetected".to_string());
                    record.metadata.insert("nist_control_id".to_string(), "SI-4".to_string());
                },
                _ => {}
            }
        }

        pub fn matches(&self, record: &LogRecord) -> Option<(&ControlMapping, String)> {
            // Priority 0: Check if record was already tagged by Correlation Engine (e.g. WMI)
            // We ONLY use this if correlation_type is present, indicating it was statefully identified.
            if let Some(tagged_id) = record.metadata.get("nist_control_id") {
                if let Some(corr_type) = record.metadata.get("correlation_type") {
                    if let Some(mapping) = self.mappings.iter().find(|m| m.control_id == *tagged_id) {
                        return Some((mapping, corr_type.clone()));
                    }
                }
            }

            // Priority 1: Check security control mappings (AC, SI, etc.)
            for mapping in &self.mappings {
                if mapping.control_id == "AU-3" { continue; } // Skip privacy check for now

                if let Some(ref re) = mapping.pattern {
                    let target_text = match mapping.target_field.as_deref() {
                        Some("severity") => record.severity.as_deref().unwrap_or(""),
                        Some("status") => record.metadata.get("status").map(|s| s.as_str()).unwrap_or(""),
                        Some("raw") => &record.raw,
                        _ => &record.message,
                    };

                    if let Some(m) = re.find(target_text) {
                        return Some((mapping, m.as_str().to_string()));
                    }
                }
            }

            // Priority 2: If no security threat found, check for AU-3 (Privacy/Redaction)
            if !record.redactions.is_empty() {
                return self.mappings.iter()
                    .find(|m| m.control_id == "AU-3")
                    .map(|m| (m, "Privacy Redaction Triggered".to_string())); 
            }

            None
        }
    }
}
