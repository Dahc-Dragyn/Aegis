# Aegis Forensic Pulse Assessment Report

**Date**: 2026-04-10 09:42
**Framework**: NIST SP 800-53 Rev. 5 (Federal High)
**Objective**: Baseline assessment of 20 forensic attack samples.

| ID | Forensic Sample | Pulse Status | Triggered Controls | Signals | Executive Summary |
|:---|:---|:---|:---|:---|:---|
| 1 | `bits_openvpn.evtx` | =ï¿½ï¿½ï¿½ F (CRITICAL) | AC-3: COMPLIANCE WARNING: Unauthorized Access / Lateral Movement | 54 | Unauthorized access attempts or unusual process execution in sensitive directories have been detected. This indicates a high risk of lateral movement across the network. |
#| 2 | `dc_applog_ntdsutil_dfir_325_326_327.evtx` | #########| None Detected | 0 | N/A |
| 3 | `DE_1102_security_log_cleared.evtx` | =ï¿½ï¿½ï¿½ F (CRITICAL) | AU-9: NIST COMPLIANCE GAP DETECTED<br/>SI-4: ACTIVE THREAT: Defensive Evasion Detected | 111 | Forensic anomalies have been detected that deviate from the authorized system baseline, requiring immediate review to maintain compliance.<br/>An attacker is attempting to hide malicious code by cloaking it within legitimate system processes or by tampering with binary integrity. This bypasses traditional security and prevents NIST certification. |
| 4 | `DE_EventLog_Service_Crashed.evtx` | = C (CAUTION) | AC-3: COMPLIANCE WARNING: Unauthorized Access / Lateral Movement | 4 | Unauthorized access attempts or unusual process execution in sensitive directories have been detected. This indicates a high risk of lateral movement across the network. |
#| 5 | `DE_ProcessHerpaderping_Sysmon_11_10_1_7.evtx` |#########| None Detected | 0 | N/A |
| 6 | `de_PsScriptBlockLogging_disabled_sysmon12_13.evtx` ###########| 0 | N/A |
| 7 | `DE_RDP_Tunneling_4624.evtx` | =ï¿½ï¿½ï¿½ F (CRITICAL) | SI-4: ACTIVE THREAT: Defensive Evasion Detected | 13 | An attacker is attempting to hide malicious code by cloaking it within legitimate system processes or by tampering with binary integrity. This bypasses traditional security and prevents NIST certification. |
| 8 | `de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx` | 🔴 F (CRITICAL) | SI-4: ACTIVE THREAT: Defensive Evasion Detected | 2 | Unmanaged PowerShell (PSInject) detected via cross-process module load telemetry. |
| 9 | `discovery_bloodhound.evtx` | =ï¿½ï¿½ï¿½ C (CAUTION) | AU-9: NIST COMPLIANCE GAP DETECTED | 1 | Forensic anomalies have been detected that deviate from the authorized system baseline, requiring immediate review to maintain compliance. |
| 10 | `exec_emotet_ps_4104.evtx` | 🔴 F (CRITICAL) | SI-4: ACTIVE THREAT: Defensive Evasion Detected | 1 | Emotet PowerShell dropper detected via ScriptBlock obfuscation patterns. |
| 11 | `exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx` | ?? SECURE | None Detected | 0 | N/A |
| 12 | `LM_5145_Remote_FileCopy.evtx` | ?? SECURE | None Detected | 0 | N/A |
| 13 | `LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx` | ?? SECURE | None Detected | 0 | N/A |
| 14 | `LM_wmiexec_impacket_sysmon_whoami.evtx` | ?? SECURE | None Detected | 0 | N/A |
| 15 | `net_share_drive_5142.evtx` | =ï¿½ï¿½ï¿½ C (CAUTION) | AU-9: NIST COMPLIANCE GAP DETECTED | 1 | Forensic anomalies have been detected that deviate from the authorized system baseline, requiring immediate review to maintain compliance. |
| 16 | `persistence_accessibility_features_osk_sysmon1.evtx` | =ï¿½ï¿½ï¿½ C (CAUTION) | SI-4: ACTIVE THREAT: Defensive Evasion Detected | 1 | An attacker is attempting to hide malicious code by cloaking it within legitimate system processes or by tampering with binary integrity. This bypasses traditional security and prevents NIST certification. |
| 17 | `persistence_startup_UserShellStartup_Folder_Changed_sysmon_13.evtx` | ?? SECURE | None Detected | 0 | N/A |
| 18 | `sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx` | =ï¿½ï¿½ï¿½ C (CAUTION) | SI-4: ACTIVE THREAT: Defensive Evasion Detected | 1 | An attacker is attempting to hide malicious code by cloaking it within legitimate system processes or by tampering with binary integrity. This bypasses traditional security and prevents NIST certification. |
| 19 | `Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx` | ?? SECURE | None Detected | 0 | N/A |
| 20 | `sysmon_mshta_sharpshooter_stageless_meterpreter.evtx` | ?? SECURE | None Detected | 0 | N/A |
