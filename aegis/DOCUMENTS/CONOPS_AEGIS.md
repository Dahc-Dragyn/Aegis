# Concept of Operations (CONOPS): Project Aegis 🛡️

**Project Codename**: Aegis (The Compliance-as-Code Sentinel)  
**Persona**: The Field Engineer & The NIST Auditor  
**Strategic Goal**: Turn raw telemetry into signed, quarterly compliance certifications.

---

## 1. Operational Overview: The Field Engineer 👷

### A. Deployment (The "Drop-in" Mission)
The field engineer receives the single, statically-linked `aegis` binary.
1.  **Installation**: The engineer drops the binary onto the target system (Linux/Windows).
2.  **Configuration**: Points Aegis to the system log directory and the `nist-800-53-au.json` mapping database.
3.  **Activation**: `sudo ./aegis start --daemon`.

### B. The "Heartbeat" (Daily Posture Check)
The engineer uses `aegis status` to view the **Real-Time Compliance Posture (RCP)**. It functions like a triage board:
- **🟢 GREEN (Posture Nominal)**: All AU-2, AU-6, and AU-12 log vectors are active. System events (Auth, Sudo, Kernel) are being captured within the defined 15-minute window.
- **🟡 YELLOW (Posture Drift)**: A required event window has closed without telemetry (e.g., "AU-12 hasn't seen a record in 4 hours"). This triggers an internal investigation: Is the logging service down?
- **🔴 RED (Posture Critical)**: Ingestion failure or suspected tampering. The binary’s self-audit (Gate 4) has detected a hash mismatch or the log files have been deleted.

---

## 2. The Operational Crisis Workflow 🚨

When a **RED Heartbeat** is detected:
1.  **Aegis** fires a "Critical Gap" alert via local syslog or webhook.
2.  **The Field Engineer** runs `aegis triage` to identify the specific break (e.g., `Control AU-6: Review Failure - Regex mismatch on new auth.log format`).
3.  **Remediation**: The engineer updates the Regex pattern or restores the logging service. Aegis resets the heartbeat once the first "Resumption Event" is captured.

---

## 3. The Auditor Perspective: Quarterly Sign-off 🖋️

Every 90 days, the organization must certify its compliance state to a human auditor (Government POC or ISSO).

### A. The "Certification" Command
`aegis export --quarterly --output-dir ./q1_audits`

### B. The Audit Manifest (The "Evidence File")
The command generates a **Forensic Audit Manifest** (PDF or Markdown) consisting of:
1.  **Liveness Table**: A percentage-of-time breakdown for every mapped NIST AU-control (Target 99.9% uptime).
2.  **The Proof Block**: Randomly sampled, anonymized log records mapped to Control IDs (e.g., "See Line 42: AU-2 Record found at 2026-04-02 14:00Z").
3.  **Integrity Seal**: A SHA-256 hash of the entire three-month audit trail.
4.  **Sign-off Block**: A formal space for the Auditor and the ISSO to countersign the digital record.

---

## 4. Hardware Synergy: User Experience ⚡

On the **Ryzen 3600X**, the user experiences **Zero Impact On Production**. 
- Even when Aegis is processing 10,000 EPS, its async thread model ensures the system remains responsive for the primary application workload.
- The auditor's export takes seconds, not hours, due to the Rayon-powered batch aggregation of the quarter's posture state.
