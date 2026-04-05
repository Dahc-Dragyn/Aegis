# Preliminary Design Review: Project Aegis (Compliance-as-Code Sentinel) 🛡️

**Version**: 0.1.0-DRAFT  
**Status**: PENDING_REVIEW  
**Target Compliance**: NIST SP 800-53 (Rev 5) — Audit and Accountability (AU) Family

---

## 1. Executive Summary: The "Audit-in-a-Box"

Project Aegis is a specialized, high-performance evolution of the **Log Sentinel**. It transforms raw system telemetry into real-time, actionable compliance data. Designed specifically for small-to-medium defense contractors (DIB), it automates the expensive and manual process of mapping system logs to specific federal security controls.

### Value Proposition:
- **Zero-Dependency Binary**: Distribute as a single, statically-linked Rust executable. No JVM, no Python, no bloat.
- **Memory-Safe Compliance**: Rust’s ownership model eliminates buffer overflows—making Aegis its own "Security Control."
- **NIST Integrated**: Direct mapping of log patterns (failed logins, privilege escalation) to NIST Control IDs.

---

## 2. Technical Architecture 🏗️

### A. The Aegis Pipeline
1.  **Ingestion Layer (Tokio + Notify)**: Utilizes asynchronous file-watching to tail system logs (e.g., `auth.log`, `syslog`, `windows-event-v2`) with zero-latency.
2.  **The Mapping Engine (JSON/YAML Database)**: A highly-efficient pattern-matcher that links Regex/Grok signatures to NIST SP 800-53 Control IDs.
3.  **The Posture Aggregator (State Machine)**: Tracks the "Liveness" of each control. If AU-2 (Event Selection) hasn't seen a log in 24 hours, the heartbeat alerts.

### B. NIST Control Mapping Matrix (Phase 1)
| Control ID | Title | Aegis Implementation | Log Vector Example |
| :--- | :--- | :--- | :--- |
| **AU-2** | Event Logging | Detects when auditable events occur. | `sshd[123]: Failed password for root` |
| **AU-6** | Review / Analysis | Automated flagging of unusual event spikes. | Pattern mismatch or volume anomaly. |
| **AU-12** | Record Generation | Real-time generation of audit records. | Timestamp-to-NIST formatted JSON. |
| **AC-2** | Account Management | Monitors user creation/deletion events. | `/bin/useradd: new user added` |

---

## 3. Core Features 🌟

### 📊 Real-Time Compliance Heartbeat
A CLI-based (or JSON-over-Socket) status indicator showing the **Current Compliance Posture (CCP)**.
- **Green**: 100% of required AU-controls are surfacing events.
- **Yellow**: Coverage gaps detected (e.g., Log rotation failure).
- **Red**: Critical control failure (e.g., Logging daemon stopped).

### 🛠️ The "Audit-Ready" Export
A one-command export tool (`aegis export --quarterly`) that generates a structured report for RMF/DoD auditors, proving that log review occurred consistently over the period.

---

## 4. Hardware Synergy (The 3600X Strategy) ⚡

- **Parallel Ingestion**: Across high-velocity server logs, Aegis will utilize all **12 threads** of the Ryzen 3600X to perform parallel pattern-matching on incoming log buffers using **Rayon**.
- **Lock-Free State**: Use atomic counters and non-blocking I/O to ensure the "Security Control" never becomes a "Performance Bottleneck."

---

## 5. Security & Safety Gate 🛡️

- **Gate 4 (Continuous Audit)**: Every build cycle will automatically run `cargo audit`. The product itself will ships with its own Dependency Audit report to prove a pristine supply chain.
- **Self-Monitoring**: Aegis monitors its own memory and process health—if its PID is tampered with, it logs a "Tamper Event" to a remote syslog (Self-Preservation).
