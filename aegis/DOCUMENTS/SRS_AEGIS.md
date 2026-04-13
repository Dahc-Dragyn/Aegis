# Software Requirements Specification: Project Aegis 🛡️

**Project Codename**: Aegis (The Compliance-as-Code Sentinel)  
**Status**: DRAFT-VERIFIED  
**Baseline Hardware**: AMD Ryzen 5 3600X (12 Threads)

---

## 1. Functional Requirements (FR)

### FR-1: Log Ingestion
- **FR-1.1**: The system **shall** tail flat-text log files (e.g., `auth.log`, `syslog`) in real-time.
- **FR-1.2**: The system **shall** support asynchronous, non-blocking file watching using the `notify` and `tokio` frameworks.
- **FR-1.3**: The system **shall** maintain persistent byte-offsets to ensure zero-loss monitoring across reboots.

### FR-2: NIST Control Mapping
- **FR-2.1**: The system **shall** map `sshd` failure patterns (Failed Password, Invalid User) to **NIST SP 800-53 Control AU-2** (Event Logging).
- **FR-2.2**: The system **shall** map `sudo` privilege escalation attempts to **NIST SP 800-53 Control AC-3** (Access Enforcement).
- **FR-2.3**: The system **shall** map user creation/deletion events to **NIST SP 800-53 Control AC-2** (Account Management).
- **FR-2.4**: The system **shall** generate a "Compliance Heartbeat" reporting the current capture status of all mapped controls.

---

## 2. Performance Requirements (PR)

### PR-1: Throughput (The 3600X Benchmark)
- **PR-1.1**: The system **shall** process log events at a minimum sustained rate of **10,000 EPS (Events Per Second)** on the baseline hardware.
- **PR-1.2**: The system **shall** utilize all **12 worker threads** for parallel pattern-matching tasks during high-velocity bursts.

### PR-2: Latency
- **PR-2.1**: The time from log ingestion to NIST control mapping **shall** not exceed 10ms for 99% of events (p99).

---

## 3. Security & Safety Requirements (SR)

### SR-1: Binary Integrity
- **SR-1.1**: The system **shall** be distributed as a single, statically-linked binary with zero external runtime dependencies.
- **SR-1.2**: The system **shall** be compiled with stack protections and memory-safety flags enabled.

### SR-2: Supply Chain Audit (Gate 4)
- **SR-2.1**: Every production-ready build **shall** pass a full `cargo audit` with zero critical or high-severity vulnerabilities.

---

## 4. Operational Interface (OR)

### OR-1: Reporting
- **OR-1.1**: The system **shall** produce a structured JSON heartbeat output at an organization-defined interval (default 5 minutes).
- **OR-1.2**: The system **shall** support a manual "Audit Export" that aggregates all captured compliance events for a defined time range into a machine-readable format.
