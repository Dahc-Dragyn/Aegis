# Software Test Plan (STP): Project Aegis 🛡️

**Project Codename**: Aegis (The Compliance-as-Code Sentinel)  
**Verification Engine**: `cargo nextest` (Parallel execution)  
**Baseline Hardware**: AMD Ryzen 5 3600X (12 Threads)

---

## 1. Functional Test Battery (NIST Mapping)

### Test Case: TC-AU2-01 (Event Ingestion)
- **Objective**: Prove the system correctly identifies and maps a failed login.
- **Input**: `Apr 02 14:00:00 server sshd[123]: Failed password for root from 192.168.1.1 port 22`
- **Expected Result**: 
    - Event emitted as JSON.
    - `control_id` equals `AU-2`.
    - `category` equals `Logging`.
- **Success Criteria**: Match verified via `assert_eq!`.

### Test Case: TC-AC3-01 (Privilege Escalation)
- **Objective**: Prove the system identifies unauthorized `sudo` attempts.
- **Input**: `Apr 02 14:05:00 server sudo: pam_unix(sudo:auth): authentication failure; logname=user uid=1000 euid=0`
- **Expected Result**: 
    - Event emitted as JSON.
    - `control_id` equals `AC-3`.
    - `metadata.user` matches `user`.
- **Success Criteria**: Field extraction verified via `Regex` captures.

---

## 2. Performance & Stress Battery (3600X Baseline)

### Test Case: TC-PR1-01 (Throughput Stress)
- **Objective**: Verify the 10,000 EPS (Events Per Second) requirement.
- **Input**: 600,000 mock log lines streamed over a 60-second window.
- **Expected Result**: 
    - Zero dropped events.
    - Average processing time per event < 1ms.
    - CPU utilization balanced across all 12 worker threads.
- **Success Criteria**: Throughput calculation >= 10,000 EPS.

### Test Case: TC-PR1-02 (Memory Stability)
- **Objective**: Prove zero memory leaks during high-velocity bursts.
- **Input**: Sustained 5,000 EPS for 10 minutes.
- **Expected Result**: 
    - Resident Set Size (RSS) remains within +/- 5% of initial baseline after first 30 seconds.
- **Success Criteria**: Heap memory profiling via `valgrind` or `dhat` shows minimal fragmentation.

---

## 3. Security & Safety Battery (Gate 4)

### Test Case: TC-SR1-01 (Supply Chain Audit)
- **Objective**: Certify that the Aegis binary is free of known vulnerabilities.
- **Input**: `cargo audit` command execution.
- **Expected Result**: 
    - 0 Critical advisory found.
    - 0 High advisory found.
- **Success Criteria**: Exit code 0.

### Test Case: TC-SR1-02 (Static Binary Portability)
- **Objective**: Prove zero external runtime library dependencies.
- **Input**: `ldd ./target/release/aegis` (or equivalent `dumpbin` on Windows).
- **Expected Result**: 
    - Only core system libraries (kernel32.dll/ntdll.dll) linked.
    - No dynamic linkage to OpenSSL or LibC (musl/static linking enabled).
- **Success Criteria**: Binary executes on a "clean room" OS environment.

---

## 4. Operational Interface Battery

### Test Case: TC-OR1-01 (Audit Trail Integrity)
- **Objective**: Verify the `aegis export --quarterly` command integrity.
- **Input**: 1,000 captured events over a mock "Quarter".
- **Expected Result**: 
    - Generated Markdown/PDF manifest contains all event timestamps.
    - SHA-256 hash matches the original event buffer.
- **Success Criteria**: Integrity hash verification returns `MATCH`.
