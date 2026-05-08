# 🛡️ Aegis Forensic Sentinel
### **High-Throughput C4ISR Detection Engine & Standalone Tactical Manifold**

Aegis is an enterprise-grade, zero-dependency forensic sentinel engineered to correlate complex, multi-stage Advanced Persistent Threat (APT) behaviors at line speed. 

By decoupling a zero-cost abstraction Rust core from a dynamic threat intelligence manifold, Aegis evaluates live system telemetry against **7,600+ concurrent behavioral tripwires** at **80,000+ Events Per Second (EPS)**. The system is now fully self-contained, serving a high-density Tactical HUD directly from the native binary.

---

## 🛰️ System Architecture (LONE SENTINEL)

### **1. The Core (NistEngine)**
*   **Language**: Pure Rust (Self-Contained).
*   **Logic**: Stateful behavioral correlation and **Offline Provenance Engine** using `petgraph` for DAG-based process lineage reconstruction.
*   **Edge Resilience**: Integrated `redb` disk-backed spillover buffer for zero-loss ingestion during network blackouts.
*   **Compliance**: Native NIST 800-53 rev5 mapping for every signal.

### **2. The Internal Hub (Axum Server)**
*   **Native Web Server**: Built-in `Axum` server replaces the legacy Python bridge, providing high-performance REST endpoints directly from the `aegis.exe`.
*   **Embedded HUD**: The Next.js Tactical HUD is **baked into the binary** using `rust-embed`. It serves the interface instantly from memory without external files.
*   **SPA Integrity**: Industrial-grade routing with "Refresh" guards and MIME-type hardening for binary-stable browser sessions.

### **3. The Tactical HUD**
*   **Interface**: Next.js C4ISR interface featuring **DOM Virtualization**, **60FPS Physics Governor**, and **Theater Mode** (React Portals).
*   **Signal Silence**: 1:Suppressing noise (SNR) to maintain UI stability during high-velocity telemetry floods (50k+ EPS).
*   **AI Advisor**: Model-locked to `gemini-1.5-flash` for regulatory-grounded triage and automated SITREP generation.

---

## 🚀 Operational Deployment

### **Operation LONE SENTINEL (Standalone Gold Master)**
*Objective: Deploy a full forensic hub with a single file.*

1. **Execution**:
   ```powershell
   .\aegis.exe --mode standalone --auto-open
   ```
2. **Result**: 
   - Launches a native web server on `http://localhost:8080`.
   - Automatically opens the default browser to the Tactical HUD.
   - Operates in **Pure Hub** mode—ready to ingest logs via the **Ingestion Manifold** or monitor the tactical stream.

### **Operation FOB SENTINEL (CLI / Air-Gapped)**
*Objective: High-speed forensic audit of local logs.*

1. **Execution**:
   ```powershell
   .\aegis.exe <PATH_TO_LOGS> --profile 53 --output-dir forensic_results
   ```
2. **Result**: Full NIST-compliant forensic audit and sealed artifact vault (`.jsonl.gz`) generated in `forensic_results/`.

---

## 🛡️ Security & Integrity
*   **Zero-File Footprint**: The HUD and Server are internal to the binary. No Docker or Python runtime required on the host.
*   **Structural Integrity**: Hardened SPA routing prevents session loss during browser refreshes.
*   **Audit-Ready**: Native OSCAL, MANIFEST, and AU-6 receipt generation.
*   **Lineage Integrity**: DAG-based process tracking prevents PID-reuse contamination.

---
**Status: 🟢 MISSION READY | STANDALONE GOLD MASTER | LONE SENTINEL ACTIVE | Q2 2026**