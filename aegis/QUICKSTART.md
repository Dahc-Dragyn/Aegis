# Aegis Quickstart Guide: Operation Platinum

This guide outlines the end-to-end workflow for the Aegis "Lone Sentinel" forensic manifold, integrating the high-performance Rust ingestion engine with the Gemini-powered AI Advisor.

## 🛠️ Architecture Overview
1.  **The Sentinel (Rust)**: High-velocity forensic ingestion (12,400+ EPS) and NIST 800-53 correlation.
2.  **The Advisor (Python)**: Agentic reasoning engine (Gemini 3.1 Flash-Lite) for automated SITREP synthesis and remediation.

---

## 🚀 Execution Workflow

### Step 1: Ingest & Correlate (Sentinel)
Run the Rust engine to parse EVTX logs and generate the forensic manifold.
```powershell
# Build the production binary
cargo build --release

# Execute ingestion against a target log set
./target/release/aegis.exe --logs ./logs/target_attack.evtx --output ./oscal-assessment-results.json
```

### Step 2: Initialize the Advisor (One-time)
Setup the Python environment for the reasoning engine.
```powershell
cd aegis_adviser
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### Step 3: Generate the SITREP (Advisor)
Trigger the 3.1 Agentic Loop to synthesize the findings and open the interactive gate.
```powershell
# Ensure your AEGIS_GEMINI_KEY is in the root .env file
python advisor_cli.py
```

---

## 📊 Outputs & Artifacts
- **`oscal-assessment-results.json`**: The raw machine-readable forensic ledger.
- **`COMMANDERS_BRIEF.md`**: The AI-synthesized executive SITREP with NIST remediation advice.
- **`Interactive REPL`**: The Advisor stays online to answer follow-up forensic questions.

---
**STATUS: PLATINUM CERTIFIED**
**AUTHOR: AEGIS COMMAND**
