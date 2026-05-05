# 📡 Aegis Tactical HUD: C4ISR Engineering Guide
**Version: 1.0.0 | Security Classification: UNCLASSIFIED/FOUO**

## 1. Operational Context (CONOPS)
The Aegis Tactical HUD is NOT a dashboard; it is a **Tactical Glass** for high-velocity forensic correlation. It must maintain stability under 79k EPS while providing the Commander with an immediate W5 Brief (Who, What, When, Where, Why).

---

## 2. Design Architecture (MIL-SPEC)

### **A. Visual Language (MIL-STD-1472H)**
- **Palette**: Use `#121212` (Slate Black) background. Contrast is life. 
- **Symbology (MIL-STD-2525D)**:
  - **Hostile**: Red Diamond Frames (`#FF0000`).
  - **Friendly**: Green Circle Frames (`#00FF00`).
  - **Unknown**: Yellow Square Frames (`#FFFF00`).
- **Typography**: 
  - **Telemetry**: `JetBrains Mono` or `Fira Code`. 10pt for dense data grids.
  - **Command**: `Inter` or `Outfit`. Bold for SITREPs.

### **B. The 12-Column Tactical Grid**
- **Upper Quadrant**: Heartbeat Posture (System Integrity, Ingestion Liveness).
- **Center Mass**: The Commander’s SITREP Pane (Gemini-3.1 Synthesis).
- **Left Flank**: Provenance Graph (D3.js Process Lineage).
- **Right Flank**: Kill Chain Interface (SOAR Controls with Safety-Off triggers).
- **Sub-Floor**: High-Velocity Telemetry Feed (Virtualized).

---

## 3. Engineering Requirements

### **A. Performance (The 79k EPS Challenge)**
- **Virtualized Rendering**: Use `@tanstack/react-virtual` for all telemetry feeds.
- **Micro-Batching**: Buffer incoming WebSockets for 100ms before state updates.
- **Off-Main-Thread**: Perform complex lineage tree calculations in a Web Worker to prevent UI stutter.

### **B. Data Integration**
- **Bridge**: Connection to `aegis_mcp/server.py` via WebSockets.
- **End-to-End Latency**: Target <100ms from Detection to HUD Render.
- **State Management**: `Zustand` with transient updates for high-frequency severity counters.

### **C. The Auditor's "Proof Block" (CONOPS 3.B)**
- **Requirement**: A specialized view for quarterly sign-off.
- **Visuals**: 
  - **Random Sampler**: Displays 10-20 randomly selected logs with their cryptographic hashes.
  - **Uptime Matrix**: A percentage-of-time breakdown for every NIST control.
  - **The Seal**: A SHA-256 integrity seal for the entire quarter's ledger.
  - **Sign-off Interface**: Dual signature blocks (Auditor + ISSO) for final certification.

---

## 4. NIST Compliance Features (AU/SI)

### **A. AU-6/AU-11 Audit Chain**
- Implement a **"Vault View"** that displays the SHA-256 hash and cryptographic signature for every audit record.
- Visual proof of chain-of-custody for courtroom-ready forensics.

### **B. Access Control (AC-7)**
- Mandatory **DoD System Use Notification Banner** on the `/login` route.
- Session-Zeroing: Auto-purge local state on timeout or disconnect.

---

## 5. Component Implementation Checklist

- [ ] **Heartbeat Component**: SVG-based pulse reflecting Rust engine health.
- [ ] **Provenance Graph**: D3.js force-directed graph with parent/child node relationships.
- [ ] **SITREP Pane**: Markdown renderer for Gemini-3.1 synthesized briefings.
- [ ] **Safety-Off Button**: A "Hold-to-Confirm" or "Flip-Switch" UI component for SOAR actions.
- [ ] **Virtualized Ledger**: 60fps scrolling for high-density log data.

---
**"Data is the ammunition. The HUD is the sight."**
