# 🖥️ Aegis Tactical HUD
**Forensic Visualization & Real-Time Posture Management**

The Tactical HUD is a high-fidelity, glassmorphic dashboard built with Next.js and Tailwind CSS. it provides security commanders with a real-time view of the forensic landscape and NIST compliance status.

---

## ✨ Key Features

### **1. Heartbeat Posture Monitor**
Real-time status indicators (Green/Yellow/Red) tracking System Integrity, Forensic Liveness, and Compliance Drift.

### **2. NIST AU-Control Liveness Table**
A live mapping of current forensic ingestion against NIST 800-53 controls.
- **AU-3**: Audit Content Fidelity.
- **AU-6**: Audit Review, Analysis, and Reporting.
- **AU-12**: Audit Record Generation.

### **3. Forensic Command Stream**
A low-latency feed of forensic signals directly from the Aegis Rust engine.

---

## 🛠️ Tech Stack
- **Framework**: Next.js 14+ (App Router)
- **Styling**: Tailwind CSS
- **Design Language**: Cyber-forensic Dark Mode / Neon Accents
- **Icons**: Lucide React

---

## 🚀 Development
```bash
# Install dependencies
npm install

# Run the dev server
npm run dev
```

---

## 🔗 Backend Integration
The HUD is designed to communicate with the **Aegis FastMCP Bridge**, allowing for real-time triage and AI-generated remediation plans.

---
**Status: TACTICAL READY | HUD VERSION 1.0**
