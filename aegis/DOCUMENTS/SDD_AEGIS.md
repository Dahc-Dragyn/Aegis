# Software Design Document: Project Aegis 🛡️

**Project Codename**: Aegis (The Compliance-as-Code Sentinel)  
**Status**: DRAFT-VERIFIED  
**Architecture Type**: Async/Parallel Hybrid (Tokio + Rayon)

---

## 1. System Architecture Overview 🏗️

Project Aegis uses a multi-stage pipeline designed for high-velocity log ingestion and parallelized NIST-control analysis.

### A. The Ingestion Stage (Tokio)
The "Watcher" utilizes the **Tokio async runtime** and the **Notify** crate to monitor the filesystem for log changes. It tails specified files without blocking, collecting line-buffers into an asynchronous **MPSC (Multi-Producer, Single-Consumer) Channel**.

### B. The Processing Stage (Rayon)
The "Analyzer" consumes the MPSC channel. When a batch of logs arrives, the system spawns a **Rayon Thread Pool** (optimized for the 12 threads of the Ryzen 3600X) to perform parallel Regex/Grok pattern matching.

### C. The Mapping Engine (Core Logic)
The engine maintains a pre-compiled `ControlMapping` database (JSON/YAML) that links log signatures to the official **NIST SP 800-53** Control IDs (AU-2, AU-6, etc.).

---

## 2. Core Data Structures 📋

### `ControlMapping` Struct
Defines the link between a log signature and its regulatory control.
```rust
struct ControlMapping {
    pattern: Regex,         // Compiled Regex signature
    control_id: String,     // NIST Control ID (e.g., "AU-2")
    category: String,       // Control category (e.g., "Audit")
    description: String     // Purpose of the log event
}
```

### `PostureEvent` Struct
The structured packet emitted when a match occurs.
```rust
struct PostureEvent {
    timestamp: DateTime<Utc>,
    control_id: String,
    raw_log: String,
    metadata: HashMap<String, String> // Extracted fields (User, SrcIP, etc.)
}
```

---

## 3. Persistent State Management 🛡️

### The "Atomic-Move" Pattern (Write-Then-Rename)
Aegis ensures that the "Compliance Posture" (state) and "Log Offsets" are never corrupted by disk failures or system crashes.
1.  **Stage State**: Write current state to `aegis_state.json.tmp`.
2.  **Disk Sync**: Ensure the file is fully committed to the physical platter.
3.  **Rename**: Atomically rename the `.tmp` to the live `.json` file. This prevents partial-write corruption.

---

## 4. Concurrency & Thread Model (The 3600X Synergy) ⚡

Project Aegis follows a high-density threading model to ensure maximum throughput:
- **1x Async Watcher (Tokio)**: Lightweight ingestion thread.
- **1x Dispatcher (Tokio)**: Managing the MPSC queue.
- **10x Parallel Workers (Rayon)**: Dedicated to the heavy lifting of regex parsing and NIST-control correlation. This balances across the **12 logical cores** of the 3600X, leaving headroom for system O/S tasks.

---

## 5. Security Gates (The Vortex Standard) 🛡️

- **Gate 4 Integration**: Aegis incorporates a self-audit feature. Every 24 hours, it launches a sub-process to verify its own SHA-256 binary hash against a "Pristine Manifest" to detect code-tampering.
- **Lock-Free State**: Utilizes `dashmap` or atomic primitives for high-concurrency state updates, avoiding expensive global mutexes.
