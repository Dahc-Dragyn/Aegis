# System Architecture Document (SAD): ForgeControl (vta-core)

## 1. System Overview & Objectives
ForgeControl (vta-core) is a high-performance, local-first transparency daemon engineered in Rust. It serves as the automated core for the Vancouver Transparency Agent, actively auditing municipality records to surface high-impact regional signals. By replacing legacy, resource-heavy Python browser infrastructure with a compiled, asynchronous runtime, the system maximizes execution speed while maintaining a near-zero memory footprint.

**Core Architecture Goals**
- **Performance**: Achieve deterministic, ultra-low latency scheduling loops using a compiled memory-safe runtime.
- **Decoupled Web Ingestion**: Delegate complex DOM rendering, proxy rotation, and PDF parsing entirely to an isolated Model Context Protocol (MCP) server.
- **Cost Minimization**: Restructure prompt traffic patterns to utilize cost-efficient, high-speed lean inference loops.
- **Platform Stability**: Prevent execution hangs or state leaks through isolated subprocess sandboxing and stateless REST patterns.

## 2. High-Level Component View
The architecture separates responsibilities into distinct modules within the unified vta-core crate, communicating across strictly decoupled boundaries.

```text
       +-------------------------------------------------------+
       |                  vta-core (Rust Core)                 |
       |  +-------------------------------------------------+  |
       |  |          Job Scheduler (Tokio / 6-Hour)         |  |
       |  +------------------------+------------------------+  |
       |                           |                           |
       +---------------------------+---------------------------+
               |                   |                   |
    (Local HTTP / SSE)       (HTTPS REST)        (HTTPS REST)
               |                   |                   |
               v                   v                   v
      +-----------------+ +-----------------+ +-----------------+
      |  Firecrawl MCP  | |   Gemini API    | |  Firestore API  |
      |   (Local TCP)   | |  (3.1-Flash-Lite)| |     (Stateless)   |
      +-----------------+ +-----------------+ +-----------------+
                                                       |
                                            (Friday Digest Event)
                                                       |
                                                       v
                                              +-----------------+
                                              |  vta_publisher  |
                                              |  (Python SubPr) |
                                              +-----------------+
                                                       |
                                                       v
                                              +-----------------+
                                              | Substack Engine |
                                              +-----------------+
```

## 3. Subsystem Decomposition

### 3.1 The Orchestrator (`main.rs`)
The backbone execution manager operating on a multi-threaded tokio asynchronous runtime. It initializes the execution context, evaluates local configurations, and anchors the persistent lifecycle of the daemon via an asynchronous cron engine (tokio-cron-scheduler) set to hard 6-hour execution intervals.

### 3.2 The Scout (`scout.rs`)
Manages the web collection protocol. Instead of maintaining local browser state, it acts as a stateless client communicating with a dedicated Firecrawl MCP instance over a local TCP loopback via Server-Sent Events (SSE). It streams clean Markdown data back to the core and enforces strict validation checks to drop "Empty Shell" server responses before wasting downstream context window space.

### 3.3 The Brain (`brain.rs`)
Coordinates contextual interpretation by routing structured Markdown text directly through the Gemini API. It leverages the hyper-lean gemini-3.1-flash-lite model instance to score meeting data on a metric scale of 1–10 and maps the returned raw string back into immutable type-safe Rust structures.

### 3.4 The Memory (`memory.rs`)
Handles database interaction. It completely bypasses heavy, slow-to-update client SDK layers, interacting directly with the Google Firestore REST API endpoint using standard asynchronous reqwest calls and transactional JSON payloads.

### 3.5 The Publisher (`publisher.rs`)
Manages the end-of-week compilation. Every Friday, it queries historical entries from the persistence layer, leverages inference to format a comprehensive HTML digest, and spawns an isolated Python runtime instance to execute the actual publication.

## 4. Interfaces & Data Flow

### 4.1 Chronological Processing Loop (6-Hour Interval)
- **Trigger**: JobScheduler fires an asynchronous event.
- **State Retrieval**: memory.rs requests active targets and bookmark keys from Firestore via HTTP GET.
- **Extraction Stream**: scout.rs connects to the local Firecrawl MCP server, requesting document processing via SSE.
- **Analysis**: brain.rs serializes the returned text into a structured JSON request payload for gemini-3.1-flash-lite.
- **Persistence**: Scored payloads that clear the safety validation gate (Score >= 7) are written directly back to Firestore over HTTPS POST.

### 4.2 Substack Publishing Sequence (Weekly)
Because Substack lacks an open write API, web automation must be strictly sandboxed to protect the stability of the core daemon:

```text
+----------+             +---------------+             +-------------------+
| vta-core |             |  publisher.rs |             | vta_publisher.py  |
+----+-----+             +-------+-------+             +---------+---------+
     |                           |                               |
     | Trigger Friday Event      |                               |
     |-------------------------->|                               |
     |                           |                               |
     |                           | Spawn Subprocess Context      |
     |                           |------------------------------>|
     |                           |                               | --+
     |                           |                               |   | Execute Playwright
     |                           |                               |   | Login & Injection
     |                           |                               | <-+
     |                           |                               |
     |                           | Return Command Exit Status    |
     |                           |<------------------------------|
     |                           |                               |
     | Clean Resource Deallocation|                               |
     |<--------------------------|                               |
```

## 5. Security Boundaries & Operational Defenses
- **Isolated Networking**: The connection between vta-core and the Firecrawl MCP is hard-locked to the local loopback boundary (127.0.0.1). This blocks external intercept vectors and eliminates standard Windows Named Pipe handle exhaustion vulnerabilities.
- **Type-Safe Validation**: Every single external endpoint return boundary is rigorously audited by serde. Hallucinated or malformed JSON payloads fail instantly at the interface tier before corrupting internal memory states.
- **Memory Leaking Containment**: Headless browsers naturally leak memory over long operational durations. By offloading this task to a decoupled MCP process and isolating Substack publishing within a short-lived Python script execution, the primary Rust engine remains perfectly stable indefinitely.