# 1. Executive Summary
The Vancouver Transparency Agent (VTA), currently operating as a Python-based orchestrator utilizing Playwright for web extraction, is undergoing a full architectural rewrite into Rust (vta-core). This rewrite will eliminate the fragility of headless browser automation, drastically reduce memory footprint, and increase deterministic execution speed. Complex scraping and JavaScript rendering are offloaded entirely to a local Firecrawl Model Context Protocol (MCP) server.

# 2. System Architecture
The vta-core architecture operates as a lightweight, asynchronously scheduled daemon. The proposed system design breaks down into four core components:
- **The Orchestrator (Rust Core)**: A compiled tokio runtime that handles cron-based scheduling (tokio-cron-scheduler) and coordinates external API calls.
- **The Scout (Firecrawl MCP)**: A dedicated local server that handles dynamic DOM rendering, PDF parsing, and markdown extraction.
- **The Brain (Gemini Inference)**: Evaluates extracted meeting records against a predefined analytical persona utilizing gemini-3.1-flash-lite.
- **The Memory (Firestore)**: Persists configuration states, bookmark fingerprints, and scored signals via the Firestore REST API.

# 3. Communication Interfaces
To determine consistency and reduce internal dependencies, the vta-core orchestrator utilizes reqwest to manage all external boundaries via standard HTTP requests.
- **MCP Boundary**: Connects to the local Firecrawl server (e.g., 127.0.0.1:8080) over Server-Sent Events (SSE) to request target URLs and stream back markdown. This cleanly avoids Windows-specific named pipe exhaustion.
- **Inference Boundary**: Formats and transmits extracted context to the Gemini API, expecting a structured JSON response containing the analysis and risk scores.
- **Database Boundary**: Executes stateless GET and POST requests directly against the Firestore REST API using serde_json, eliminating the need for heavyweight, lagging SDK dependencies.

# 4. Subprocess Management & Publishing
Substack publishing relies on a strictly isolated execution environment to circumvent API limitations.
- **Trigger**: Upon compiling the Friday digest, the Rust orchestrator spawns a localized Python subprocess (vta_publisher.py).
- **Execution**: The Python wrapper temporarily spins up a Playwright context solely to authenticate and inject the formatted HTML draft into the Substack interface.
- **Cleanup**: Once the subprocess returns a success exit code, the Rust orchestrator cleanly releases the memory allocation.

# 5. Security & Error Handling
- **Fault Tolerance**: Async network requests are wrapped in explicit timeout and recovery strategies to ensure the daemon does not hang on degraded API endpoints.
- **Data Validation**: All incoming JSON payloads from Gemini and Firestore are rigorously verified using strict serde structs.
- **Process Isolation**: By segregating the web scraper (Firecrawl) and the publisher (Python) from the main executable, vta-core acts purely as a secure router, immune to internal browser crashes.