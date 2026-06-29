# Vancouver Transparency Agent (vta-core)

A high-performance Rust daemon orchestrating municipal data extraction, LLM inference, and automated newsletter publishing.

## Architecture & Subsystems
- **Scout (`scout.rs`)**: Interfaces directly with a local Firecrawl Docker API (`http://127.0.0.1:3002/v1/scrape`) to extract Markdown from heavy SPAs like the CivicClerk portal.
- **Brain (`brain.rs`)**: Connects to the Gemini REST API (gemini-3.1-flash-lite) to score public relevance (1-10) and summarize meeting topics into a strict JSON schema.
- **Memory (`memory.rs`)**: Utilizes `gcp_auth` and the Firestore REST API for serverless bookmarking and high-value signal persistence.
- **Publisher (`publisher.rs`)**: Cron-driven weekly HTML digest generation that aggregates historical signals and delegates final publication to a Python subprocess.
- **Orchestrator (`main.rs`)**: Runs the asynchronous `tokio-cron-scheduler` to manage the daemon's heartbeat.

## Setup Requirements
Ensure the following environment variables are mapped (via `.env` or system):
- `GEMINI_API_KEY`
- `FIRECRAWL_API_URL` (Defaults to localhost:3002 if unset)
- `GOOGLE_APPLICATION_CREDENTIALS` (Path to your `service-account.json`)

To execute a dry-fire test and start the daemon:
```bash
cargo run
```
