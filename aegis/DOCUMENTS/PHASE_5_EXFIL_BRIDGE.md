# Phase 5 Implementation Plan: The Exfil Bridge

This plan details the construction of the "Exfil Bridge" to bridge air-gapped forensic artifacts from the Aegis Rust engine into the Enterprise Tactical HUD. It involves creating a Python ingestion endpoint for decompression and processing, and updating the Next.js frontend with a Drag-and-Drop dropzone for field-ready exfiltration.

## User Review Required
> [!IMPORTANT]
> The Rust core is now LOCKED. No modifications to `.rs` files will be made. All logic for decompression and lineage reconstruction will be implemented in the Python layer.

## Proposed Changes

### Python Command Hub (aegis_mcp)
#### [MODIFY] [server.py](file:///c:/Antigravity%20projects/Rust/aegis/aegis_mcp/server.py)
- Implement `@app.post("/exfil/upload")` endpoint.
- Integrate `gzip` decompression for `.jsonl.gz` ledgers.
- Implement logic to hydrate `telemetry_ledger.json` from the exfiltrated data.
- Overwrite `COMMANDERS_BRIEF.md` with the field-generated brief.

#### [MODIFY] [requirements.txt](file:///c:/Antigravity%20projects/Rust/aegis/aegis_mcp/requirements.txt)
- Add `python-multipart` for robust file ingestion.

### Tactical HUD (frontend)
#### [MODIFY] [IngestionManifold.tsx](file:///c:/Antigravity%20projects/Rust/aegis/frontend/src/components/IngestionManifold.tsx)
- Transform the "Signal Manifold" into a high-fidelity Drag-and-Drop Dropzone.
- Implement specialized handling for `.gz` and `.md` forensic artifacts.
- Prompt: "DEPLOY SENSOR ARTIFACTS: Drop Aegis .gz Ledger Here."

#### [MODIFY] [page.tsx](file:///c:/Antigravity%20projects/Rust/aegis/frontend/src/app/page.tsx)
- Ensure the HUD state hydrates immediately upon successful exfil upload.

## Verification Plan
### Automated Tests
- `python scripts/test_exfil_bridge.py`: A new script to simulate dropping a `.gz` file and verifying backend parsing.
### Manual Verification
- Drag and drop the stress test `.gz` artifact produced in Phase 4 into the HUD.
- Verify "Commander's Sitrep" and "Intelligence Stream" populate with 60k event data.
