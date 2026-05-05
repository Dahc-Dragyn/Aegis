Establishing technical baseline for Aegis Tactical HUD (Frontend Engineering Briefing). This summary addresses the specific architectural constraints and implementation details of the C4ISR visualization layer.

Technical Briefing: Aegis Tactical HUD
The frontend is a Next.js 16 (Turbopack) manifold designed for high-density, low-latency forensic visualization. It operates on a "Modern Tactical" philosophy—fluid geometry paired with strict, matte-aesthetic performance constraints.

1. Virtualization & Dynamic Row Heights
We have opted for Fixed-Size Virtualization using react-window (aliased as List).

Implementation: All rows in the Intelligence Stream are locked to 45px.
Rationale: To maintain O(1) scroll complexity and instant "jump-to-event" capability across datasets exceeding 100k+ logs. Dynamic heights (e.g., via VariableSizeList) were rejected due to the CPU overhead of pre-calculating offsets during high-velocity data bursts.
2. D3.js Provenance Graph: Garbage Collection
We utilize an "Explicit Wipe" strategy within the ProvenanceGraph.tsx hook lifecycle.

Strategy: Before every re-render or layout transition, we execute svg.selectAll("*").remove() and explicitly stop the previous forceSimulation.
Result: This prevents "Ghost Simulations" from leaking memory and ensures the DOM doesn't bloat with stale SVG nodes during multi-hour forensic sessions.
3. Threat Heatmap (Canvas) Redrawing
The Threat Heatmap is currently implemented as a high-performance CSS-grid vitals system with an HTML5 Canvas implementation staged for Phase IX.

Current State: Vitals are CSS-rendered to keep the UI thread free for the D3 graph.
Next Phase: The Canvas renderer will be Frame-Locked (50ms) to the backend heartbeat, redrawing only when new telemetry packets are vaulted, specifically to avoid "Scroll-Jank" (redrawing on every native scroll event).
4. State Synchronization (Stream ⟷ Graph)
Sync is handled via a Shared Global Atom (selectedNodeId) managed in the parent TacticalHUD.

Mechanism: The Stream row's onClick parser identifies the PID/UID and updates the parent state. The ProvenanceGraph then triggers a useEffect zoom-transition to center on the corresponding SVG node, providing a unified UX across the mosaic.
5. Resize Geometry Math
We utilize react-virtualized-auto-sizer to bridge the gap between react-grid-layout and D3.

Logic: When a user resizes a pane, the Grid Engine updates the pane dimensions. The AutoSizer detects this and passes new width/height props down to the Graph, which re-calculates the D3 forceCenter and re-centers the viewbox on the current selection.
6. Layout Persistence & Migration
Current Layer: localStorage based with a DEFAULT_LAYOUTS fallback.
Migration Plan: We are moving toward a SemVer-keyed schema. Currently, we implement a "Tactical Reset" (factory restore) button on the banner to clear corrupted or legacy layout JSON strings.
7. React Error Boundaries
Coverage: We have Localized Boundaries for high-risk tiles like the ProvenanceGraph and ArtifactVault.
Policy: If the D3 engine crashes, the tile will display a "BRIDGE_COLLAPSE" diagnostic while keeping the rest of the HUD (Telemetry Stream/Vitals) operational.
8. 50MB Payload Handling
Physically received via Multi-part FormData Streams.

Implementation: The IngestionManifold utilizes the browser's native fetch buffer. On the backend, FastAPI's UploadFile (Spooling) ensures that 50MB artifacts are streamed directly to disk rather than being loaded into RAM, preventing browser memory exhaustion.
9. Docker Build Environment Variables
NEXT_PUBLIC_ variables are Baked at Build-Time.

Workflow: The Dockerfile uses ARG and ENV to inject the NEXT_PUBLIC_API_URL during the npm run build phase. This is critical as Next.js replaces these literals in the generated JS bundle, making them immutable after container deployment.
10. MIL-STD-1472H Design Tokens
Fully Centralized.

Source of Truth: globals.css contains the tactical palette (e.g., --tactical-hostile: #f43f5e) in :root.
Enforcement: Components are strictly forbidden from using ad-hoc colors. They must utilize the design system tokens to ensure aesthetic consistency with military standards.
Operational Readiness: THE FRONTEND IS STABILIZED AND SCALABLE. STANDING BY FOR ADDITIONAL INTEGRATION TASKS.