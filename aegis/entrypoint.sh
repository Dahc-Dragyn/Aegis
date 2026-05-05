#!/bin/bash
set -e

echo "[AEGIS] IGNITING COMMAND HUB..."
echo "[AEGIS] BINDING TO PORT 8080 (SSE)"

# Start the server and hold the process
python -u aegis_mcp/server.py
