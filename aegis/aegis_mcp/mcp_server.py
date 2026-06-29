import json
import os
import gzip
import shutil
from datetime import datetime
from typing import Dict, List, Any, Optional
from mcp.server.fastmcp import FastMCP

# Initialize Unified Aegis MCP Server
mcp = FastMCP("Aegis-Sentinel")

# --- PATH CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE_DIR, "forensic_results")
OSCAL_PATH = os.path.join(BASE_DIR, "oscal-assessment-results.json")
LEDGER_PATH = os.path.join(RESULTS_DIR, "telemetry_ledger.json")
ISOLATION_STATE_PATH = os.path.join(RESULTS_DIR, "isolation_state.json")
NIST_MAPPINGS_PATH = os.path.join(BASE_DIR, "intel", "nist_mappings.json")

os.makedirs(RESULTS_DIR, exist_ok=True)

# --- UTILS ---
def _load_json(path: str) -> Any:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

def _save_json(path: str, data: Any):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# --- TOOLS (From aegis_adviser/mcp_server.py) ---

@mcp.tool()
def get_system_posture() -> str:
    """
    Returns the high-level pass/fail status of the target system based on the Aegis OSCAL output.
    """
    data = _load_json(OSCAL_PATH)
    results = data.get("assessment-results", {}).get("results", [])
    if not results:
        return "CRITICAL: No forensic results found."
    
    findings = results[0].get("findings", [])
    deviations = [f for f in findings if f.get("target", {}).get("status", {}).get("state") == "not-satisfied"]
    
    if not deviations:
        return "SECURE: All NIST controls satisfied."
    else:
        return f"FAILED: {len(deviations)} compliance deviations detected."

@mcp.tool()
def list_attack_chains() -> List[str]:
    """
    Returns a list of all unique incident-id UUIDs (Attack Chains) found in the report.
    """
    data = _load_json(OSCAL_PATH)
    results = data.get("assessment-results", {}).get("results", [])
    if not results:
        return []
    
    findings = results[0].get("findings", [])
    chains = list(set(f.get("uuid") for f in findings if f.get("target", {}).get("status", {}).get("state") == "not-satisfied"))
    return chains

@mcp.tool()
def get_chain_details(chain_id: str) -> Dict[str, Any]:
    """
    Accepts a UUID and returns the detailed alerts, description, and NIST deviations for that specific chain.
    """
    data = _load_json(OSCAL_PATH)
    results = data.get("assessment-results", {}).get("results", [])
    if not results:
        return {"error": "No results found."}
    
    findings = results[0].get("findings", [])
    for f in findings:
        if f.get("uuid") == chain_id:
            return {
                "id": chain_id,
                "title": f.get("title"),
                "description": f.get("description"),
                "occurrence_count": f.get("occurrence-count"),
                "status": f.get("target", {}).get("status", {}).get("state")
            }
    return {"error": f"Chain {chain_id} not found."}

# --- TOOLS (From aegis_mcp/server.py) ---

@mcp.tool()
def get_commander_sitrep() -> str:
    """
    Retrieves the latest Commander's Brief (SITREP) from the forensic results.
    """
    path = os.path.join(RESULTS_DIR, "COMMANDERS_BRIEF.md")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return "WAITING FOR SIGNAL... (No sitrep found)"

@mcp.tool()
def list_forensic_artifacts() -> List[Dict[str, str]]:
    """
    Lists all artifacts in the forensic vault (MD, JSON, EVTX, etc.)
    """
    if not os.path.exists(RESULTS_DIR): return []
    
    files = []
    ALLOWED_EXT = [".md", ".json", ".pdf", ".log", ".txt", ".evtx", ".gz"]
    EXCLUDE = ["telemetry_ledger.json", "isolation_state.json"]
    
    raw_files = os.listdir(RESULTS_DIR)
    filtered = [f for f in raw_files if os.path.splitext(f)[1].lower() in ALLOWED_EXT and f not in EXCLUDE]
    filtered.sort(key=lambda x: os.path.getmtime(os.path.join(RESULTS_DIR, x)), reverse=True)

    for f in filtered:
        f_lower = f.lower()
        type_tag = "LOG"
        if "brief" in f_lower: type_tag = "BRIEF"
        elif "nist" in f_lower: type_tag = "NIST"
        elif "oscal" in f_lower: type_tag = "OSCAL"
        elif f_lower.endswith(".gz"): type_tag = "LEDGER"
        
        files.append({
            "name": f, 
            "type": type_tag,
            "timestamp": datetime.fromtimestamp(os.path.getmtime(os.path.join(RESULTS_DIR, f))).strftime("%H:%M:%S")
        })
    return files

@mcp.tool()
def get_telemetry_history(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Retrieves the most recent telemetry events from the ledger.
    """
    history = _load_json(LEDGER_PATH)
    if isinstance(history, list):
        return history[:limit]
    return []

@mcp.tool()
def get_isolation_status() -> Dict[str, bool]:
    """
    Checks if the system is currently in ACTIVE_ISOLATION mode.
    """
    return _load_json(ISOLATION_STATE_PATH) or {"isolated": False}

@mcp.tool()
def toggle_system_isolation() -> str:
    """
    Toggles the system between PASSIVE_MONITORING and ACTIVE_ISOLATION.
    """
    state = _load_json(ISOLATION_STATE_PATH) or {"isolated": False}
    state["isolated"] = not state["isolated"]
    _save_json(ISOLATION_STATE_PATH, state)
    status = "ACTIVE_ISOLATION" if state["isolated"] else "PASSIVE_MONITORING"
    return f"System transitioned to {status}."

@mcp.tool()
def get_nist_remediation_advice(control_id: str) -> str:
    """
    Provides remediation advice for a specific NIST control ID.
    """
    mappings = _load_json(NIST_MAPPINGS_PATH)
    if isinstance(mappings, list):
        for item in mappings:
            if item.get("control_id") == control_id:
                return item.get("remediation", "No specific advice found.")
    return f"No mapping found for control {control_id}."

if __name__ == "__main__":
    mcp.run()
