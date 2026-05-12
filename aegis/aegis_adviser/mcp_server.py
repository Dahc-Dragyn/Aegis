import json
import os
from typing import Dict, List, Any, Optional
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP Server
mcp = FastMCP("AegisAdvisor")

OSCAL_PATH = "../oscal-assessment-results.json"

def _load_oscal():
    if not os.path.exists(OSCAL_PATH):
        return {}
    with open(OSCAL_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

@mcp.tool()
def get_system_posture() -> str:
    """
    Returns the high-level pass/fail status of the target system based on the Aegis OSCAL output.
    """
    data = _load_oscal()
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
    data = _load_oscal()
    results = data.get("assessment-results", {}).get("results", [])
    if not results:
        return []
    
    findings = results[0].get("findings", [])
    # In OSCAL, the UUID of the finding often maps to the chain in our specific schema
    chains = list(set(f.get("uuid") for f in findings if f.get("target", {}).get("status", {}).get("state") == "not-satisfied"))
    return chains

@mcp.tool()
def get_chain_details(chain_id: str) -> Dict[str, Any]:
    """
    Accepts a UUID and returns the detailed alerts, description, and NIST deviations for that specific chain.
    """
    data = _load_oscal()
    results = data.get("assessment-results", {}).get("results", [])
    if not results:
        return {}
    
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

if __name__ == "__main__":
    mcp.run()
