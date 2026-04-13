import sys
import os

# Add the server directory to the path
sys.path.insert(0, os.path.dirname(__file__))

from server import run_aegis_scan, query_compliance_ledger, draft_poam_ticket, update_aegis_baseline

print("🧪 Testing Aegis MCP Tools...")

# 1. Test run_aegis_scan
print("\n--- Testing run_aegis_scan ---")
scan_result = run_aegis_scan("logs/extralogfile.csv", "171")
print(scan_result)

# 2. Test query_compliance_ledger
print("\n--- Testing query_compliance_ledger (Severity: Info) ---")
# Using Info because CBS logs have many info events
ledger_result = query_compliance_ledger("Info")
try:
    import json
    data = json.loads(ledger_result)
    print(f"Successfully retrieved {len(data)} records.")
    print(f"First record sample: {data[0]['message']}")
except Exception as e:
    print(f"Query failed or returned non-JSON: {ledger_result}")

# 3. Test draft_poam_ticket
print("\n--- Testing draft_poam_ticket ---")
draft_result = draft_poam_ticket("3.14.3", "Tactical_Node_Alpha", "Immediate isolation of the suspect host and forensic dump of the CBS logs.")
print(draft_result)

# 4. Test update_aegis_baseline
print("\n--- Testing update_aegis_baseline ---")
baseline_result = update_aegis_baseline("processes", "svchost.exe", "Authorized Windows service host")
print(baseline_result)
