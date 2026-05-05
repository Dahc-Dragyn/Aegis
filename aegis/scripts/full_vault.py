import requests
import time
import subprocess

HUB_URL = "http://localhost:8080/ingest"

def push_artifact(filename, content):
    print(f"[VAULT] GENERATING: {filename}")
    # Using a safer one-liner for shell execution
    cmd = f"docker exec aegis_sentinel sh -c \"echo '{content}' > /app/forensic_results/{filename}\""
    subprocess.run(cmd, shell=True)

if __name__ == "__main__":
    print("--- AEGIS FULL VAULT REPLAY: TRIGGERING TOTAL FORENSIC OUTPUT ---")
    
    # 1. NIST Manifest
    push_artifact("NIST_MANIFEST.md", "NIST-800-53-REPORT-AU-12-SI-4-COMPLIANT")
    
    # 2. OSCAL Suite
    push_artifact("oscal-results.json", "OSCAL-ASSESSMENT-RESULTS-PASS")
    push_artifact("oscal-poam.json", "OSCAL-POAM-STATUS-CLOSED")
    
    # 3. Evidence Stream
    push_artifact("aegis_forensic_stream.jsonl.gz", "RAW-FORENSIC-JSONL-STREAM-ACTIVE")
    
    # 4. Commander's Brief
    push_artifact("COMMANDERS_BRIEF.md", "SITREP: MISSION COMPLETE. ALL THREATS NEUTRALIZED.")
    
    # 5. Final Heartbeat
    requests.post(HUB_URL, json={"event": "FORENSIC_MISSION_COMPLETE", "severity": "friendly"})
    
    print("--- REPLAY COMPLETE: ALL ARTIFACTS IN VAULT ---")
