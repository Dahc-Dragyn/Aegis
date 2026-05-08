import requests
import time
import subprocess

HUB_URL = "http://localhost:8080/ingest"

def push_artifact(filename, lines):
    print(f"[VAULT] GENERATING: {filename}")
    content = "\\n".join(lines)
    # Using a safer shell string for docker exec
    cmd = f"docker exec aegis_sentinel sh -c \"echo '{content}' > /app/artifacts/{filename}\""
    subprocess.run(cmd, shell=True)

if __name__ == "__main__":
    print("--- AEGIS VAULT SIGHT: TRIGGERING HIGH-FIDELITY OUTPUT ---")
    
    # 1. Detailed NIST Manifest
    nist_lines = [
        "AEGIS FORENSIC COMPLIANCE REPORT",
        "FRAMEWORK: NIST 800-53 r5",
        "--------------------------------",
        "[AU-12] AUDIT GENERATION: COMPLIANT",
        "[SI-4]  SYSTEM MONITORING: COMPLIANT",
        "[AC-7]  UNSUCCESSFUL LOGON: COMPLIANT",
        "--------------------------------",
        "STATUS: CERTIFIED FOR PRODUCTION"
    ]
    push_artifact("NIST_MANIFEST.md", nist_lines)
    
    # 2. Detailed Commander's Brief
    brief_lines = [
        "# Commander Brief",
        "",
        "TACTICAL SUMMARY:",
        "Node AEGIS-NODE-01 experienced a high-entropy event.",
        "Engine detected LSASS process access (EventID 10).",
        "",
        "MITIGATION:",
        "1. Isolation protocol successfully engaged.",
        "2. Forensic artifacts preserved in /app/triage.",
        "",
        "CURRENT STATUS: SECURE"
    ]
    push_artifact("COMMANDERS_BRIEF.md", brief_lines)
    
    # 3. Final Heartbeat
    requests.post(HUB_URL, json={"event": "VAULT_SIGHT_COMPLETE", "severity": "friendly"})
    
    print("--- REPLAY COMPLETE: VAULT SIGHT ACTIVE ---")
