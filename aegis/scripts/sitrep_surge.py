import requests
import time
import os
import subprocess

HUB_URL = "http://localhost:8080/ingest"

def update_sitrep(text):
    print(f"[HUD] UPDATING SITREP: {text}")
    cmd = f"docker exec aegis_sentinel sh -c \"echo '# Commander Brief\\n\\n{text}' > /app/forensic_results/COMMANDERS_BRIEF.md\""
    subprocess.run(cmd, shell=True)

def fire_signal(event, severity):
    payload = {"event": event, "severity": severity}
    requests.post(HUB_URL, json=payload)
    print(f"[FIRE] {event} ({severity})")

if __name__ == "__main__":
    print("--- AEGIS SITREP SURGE: STARTING DYNAMIC REPLAY ---")
    
    # Phase 1: Incursion
    update_sitrep("ANALYZING MANIFOLD... SCANNING NODES.")
    for _ in range(5):
        fire_signal("SCANNING_PORTS", "neutral")
        time.sleep(1)

    # Phase 2: Detection
    update_sitrep("WARNING: UNKNOWN PROCESS DETECTED IN NODE_01.")
    for _ in range(5):
        fire_signal("UNAUTHORIZED_PROCESS", "warning")
        time.sleep(1)

    # Phase 3: Critical
    update_sitrep("CRITICAL: LSASS ACCESS DETECTED. CREDENTIAL THEFT LIKELY.")
    for _ in range(5):
        fire_signal("CHROME_CREDENTIAL_THEFT", "hostile")
        time.sleep(1)

    # Phase 4: Resolution
    update_sitrep("THREAT NEUTRALIZED. ISOLATION PROTOCOL ENGAGED.")
    fire_signal("NODE_ISOLATED", "friendly")
    
    print("--- REPLAY COMPLETE ---")
