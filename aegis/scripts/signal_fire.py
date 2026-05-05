import requests
import json
import time
import random

HUB_URL = "http://localhost:8080/ingest"

SIGNALS = [
    ("SI-4 VIOLATION", "hostile"),
    ("AC-7 TRIGGERED", "warning"),
    ("CHROME_CREDENTIAL_THEFT", "hostile"),
    ("TCC_BYPASS_ATTEMPT", "warning"),
    ("PROCESS_INJECTION_DETECTED", "hostile"),
    ("NETWORK_BEACONING", "warning"),
    ("SYSMON_EVENT_10", "neutral"),
    ("NIST_COMPLIANCE_CHECK", "friendly"),
    ("KERNEL_SIGNAL_INTERCEPT", "neutral")
]

def fire_signal():
    event, severity = random.choice(SIGNALS)
    payload = {
        "timestamp": time.strftime("%H:%M:%S", time.localtime()),
        "event": event,
        "severity": severity,
        "details": f"Forensic Artifact: {random.getrandbits(32):x}"
    }
    
    try:
        response = requests.post(HUB_URL, json=payload, timeout=1)
        if response.status_code == 200:
            print(f"[FIRE] {event} ({severity}) -> INGESTED")
        else:
            print(f"[FAIL] {response.status_code}")
    except Exception as e:
        print(f"[ERR] {str(e)}")

if __name__ == "__main__":
    print("--- AEGIS SIGNAL FIRE: STARTING HIGH-LOAD REPLAY ---")
    print("TARGET: " + HUB_URL)
    
    # We'll fire 100 signals at high speed
    for i in range(100):
        fire_signal()
        # High speed injection: 10 signals per second
        time.sleep(0.1)
    
    print("--- REPLAY COMPLETE ---")
