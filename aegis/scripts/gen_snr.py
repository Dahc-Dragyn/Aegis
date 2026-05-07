import json
import random
from datetime import datetime, timedelta

def generate_snr_stress_test():
    start_time = datetime.now()
    logs = []
    
    # 1. Generate 50,000 "dir" commands (Neutral)
    for i in range(50000):
        current_time = start_time + timedelta(milliseconds=i * 0.1)
        log = {
            "timestamp": current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "message": f"cmd.exe /c dir C:\\Users\\Public\\Documents\\temp_{i}.txt",
            "severity": "neutral"
        }
        logs.append(json.dumps(log))
    
    # 2. Inject a high-fidelity Mimikatz strike in the middle
    strike_time = start_time + timedelta(milliseconds=25000)
    mimikatz_log = {
        "timestamp": strike_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "message": "mimikatz.exe sekurlsa::logonpasswords",
        "severity": "hostile"
    }
    logs.insert(25000, json.dumps(mimikatz_log))
    
    with open("snr_stress_50k.jsonl", "w") as f:
        for line in logs:
            f.write(line + "\n")
            
    print(f"Generated 50,001 logs for SNR stress test.")

if __name__ == "__main__":
    generate_snr_stress_test()
