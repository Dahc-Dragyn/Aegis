import json
import random
from datetime import datetime, timedelta

def generate_logs(count=60000):
    start_time = datetime(2026, 5, 3, 10, 0, 0)
    logs = []
    
    # Track processes for fusion and recycling
    active_pids = {}
    
    correlated_count = 0
    anomalies_count = 0
    
    # Pre-defined shells for anomalies
    shells = ["powershell.exe", "cmd.exe", "pwsh.exe", "mshta.exe"]
    
    for i in range(count):
        current_time = start_time + timedelta(milliseconds=i * 10) # 100 EPS
        timestamp_str = current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        
        rand_val = random.random()
        
        if rand_val < 0.4: # Security 4688
            pid = random.randint(1000, 20000)
            
            # Potential anomaly: 1% chance
            if random.random() < 0.01:
                parent_image = "C:\\Windows\\System32\\notepad.exe"
                image = f"C:\\Windows\\System32\\{random.choice(shells)}"
                anomalies_count += 1
            else:
                parent_image = "C:\\Windows\\explorer.exe"
                image = f"C:\\Windows\\System32\\proc_{pid % 100}.exe"
            
            log = {
                "timestamp": timestamp_str,
                "Event": {
                    "System": {"EventID": 4688},
                    "EventData": {
                        "NewProcessId": hex(pid),
                        "NewProcessName": image,
                        "ProcessId": "0x3e8",
                        "ParentProcessName": parent_image
                    }
                }
            }
            active_pids[pid] = (current_time, image)
            
        elif rand_val < 0.8: # Sysmon 1
            target_pid = None
            if active_pids:
                recent_pids = [p for p, (t, img) in active_pids.items() if (current_time - t).total_seconds() < 0.4]
                if recent_pids and random.random() < 0.5:
                    target_pid = random.choice(recent_pids)
                    correlated_count += 1
            
            if target_pid:
                pid = target_pid
                image = active_pids[pid][1]
            else:
                pid = random.randint(1000, 20000)
                image = f"C:\\Windows\\System32\\sysmon_proc_{pid % 100}.exe"
            
            log = {
                "timestamp": timestamp_str,
                "Event": {
                    "System": {"EventID": 1},
                    "EventData": {
                        "ProcessId": pid,
                        "Image": image,
                        "CommandLine": f"{image} --args {random.randint(1, 1000)}",
                        "Hashes": f"SHA256={random.getrandbits(256):x}",
                        "ParentProcessId": 1000
                    }
                }
            }
        else: # Other log
            log = {
                "timestamp": timestamp_str,
                "Event": {
                    "System": {"EventID": 4624},
                    "EventData": {
                        "TargetUserName": f"user_{random.randint(1, 50)}",
                        "IpAddress": f"192.168.1.{random.randint(10, 200)}"
                    }
                }
            }
            
        logs.append(json.dumps(log))
        
    with open("stress_test_60k.jsonl", "w") as f:
        for line in logs:
            f.write(line + "\n")
            
    print(f"Generated {len(logs)} logs.")
    print(f"Expected Correlated: ~{correlated_count}")
    print(f"Expected Anomalies: ~{anomalies_count}")

if __name__ == "__main__":
    generate_logs()
