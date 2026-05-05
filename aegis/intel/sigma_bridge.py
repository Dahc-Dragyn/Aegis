import os
import yaml
import json
import subprocess
import shutil
from pathlib import Path

# --- TACTICAL CONFIGURATION ---
SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma.git"
TEMP_DIR = os.path.abspath("./temp_sigma")
POLICY_FILE = "forensic_policy.json"
TARGET_DIRS = ["rules/windows", "rules/network"]

def drop_the_hammer():
    """Execute high-velocity local ingestion via git clone bypass."""
    print("Aegis Bridge: Initiating 'git clone' bypass to scale intelligence...")
    
    # 1. Clean previous artifacts
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)
    
    # 2. Shallow Clone (Depth 1) - Sub-4 second execution
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", SIGMA_REPO_URL, TEMP_DIR],
            check=True,
            capture_output=True
        )
        print(f"Aegis Bridge: Local repository buffer established at {TEMP_DIR}")
    except subprocess.CalledProcessError as e:
        print(f"Aegis Bridge: Clone failed! Stderr: {e.stderr.decode()}")
        return

    # 3. Recursive Parsing Matrix
    lethal_indicators = []
    processed_count = 0
    
    for sub_dir in TARGET_DIRS:
        search_path = Path(TEMP_DIR) / sub_dir
        if not search_path.exists():
            continue
            
        print(f"Aegis Bridge: Scanning {sub_dir} for high-fidelity signatures...")
        
        for yaml_file in search_path.rglob("*.yml"):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    content = yaml.safe_load(f)
                    
                level = content.get('level', '').lower()
                status = content.get('status', '').lower()
                
                # Filter for High/Critical stable rules
                if level in ['high', 'critical']:
                    processed_count += 1
                    
                    patterns = []
                    detection = content.get('detection', {})
                    
                    def extract_strings(obj):
                        if isinstance(obj, str) and len(obj) > 4:
                            patterns.append(obj)
                        elif isinstance(obj, list):
                            for item in obj: extract_strings(item)
                        elif isinstance(obj, dict):
                            for v in obj.values(): extract_strings(v)

                    extract_strings(detection)
                    
                    if patterns:
                        lethal_indicators.append({
                            "id": content.get('id', 'unknown'),
                            "name": content.get('title', 'Unknown Sigma Rule'),
                            "severity": level.upper(),
                            "patterns": list(set(patterns))[:10]
                        })
            except Exception:
                continue

    # 4. Commit to Manifold
    policy_payload = {
        "metadata": {
            "source": "SigmaHQ Global Intelligence",
            "version": "2026.Q2.OVERWATCH",
            "rule_count": len(lethal_indicators)
        },
        "indicators": lethal_indicators
    }
    
    with open(POLICY_FILE, 'w') as f:
        json.dump(policy_payload, f, indent=4)
    
    print(f"Aegis Bridge: OPERATION COMPLETE.")
    print(f"Total Rules Scanned: {processed_count}")
    print(f"Lethal Indicators Ingested: {len(lethal_indicators)}")
    
    # 5. Cover Tracks
    shutil.rmtree(TEMP_DIR)
    print("Aegis Bridge: Temporary buffer cleared.")

if __name__ == "__main__":
    drop_the_hammer()
