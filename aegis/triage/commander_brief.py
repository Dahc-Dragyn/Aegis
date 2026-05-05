import os
import json
import gzip
import glob
import sys
from datetime import datetime

# NOTE: This script requires GOOGLE_API_KEY to be set in the environment
try:
    import google.generativeai as genai
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("AI Hook Error: packages not found. Run 'pip install google-generativeai python-dotenv'")
    sys.exit(1)

# --- CONFIGURATION ---
MODEL_NAME = "gemini-2.0-flash" # Defaulting to available flash model
RESULTS_DIR = "forensic_results"
COMMANDER_BRIEF_OUTPUT = "COMMANDER_BRIEF.md"

def get_latest_ledger():
    """Find the most recent .jsonl.gz forensic ledger"""
    files = glob.glob(os.path.join(RESULTS_DIR, "aegis_forensic_ledger_*.jsonl.gz"))
    if not files: return None
    return max(files, key=os.path.getmtime)

def synthesize_brief(ledger_path: str):
    """Read ledger, extract Sigma alerts, and generate brief via Gemini"""
    print(f"AI Synthesis Hook: Reading ledger {ledger_path}...")
    
    alerts = []
    try:
        if ledger_path.endswith(".gz"):
            f = gzip.open(ledger_path, "rt")
        else:
            f = open(ledger_path, "r", encoding="utf-8")
            
        with f:
            for line in f:
                if not line.strip(): continue
                record = json.loads(line)
                # Filter for Sigma-prefixed alerts or Critical events
                msg = record.get("message", "")
                # Normalize severity and level for filtering
                sev = str(record.get("severity", "")).upper()
                lvl = str(record.get("level", "")).upper()
                
                if "[SIGMA_" in msg.upper() or "CRITICAL" in sev or "CRITICAL" in lvl or "HIGH" in sev or "HIGH" in lvl:
                    alerts.append({
                        "timestamp": record.get("timestamp"),
                        "alert": msg,
                        "metadata": record.get("metadata", {})
                    })
    except Exception as e:
        print(f"Error reading ledger: {e}")
        return

    if not alerts:
        print("AI Synthesis Hook: No critical Sigma alerts found to synthesize.")
        return

    # PREPARE PROMPT
    prompt = f"""
    You are the Aegis AI Tactical Officer. 
    Analyze the following {len(alerts)} correlated Sigma forensic alerts and generate a 'W5 Commander's Brief'.
    
    The brief MUST follow this format:
    1. **WHO**: Target hosts/users involved.
    2. **WHAT**: The specific nature of the attack/anomaly.
    3. **WHERE**: Network segments, ports, or filesystems affected.
    4. **WHEN**: Timeline of the activity.
    5. **WHY**: Likely adversary objective (Lateral Movement, Exfiltration, etc.).
    
    DATA:
    {json.dumps(alerts, indent=2)}
    
    Style: Lethal, concise, military-grade. No fluff.
    """

    print("AI Synthesis Hook: Transmitting data to Gemini...")
    try:
        api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            print("Error: API Key (GOOGLE_API_KEY or GEMINI_API_KEY) not found in environment.")
            return

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(MODEL_NAME)
        response = model.generate_content(prompt)
        
        with open(COMMANDER_BRIEF_OUTPUT, "w", encoding="utf-8") as f:
            f.write(f"# AEGIS COMMANDER'S BRIEF - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(response.text)
        
        print(f"\n🚀 Brief Generated: {COMMANDER_BRIEF_OUTPUT}")

    except Exception as e:
        print(f"AI Synthesis Hook Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_path = sys.argv[1]
        if os.path.exists(target_path):
            synthesize_brief(target_path)
        else:
            print(f"Error: Target path {target_path} not found.")
    else:
        latest = get_latest_ledger()
        if latest:
            synthesize_brief(latest)
        else:
            print("No forensic ledgers found. Please provide a path to a .jsonl or .jsonl.gz file.")
