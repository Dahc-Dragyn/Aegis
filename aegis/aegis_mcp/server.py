import sys
import os
import json
import uvicorn
import logging
import time
import gzip
import shutil
import aiofiles
from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# --- PATH ROBUSTNESS ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path: sys.path.append(BASE_DIR)

# Import AegisAdvisor from triage module
try:
    from triage.aegis_advisor import AegisAdvisor
    advisor = AegisAdvisor()
except ImportError:
    print("[ERROR] FAILED TO IMPORT AEGIS_ADVISOR. ADVISOR LOGIC DISABLED.")
    advisor = None

# Load environment
load_dotenv()

# Configure Paths
IS_DOCKER = os.path.exists("/.dockerenv")
RESULTS_DIR = "/app/forensic_results" if IS_DOCKER else os.path.join(BASE_DIR, "forensic_results")
LEDGER_PATH = os.path.join(RESULTS_DIR, "telemetry_ledger.json")
ISOLATION_STATE_PATH = os.path.join(RESULTS_DIR, "isolation_state.json")
os.makedirs(RESULTS_DIR, exist_ok=True)

# --- MISSION-ZERO: COLD START PURGE ---
def _cold_start_purge():
    """Wipes the forensic vault on startup to ensure a clean-room state."""
    print("[MISSION-ZERO] INITIATING COLD START PURGE...")
    try:
        for f in os.listdir(RESULTS_DIR):
            path = os.path.join(RESULTS_DIR, f)
            if os.path.isfile(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
        print("[MISSION-ZERO] VAULT PURGED. READY FOR MISSION.")
    except Exception as e:
        print(f"[MISSION-ZERO] PURGE_ERROR: {e}")

_cold_start_purge()

app = FastAPI(title="Aegis Tactical Hub [NATIVE BRIDGE]")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# --- CACHE-CONTROL MIDDLEWARE ---
@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.get("/sitrep")
async def get_sitrep():
    """Serves the latest Commander's Brief produced by the Native Engine or Advisor."""
    path = os.path.join(RESULTS_DIR, "COMMANDERS_BRIEF.md")
    if os.path.exists(path):
        async with aiofiles.open(path, "r", encoding="utf-8") as f:
            content = await f.read()
            if "---" in content:
                parts = content.split("---")
                if len(parts) >= 3:
                    return {"sitrep": parts[1].strip()}
            return {"sitrep": content.strip()}
    return {"sitrep": "WAITING FOR SIGNAL..."}

@app.get("/artifacts")
async def get_artifacts():
    """Lists current artifacts in the Vault. Expanded to show all forensic assets."""
    files = []
    ALLOWED_EXT = [".md", ".json", ".pdf", ".log", ".txt", ".evtx", ".gz"]
    EXCLUDE = ["telemetry_ledger.json", "isolation_state.json"]
    
    if not os.path.exists(RESULTS_DIR): return []
    
    raw_files = os.listdir(RESULTS_DIR)
    # Filter and sort by mtime
    filtered = [f for f in raw_files if os.path.splitext(f)[1].lower() in ALLOWED_EXT and f not in EXCLUDE]
    filtered.sort(key=lambda x: os.path.getmtime(os.path.join(RESULTS_DIR, x)), reverse=True)

    for f in filtered:
        f_lower = f.lower()
        type_tag = "LOG"
        if "brief" in f_lower: type_tag = "BRIEF"
        elif "nist" in f_lower: type_tag = "NIST"
        elif "oscal" in f_lower: type_tag = "OSCAL"
        elif "poam" in f_lower: type_tag = "TRIAGE"
        elif f_lower.endswith(".gz"): type_tag = "LEDGER"
        elif f_lower.endswith(".evtx"): type_tag = "TRIAGE"
        
        files.append({
            "name": f, 
            "type": type_tag,
            "path": f"/artifacts/view/{f}",
            "timestamp": datetime.fromtimestamp(os.path.getmtime(os.path.join(RESULTS_DIR, f))).strftime("%H:%M:%S")
        })
    return files

@app.get("/artifacts/view/{file_name}")
async def view_artifact(file_name: str):
    file_path = os.path.join(RESULTS_DIR, file_name)
    if os.path.exists(file_path):
        if file_name.endswith(".json"):
            async with aiofiles.open(file_path, "r") as f:
                return JSONResponse(content=json.loads(await f.read()))
        async with aiofiles.open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return {"content": await f.read()}
    return JSONResponse(status_code=404, content={"error": "Not Found"})

@app.post("/exfil/upload")
async def exfil_upload(request: Request):
    """
    INGESTION FORK:
    Path A (.jsonl.gz) -> Decompress & Hydrate Ledger (Rust Edge Sensor Output)
    Path B (.log, .txt, .evtx) -> Process via AegisAdvisor (Raw Field Log)
    """
    form = await request.form()
    files = form.getlist("files")
    if not files:
        files = [v for k, v in form.items() if isinstance(v, UploadFile)]
        
    print(f"[BRIDGE] INGESTION_REQUEST: {len(files)} ARTIFACTS RECEIVED")
    results = []
    
    # Load current ledger
    ledger = []
    if os.path.exists(LEDGER_PATH):
        try:
            async with aiofiles.open(LEDGER_PATH, "r") as f: ledger = json.loads(await f.read())
        except: ledger = []

    for file in files:
        f_name = file.filename
        save_path = os.path.join(RESULTS_DIR, f_name)
        
        # Save raw file first
        content = await file.read()
        async with aiofiles.open(save_path, "wb") as buffer:
            await buffer.write(content)
        
        # --- THE INGESTION FORK ---
        if f_name.endswith(".jsonl.gz"):
            # PATH A: RUST EDGE SENSOR LEDGER
            print(f"[PATH-A] DECOMPRESSING RUST LEDGER: {f_name}")
            try:
                with gzip.open(save_path, "rb") as f_in:
                    content = f_in.read().decode("utf-8")
                    for line in content.strip().split("\n"):
                        if line:
                            event = json.loads(line)
                            ledger.insert(0, event)
                    # Path A Sitrep (Automated)
                    async with aiofiles.open(os.path.join(RESULTS_DIR, "COMMANDERS_BRIEF.md"), "w") as f:
                        await f.write(f"# TACTICAL SITREP: HYDRA_INGESTED\n---\n**STATUS**: Forensic payload hydrated.\n**ASSETS**: {f_name}\n**TIMESTAMP**: {datetime.now().strftime('%H:%M:%S')}\n---")
                    
                    results.append({"file": f_name, "status": "HYDRATED", "path": "A"})
            except Exception as e:
                print(f"[PATH-A] ERROR: {e}")
                results.append({"file": f_name, "status": "FAILED", "error": str(e)})

        elif any(f_name.lower().endswith(ext) for ext in [".log", ".txt", ".evtx"]):
            # PATH B: RAW FIELD LOG -> ADVISOR
            print(f"[PATH-B] PROCESSING RAW LOG VIA ADVISOR: {f_name}")
            if advisor:
                try:
                    # Read content for triage
                    async with aiofiles.open(save_path, "r", errors="ignore") as f:
                        raw_content = await f.read()
                    
                    # Generate Pentad
                    brief = advisor.triage(raw_content, f_name)
                    nist = advisor.generate_nist_manifest(raw_content, f_name)
                    
                    # Save artifacts
                    async with aiofiles.open(os.path.join(RESULTS_DIR, "COMMANDERS_BRIEF.md"), "w") as f:
                        await f.write(brief)
                    async with aiofiles.open(os.path.join(RESULTS_DIR, "NIST_MANIFEST.md"), "w") as f:
                        await f.write(nist)
                    
                    # Create Mock OSCAL/POAM for HUD completion
                    oscal = {"report": "OSCAL_V1_CERTIFIED", "source": f_name, "timestamp": datetime.now().isoformat()}
                    async with aiofiles.open(os.path.join(RESULTS_DIR, "OSCAL_REPORT.json"), "w") as f:
                        await f.write(json.dumps(oscal))
                        
                    ledger.insert(0, {
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "event": "FORENSIC_TRIAGE_COMPLETE",
                        "severity": "high" if "CRITICAL" in brief or "HIGH" in brief else "info",
                        "details": f"Advisor processed {f_name}. Pentad generated."
                    })
                    results.append({"file": f_name, "status": "TRIAGED", "path": "B"})
                except Exception as e:
                    print(f"[PATH-B] ERROR: {e}")
                    results.append({"file": f_name, "status": "FAILED", "error": str(e)})
            else:
                results.append({"file": f_name, "status": "VAULTED", "details": "ADVISOR_OFFLINE"})
        else:
            results.append({"file": f_name, "status": "VAULTED", "path": "OTHER"})

    # Save updated ledger (100k capacity)
    async with aiofiles.open(LEDGER_PATH, "w") as f:
        await f.write(json.dumps(ledger[:100000]))
            
    return {"status": "SUCCESS", "ingested": results}

@app.get("/telemetry/history")
async def get_history():
    if not os.path.exists(LEDGER_PATH): return []
    try:
        async with aiofiles.open(LEDGER_PATH, "r") as f:
            content = await f.read()
            return JSONResponse(content=json.loads(content))
    except Exception as e:
        print(f"[ERROR] LEDGER_READ_FAILED: {e}")
        return []

@app.get("/isolation/status")
async def isolation_status():
    if os.path.exists(ISOLATION_STATE_PATH):
        async with aiofiles.open(ISOLATION_STATE_PATH, "r") as f: 
            return json.loads(await f.read())
    return {"isolated": False}

@app.post("/isolation/toggle")
async def toggle_isolation():
    state = {"isolated": False}
    if os.path.exists(ISOLATION_STATE_PATH):
        async with aiofiles.open(ISOLATION_STATE_PATH, "r") as f: 
            state = json.loads(await f.read())
    state["isolated"] = not state["isolated"]
    async with aiofiles.open(ISOLATION_STATE_PATH, "w") as f: 
        await f.write(json.dumps(state))
    return state

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
