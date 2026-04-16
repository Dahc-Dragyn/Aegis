import requests
import gzip
import json
import os
import sys

# Configuration
URL_V3 = "https://botsdataset.s3.amazonaws.com/botsv3/botsv3.json.gz"
URL_V1 = "https://s3.amazonaws.com/botsdataset/botsv1/botsv1.json.gz"
OUTPUT_DIR = "logs/bots_dataset"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "bots_curated.json")
BYTE_CAP = 250 * 1024 * 1024  # 250 MB

# High-Value Sourcetypes
TARGET_SOURCETYPES = {
    "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "WinEventLog:Security",
    "stream:http",
    "aws:cloudtrail"
}

def stream_curated_bots():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    print(f"[*] Initializing curated stream for BOTS telemetry...")
    
    # Attempt V3, fallback to V1
    target_url = URL_V3
    print(f"[*] Targeting: {target_url}")
    
    try:
        # Check if the URL is accessible via a HEAD request first, or just try GET
        # We use stream=True to avoid loading the entire 11GB into memory
        response = requests.get(target_url, stream=True, timeout=30)
        
        # Explicitly handle 403 Forbidden or 404
        if response.status_code in [403, 404]:
            print(f"[!] {target_url} returned {response.status_code}. Falling back to verified BOTS v1...")
            target_url = URL_V1
            response = requests.get(target_url, stream=True, timeout=30)
        
        response.raise_for_status()
    except Exception as e:
        print(f"[ERROR] Failed to establish stream: {e}")
        return

    bytes_written = 0
    lines_processed = 0
    matches_found = 0

    print(f"[*] Stream established. Decompressing and filtering in-memory...")
    
    try:
        # Wrap the raw response stream in a GzipFile
        # response.raw is the raw socket stream
        with gzip.GzipFile(fileobj=response.raw) as gzf:
            with open(OUTPUT_FILE, "wb") as out_f:
                for line in gzf:
                    lines_processed += 1
                    
                    # Periodic progress update every 50k lines to avoid console spam
                    if lines_processed % 50000 == 0:
                        progress = (bytes_written / BYTE_CAP) * 100
                        print(f"[*] Processed {lines_processed} lines | Matches: {matches_found} | Progress: {progress:.2f}%", end='\r')

                    try:
                        # Quick byte-level check for target sourcetypes to avoid overhead of json.loads
                        if any(st.encode() in line for st in TARGET_SOURCETYPES):
                            out_f.write(line)
                            bytes_written += len(line)
                            matches_found += 1
                            
                            if bytes_written >= BYTE_CAP:
                                print(f"\n[+] Byte cap of {BYTE_CAP / (1024*1024)} MB reached. Terminating.")
                                break
                    except Exception:
                        continue # Skip malformed lines

    except KeyboardInterrupt:
        print("\n[!] User interrupted download.")
    except Exception as e:
        print(f"\n[ERROR] Stream processing failed: {e}")
    finally:
        response.close()
        print(f"\n[+] Final Stats:")
        print(f"    - Bytes Written: {bytes_written / (1024*1024):.2f} MB")
        print(f"    - Matches Saved: {matches_found}")
        print(f"    - Output Path: {OUTPUT_FILE}")

if __name__ == "__main__":
    stream_curated_bots()
