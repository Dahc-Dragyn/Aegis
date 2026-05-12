import os
import json
import sys
from typing import Dict, List, Any
from dotenv import load_dotenv
from google import genai
from google.genai import types

# Load environment variables (AEGIS_GEMINI_KEY)
load_dotenv(dotenv_path="../.env")
api_key = os.getenv("AEGIS_GEMINI_KEY")

if not api_key:
    raise ValueError("❌ AEGIS_GEMINI_KEY not found in .env file.")

# Initialize Gemini Client
client = genai.Client(api_key=api_key)
MODEL_ID = "gemini-3.1-flash-lite"

# Import the tools from our MCP server (simulated for the loop)
from mcp_server import get_system_posture, list_attack_chains, get_chain_details

def _load_remediation_map() -> Dict[str, str]:
    """Loads NIST mappings to provide remediation context to the Agent."""
    map_path = "../intel/nist_mappings.json"
    if not os.path.exists(map_path):
        return {}
    with open(map_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        # Create a lookup for control_id -> remediation
        return {item["control_id"]: item.get("remediation", "No specific remediation advice available.") for item in data}

def advisor_loop():
    print("[INIT] Aegis Advisor: Initializing Platinum Agentic Loop (3.1)...")
    
    remediation_context = _load_remediation_map()
    
    system_instruction = (
        "You are the Aegis AI Advisor, a Tier-1 cybersecurity analyst. Your objective is to write the COMMANDERS_BRIEF.md.\n\n"
        "STEPS:\n"
        "1. Use get_system_posture to assess overall damage.\n"
        "2. Use list_attack_chains to find all threat UUIDs.\n"
        "3. For each UUID, use get_chain_details to extract forensic specifics.\n"
        "4. CROSS-WALK: Use the provided NIST Remediation Map to enrich each finding with actionable advice.\n"
        "5. SYNTHESIS: Write a tactical 3-sentence summary per chain + 1 remediation sentence. Finalize in Markdown.\n\n"
        f"NIST REMEDIATION MAP:\n{json.dumps(remediation_context, indent=2)}\n\n"
        "POST-BRIEF: Once the file is written, remain in the chat to answer the Commander's follow-up questions."
    )

    tools = [get_system_posture, list_attack_chains, get_chain_details]

    chat = client.chats.create(
        model=MODEL_ID,
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            tools=tools,
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=False)
        )
    )

    print("[REASONING] Generating COMMANDERS_BRIEF.md...")
    response = chat.send_message("Initiate Forensic Synthesis Protocol. Generate the COMMANDERS_BRIEF.md.")

    # Save the output
    brief_content = response.text
    with open("../COMMANDERS_BRIEF.md", "w", encoding="utf-8") as f:
        f.write(brief_content)
    
    print("\n[SUCCESS] COMMANDERS_BRIEF.md generated with NIST Enrichment.")
    print("\n--- EXECUTIVE BRIEFING PREVIEW ---\n")
    print(brief_content)
    print("\n----------------------------------\n")

    # Interactive REPL
    print("[GATE] Aegis Advisor REPL Open. Enter 'exit' to terminate session.")
    while True:
        try:
            user_input = input("\nCommander > ")
            if user_input.lower() in ["exit", "quit", "bye"]:
                print("[OFFLINE] Advisor standing down.")
                break
            
            if not user_input.strip():
                continue

            response = chat.send_message(user_input)
            print(f"\nAdvisor > {response.text}")
            
        except KeyboardInterrupt:
            print("\n[OFFLINE] Advisor standing down.")
            break
        except Exception as e:
            print(f"\n[ERROR] Advisor encountered a reasoning fault: {e}")

if __name__ == "__main__":
    advisor_loop()
