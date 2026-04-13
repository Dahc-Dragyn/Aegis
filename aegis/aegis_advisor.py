import os
import sys
from dotenv import load_dotenv
from google import genai
from google.genai import types

# Load environment variables (GEMINI_API_KEY is standard for Aegis)
load_dotenv(override=True)
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    # Diagnostic fallback: Check for GOOGLE_API_KEY common alternative
    api_key = os.getenv("GOOGLE_API_KEY")

if not api_key:
    print("❌ ERROR: GEMINI_API_KEY or GOOGLE_API_KEY not found in .env file.")
    print("Please ensure your .env contains: GEMINI_API_KEY=AIza...")
    sys.exit(1)

# Initialize Gemini 2.x/2.5 Flash Lite (Stable) via the new Google GenAI SDK
client = genai.Client(api_key=api_key)
MODEL_STRING = "gemini-2.5-flash-lite"

def load_aegis_context():
    """Reads the core forensic artifacts into memory."""
    context = {}
    files = {
        "NIST_MANIFEST.md": "NIST Compliance Manifest (Remediation Playbook)",
        "oscal-assessment-results.json": "OSCAL Assessment Results (Technical Findings)",
        "oscal-poam.json": "OSCAL Plan of Action & Milestones (Tracked Items)",
        "COMMANDERS_BRIEF.md": "Executive Commander's Brief (Strategic Summary)"
    }
    
    print("🛰️ Aegis Advisor: Ingesting forensic context...")
    for filename, description in files.items():
        try:
            if os.path.exists(filename):
                with open(filename, 'r', encoding='utf-8') as f:
                    context[filename] = f.read()
                    print(f"✅ Loaded: {filename} ({description})")
            else:
                print(f"⚠️ Warning: Missing {filename}. Proceeding with limited context.")
        except Exception as e:
            print(f"❌ Error reading {filename}: {e}")
            
    return context

def start_advisor():
    """Starts the interactive ISSO remediation loop."""
    context = load_aegis_context()
    
    # SYSTEM INSTRUCTION (NIST Strict ISSO Persona)
    system_prompt = (
        "You are the Aegis Lead Information System Security Officer (ISSO).\n\n"
        "Your mission is to provide authoritative, technical, and step-by-step remediation guidance "
        "to a SOC Commander based on the provided Aegis Forensic Sentinel artifacts.\n\n"
        "Guidelines:\n"
        "1. BE AUTHORITATIVE: Reference specific NIST 800-53 or 800-171 control IDs in your answers.\n"
        "2. BE PRACTICAL: Provide exact commands or configuration steps for Windows systems or AI environments where possible.\n"
        "3. STAY WITHIN CONTEXT: Use the provided JSON findings and Manifest playbooks as the ground truth. "
        "DO NOT hallucinate failures that are not present in the data.\n"
        "4. NO TRUNCATION: You have access to the full, compressed forensic roll-up. Analyze the trend data (occurrence counts).\n\n"
        "CURRENT FORENSIC CONTEXT:\n"
    )
    
    # Append the artifact context
    for filename, content in context.items():
        system_prompt += f"\n--- {filename} ---\n{content}\n"

    print("\n" + "="*80)
    print("🛡️ AEGIS INTERACTIVE AI ADVISOR (Lead ISSO Persona) ACTIVE")
    print(f"📡 Backend: {MODEL_STRING}")
    print("Type 'exit' or 'quit' to terminate the session.")
    print("="*80 + "\n")

    # Initialize Chat using new SDK
    chat = client.chats.create(
        model=MODEL_STRING,
        config=types.GenerateContentConfig(system_instruction=system_prompt)
    )

    while True:
        try:
            user_input = input("USER (SOC Commander) > ").strip()
            
            if user_input.lower() in ['exit', 'quit']:
                print("🛡️ Aegis Advisor: Standing down. Stay secure.")
                break
                
            if not user_input:
                continue

            print("ISSO thinking...", end="\r")
            
            # Send message and stream response (new SDK syntax)
            response = chat.send_message_stream(user_input)
            
            print("\nAegis Advisor (ISSO) > ", end="")
            for chunk in response:
                if chunk.text:
                    print(chunk.text, end="", flush=True)
            print("\n")

        except KeyboardInterrupt:
            print("\n🛡️ Aegis Advisor: Session interrupted.")
            break
        except Exception as e:
            print(f"\n❌ Error during advisory: {e}")

if __name__ == "__main__":
    start_advisor()
