import asyncio
import os
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def run_mcp_test():
    print("🚀 Initializing Aegis Unified Sentinel Full-Stack Test...")
    
    # Configuration
    binary_path = os.path.abspath("../target/debug/aegis.exe")
    env = os.environ.copy()
    env["AEGIS_BINARY_PATH"] = binary_path

    server_params = StdioServerParameters(
        command=os.path.abspath(".venv/Scripts/python"),
        args=[os.path.abspath("server.py")],
        env=env
    )

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                # 1. Initialize
                print("📡 Connecting to Aegis MCP Server...")
                await session.initialize()
                
                # 2. List Tools
                print("\n📦 Available AI Tools:")
                tools = await session.list_tools()
                for tool in tools.tools:
                    print(f" - {tool.name}: {tool.description}")

                # 3. Test: run_aegis_scan (AI RMF 100-1)
                print("\n🧪 Test 1: Executing AI RMF Audit (Profile 100-1)...")
                scan_result = await session.call_tool("run_aegis_scan", {
                    "target_path": os.path.abspath("../logs/mock_ai_gateway.jsonl"),
                    "framework_profile": "100-1"
                })
                print(f"✅ Scan Result (100-1 Profile):\n{scan_result.content[0].text[:500]}...")

                # 4. Test: generate_executive_brief (AI-Powered Executive Overview)
                print("\n🧪 Test 2: Generating AI-Powered Executive Brief (Gemini)...")
                brief_result = await session.call_tool("generate_executive_brief", {})
                print(f"✅ Briefing Status: {brief_result.content[0].text}")
                
                # Verify file creation
                root_dir = os.path.abspath("..")
                brief_path = os.path.join(root_dir, "COMMANDERS_BRIEF.md")
                if os.path.exists(brief_path):
                    print(f"✅ Persistent Artifact Verified: {brief_path}")
                else:
                    print(f"❌ Error: Persistent Artifact NOT found at {brief_path}")

                # 5. Test: query_compliance_ledger
                print("\n🧪 Test 3: Querying Forensic Ledger (Severity: High)...")
                ledger_result = await session.call_tool("query_compliance_ledger", {"severity_filter": "High"})
                data = json.loads(ledger_result.content[0].text)
                print(f"✅ Successfully retrieved {len(data)} High-Severity forensic signals.")
                if data:
                    print(f"   [Sample]: {data[0]['message']} | Severity: {data[0]['severity']}")

                # 6. Test: draft_poam_ticket (NIST AI RMF HITL)
                print("\n🧪 Test 4: Drafting AI RMF Remediation Ticket (HITL Isolation)...")
                ticket_result = await session.call_tool("draft_poam_ticket", {
                    "control_id": "Secure & Resilient",
                    "system_id": "llama-3-70b",
                    "ai_remediation_advice": "Immediate deployment of a prompt-injection firewall and toxicity filter baseline."
                })
                print(f"✅ Ticket Drafted: {ticket_result.content[0].text}")

    except Exception as e:
        import traceback
        print(f"❌ Full-Stack Test Failed: {str(e)}")
        traceback.print_exc()

if __name__ == "__main__":
    # Change to server directory for correct local resolution
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    asyncio.run(run_mcp_test())
