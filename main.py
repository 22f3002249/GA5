"""
Single-app exam server.
Each question lives in its own module under app_routes/ and gets mounted
here under its own path prefix. This file only wires things together.
"""

from fastapi import FastAPI
from app_routes import proration
from app_routes import guardrail
from app_routes import runcontrol
from app_routes import skillscan
from app_routes import redteam_guardrail
from app_routes import mcp_server
from app_routes import mailroom
from app_routes import a2a

app = FastAPI(title="exam-endpoints")

# --- Q2: Proration calculator ---
app.include_router(proration.router)

# --- Q3: Pre-tool-call guardrail ---
app.include_router(guardrail.router)

# --- Q5: Run-budget-and-loop-guard ---
app.include_router(runcontrol.router)

# --- Q4: Skill vulnerability scanner ---
app.include_router(skillscan.router)

# --- Q8: Red-team guardrail (real read_file / fetch_url execution) ---
app.include_router(redteam_guardrail.router)

# --- Q6: MCP Server ---
app.include_router(mcp_server.router)

# --- Q9: Mailroom ---
app.include_router(mailroom.router)

--- Q10: A2A ---
@app.get("/.well-known/agent-card.json")
async def agent_card():
    return {
        "name": "Audit Agent",
        "version": "1.0.0",
        "supportedInterfaces": [{"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0", "endpoint": os.environ.get("BASE_URL")}],
        "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
        "defaultOutputModes": ["application/vnd.ga5.invoice-action-proposals+json", "application/vnd.ga5.invoice-action-receipts+json"]
    }
app.include_router(a2a.router, prefix="/a2a")

# Q11 will be added here as we build them ---
#
# from app_routes import redteam_guardrail
# app.include_router(redteam_guardrail.router)
#
# from app_routes import a2a
# app.include_router(a2a.router)
#
# from app_routes import incidents
# app.include_router(incidents.router)


@app.get("/")
def health():
    return {"status": "ok"}
