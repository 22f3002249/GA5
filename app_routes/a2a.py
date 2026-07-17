import hashlib
import json
import os
import asyncio
import google.generativeai as genai
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Request, Response, HTTPException, Header, Depends
from fastapi.responses import JSONResponse

router = APIRouter()

# --- Configuration ---
GEMINI_KEY = os.environ.get("GEMINI_API_KEY")
if GEMINI_KEY:
    genai.configure(api_key=GEMINI_KEY)

# Use the base name; the SDK handles the versioning
ai_model = genai.GenerativeModel('gemini-1.5-flash')

BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")

# --- Persistence ---
STORAGE_FILE = "a2a_state.json"
STATE_LOCK = asyncio.Lock()

def load_state():
    if os.path.exists(STORAGE_FILE):
        try:
            with open(STORAGE_FILE, "r") as f: return json.load(f)
        except: pass
    return {"tasks": {}, "idempotency": {}}

_state = load_state()

async def save_state():
    async with STATE_LOCK:
        with open(STORAGE_FILE, "w") as f:
            json.dump(_state, f)

# --- A2A Response Helper ---

class A2AResponse(JSONResponse):
    media_type = "application/a2a+json"

# --- Helper Functions ---

def get_fingerprint(data: Any) -> str:
    """Canonical JSON fingerprint."""
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

async def validate_a2a(request: Request, a2a_version: str = Header(None)):
    if a2a_version != "1.0":
        raise HTTPException(status_code=400, detail="Invalid version")
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401)
    return auth.split(" ")[1]

async def analyze_invoice_batch(packages: List[Dict]) -> List[Dict]:
    """Enhanced prompt for semantic accuracy and rationale requirements."""
    prompt = f"""You are a senior invoice auditor. Analyze these {len(packages)} packages.
    ACTIONS: 
    - settle_invoice: Fully valid, matches policy.
    - request_approval: Valid but high value (needs human eyes).
    - hold_invoice: Missing info or verification needed.
    - reject_duplicate: Already paid.
    - open_exception: Data mismatch (e.g., amount or vendor name).

    For each package, return a JSON object with:
    - packageId: the input id
    - actionId: a random unique string
    - action: one of the 5 strings above
    - facts: {{vendorName, invoiceNumber, amountMinor, currency}}
    - evidenceRefs: list of EXACT snippets from the source text supporting the decision
    - rationale: A DETAILED explanation (100-500 characters). 
      MENTION the action name and CITE the evidenceRefs specifically.
    
    DATA: {json.dumps(packages)}"""

    try:
        res = await ai_model.generate_content_async(
            prompt, 
            generation_config={"response_mime_type": "application/json"}
        )
        return json.loads(res.text)
    except Exception as e:
        print(f"AI_ERR: {e}")
        # Return fallback to keep protocol moving
        return [{"packageId": p['packageId'], "actionId": f"f_{p['packageId']}", "action": "hold_invoice", "facts": {"vendorName": "NA", "invoiceNumber": "0", "amountMinor": 0, "currency": "INR"}, "evidenceRefs": [], "rationale": "Manual review required due to system timeout."} for p in packages]

# --- Protocol Implementation ---

async def get_card_data():
    return {
        "name": "Invoice Logic Agent",
        "description": "Enterprise invoice processing with durable receipts.",
        "version": "1.0.0",
        "capabilities": {"invoice_action_agent": {"name": "Audit", "description": "Audits batches"}},
        "supportedInterfaces": [{"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0", "endpoint": f"{BASE_URL}"}],
        "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
        "defaultOutputModes": ["application/vnd.ga5.invoice-action-proposals+json", "application/vnd.ga5.invoice-action-receipts+json"]
    }

@router.get("/.well-known/agent-card.json")
async def public_card():
    return await get_card_data()

@router.post("/message:send")
async def message_send(request: Request, principal: str = Depends(validate_a2a)):
    body = await request.json()
    msg = body.get("message", {})
    msg_id = msg.get("messageId")
    parts = msg.get("parts", [])
    
    idem_key = f"{principal}:{msg_id}"
    if idem_key in _state["idempotency"]:
        return A2AResponse({"task": _state["tasks"][_state["idempotency"][idem_key]]["data"]})

    if not parts: raise HTTPException(status_code=400)
    media_type = parts[0]["mediaType"]

    if media_type == "application/vnd.ga5.invoice-claim-batch+json":
        data = parts[0]["data"]
        task_id = f"t_{get_fingerprint(msg_id)[:12]}"
        
        proposals = await analyze_invoice_batch(data["packages"])
        
        task = {
            "taskId": task_id, "contextId": f"ctx_{task_id}",
            "state": "TASK_STATE_INPUT_REQUIRED",
            "history": [msg],
            "artifacts": [{
                "mediaType": "application/vnd.ga5.invoice-action-proposals+json",
                "data": {"batchId": data["batchId"], "proposals": proposals}
            }]
        }
        
        _state["tasks"][task_id] = {"data": task, "owner": principal}
        _state["idempotency"][idem_key] = task_id
        await save_state()
        return A2AResponse({"task": task})

    elif media_type == "application/vnd.ga5.invoice-action-results+json":
        task_id = msg.get("taskId")
        if task_id not in _state["tasks"]: raise HTTPException(status_code=404)
        entry = _state["tasks"][task_id]
        if entry["owner"] != principal: raise HTTPException(status_code=403)
        
        task = entry["data"]
        results_data = parts[0]["data"]
        proposals = task["artifacts"][0]["data"]["proposals"]
        
        executions = []
        for res in results_data.get("results", []):
            if res["outcome"] == "ACCEPTED":
                match = next((p for p in proposals if p["actionId"] == res["actionId"]), None)
                if match:
                    executions.append({
                        "packageId": match["packageId"], "actionId": match["actionId"],
                        "action": match["action"], "receiptNonce": res["receiptNonce"],
                        "facts": match["facts"], "evidenceRefs": match["evidenceRefs"]
                    })
        
        task["state"] = "TASK_STATE_COMPLETED"
        task["history"].append(msg)
        task["artifacts"].append({
            "mediaType": "application/vnd.ga5.invoice-action-receipts+json",
            "data": {"batchId": results_data["batchId"], "executions": executions}
        })
        await save_state()
        return A2AResponse({"task": task})

    raise HTTPException(status_code=400)

@router.get("/tasks/{task_id}")
async def get_task(task_id: str, principal: str = Depends(validate_a2a)):
    entry = _state["tasks"].get(task_id)
    if not entry or entry["owner"] != principal: raise HTTPException(status_code=404)
    return A2AResponse(entry["data"])

@router.get("/tasks")
async def list_tasks(principal: str = Depends(validate_a2a)):
    tasks = [t["data"] for t in _state["tasks"].values() if t["owner"] == principal]
    return A2AResponse({"tasks": tasks})
