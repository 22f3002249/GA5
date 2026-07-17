import hashlib
import json
import os
import asyncio
import google.generativeai as genai
from typing import List, Dict, Any
from fastapi import APIRouter, Request, Response, HTTPException, Header, Depends

router = APIRouter()

# --- Config ---
# Ensure you set these in Render Environment Variables
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-1.5-flash')
# The portal will ask for this URL. Ensure it matches what you enter there.
# Example: https://ga5-1.onrender.com/a2a
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")

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

# --- Middleware-like Checks ---

async def validate_a2a(request: Request, a2a_version: str = Header(None)):
    # Spec: Require A2A-Version: 1.0
    if a2a_version != "1.0":
        raise HTTPException(status_code=400, detail="Invalid A2A-Version")
    
    # Spec: Require exact Bearer token per principal
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401)
    return auth.split(" ")[1]

# --- AI Logic ---

async def analyze_batch(packages: List[Dict]) -> List[Dict]:
    # We batch all 12 invoices into ONE AI call to save money/time
    prompt = f"""Analyze these invoice packages. For each, pick ONE: 
    settle_invoice, request_approval, hold_invoice, reject_duplicate, open_exception.
    Return ONLY a JSON list of objects with keys: packageId, actionId, action, facts, evidenceRefs, rationale.
    FACTS must include: vendorName, invoiceNumber, amountMinor, currency.
    DATA: {json.dumps(packages)}"""

    try:
        res = await model.generate_content_async(prompt, generation_config={"response_mime_type": "application/json"})
        return json.loads(res.text)
    except:
        return []

# --- Routes ---

# 1. Discovery (Must be available without Auth)
@router.get("/.well-known/agent-card.json")
async def get_card():
    return {
        "name": "Invoice Action Agent",
        "description": "Persistent AI agent for processing invoice batches.",
        "version": "1.0.0",
        "capabilities": {"invoice_processing": {}},
        "supportedInterfaces": [{
            "protocolBinding": "HTTP+JSON",
            "protocolVersion": "1.0",
            "endpoint": f"{BASE_URL}"
        }],
        "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
        "defaultOutputModes": [
            "application/vnd.ga5.invoice-action-proposals+json",
            "application/vnd.ga5.invoice-action-receipts+json"
        ]
    }

# 2. Messaging
@router.post("/message:send")
async def message_send(request: Request, principal: str = Depends(validate_a2a)):
    body = await request.json()
    msg = body.get("message", {})
    msg_id = msg.get("messageId")
    parts = msg.get("parts", [])
    
    # Idempotency Key = (Principal, MessageId)
    idem_key = f"{principal}:{msg_id}"
    if idem_key in _state["idempotency"]:
        task_id = _state["idempotency"][idem_key]
        return {"task": _state["tasks"][task_id]}

    # Route logic based on MediaType
    media_type = parts[0]["mediaType"] if parts else ""

    # Case A: Initial Batch
    if media_type == "application/vnd.ga5.invoice-claim-batch+json":
        data = parts[0]["data"]
        task_id = f"task_{hashlib.md_5(msg_id.encode()).hexdigest()[:12]}"
        
        proposals = await analyze_batch(data["packages"])
        
        task = {
            "taskId": task_id,
            "contextId": f"ctx_{task_id}",
            "state": "TASK_STATE_INPUT_REQUIRED",
            "history": [msg],
            "artifacts": [{
                "mediaType": "application/vnd.ga5.invoice-action-proposals+json",
                "data": {"batchId": data["batchId"], "proposals": proposals}
            }]
        }
        
        _state["tasks"][task_id] = task
        _state["idempotency"][idem_key] = task_id
        await save_state()
        return {"task": task}

    # Case B: Results/Receipts Continuation
    elif media_type == "application/vnd.ga5.invoice-action-results+json":
        task_id = msg.get("taskId")
        if task_id not in _state["tasks"]: raise HTTPException(status_code=404)
        task = _state["tasks"][task_id]
        
        results_data = parts[0]["data"]
        proposals = task["artifacts"][0]["data"]["proposals"]
        
        executions = []
        for res in results_data["results"]:
            if res["outcome"] == "ACCEPTED":
                match = next((p for p in proposals if p["actionId"] == res["actionId"]), None)
                if match:
                    executions.append({**match, "receiptNonce": res["receiptNonce"]})
        
        task["state"] = "TASK_STATE_COMPLETED"
        task["history"].append(msg)
        task["artifacts"].append({
            "mediaType": "application/vnd.ga5.invoice-action-receipts+json",
            "data": {"batchId": results_data["batchId"], "executions": executions}
        })
        await save_state()
        return {"task": task}

    raise HTTPException(status_code=400)

@router.get("/tasks/{task_id}")
async def get_task(task_id: str, principal: str = Depends(validate_a2a)):
    if task_id not in _state["tasks"]: raise HTTPException(status_code=404)
    return _state["tasks"][task_id]
