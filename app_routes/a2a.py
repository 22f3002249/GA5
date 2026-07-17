import hashlib
import json
import os
import asyncio
import google.generativeai as genai
from typing import List, Dict, Any
from fastapi import APIRouter, Request, Response, HTTPException, Header, Depends
from fastapi.responses import JSONResponse

router = APIRouter()

# --- Configuration ---
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
# Using the explicit model path to avoid the 404 seen in your logs
model_name = "models/gemini-1.5-flash"
ai_model = genai.GenerativeModel(model_name)

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
    """Custom response to ensure the strict application/a2a+json media type."""
    media_type = "application/a2a+json"

# --- Helper Functions ---

def get_fingerprint(data: Any) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

async def validate_a2a(request: Request, a2a_version: str = Header(None)):
    """Enforces protocol version and authentication."""
    if a2a_version != "1.0":
        raise HTTPException(status_code=400, detail="Require A2A-Version: 1.0")
    
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401)
    return auth.split(" ")[1]

async def analyze_invoice_batch(packages: List[Dict]) -> List[Dict]:
    prompt = f"""You are an invoice audit agent. Pick ONE action for each package: 
    settle_invoice, request_approval, hold_invoice, reject_duplicate, open_exception.
    Return ONLY a JSON list of objects with: packageId, actionId, action, facts, evidenceRefs, rationale.
    DATA: {json.dumps(packages)}"""

    try:
        res = await ai_model.generate_content_async(
            prompt, 
            generation_config={"response_mime_type": "application/json"}
        )
        return json.loads(res.text)
    except Exception as e:
        print(f"AI_ERR: {e}")
        return []

# --- Routes ---

async def get_card_data():
    return {
        "name": "Invoice Agent",
        "description": "A2A 1.0 compliant invoice processing agent.",
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

@router.get("/.well-known/agent-card.json")
async def public_card():
    # Note: Spec says card is public, so no version check/auth here
    return await get_card_data()

@router.post("/message:send")
async def message_send(request: Request, principal: str = Depends(validate_a2a)):
    body = await request.json()
    msg = body.get("message", {})
    msg_id = msg.get("messageId")
    parts = msg.get("parts", [])
    
    idem_key = f"{principal}:{msg_id}"
    if idem_key in _state["idempotency"]:
        task_id = _state["idempotency"][idem_key]
        return A2AResponse({"task": _state["tasks"][task_id]["data"]})

    if not parts: raise HTTPException(status_code=400)
    media_type = parts[0]["mediaType"]

    if media_type == "application/vnd.ga5.invoice-claim-batch+json":
        data = parts[0]["data"]
        task_id = f"t_{get_fingerprint(msg_id)[:12]}"
        
        proposals = await analyze_invoice_batch(data["packages"])
        
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
                    executions.append({**match, "receiptNonce": res["receiptNonce"]})
        
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
    if task_id not in _state["tasks"]: raise HTTPException(status_code=404)
    entry = _state["tasks"][task_id]
    if entry["owner"] != principal: raise HTTPException(status_code=404)
    return A2AResponse(entry["data"])

@router.get("/tasks")
async def list_tasks(principal: str = Depends(validate_a2a)):
    tasks = [t["data"] for t in _state["tasks"].values() if t["owner"] == principal]
    return A2AResponse({"tasks": tasks})
