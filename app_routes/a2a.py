import hashlib
import json
import os
import asyncio
import google.generativeai as genai
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Request, Response, HTTPException, Header, Depends

router = APIRouter()

# --- Configuration ---
GEMINI_KEY = os.environ.get("GEMINI_API_KEY")
if GEMINI_KEY:
    genai.configure(api_key=GEMINI_KEY)
ai_model = genai.GenerativeModel('gemini-1.5-flash')

# Base URL from Render Environment (e.g., https://yourapp.onrender.com/a2a)
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

# --- Helper Functions ---

def get_fingerprint(data: Any) -> str:
    """Recursively key-sorted compact JSON hash."""
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

async def validate_a2a_request(request: Request, a2a_version: str = Header(None)):
    """Enforces protocol version and authentication."""
    if a2a_version != "1.0":
        raise HTTPException(status_code=400, detail="Require A2A-Version: 1.0")
    
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401)
    
    # Return the token string as the 'Principal ID' for tenant isolation
    return auth.split(" ")[1]

async def analyze_invoice_batch(packages: List[Dict]) -> List[Dict]:
    """Calls Gemini to classify the batch of invoices."""
    prompt = f"""You are a professional invoice auditing agent. 
    Analyze the following invoice packages and assign EXACTLY ONE business action to each.
    
    ALLOWED ACTIONS:
    - settle_invoice: Valid, matched to records, within authority.
    - request_approval: Commercially valid but exceeds spending limit.
    - hold_invoice: Payment paused pending specific verification.
    - reject_duplicate: This specific invoice number was already paid.
    - open_exception: Data mismatch between records (e.g. amount or vendor mismatch).

    Return ONLY a JSON list of objects with these keys: 
    packageId, actionId (uuid), action, facts (object with vendorName, invoiceNumber, amountMinor, currency), 
    evidenceRefs (list of specific strings), rationale (60-1500 chars).
    
    DATA: {json.dumps(packages)}"""

    try:
        res = await ai_model.generate_content_async(
            prompt, 
            generation_config={"response_mime_type": "application/json"}
        )
        return json.loads(res.text)
    except Exception as e:
        print(f"AI_FAILURE: {e}")
        return []

# --- Protocol Implementation ---

async def get_card_data():
    """Logic for the public Agent Card."""
    return {
        "name": "Invoice Audit Agent",
        "description": "Analyzes messy invoice batches and manages business approval workflows.",
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
    """Handles the card route if it's called at the sub-path."""
    return await get_card_data()

@router.post("/message:send")
async def message_send(request: Request, principal: str = Depends(validate_a2a_request)):
    body = await request.json()
    msg = body.get("message", {})
    msg_id = msg.get("messageId")
    parts = msg.get("parts", [])
    
    # 1. Idempotency Check (Principal + MessageId must be unique)
    idem_key = f"{principal}:{msg_id}"
    if idem_key in _state["idempotency"]:
        task_id = _state["idempotency"][idem_key]
        # Return same task, but check for content conflict (Optional but good)
        return {"task": _state["tasks"][task_id]}

    if not parts: raise HTTPException(status_code=400)
    media_type = parts[0]["mediaType"]

    # --- CASE 1: Initial Invoice Batch ---
    if media_type == "application/vnd.ga5.invoice-claim-batch+json":
        data = parts[0]["data"]
        task_id = f"task_{get_fingerprint(msg_id)[:12]}"
        
        # Semantic Reasoning
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
        
        # Persist (Isolated to this principal)
        _state["tasks"][task_id] = {"data": task, "owner": principal}
        _state["idempotency"][idem_key] = task_id
        await save_state()
        return {"task": task}

    # --- CASE 2: Receiving Acceptance Nonces (Commit) ---
    elif media_type == "application/vnd.ga5.invoice-action-results+json":
        task_id = msg.get("taskId")
        if task_id not in _state["tasks"]: raise HTTPException(status_code=404)
        
        stored_entry = _state["tasks"][task_id]
        if stored_entry["owner"] != principal: raise HTTPException(status_code=403)
        
        task = stored_entry["data"]
        results_data = parts[0]["data"]
        proposals = task["artifacts"][0]["data"]["proposals"]
        
        executions = []
        for res in results_data.get("results", []):
            if res["outcome"] == "ACCEPTED":
                match = next((p for p in proposals if p["actionId"] == res["actionId"]), None)
                if match:
                    # Bind the proposal to the receipt nonce
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
async def get_task(task_id: str, principal: str = Depends(validate_a2a_request)):
    if task_id not in _state["tasks"]: raise HTTPException(status_code=404)
    entry = _state["tasks"][task_id]
    if entry["owner"] != principal: raise HTTPException(status_code=404)
    return entry["data"]

@router.get("/tasks")
async def list_tasks(principal: str = Depends(validate_a2a_request)):
    return {"tasks": [t["data"] for t in _state["tasks"].values() if t["owner"] == principal]}
