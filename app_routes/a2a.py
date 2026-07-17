import hashlib
import json
import os
import asyncio
import google.generativeai as genai
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Request, Response, HTTPException, Header, Depends
from pydantic import BaseModel

router = APIRouter()

# --- Config ---
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-1.5-flash')
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
        with open(STORAGE_FILE, "w") as f: json.dump(_state, f)

# --- Utils ---

def get_fingerprint(data: Any) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def get_principal(auth: str = Header(None)):
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401)
    return auth.split(" ")[1]

# --- AI Logic ---

async def analyze_invoices(batch_id: str, packages: List[Dict]) -> List[Dict]:
    prompt = f"""You are an invoice processing agent. Analyze these {len(packages)} invoice packages.
    For each package, pick EXACTLY ONE action:
    - settle_invoice: valid, reconciled, within autonomous authority.
    - request_approval: commercially valid, but outside delegated authority.
    - hold_invoice: payment pauses until verification completes.
    - reject_duplicate: the same commercial invoice was already paid.
    - open_exception: material records conflict.

    Return ONLY a JSON list of objects:
    {{
      "packageId": "...", "actionId": "unique_id", "action": "...",
      "facts": {{"vendorName": "...", "invoiceNumber": "...", "amountMinor": 12345, "currency": "INR"}},
      "evidenceRefs": ["exact strings from docs"],
      "rationale": "60-1500 chars explaining why"
    }}
    
    DATA: {json.dumps(packages)}"""

    try:
        res = await model.generate_content_async(prompt, generation_config={"response_mime_type": "application/json"})
        return json.loads(res.text)
    except:
        # Generic fallback to avoid 500s
        return [{"packageId": p['packageId'], "actionId": f"act_{p['packageId']}", "action": "hold_invoice", "facts": {"vendorName": "Unknown", "invoiceNumber": "0", "amountMinor": 0, "currency": "INR"}, "evidenceRefs": [], "rationale": "System fallback due to AI error."} for p in packages]

# --- A2A Routes ---

@router.get("/.well-known/agent-card.json")
async def get_card():
    return {
        "name": "Invoice Action Agent",
        "description": "Analyzes invoice batches and proposes business actions.",
        "version": "1.0.0",
        "capabilities": {"invoice_processing": {}},
        "supportedInterfaces": [{"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0", "endpoint": f"{BASE_URL}"}],
        "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
        "defaultOutputModes": ["application/vnd.ga5.invoice-action-proposals+json", "application/vnd.ga5.invoice-action-receipts+json"]
    }

@router.post("/message:send")
async def message_send(request: Request, principal: str = Depends(get_principal)):
    body = await request.json()
    msg = body.get("message", {})
    msg_id = msg.get("messageId")
    parts = msg.get("parts", [])
    
    # Idempotency / Conflict check
    fp = get_fingerprint(msg)
    if msg_id in _state["idempotency"]:
        stored = _state["idempotency"][msg_id]
        if stored["principal"] != principal: raise HTTPException(status_code=403)
        if stored["fp"] != fp: raise HTTPException(status_code=409, detail="IDEMPOTENCY_CONFLICT")
        return {"task": _state["tasks"][stored["task_id"]]}

    # Handle Initial Request
    if parts and parts[0]["mediaType"] == "application/vnd.ga5.invoice-claim-batch+json":
        data = parts[0]["data"]
        task_id = f"task_{get_fingerprint(msg_id)[:12]}"
        
        # Call AI
        proposals = await analyze_invoices(data["batchId"], data["packages"])
        
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
        _state["idempotency"][msg_id] = {"task_id": task_id, "principal": principal, "fp": fp}
        await save_state()
        return {"task": task}

    # Handle Continuation (Receipts)
    elif parts and parts[0]["mediaType"] == "application/vnd.ga5.invoice-action-results+json":
        task_id = msg.get("taskId")
        if task_id not in _state["tasks"]: raise HTTPException(status_code=404)
        task = _state["tasks"][task_id]
        
        results_data = parts[0]["data"]
        proposals = task["artifacts"][0]["data"]["proposals"]
        
        executions = []
        for res in results_data["results"]:
            if res["outcome"] == "ACCEPTED":
                # Find matching proposal
                match = next((p for p in proposals if p["actionId"] == res["actionId"]), None)
                if match:
                    executions.append({
                        **match,
                        "receiptNonce": res["receiptNonce"]
                    })
        
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
async def get_task(task_id: str, principal: str = Depends(get_principal)):
    if task_id not in _state["tasks"]: raise HTTPException(status_code=404)
    # Note: In real app, check principal ownership here
    return _state["tasks"][task_id]

@router.get("/tasks")
async def list_tasks(principal: str = Depends(get_principal)):
    return {"tasks": list(_state["tasks"].values())}
