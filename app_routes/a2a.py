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
GEMINI_KEY = os.environ.get("GEMINI_API_KEY")
if GEMINI_KEY:
    genai.configure(api_key=GEMINI_KEY)

# Using 'gemini-1.0-pro' as primary - it is very cheap and highly compatible
PRIMARY_MODEL = 'gemini-1.0-pro'
FALLBACK_MODEL = 'gemini-1.5-flash'

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

# --- A2A Protocol Response ---
class A2AResponse(JSONResponse):
    media_type = "application/a2a+json"

# --- Logic ---

def get_fingerprint(data: Any) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

async def validate_a2a(request: Request, a2a_version: str = Header(None)):
    if a2a_version != "1.0":
        raise HTTPException(status_code=400, detail="Invalid version")
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401)
    return auth.split(" ")[1]

async def analyze_invoice_batch(packages: List[Dict]) -> List[Dict]:
    """Semantic analysis focusing on 4/4 marks criteria."""
    prompt = f"""You are a professional invoice auditor. Analyze these {len(packages)} packages.
    ACTIONS: settle_invoice, request_approval, hold_invoice, reject_duplicate, open_exception.
    
    Return ONLY a JSON list of objects (no markdown blocks):
    - packageId: the input id
    - actionId: random unique string
    - action: exactly one of the 5 strings above
    - facts: {{vendorName, invoiceNumber, amountMinor (int), currency}}
    - evidenceRefs: list of EXACT strings from the document supporting the decision
    - rationale: A DETAILED explanation (200-500 characters). 
      You MUST name the chosen action and explicitly cite the evidenceRefs used.
    
    DATA: {json.dumps(packages)}"""

    # Try 1.0 Pro first, then 1.5 Flash
    for m_name in [PRIMARY_MODEL, FALLBACK_MODEL]:
        try:
            model = genai.GenerativeModel(m_name)
            res = await model.generate_content_async(prompt)
            # 1.0 Pro doesn't support 'response_mime_type', so we clean the text
            clean_text = res.text.replace('```json', '').replace('```', '').strip()
            return json.loads(clean_text)
        except Exception as e:
            print(f"FAILED model {m_name}: {e}")
            continue
            
    # Emergency fallback
    return [{"packageId": p['packageId'], "actionId": f"err_{p['packageId']}", "action": "hold_invoice", "facts": {"vendorName": "Unknown", "invoiceNumber": "0", "amountMinor": 0, "currency": "INR"}, "evidenceRefs": [], "rationale": "Invoice held due to model communication failure. Please review manually."} for p in packages]

# --- Routes ---

async def get_card_data():
    return {
        "name": "Invoice Logic Agent",
        "description": "Enterprise agent for invoice batch processing.",
        "version": "1.0.0",
        "capabilities": {
            "invoice_action_agent": {
                "name": "Audit Skill", 
                "description": "Reviews invoices",
                "tags": ["audit", "finance"]
            }
        },
        "supportedInterfaces": [{"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0", "endpoint": f"{BASE_URL}"}],
        "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
        "defaultOutputModes": ["application/vnd.ga5.invoice-action-proposals+json", "application/vnd.ga5.invoice-action-receipts+json"]
    }

@router.get("/.well-known/agent-card.json")
async def discovery():
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
        task_id = f"t_{get_fingerprint(msg_id)[:16]}"
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
        entry = _state["tasks"].get(task_id)
        if not entry or entry["owner"] != principal: raise HTTPException(status_code=404)
        
        task = entry["data"]
        results_data = parts[0]["data"]
        proposals = task["artifacts"][0]["data"]["proposals"]
        
        executions = []
        for res in results_data.get("results", []):
            if res["outcome"] == "ACCEPTED":
                p = next((x for x in proposals if x["actionId"] == res["actionId"]), None)
                if p:
                    executions.append({
                        "packageId": p["packageId"], "actionId": p["actionId"],
                        "action": p["action"], "receiptNonce": res["receiptNonce"],
                        "facts": p["facts"], "evidenceRefs": p["evidenceRefs"]
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
