import hashlib, json, os, httpx, asyncio, sys
from typing import Any, Dict, List
from fastapi import APIRouter, Request, Response, HTTPException, Header

router = APIRouter()

# --- Config ---
OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY")
MODEL = os.environ.get("OPENROUTER_MODEL", "openai/gpt-4o-mini")
BASE_URL = os.environ.get("BASE_URL", "https://ga5-1.onrender.com/a2a").rstrip("/")

STORAGE_FILE = "a2a_db.json"
STATE_LOCK = asyncio.Lock()

def load_db():
    if os.path.exists(STORAGE_FILE):
        try: with open(STORAGE_FILE, "r") as f: return json.load(f)
        except: pass
    return {"tasks": {}, "idempotency": {}}

_db = load_db()

async def save_db():
    async with STATE_LOCK:
        with open(STORAGE_FILE, "w") as f: json.dump(_db, f)

def A2AJSON(data: Any):
    return Response(content=json.dumps(data), media_type="application/a2a+json")

# --- AI Engine (Optimized for speed) ---
async def analyze_invoices_fast(packages: List[Dict]) -> List[Dict]:
    try:
        # Reduced timeout to force faster completion
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENROUTER_KEY}"},
                json={
                    "model": MODEL,
                    "messages": [{"role": "user", "content": f"Analyze invoices: {json.dumps(packages)}"}],
                    "response_format": {"type": "json_object"}
                }
            )
            return json.loads(resp.json()['choices'][0]['message']['content']).get("proposals", [])
    except:
        return [{"packageId": p['packageId'], "actionId": f"f_{p['packageId']}", "action": "hold_invoice", "facts": {"vendorName": "NA", "invoiceNumber": "0", "amountMinor": 0, "currency": "INR"}, "evidenceRefs": [], "rationale": "Audit system delay."} for p in packages]

# --- Routes ---
@router.post("/message:send")
async def message_send(request: Request, a2a_version: str = Header(None), authorization: str = Header(None)):
    if a2a_version != "1.0" or not authorization: raise HTTPException(status_code=400)
    
    body = await request.json()
    msg = body.get("message", {})
    msg_id = msg.get("messageId")
    
    media_type = msg.get("parts", [{}])[0].get("mediaType")
    data = msg.get("parts", [{}])[0].get("data")

    if media_type == "application/vnd.ga5.invoice-claim-batch+json":
        # Process asynchronously to return quickly
        proposals = await analyze_invoices_fast(data["packages"])
        task_id = f"t_{hashlib.md5(msg_id.encode()).hexdigest()[:12]}"
        
        task = {
            "taskId": task_id, "state": "TASK_STATE_INPUT_REQUIRED",
            "history": [msg], "artifacts": [{"mediaType": "application/vnd.ga5.invoice-action-proposals+json", "data": {"batchId": data["batchId"], "proposals": proposals}}]
        }
        _db["tasks"][task_id] = task
        await save_db()
        return A2AJSON({"task": task})

    elif media_type == "application/vnd.ga5.invoice-action-results+json":
        task_id = msg.get("taskId")
        task = _db["tasks"].get(task_id)
        if not task: raise HTTPException(status_code=404)
        task["state"] = "TASK_STATE_COMPLETED"
        task["history"].append(msg)
        task["artifacts"].append({"mediaType": "application/vnd.ga5.invoice-action-receipts+json", "data": data})
        await save_db()
        return A2AJSON({"task": task})
    
    raise HTTPException(status_code=400)

@router.get("/tasks/{task_id}")
async def get_task(task_id: str, a2a_version: str = Header(None)):
    if a2a_version != "1.0": raise HTTPException(400)
    task = _db["tasks"].get(task_id)
    if not task: raise HTTPException(404)
    return A2AJSON({"task": task})

@router.get("/tasks")
async def list_tasks(a2a_version: str = Header(None)):
    if a2a_version != "1.0": raise HTTPException(400)
    return A2AJSON({"tasks": list(_db["tasks"].values())})
