import hashlib, json, os, httpx, asyncio, sys
from typing import Any, Dict, List
from fastapi import APIRouter, Request, Response, HTTPException

router = APIRouter()

# --- Config ---
OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY")
MODEL = os.environ.get("OPENROUTER_MODEL")

STORAGE_FILE = "a2a_db.json"
STATE_LOCK = asyncio.Lock()

def load_db():
    if os.path.exists(STORAGE_FILE):
        try:
            with open(STORAGE_FILE, "r") as f: return json.load(f)
        except: pass
    return {"tasks": {}, "idempotency": {}}

_db = load_db()

async def save_db():
    async with STATE_LOCK:
        with open(STORAGE_FILE, "w") as f: json.dump(_db, f)

def A2AJSON(data: Any):
    return Response(content=json.dumps(data), media_type="application/a2a+json")

def get_fingerprint(data: Any) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

# --- AI Engine ---
async def analyze_invoices(packages: List[Dict]) -> List[Dict]:
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENROUTER_KEY}"},
                json={
                    "model": MODEL,
                    "messages": [{"role": "user", "content": f"Analyze invoices. Return JSON: {json.dumps(packages)}"}],
                    "response_format": {"type": "json_object"}
                }, timeout=45.0
            )
            # Log raw response for debugging in Render logs if AI fails
            if resp.status_code != 200:
                print(f"AI_DEBUG_ERROR: {resp.text}", file=sys.stderr)
            return json.loads(resp.json()['choices'][0]['message']['content']).get("proposals", [])
    except Exception as e:
        print(f"AI_ERR: {e}", file=sys.stderr)
        return [{"packageId": p['packageId'], "actionId": f"f_{p['packageId']}", "action": "hold_invoice", "facts": {"vendorName": "NA", "invoiceNumber": "0", "amountMinor": 0, "currency": "INR"}, "evidenceRefs": [], "rationale": "Audit in progress."} for p in packages]

# --- Routes ---
@router.post("/message:send")
async def message_send(request: Request):
    # 1. Header Validation (FastAPI lowercase headers: 'authorization', 'a2a-version')
    headers = request.headers
    if headers.get("a2a-version") != "1.0":
        raise HTTPException(status_code=400, detail="Invalid A2A-Version")
    
    auth = headers.get("authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    principal = auth.split(" ")[1]
    body = await request.json()
    msg = body.get("message", {})
    msg_id = msg.get("messageId")
    
    # 2. Idempotency
    idem_key = f"{principal}:{msg_id}"
    if idem_key in _db["idempotency"]:
        return A2AJSON({"task": _db["tasks"][_db["idempotency"][idem_key]]})

    media_type = msg.get("parts", [{}])[0].get("mediaType")
    data = msg.get("parts", [{}])[0].get("data")

    if media_type == "application/vnd.ga5.invoice-claim-batch+json":
        proposals = await analyze_invoices(data["packages"])
        task_id = f"t_{hashlib.md5(msg_id.encode()).hexdigest()[:12]}"
        task = {
            "taskId": task_id, "contextId": f"ctx_{task_id}",
            "state": "TASK_STATE_INPUT_REQUIRED",
            "history": [msg],
            "artifacts": [{"mediaType": "application/vnd.ga5.invoice-action-proposals+json", "data": {"batchId": data["batchId"], "proposals": proposals}}]
        }
        _db["tasks"][task_id] = task
        _db["idempotency"][idem_key] = task_id
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
async def get_task(task_id: str, auth: str = Header(None)):
    if not auth: raise HTTPException(status_code=401)
    task = _db["tasks"].get(task_id)
    if not task: raise HTTPException(status_code=404)
    return A2AJSON({"task": task})

@router.get("/tasks")
async def list_tasks(auth: str = Header(None)):
    if not auth: raise HTTPException(status_code=401)
    return A2AJSON({"tasks": list(_db["tasks"].values())})
