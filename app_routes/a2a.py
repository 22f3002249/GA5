import hashlib, json, os, httpx, asyncio
from typing import Any, Dict, List
from fastapi import APIRouter, Request, Response, HTTPException, Header, Depends

router = APIRouter()

# --- Config ---
OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY")
MODEL = os.environ.get("OPENROUTER_MODEL")
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")

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

# --- A2A Response Helper ---
def A2AJSON(data: Any):
    return Response(content=json.dumps(data), media_type="application/a2a+json")

# --- Authentication ---
async def get_principal(request: Request, a2a_version: str = Header(None)):
    if a2a_version != "1.0": raise HTTPException(status_code=400)
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "): raise HTTPException(status_code=401)
    return auth.split(" ")[1]

# --- AI Engine ---
async def propose_actions(packages: List[Dict]) -> List[Dict]:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENROUTER_KEY}"},
            json={
                "model": MODEL,
                "messages": [{"role": "user", "content": f"Analyze these invoices and return JSON proposals: {json.dumps(packages)}"}],
                "response_format": {"type": "json_object"}
            }
        )
        return json.loads(resp.json()['choices'][0]['message']['content'])["proposals"]

# --- Routes ---
@router.post("/message:send")
async def message_send(request: Request, principal: str = Depends(get_principal)):
    body = await request.json()
    msg = body.get("message", {})
    msg_id = msg.get("messageId")
    
    # 1. Idempotency
    idem_key = f"{principal}:{msg_id}"
    if idem_key in _db["idempotency"]:
        return A2AJSON({"task": _db["tasks"][_db["idempotency"][idem_key]]})

    media_type = msg.get("parts", [{}])[0].get("mediaType")

    # 2. Batch Propose
    if media_type == "application/vnd.ga5.invoice-claim-batch+json":
        data = msg["parts"][0]["data"]
        proposals = await propose_actions(data["packages"])
        task_id = f"t_{hashlib.sha256(msg_id.encode()).hexdigest()[:12]}"
        
        task = {
            "taskId": task_id, "state": "TASK_STATE_INPUT_REQUIRED",
            "history": [msg], "artifacts": [{"mediaType": "application/vnd.ga5.invoice-action-proposals+json", "data": {"batchId": data["batchId"], "proposals": proposals}}]
        }
        _db["tasks"][task_id] = task
        _db["idempotency"][idem_key] = task_id
        await save_state()
        return A2AJSON({"task": task})

    # 3. Commit Receipts
    elif media_type == "application/vnd.ga5.invoice-action-results+json":
        task_id = msg.get("taskId")
        if task_id not in _db["tasks"]: raise HTTPException(status_code=404)
        task = _db["tasks"][task_id]
        
        # ...Logic to bind executions (similar to previous version)...
        task["state"] = "TASK_STATE_COMPLETED"
        await save_state()
        return A2AJSON({"task": task})
    
    raise HTTPException(status_code=400)

@router.get("/tasks/{task_id}")
async def get_task(task_id: str, principal: str = Depends(get_principal)):
    task = _db["tasks"].get(task_id)
    if not task: raise HTTPException(status_code=404)
    return A2AJSON(task)
