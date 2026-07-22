import hashlib, json, os, httpx, asyncio, sys
from typing import List, Dict, Any
from fastapi import APIRouter, Request, Response, HTTPException, Header, Depends

router = APIRouter()

# --- Config ---
OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY")
MODEL = os.environ.get("MODEL_NAME", "openai/gpt-4o-mini")
BASE_URL = os.environ.get("BASE_URL", "https://ga5-1.onrender.com/a2a").rstrip("/")

STORAGE_FILE = "a2a_db.json"
STATE_LOCK = asyncio.Lock()

def load_db():
    if os.path.exists(STORAGE_FILE):
        try:
            with open(STORAGE_FILE, "r") as f: return json.load(f)
        except: pass
    return {"tasks": {}, "idempotency": {}, "cache": {}}

_db = load_db()

async def save_db():
    async with STATE_LOCK:
        with open(STORAGE_FILE, "w") as f: json.dump(_db, f)

def A2AJSON(data: Any):
    return Response(content=json.dumps(data), media_type="application/a2a+json")

def get_fingerprint(data: Any) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

# --- Security/Auth ---
async def validate_a2a(request: Request, a2a_version: str = Header(None, alias="A2A-Version")):
    print(f"DEBUG_HEADERS: {dict(request.headers)}", file=sys.stderr)
    if a2a_version != "1.0":
        raise HTTPException(status_code=400, detail="Invalid A2A-Version")
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Auth")
    return auth.split(" ")[1]

# --- AI Engine ---
async def analyze_invoices(packages: List[Dict]) -> List[Dict]:
    prompt = f"""You are an auditor. Analyze these invoices.
    Actions: settle_invoice, request_approval, hold_invoice, reject_duplicate, open_exception.
    Return JSON list: [{{"packageId": str, "actionId": str, "action": str, "facts": {{...}}, "evidenceRefs": [str], "rationale": str}}]
    DATA: {json.dumps(packages)}"""
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENROUTER_KEY}"},
                json={
                    "model": MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "response_format": {"type": "json_object"}
                }, timeout=45.0
            )
            return json.loads(resp.json()['choices'][0]['message']['content'])["proposals"]
    except Exception as e:
        print(f"AI_ERR: {e}", file=sys.stderr)
        return [{"packageId": p['packageId'], "actionId": f"f_{p['packageId']}", "action": "hold_invoice", "facts": {"vendorName": "NA", "invoiceNumber": "0", "amountMinor": 0, "currency": "INR"}, "evidenceRefs": [], "rationale": "Audit failed."} for p in packages]

# --- Protocol ---
async def get_card_data():
    return {
        "name": "Invoice Audit Agent",
        "description": "A2A 1.0 compliant agent.",
        "version": "1.0.0",
        "capabilities": {"invoice_action_agent": {}},
        "supportedInterfaces": [{"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0", "endpoint": BASE_URL}],
        "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
        "defaultOutputModes": ["application/vnd.ga5.invoice-action-proposals+json", "application/vnd.ga5.invoice-action-receipts+json"]
    }

@router.post("/message:send")
async def message_send(request: Request, principal: str = Depends(validate_a2a)):
    body = await request.json()
    msg = body.get("message", {})
    msg_id = msg.get("messageId")
    
    idem_key = f"{principal}:{msg_id}"
    if idem_key in _db["idempotency"]:
        return A2AJSON({"task": _db["tasks"][_db["idempotency"][idem_key]]})

    media_type = msg.get("parts", [{}])[0].get("mediaType")
    data = msg.get("parts", [{}])[0].get("data")

    if media_type == "application/vnd.ga5.invoice-claim-batch+json":
        proposals = await analyze_invoices(data["packages"])
        task_id = f"t_{get_fingerprint(msg_id)[:12]}"
        task = {
            "taskId": task_id, "state": "TASK_STATE_INPUT_REQUIRED",
            "history": [msg], "artifacts": [{"mediaType": "application/vnd.ga5.invoice-action-proposals+json", "data": {"batchId": data["batchId"], "proposals": proposals}}]
        }
        _db["tasks"][task_id] = task
        _db["idempotency"][idem_key] = task_id
        await save_db()
        return A2AJSON({"task": task})

    elif media_type == "application/vnd.ga5.invoice-action-results+json":
        task_id = msg.get("taskId")
        if task_id not in _db["tasks"]: raise HTTPException(status_code=404)
        task = _db["tasks"][task_id]
        task["state"] = "TASK_STATE_COMPLETED"
        task["history"].append(msg)
        task["artifacts"].append({"mediaType": "application/vnd.ga5.invoice-action-receipts+json", "data": data})
        await save_db()
        return A2AJSON({"task": task})
    
    raise HTTPException(status_code=400)

@router.get("/tasks/{task_id}")
async def get_task(task_id: str, principal: str = Depends(validate_a2a)):
    task = _db["tasks"].get(task_id)
    if not task: raise HTTPException(status_code=404)
    return A2AJSON({"task": task})

@router.get("/tasks")
async def list_tasks(principal: str = Depends(validate_a2a)):
    return A2AJSON({"tasks": list(_db["tasks"].values())})
