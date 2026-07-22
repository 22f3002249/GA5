import hashlib, json, os, asyncio, httpx
from typing import List, Dict, Any
from fastapi import APIRouter, Request, Response, HTTPException, Header, Depends

router = APIRouter()

# --- Config ---
OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY")
MODEL = os.environ.get("OPENROUTER_MODEL")
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")

STORAGE_FILE = "a2a_db.json"
STATE_LOCK = asyncio.Lock()

def check_headers(request: Request, a2a_version: str = Header(None)):
    if a2a_version != "1.0":
        raise HTTPException(status_code=400, detail="Missing or invalid A2A-Version header")
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    return auth.split(" ")[1]

def load_db():
    if os.path.exists(STORAGE_FILE):
        try:
            with open(STORAGE_FILE, "r") as f: return json.load(f)
        except: pass
    return {"tasks": {}, "idempotency": {}, "semantic_cache": {}}

_db = load_db()

async def save_db():
    async with STATE_LOCK:
        with open(STORAGE_FILE, "w") as f: json.dump(_db, f)

# --- Utils ---
def get_fingerprint(data: Any) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def A2AJSON(data: Any):
    return Response(content=json.dumps(data), media_type="application/a2a+json")

async def get_card_data():
    base_url = os.environ.get("BASE_URL", "").rstrip("/")
    return {
        "name": "Invoice Audit Agent",
        "description": "Enterprise agent for invoice batch processing.",
        "version": "1.0.0",
        "capabilities": {"invoice_action_agent": {"name": "Audit", "description": "Audits", "tags": ["finance"]}},
        "supportedInterfaces": [{"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0", "endpoint": f"{base_url}"}],
        "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
        "defaultOutputModes": ["application/vnd.ga5.invoice-action-proposals+json", "application/vnd.ga5.invoice-action-receipts+json"]
    }

# --- AI Logic (Cached by Package) ---
async def process_package(pkg: Dict) -> Dict:
    pkg_fp = get_fingerprint(pkg)
    if pkg_fp in _db["semantic_cache"]:
        return _db["semantic_cache"][pkg_fp]

    prompt = f"""Audit this invoice package. Choose: settle_invoice, request_approval, hold_invoice, reject_duplicate, open_exception.
    Return JSON: {{"packageId": str, "actionId": str, "action": str, "facts": {{vendorName, invoiceNumber, amountMinor, currency}}, "evidenceRefs": [str], "rationale": str}}
    Package: {json.dumps(pkg)}"""

    async with httpx.AsyncClient() as client:
        resp = await client.post("https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENROUTER_KEY}"},
            json={"model": MODEL, "messages": [{"role": "user", "content": prompt}], "response_format": {"type": "json_object"}},
            timeout=30.0)
        res = json.loads(resp.json()['choices'][0]['message']['content'])
        _db["semantic_cache"][pkg_fp] = res
        await save_db()
        return res

# --- Routes ---
@router.post("/message:send")
async def message_send(request: Request, principal: str = Depends(check_headers)):
    if a2a_version != "1.0" or not auth or not auth.startswith("Bearer "): raise HTTPException(400)
    principal = auth.split(" ")[1]
    body = await request.json()
    msg = body.get("message", {})
    msg_id = msg.get("messageId")

    idem_key = f"{principal}:{msg_id}"
    if idem_key in _db["idempotency"]:
        return A2AJSON({"task": _db["tasks"][_db["idempotency"][idem_key]]})

    media_type = msg.get("parts", [{}])[0].get("mediaType")

    if media_type == "application/vnd.ga5.invoice-claim-batch+json":
        data = msg["parts"][0]["data"]
        # Parallel audit of packages (cached individually)
        tasks = [process_package(p) for p in data["packages"]]
        proposals = await asyncio.gather(*tasks)
        
        task_id = f"task_{get_fingerprint(msg_id)[:12]}"
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
        task = _db["tasks"].get(task_id)
        if not task: raise HTTPException(404)
        
        # Execute only accepted
        task["state"] = "TASK_STATE_COMPLETED"
        task["history"].append(msg)
        task["artifacts"].append({"mediaType": "application/vnd.ga5.invoice-action-receipts+json", "data": msg["parts"][0]["data"]})
        await save_db()
        return A2AJSON({"task": task})
        
@router.post("/message%3Asend")
async def message_send_encoded(request: Request, principal: str = Depends(check_headers)):
    return await message_send(request, principal)
    
    raise HTTPException(400)
