import hashlib, json, os, httpx, asyncio
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Request

router = APIRouter()

# --- Config ---
HF_TOKEN = os.environ.get("HF_TOKEN")
HF_URL = "https://api-inference.huggingface.co/models/google/gemma-2-2b-it"
PROFILE = "ga5-mailroom-action-gate/v2"

STORAGE_FILE = "mailroom_state.json"
STATE_LOCK = asyncio.Lock()

def load_state():
    if os.path.exists(STORAGE_FILE):
        try:
            with open(STORAGE_FILE, "r") as f: return json.load(f)
        except: pass
    return {"evals": {}, "cache": {}}

_state = load_state()

async def save_state():
    async with STATE_LOCK:
        with open(STORAGE_FILE, "w") as f: json.dump(_state, f)

def get_digest(data: Any) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

# --- AI Logic ---
async def call_gemma(dossier: Dict, allowed: List[str]) -> Dict:
    content_hash = get_digest(dossier)
    if content_hash in _state["cache"]: return _state["cache"][content_hash]

    prompt = f"""<start_of_turn>user
    Analyze the dossier. Output strictly valid JSON.
    ALLOWED: {allowed}
    Schema: {{"action": str, "target": dict|null, "payload": dict, "evidence": [str]}}
    Dossier: {json.dumps(dossier)}<end_of_turn>
    <start_of_turn>model
    """
    
    async with httpx.AsyncClient() as client:
        resp = await client.post(HF_URL, headers={"Authorization": f"Bearer {HF_TOKEN}"}, json={"inputs": prompt})
        try:
            raw = resp.json()[0]['generated_text'].split("<start_of_turn>model")[-1].strip()
            decision = json.loads(raw)
            _state["cache"][content_hash] = decision
            return decision
        except:
            return {"action": "no_action", "target": None, "payload": {"reasonCode": "INFORMATIONAL"}, "evidence": []}

@router.post("/mailroom")
async def mailroom_gate(request: Request):
    body = await request.json()
    op, eval_id = body.get("operation"), body.get("evaluationId")

    if op == "propose":
        dossiers = body.get("dossiers", [])
        input_digest = get_digest(dossiers)

        # Idempotency check
        if eval_id in _state["evals"]:
            if _state["evals"][eval_id]["inputDigest"] != input_digest:
                raise HTTPException(status_code=409)
            return {"profile": PROFILE, "evaluationId": eval_id, "status": "awaiting_receipts", 
                    "inputDigest": input_digest, "proposals": list(_state["evals"][eval_id]["proposals"].values())}

        proposals = []
        for d in dossiers:
            decision = await call_gemma(d, body.get("allowedActions", []))
            cid = f"c_{get_digest(d['dossierId'])}" # Stable callId
            proposals.append({"dossierId": d["dossierId"], "callId": cid, **decision})

        _state["evals"][eval_id] = {"inputDigest": input_digest, "proposals": {p["dossierId"]: p for p in proposals}}
        await save_state()
        return {"profile": PROFILE, "evaluationId": eval_id, "status": "awaiting_receipts", "inputDigest": input_digest, "proposals": proposals}

    elif op == "commit":
        stored = _state["evals"].get(eval_id)
        if not stored: raise HTTPException(status_code=400)
        
        outcomes = []
        for r in body.get("receipts", []):
            p = stored["proposals"].get(r["dossierId"])
            # Digest validation for receipts
            p_dig = get_digest({k: p[k] for k in ["dossierId", "callId", "action", "target", "payload", "evidence"]})
            valid = p and p["callId"] == r["callId"] and p_dig == r["proposalDigest"]
            outcomes.append({**r, "status": "executed" if (valid and r["accepted"]) else "rejected"})
            
        return {"profile": PROFILE, "evaluationId": eval_id, "status": "completed", 
                "inputDigest": body.get("inputDigest"), "outcomes": outcomes}
    raise HTTPException(status_code=400)
