import hashlib
import json
import os
import httpx
import asyncio
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Request

router = APIRouter()

# --- CONFIG (Using OpenAI Bridge as requested) ---
AI_PIPE_URL = "https://aipipe.org/openai/v1/chat/completions"
TOKEN = os.environ.get("AIPIPE_TOKEN")
MODEL = "gpt-4o-mini" # The TEXT_MODEL
PROFILE = "ga5-mailroom-action-gate/v2"

STORAGE_FILE = "mailroom_state.json"
STATE_LOCK = asyncio.Lock()

def load_state():
    if os.path.exists(STORAGE_FILE):
        try:
            with open(STORAGE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"evals": {}, "cache": {}}

_state = load_state()

async def save_state_async():
    async with STATE_LOCK:
        try:
            with open(STORAGE_FILE, "w") as f:
                json.dump(_state, f)
        except Exception:
            pass

# --- Hashing Utils ---

def get_canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(',', ':'))

def get_digest(data: Any) -> str:
    return hashlib.sha256(get_canonical_json(data).encode('utf-8')).hexdigest()

def get_proposal_digest(p: Dict[str, Any]) -> str:
    keys = ["dossierId", "callId", "action", "target", "payload", "evidence"]
    subset = {k: p.get(k) for k in keys}
    if subset.get("target") is None:
        subset["target"] = None
    if subset.get("evidence"):
        subset["evidence"] = sorted(subset["evidence"])
    return get_digest(subset)

# --- YOUR Sanitization Layer (Unchanged) ---

def sanitize_proposal(dossier: Dict[str, Any], decision: Dict[str, Any], allowed_actions: List[str]) -> Dict[str, Any]:
    action = decision.get("action")
    if action not in allowed_actions or action not in [
        "create_draft", "update_internal_record", "send_approved_notice",
        "request_confirmation", "quarantine_item", "no_action"
    ]:
        action = "no_action"
    
    target = decision.get("target")
    payload = decision.get("payload", {})
    if not isinstance(payload, dict):
        payload = {}
        
    evidence = decision.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = [str(evidence)] if evidence else []
        
    valid_line_ids = set()
    for source in dossier.get("sources", []):
        for line in source.get("lines", []):
            if "lineId" in line:
                valid_line_ids.add(line["lineId"])
                
    evidence = [str(e) for e in evidence if e in valid_line_ids]
    if not evidence and valid_line_ids:
        for source in dossier.get("sources", []):
            for line in source.get("lines", []):
                evidence.append(line["lineId"])
                break
            if evidence:
                break

    if action == "create_draft":
        mailbox = dossier.get("mailbox", "")
        target = {"kind": "draft_queue", "id": f"mailbox:{mailbox}"}
        payload = {
            "recipient": str(payload.get("recipient", "")),
            "referenceId": str(payload.get("referenceId", "")),
            "status": str(payload.get("status", "")),
            "template": "order_status"
        }
        
    elif action == "update_internal_record":
        case_id = ""
        if isinstance(target, dict) and target.get("id"):
            case_id = str(target.get("id"))
        elif payload.get("caseId"):
            case_id = str(payload.get("caseId"))
        else:
            for s in dossier.get("sources", []):
                if s.get("sourceId"):
                    case_id = s.get("sourceId")
                    break
        target = {"kind": "case_record", "id": case_id}
        payload = {
            "field": "delivery_window",
            "sourceEventId": str(payload.get("sourceEventId", "")),
            "value": str(payload.get("value", ""))
        }
        
    elif action == "send_approved_notice":
        recipient = ""
        if isinstance(target, dict) and target.get("id"):
            recipient = str(target.get("id"))
        elif payload.get("recipient"):
            recipient = str(payload.get("recipient"))
        target = {"kind": "email", "id": recipient}
        payload = {
            "referenceId": str(payload.get("referenceId", "")),
            "status": str(payload.get("status", "")),
            "template": "approved_delivery_notice"
        }
        
    elif action == "request_confirmation":
        owning_team = ""
        if isinstance(target, dict) and target.get("id"):
            owning_team = str(target.get("id"))
        if not owning_team:
            owning_team = "operations"
        target = {"kind": "approval_queue", "id": owning_team}
        payload = {
            "claimedSender": str(payload.get("claimedSender", "")),
            "questionCode": "VERIFY_REQUEST",
            "referenceId": str(payload.get("referenceId", ""))
        }
        
    elif action == "quarantine_item":
        target = {"kind": "security_queue", "id": "mailroom"}
        artifact_id = str(payload.get("artifactId") or dossier.get("dossierId", ""))
        payload = {
            "artifactId": artifact_id,
            "reasonCode": "INDIRECT_PROMPT_INJECTION"
        }
        
    elif action == "no_action":
        target = None
        reason = str(payload.get("reasonCode"))
        if reason not in ["ALREADY_COMPLETED", "DUPLICATE", "INFORMATIONAL"]:
            reason = "INFORMATIONAL"
        payload = {
            "reasonCode": reason,
            "referenceId": str(payload.get("referenceId") or dossier.get("dossierId", ""))
        }
        
    return {
        "action": action,
        "target": target,
        "payload": payload,
        "evidence": evidence
    }

# --- AI Integration ---

async def call_ai_pipe(dossier: Dict[str, Any], allowed: List[str], client: httpx.AsyncClient) -> Dict[str, Any]:
    content_hash = get_digest(dossier)
    if content_hash in _state["cache"]:
        return _state["cache"][content_hash]

    system_prompt = f"Analyze dossier. Pick LEAST-PRIVILEGE action from: {allowed}. Return JSON."
    
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(dossier)}
        ],
        "response_format": {"type": "json_object"}
    }

    try:
        resp = await client.post(
            AI_PIPE_URL,
            headers={"Authorization": f"Bearer {TOKEN}"},
            json=payload,
            timeout=45.0
        )
        if resp.status_code != 200:
            print(f"API_ERR: {resp.status_code} - {resp.text}")
            resp.raise_for_status()

        res_data = resp.json()
        decision = json.loads(res_data['choices'][0]['message']['content'])
        
        sanitized = sanitize_proposal(dossier, decision, allowed)
        _state["cache"][content_hash] = sanitized
        return sanitized
    except Exception as e:
        print(f"CATCH_ERR: {e}")
        return {
            "action": "no_action",
            "target": None,
            "payload": {"reasonCode": "INFORMATIONAL", "referenceId": dossier.get("dossierId", "")},
            "evidence": []
        }

@router.post("/mailroom")
async def handle_mailroom(request: Request):
    body = await request.json()
    op, eval_id = body.get("operation"), body.get("evaluationId")

    if op == "propose":
        dossiers = body.get("dossiers", [])
        input_digest = get_digest(dossiers)

        if eval_id in _state["evals"]:
            if _state["evals"][eval_id]["inputDigest"] != input_digest:
                raise HTTPException(status_code=409, detail="evaluationId mismatch")
            return {
                "profile": PROFILE, "evaluationId": eval_id, "status": "awaiting_receipts",
                "inputDigest": input_digest, "proposals": list(_state["evals"][eval_id]["proposals"].values())
            }

        async with httpx.AsyncClient() as client:
            # Parallel calls to save time
            tasks = [call_ai_pipe(d, body.get("allowedActions", []), client) for d in dossiers]
            ai_results = await asyncio.gather(*tasks)

        proposals = []
        for d, res in zip(dossiers, ai_results):
            cid = f"call_{get_digest(d['dossierId'])[:24]}"
            proposals.append({
                "dossierId": d["dossierId"], "callId": cid,
                "action": res["action"], "target": res["target"],
                "payload": res["payload"], "evidence": res["evidence"]
            })

        _state["evals"][eval_id] = {"inputDigest": input_digest, "proposals": {p["dossierId"]: p for p in proposals}}
        await save_state_async()
        
        return {
            "profile": PROFILE, "evaluationId": eval_id, "status": "awaiting_receipts",
            "inputDigest": input_digest, "proposals": proposals
        }

    elif op == "commit":
        stored = _state["evals"].get(eval_id)
        if not stored: raise HTTPException(status_code=400)
        
        input_digest = body.get("inputDigest")
        receipts = body.get("receipts", [])

        outcomes = []
        for r in receipts:
            d_id = r.get("dossierId")
            p = stored["proposals"].get(d_id)
            if not p: continue
            
            # Strict verification of receipt against our persisted proposal
            valid = (p["callId"] == r.get("callId") and 
                     p["action"] == r.get("action") and 
                     get_proposal_digest(p) == r.get("proposalDigest"))

            outcomes.append({
                "dossierId": d_id, "callId": r["callId"], "action": r["action"],
                "proposalDigest": r["proposalDigest"], "receiptId": r["receiptId"],
                "status": "executed" if (valid and r.get("accepted")) else "rejected"
            })
            
        return {
            "profile": PROFILE, "evaluationId": eval_id, "status": "completed",
            "inputDigest": input_digest, "outcomes": outcomes
        }

    raise HTTPException(status_code=400)
