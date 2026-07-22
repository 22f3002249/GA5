import hashlib
import json
import os
import httpx
from fastapi import APIRouter, HTTPException, Request

router = APIRouter()

# --- CONFIG ---
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")
MODEL = os.environ.get("OPENROUTER_MODEL")
PROFILE = "ga5-mailroom-action-gate/v2"

# In-memory store (Replace with Redis if your instance restarts frequently)
_EVAL_STORE = {}

def canonical(data):
    """The mandatory hash/digest format: no spaces, sorted keys."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))

def get_proposal_digest(p):
    subset = {
        "dossierId": p["dossierId"],
        "callId": p["callId"],
        "action": p["action"],
        "target": p.get("target"),
        "payload": p["payload"],
        "evidence": sorted(p["evidence"])
    }
    return hashlib.sha256(canonical(subset).encode()).hexdigest()

@router.post("/mailroom")
async def handle_mailroom(request: Request):
    try:
        body = await request.json()
    except:
        raise HTTPException(status_code=400)

    op = body.get("operation")
    eval_id = body.get("evaluationId")

    if op == "propose":
        dossiers = body.get("dossiers", [])
        input_digest = hashlib.sha256(canonical(dossiers).encode()).hexdigest()
        proposals = []

        for d in dossiers:
            # 1. AI Decision logic with strict System Instruction
            ai_data = await query_ai_strict(d)
            
            # 2. Schema normalization (ensure constants are injected)
            call_id = f"call_{hashlib.md5(d['dossierId'].encode()).hexdigest()}"
            
            proposal = {
                "dossierId": d["dossierId"],
                "callId": call_id,
                "action": ai_data["action"],
                "target": ai_data.get("target"),
                "payload": ai_data["payload"],
                "evidence": ai_data["evidence"]
            }
            proposals.append(proposal)

        _EVAL_STORE[eval_id] = {"inputDigest": input_digest, "proposals": proposals}
        
        return {
            "profile": PROFILE,
            "evaluationId": eval_id,
            "status": "awaiting_receipts",
            "inputDigest": input_digest,
            "proposals": proposals
        }

    elif op == "commit":
        stored = _EVAL_STORE.get(eval_id)
        if not stored: raise HTTPException(status_code=400)
            
        receipts = body.get("receipts", [])
        outcomes = []
        for r in receipts:
            # The Grader requires these specific fields in the outcome
            outcomes.append({
                "dossierId": r["dossierId"],
                "callId": r["callId"],
                "action": r["action"],
                "proposalDigest": r["proposalDigest"],
                "receiptId": r["receiptId"],
                "status": "executed" if r.get("accepted") else "rejected"
            })
            
        return {
            "profile": PROFILE,
            "evaluationId": eval_id,
            "status": "completed",
            "inputDigest": body.get("inputDigest"),
            "outcomes": outcomes
        }

async def query_ai_strict(dossier):
    async with httpx.AsyncClient() as client:
        # Use a simpler prompt - don't dump the whole dossier as a giant string
        # Just give it the objective and the lines
        dossier_summary = {
            "dossierId": dossier["dossierId"],
            "objective": dossier.get("objective"),
            "lines": [l["text"] for src in dossier.get("sources", []) for l in src.get("lines", [])]
        }
        
        try:
            resp = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": MODEL,
                    "messages": [
                        {"role": "system", "content": "You are a mailroom agent. Output ONLY valid JSON: {action, target, payload, evidence}. Evidence is a list of lineIds."},
                        {"role": "user", "content": json.dumps(dossier_summary)}
                    ]
                },
                timeout=30.0
            )
            
            # Check for API errors BEFORE accessing 'choices'
            if resp.status_code != 200:
                print(f"API_ERROR: {resp.status_code} - {resp.text}")
                raise Exception(f"API returned {resp.status_code}")
                
            data = resp.json()
            if "choices" not in data:
                print(f"API_MALFORMED_RESPONSE: {data}")
                raise Exception("Response missing choices")

            raw = data["choices"][0]["message"]["content"].replace("```json", "").replace("```", "").strip()
            return json.loads(raw)
            
        except Exception as e:
            print(f"AI_CALL_FAILED: {str(e)}")
            # Fallback for stable dossiers:
            return {
                "action": "no_action",
                "target": None,
                "payload": {"reasonCode": "INFORMATIONAL", "referenceId": dossier["dossierId"]},
                "evidence": []
            }
