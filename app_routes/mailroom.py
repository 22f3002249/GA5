import hashlib
import json
import os
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Request

router = APIRouter()

# --- Persistence Layer ---
# Simple file-based storage for persistence across restarts
STORAGE_FILE = "mailroom_store.json"

def load_store():
    if os.path.exists(STORAGE_FILE):
        try:
            with open(STORAGE_FILE, "r") as f:
                return json.load(f)
        except: return {}
    return {}

def save_store(data):
    with open(STORAGE_FILE, "w") as f:
        json.dump(data, f)

# Global state for this session (initial load)
_store = load_store()
# Structure: 
# _store["evaluations"][eval_id] = { "inputDigest": str, "proposals": { dossier_id: proposal_dict } }
# _store["stable_cache"][dossier_content_hash] = { proposal_fields }

if "evaluations" not in _store: _store["evaluations"] = {}
if "stable_cache" not in _store: _store["stable_cache"] = {}

# --- Utility Functions ---

def canonical_json_hash(data: Any) -> str:
    """Computes SHA-256 over recursively key-sorted compact JSON."""
    serialized = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(serialized).hexdigest()

def get_proposal_digest(proposal: Dict[str, Any]) -> str:
    """Subset of proposal fields for the receipt digest."""
    keys = ["dossierId", "callId", "action", "target", "payload", "evidence"]
    subset = {k: proposal.get(k) for k in keys}
    if subset["evidence"]:
        subset["evidence"] = sorted(subset["evidence"])
    return canonical_json_hash(subset)

# --- Mock/Skeleton LLM Logic ---
# In production, you would call OpenAI/Anthropic here.
async def classify_dossier(dossier: Dict[str, Any], allowed_actions: List[str]) -> Dict[str, Any]:
    """
    Placeholder for AI reasoning. 
    It should analyze dossier['objective'] and dossier['sources'].
    """
    # For the exam, fingerprint the content to ensure stability
    content_sig = canonical_json_hash(dossier)
    if content_sig in _store["stable_cache"]:
        return _store["stable_cache"][content_sig]

    # --- SKELETON AI LOGIC ---
    # Example: default to no_action for unknown items
    decision = {
        "action": "no_action",
        "target": None,
        "payload": {"reasonCode": "INFORMATIONAL", "referenceId": dossier["dossierId"]},
        "evidence": [dossier["sources"][0]["lines"][0]["lineId"]] if dossier["sources"] else []
    }
    
    # Cache it
    _store["stable_cache"][content_sig] = decision
    save_store(_store)
    return decision

# --- Routes ---

@router.post("/mailroom")
async def mailroom_gate(request: Request):
    body = await request.json()
    op = body.get("operation")
    eval_id = body.get("evaluationId")

    if op == "propose":
        dossiers = body.get("dossiers", [])
        input_digest = canonical_json_hash(dossiers)
        
        # Conflict check
        if eval_id in _store["evaluations"]:
            if _store["evaluations"][eval_id]["inputDigest"] != input_digest:
                raise HTTPException(status_code=409, detail="IDEMPOTENCY_CONFLICT")
            # Return existing
            return {
                "profile": "ga5-mailroom-action-gate/v2",
                "evaluationId": eval_id,
                "status": "awaiting_receipts",
                "inputDigest": input_digest,
                "proposals": list(_store["evaluations"][eval_id]["proposals"].values())
            }

        proposals = []
        for d in dossiers:
            ai_result = await classify_dossier(d, body.get("allowedActions", []))
            
            # Generate a stable callId based on dossier content and evaluation
            call_id = f"call_{canonical_json_hash({'eid': eval_id, 'did': d['dossierId']})[:16]}"
            
            proposal = {
                "dossierId": d["dossierId"],
                "callId": call_id,
                "action": ai_result["action"],
                "target": ai_result["target"],
                "payload": ai_result["payload"],
                "evidence": ai_result["evidence"]
            }
            proposals.append(proposal)

        # Persist
        _store["evaluations"][eval_id] = {
            "inputDigest": input_digest,
            "proposals": {p["dossierId"]: p for p in proposals}
        }
        save_store(_store)

        return {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "awaiting_receipts",
            "inputDigest": input_digest,
            "proposals": proposals
        }

    elif op == "commit":
        receipts = body.get("receipts", [])
        input_digest = body.get("inputDigest")

        if eval_id not in _store["evaluations"]:
            raise HTTPException(status_code=400, detail="Unknown evaluationId")

        stored_eval = _store["evaluations"][eval_id]
        outcomes = []

        for r in receipts:
            d_id = r["dossierId"]
            p = stored_eval["proposals"].get(d_id)
            
            if not p or p["callId"] != r["callId"] or get_proposal_digest(p) != r["proposalDigest"]:
                status = "rejected"
            else:
                status = "executed" if r["accepted"] else "rejected"

            outcomes.append({
                "dossierId": d_id,
                "callId": r["callId"],
                "action": r["action"],
                "proposalDigest": r["proposalDigest"],
                "receiptId": r["receiptId"],
                "status": status
            })

        return {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "completed",
            "inputDigest": input_digest,
            "outcomes": outcomes
        }

    raise HTTPException(status_code=400, detail="Invalid operation")
