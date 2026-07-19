import hashlib, json, os, sys
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Request
from huggingface_hub import InferenceClient

router = APIRouter()

# --- Config ---
HF_TOKEN = os.environ.get("HF_TOKEN")
# We use the inference client which manages its own connection pool
client = InferenceClient(model="google/gemma-4-12B-it", token=HF_TOKEN)

STORAGE_FILE = "mailroom_state.json"
# ... (Keep your load_state, save_state, and hashing functions here) ...

async def call_gemma(dossier: Dict, allowed: List[str]) -> Dict:
    content_hash = get_digest(dossier)
    if content_hash in _state["cache"]: return _state["cache"][content_hash]

    prompt = f"""<start_of_turn>user
    You are an invoice auditor. Pick one: {allowed}.
    Return ONLY JSON: {{"action": str, "target": dict|null, "payload": dict, "evidence": [str]}}
    Dossier: {json.dumps(dossier)}<end_of_turn>
    <start_of_turn>model
    """
    
    try:
        # Use the official HF SDK instead of raw httpx
        # This resolves the DNS/Hostname issues automatically
        response = client.text_generation(prompt, max_new_tokens=500, temperature=0.1)
        
        # Clean JSON from the response
        clean_json = response.strip()
        decision = json.loads(clean_json)
        
        _state["cache"][content_hash] = decision
        return decision
    except Exception as e:
        print(f"HF_ERR: {e}")
        return {"action": "no_action", "target": None, "payload": {"reasonCode": "INFORMATIONAL"}, "evidence": []}

@router.post("/mailroom")
async def mailroom_gate(request: Request):
    body = await request.json()
    # ... (Keep your propose/commit logic, but call await call_gemma(...) instead of httpx)
