import json
import hashlib
import base64
from fastapi import APIRouter, Request, HTTPException, Response
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric import ed25519
from app_routes import db, classifier

router = APIRouter()

def get_canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def compute_sha256(data_bytes: bytes) -> str:
    return hashlib.sha256(data_bytes).hexdigest()

def base64url_decode(s: str) -> bytes:
    # Add padding if needed
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)

def verify_ed25519_signature(public_key_jwk: dict, signature_b64: str, data_bytes: bytes) -> bool:
    try:
        x_str = public_key_jwk["x"]
        public_key_bytes = base64url_decode(x_str)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        
        # receiptSignature is standard base64 encoded
        sig_rem = len(signature_b64) % 4
        if sig_rem > 0:
            signature_b64 += "=" * (4 - sig_rem)
        signature_bytes = base64.b64decode(signature_b64)
        
        public_key.verify(signature_bytes, data_bytes)
        return True
    except Exception as e:
        print("Signature verification failed:", repr(e))
        return False

def compute_proposal_digest(proposal: dict) -> str:
    # Keep exactly dossierId, callId, action, target (use null when absent), payload, and evidence
    target = proposal.get("target")
    if target is None:
        target = None
    evidence = sorted(proposal.get("evidence", []))
    
    obj = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": target,
        "payload": proposal.get("payload"),
        "evidence": evidence
    }
    canonical = get_canonical_json(obj)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

import traceback

@router.post("/mailroom")
@router.post("/")
async def handle_mailroom(request: Request):
    try:
        body_bytes = await request.body()
        if len(body_bytes) > 512 * 1024:
            return JSONResponse(status_code=400, content={"error": "Request body exceeds 512 KiB"})
            
        req_json = json.loads(body_bytes.decode("utf-8"))
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": f"Invalid JSON format: {str(e)}"})

    # Validate profile
    profile = req_json.get("profile")
    if profile != "ga5-mailroom-action-gate/v2":
        return JSONResponse(status_code=400, content={"error": "Unsupported profile"})

    operation = req_json.get("operation")
    try:
        if operation == "propose":
            return await handle_propose(req_json)
        elif operation == "commit":
            return await handle_commit(req_json)
        else:
            return JSONResponse(status_code=400, content={"error": "Unknown operation"})
    except Exception as e:
        tb = traceback.format_exc()
        print("Internal Error during processing:\n", tb)
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal Server Error",
                "detail": str(e),
                "traceback": tb
            }
        )

async def handle_propose(req_json: dict):
    evaluation_id = req_json.get("evaluationId")
    receipt_verifier = req_json.get("receiptVerifier")
    dossiers = req_json.get("dossiers")

    if not evaluation_id or not receipt_verifier or dossiers is None:
        return JSONResponse(status_code=422, content={"error": "Missing required propose parameters"})

    # Compute inputDigest over UTF-8 bytes of recursively key-sorted, compact JSON representation of dossiers
    canonical_dossiers_json = get_canonical_json(dossiers)
    input_digest = compute_sha256(canonical_dossiers_json.encode("utf-8"))

    # Check for duplicate dossier IDs
    dossier_ids = [d.get("dossierId") for d in dossiers]
    if len(dossier_ids) != len(set(dossier_ids)):
        return JSONResponse(status_code=400, content={"error": "Duplicate dossier IDs found in request"})

    # Exact replay and conflict check
    existing_eval = db.get_evaluation(evaluation_id)
    if existing_eval:
        # If the same evaluationId was submitted before
        if existing_eval["input_digest"] == input_digest:
            # Exact replay: return the exact byte-equivalent semantic JSON
            return Response(
                content=existing_eval["response_json"],
                media_type="application/json"
            )
        else:
            # Same evaluationId, different content: conflict HTTP 409
            return JSONResponse(status_code=409, content={"error": "Conflict: evaluationId exists with different dossiers"})

    # Process each dossier
    proposals_response = []
    for dossier in dossiers:
        dossier_id = dossier.get("dossierId")
        if not dossier_id:
            return JSONResponse(status_code=400, content={"error": "Missing dossierId"})
            
        content_hash = classifier.compute_dossier_hash(dossier)
        
        # Check cache
        cached = db.get_cached_proposal(content_hash)
        if cached:
            proposal = cached
            # Wait! dossierId might be different if the content is mapped under a different ID?
            # Normally stable dossiers have the same ID. Just to be safe, override dossierId to the current one.
            proposal["dossierId"] = dossier_id
        else:
            # Deterministic call_id based on the hash of the dossier content
            call_id = f"call-{content_hash[:32]}"
            
            # Run classifier
            proposal = classifier.classify_dossier(dossier, call_id)
            proposal_digest = compute_proposal_digest(proposal)
            proposal["proposalDigest"] = proposal_digest
            
            # Save in cache
            db.save_cached_proposal(content_hash, proposal)
            
        # Store proposal for this evaluation
        db.save_proposal(evaluation_id, dossier_id, proposal)
        
        # Build response item (do not return extra internal fields like proposalDigest or status in proposals)
        proposals_response.append({
            "dossierId": proposal["dossierId"],
            "callId": proposal["callId"],
            "action": proposal["action"],
            "target": proposal["target"],
            "payload": proposal["payload"],
            "evidence": proposal["evidence"]
        })

    response_data = {
        "profile": "ga5-mailroom-action-gate/v2",
        "evaluationId": evaluation_id,
        "status": "awaiting_receipts",
        "inputDigest": input_digest,
        "proposals": proposals_response
    }
    
    # Store evaluation state for replay checks
    response_json = get_canonical_json(response_data)
    db.save_evaluation(evaluation_id, receipt_verifier, input_digest, response_json)

    return Response(content=response_json, media_type="application/json")

async def handle_commit(req_json: dict):
    evaluation_id = req_json.get("evaluationId")
    input_digest = req_json.get("inputDigest")
    receipts = req_json.get("receipts")

    if not evaluation_id or not input_digest or receipts is None:
        return JSONResponse(status_code=422, content={"error": "Missing required commit parameters"})

    # Look up evaluation
    eval_record = db.get_evaluation(evaluation_id)
    if not eval_record:
        return JSONResponse(status_code=400, content={"error": "Unknown evaluationId"})

    if eval_record["input_digest"] != input_digest:
        return JSONResponse(status_code=400, content={"error": "Mismatched inputDigest for this evaluation"})

    receipt_verifier = json.loads(eval_record["receipt_verifier"])
    public_key_jwk = receipt_verifier.get("publicKeyJwk")

    # Fetch all stored proposals for this evaluation
    stored_proposals = {p["dossierId"]: p for p in db.get_evaluation_proposals(evaluation_id)}
    
    # Verify every receipt signature and proposal match
    outcomes = []
    receipt_dossier_ids = set()
    
    for receipt in receipts:
        dossier_id = receipt.get("dossierId")
        call_id = receipt.get("callId")
        action = receipt.get("action")
        accepted = receipt.get("accepted")
        proposal_digest = receipt.get("proposalDigest")
        receipt_id = receipt.get("receiptId")
        signature_b64 = receipt.get("receiptSignature")

        if not all([dossier_id, call_id, action, proposal_digest, receipt_id, signature_b64]) or accepted is None:
            return JSONResponse(status_code=400, content={"error": "Malformed receipt object"})

        # Check for duplicates
        if dossier_id in receipt_dossier_ids:
            return JSONResponse(status_code=400, content={"error": "Duplicate receipt for dossierId"})
        receipt_dossier_ids.add(dossier_id)

        # Retrieve stored proposal
        stored = stored_proposals.get(dossier_id)
        if not stored:
            return JSONResponse(status_code=400, content={"error": f"No proposal found for dossierId {dossier_id}"})

        # Match receipt fields with persisted proposal
        if (stored["callId"] != call_id or 
            stored["action"] != action or 
            stored["proposalDigest"] != proposal_digest):
            return JSONResponse(status_code=400, content={"error": "Receipt fields mismatch stored proposal"})

        # Verify signature
        # Construct verifier JSON shape
        verifier_obj = {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": evaluation_id,
            "inputDigest": input_digest,
            "receipt": {
                "dossierId": dossier_id,
                "callId": call_id,
                "action": action,
                "accepted": accepted,
                "proposalDigest": proposal_digest,
                "receiptId": receipt_id
            }
        }
        
        canonical_verifier_json = get_canonical_json(verifier_obj)
        data_bytes = canonical_verifier_json.encode("utf-8")
        
        if not verify_ed25519_signature(public_key_jwk, signature_b64, data_bytes):
            return JSONResponse(status_code=400, content={"error": f"Invalid signature for dossierId {dossier_id}"})

        # Determine status
        status = "executed" if accepted else "rejected"
        outcomes.append({
            "dossierId": dossier_id,
            "callId": call_id,
            "action": action,
            "proposalDigest": proposal_digest,
            "receiptId": receipt_id,
            "status": status
        })

    # If all verified successfully, commit them to DB
    for outcome in outcomes:
        db.update_proposal_outcome(
            evaluation_id=evaluation_id,
            dossier_id=outcome["dossierId"],
            status=outcome["status"],
            receipt_id=outcome["receiptId"]
        )

    response_data = {
        "profile": "ga5-mailroom-action-gate/v2",
        "evaluationId": evaluation_id,
        "status": "completed",
        "inputDigest": input_digest,
        "outcomes": outcomes
    }
    
    return Response(content=get_canonical_json(response_data), media_type="application/json")
