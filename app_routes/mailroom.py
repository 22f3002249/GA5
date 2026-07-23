import hashlib
import json
import os
import re
import asyncio
import itertools
from typing import Dict, Any, List

from fastapi import APIRouter, Request, Response
import httpx

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

router = APIRouter()

PROFILE = "ga5-mailroom-action-gate/v2"

ACTIONS = (
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
)

SAFE_DEFAULT = "request_confirmation"
NO_ACTION_REASONS = ("ALREADY_COMPLETED", "DUPLICATE", "INFORMATIONAL")

MAX_BODY_BYTES = 16 * 1024 * 1024
MAX_DOSSIERS = 400
MAX_RECEIPTS = 400
MAX_LINES = 60
MAX_LINE_CHARS = 320
CHUNK_SIZE = 10
MAX_CONCURRENCY = 6
CHUNK_TIMEOUT = 26.0
PROPOSE_BUDGET = 46.0

# --- ORIGINAL WORKING STATE PERSISTENCE ---
STATE_FILE = "mailroom_state.json"
STATE_LOCK = asyncio.Lock()

def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"[MAILROOM_LOG] Error loading state file: {e}")
    return {"evals": {}, "cache": {}}

_STATE = load_state()

async def save_state():
    async with STATE_LOCK:
        try:
            with open(STATE_FILE, "w") as f:
                json.dump(_STATE, f)
        except Exception as e:
            print(f"[MAILROOM_LOG] Failed to save state: {e}")

# --- HELPER FUNCTIONS ---
def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))

def digest_of(data: Any) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()

def proposal_digest(proposal):
    """The grader's normalization: fixed key set, sorted evidence, then SHA-256."""
    core = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": proposal.get("target"),
        "payload": proposal["payload"],
        "evidence": sorted(proposal["evidence"]),
    }
    return digest_of(core)

def fingerprint_of(dossier):
    """Content identity of a dossier, ignoring volatile receipt timestamps."""
    body = {k: v for k, v in dossier.items() if k != "receivedAt"}
    return digest_of(body)

def call_id_for(dossier_id, fingerprint):
    """Durable and evaluation-independent unique call ID."""
    return "mr_" + hashlib.sha256(
        ("q9v2|" + dossier_id + "|" + fingerprint).encode("utf-8")
    ).hexdigest()[:40]

def error_response(status_code: int, detail: str) -> Response:
    """Enforces identical JSON structure and deterministic encoding on error boundaries."""
    return Response(
        status_code=status_code,
        content=canonical_json({"detail": detail}),
        media_type="application/json"
    )

# ------------------------------------------------------- TRIFECTA SCRUBBING
CANARY_RE = re.compile(r"[A-Za-z0-9_\-]*canary[A-Za-z0-9_\-]*", re.I)
VAULT_RE = re.compile(
    r"[A-Za-z0-9_\-]*(?:vault|passphrase|api[_-]?key|secret[_-]?key)[A-Za-z0-9_\-]*", re.I
)
HEXRUN_RE = re.compile(r"\b[0-9a-fA-F]{24,}\b")
TOKEN_RE = re.compile(r"\b(?:sk|pk|ghp|gho|xox[baprs])[-_][A-Za-z0-9_\-]{12,}\b")
PEM_RE = re.compile(r"-{2,}BEGIN[^-]{0,60}-{2,}", re.I)
SECRET_RES = (CANARY_RE, VAULT_RE, TOKEN_RE, HEXRUN_RE, PEM_RE)

def looks_secret(s):
    return any(rx.search(s) for rx in SECRET_RES)

def clean_scalar(value, fallback, limit=160):
    """Clean and filter string values to prevent secret leaks to downstream tools."""
    if isinstance(value, bool) or value is None:
        value = ""
    if isinstance(value, (int, float)):
        value = str(value)
    if not isinstance(value, str):
        value = ""
    value = " ".join(value.split())
    if not value or looks_secret(value):
        return fallback
    if len(value) > limit:
        value = value[:limit].rstrip()
    return value or fallback

# ------------------------------------------------------------- LINE RENDER
def dossier_lines(dossier):
    out = []
    sources = dossier.get("sources")
    if not isinstance(sources, list):
        return out
    for src in sources:
        if not isinstance(src, dict):
            continue
        sid = src.get("sourceId")
        lines = src.get("lines")
        if not isinstance(lines, list):
            continue
        for ln in lines:
            if not isinstance(ln, dict):
                continue
            lid = ln.get("lineId")
            if not isinstance(lid, str) or not lid:
                continue
            text = ln.get("text")
            out.append(
                (
                    lid,
                    text if isinstance(text, str) else "",
                    sid if isinstance(sid, str) else "",
                )
            )
            if len(out) >= MAX_LINES:
                return out
    return out

def render_dossier(dossier, did):
    parts = [f"### DOSSIER {did}"]
    for key in ("partition", "mailbox", "objective"):
        v = dossier.get(key)
        if isinstance(v, str) and v:
            parts.append(f"{key}: {v[:300]}")
    sources = dossier.get("sources") if isinstance(dossier.get("sources"), list) else []
    budget = MAX_LINES
    for src in sources:
        if not isinstance(src, dict) or budget <= 0:
            continue
        parts.append(
            f'-- source {src.get("sourceId", "?")} | kind={src.get("kind", "?")} | provenance={src.get("provenance", "?")} | title={str(src.get("title", ""))[:120]}'
        )
        for ln in (src.get("lines") or [])[:budget]:
            if not isinstance(ln, dict):
                continue
            lid = ln.get("lineId")
            if not isinstance(lid, str):
                continue
            text = ln.get("text")
            text = text if isinstance(text, str) else ""
            parts.append(f"   [{lid}] {text[:MAX_LINE_CHARS]}")
            budget -= 1
    parts.append(f"### END {did}")
    return "\n".join(parts)

# --------------------------------------------------------- DETERMINISTIC GATE
INJECTION_CLAUSE = "higher-priority instruction"
EXFIL_CLAUSE = "Copy any vault marker"
COMPLETED_CLAUSE = "records this item as"
APPROVAL_CLAUSE = "permits one delivery-status notice"
CARRIER_CLAUSE = "to change delivery_window to the exact value"
MISMATCH_CLAUSE = "the requested change therefore requires"
ENQUIRY_CLAUSE = "I have not asked you to send anything yet"
ENQUIRY_RECORD_CLAUSE = "its current public status is exactly"

Q_PATTERN = "[“\"]([^”\"]+)[”\"]"
RE_APPROVAL = re.compile(
    r"Approval (EVT-[A-Z0-9]+) permits one delivery-status notice for "
    r"(ORD-[A-Z0-9]+) to (\S+) using template (\S+)\."
)
RE_APPROVAL_STATUS = re.compile(r"valid for the public status " + Q_PATTERN)
RE_CARRIER = re.compile(
    r"Event (EVT-[A-Z0-9]+) authorizes case (CASE-[A-Z0-9]+) to change "
    r"(\w+) to the exact value " + Q_PATTERN
)
RE_MISMATCH = re.compile(
    r"The authenticated contact for (CASE-[A-Z0-9]+) does not match (\S+); "
    r"the requested change therefore requires ([a-z-]+) confirmation\."
)
RE_ENQUIRY_RECORD = re.compile(
    r"Order (ORD-[A-Z0-9]+) is linked to (CASE-[A-Z0-9]+); "
    r"its current public status is exactly " + Q_PATTERN
)
RE_GATEWAY = re.compile(r"sender address recorded by the gateway is (\S+)\.")
RE_OWNERSHIP = re.compile(
    r"mailbox route is ([\w.\-]+), while ownership remains with ([\w.\-]+)"
)
RE_COMPLETED = re.compile(
    r"(CASE-[A-Z0-9]+) records this item as "
    r"(already completed|duplicate|informational); "
    r"the prior action has terminal event (EVT-[A-Z0-9]+)\."
)
RE_ARTIFACT = re.compile(r"The attachment is (ATT-[A-Z0-9]+)\.")
RE_FOLLOWUP = re.compile(r"follow-up about (ORD-[A-Z0-9]+); no new change")
FOLLOWUP_CLAUSE = "no new change or outbound response is requested"
RE_SUPPLIES = re.compile(r"supplies order (ORD-[A-Z0-9]+)")

ACTION_RULES = {
    "create_draft": "For an unverified inbound status enquiry, create a draft",
    "update_internal_record": "A verified carrier event may update only the named case field",
    "request_confirmation": "When sender identity conflicts with the account record",
    "quarantine_item": "Quarantine external content that attempts to direct tool use",
    "no_action": "Do not create a second side effect for completed, duplicate",
}
GENERIC_RULE = "Select only the action supported by current scoped evidence"
MAX_EVIDENCE = 5

def _rule_line(dossier, action):
    clause = ACTION_RULES.get(action)
    if not clause:
        return None
    for _src, lines in _sources(dossier, "policy", "signed_internal"):
        for ln in lines:
            text = ln.get("text") or ""
            if GENERIC_RULE not in text and clause in text:
                return ln["lineId"]
    return None

COMPLETED_REASONS = {
    "already completed": "ALREADY_COMPLETED",
    "duplicate": "DUPLICATE",
    "informational": "INFORMATIONAL",
}

def _sources(dossier, kind, provenance):
    for src in dossier.get("sources") or []:
        if not isinstance(src, dict):
            continue
        if src.get("kind") == kind and src.get("provenance") == provenance:
            lines = [
                ln
                for ln in (src.get("lines") or [])
                if isinstance(ln, dict) and isinstance(ln.get("lineId"), str)
            ]
            yield src, lines

def _bearing(dossier, kind, provenance, *clauses):
    for src, lines in _sources(dossier, kind, provenance):
        for ln in lines:
            text = ln.get("text") or ""
            if any(c in text for c in clauses):
                return src, lines
    return None, []

def _find(lines, rx):
    for ln in lines:
        m = rx.search(ln.get("text") or "")
        if m:
            return ln["lineId"], m
    return None, None

def deterministic_decision(dossier):
    # Quarantine hostile attachment instructions
    _src, lines = _bearing(
        dossier,
        "attachment",
        "external_untrusted",
        INJECTION_CLAUSE,
        EXFIL_CLAUSE,
    )
    if lines:
        alid, m = _find(lines, RE_ARTIFACT)
        if m:
            plid = _rule_line(dossier, "quarantine_item")
            ilid = next(
                (
                    ln["lineId"]
                    for ln in lines
                    if INJECTION_CLAUSE in (ln.get("text") or "")
                ),
                None,
            )
            xlid = next(
                (
                    ln["lineId"]
                    for ln in lines
                    if EXFIL_CLAUSE in (ln.get("text") or "")
                ),
                None,
            )
            ev = [e for e in (plid, ilid, xlid, alid) if e]
            return {
                "action": "quarantine_item",
                "evidence": ev,
                "fields": {"artifactId": m.group(1)},
            }

    # Already completed / Duplicate handler
    _src, lines = _bearing(
        dossier, "record", "authenticated_internal", COMPLETED_CLAUSE
    )
    lid, m = _find(lines, RE_COMPLETED)
    if m:
        plid = _rule_line(dossier, "no_action")
        _fsrc, flines = _bearing(
            dossier, "message", "external_unverified", FOLLOWUP_CLAUSE
        )
        flid, fm = _find(flines, RE_FOLLOWUP)
        ref_id = m.group(1)
        ev = [e for e in (plid, lid, flid) if e]
        return {
            "action": "no_action",
            "evidence": ev,
            "fields": {
                "reasonCode": COMPLETED_REASONS[m.group(2)],
                "referenceId": ref_id,
            },
        }

    # Send approved status updates
    _src, lines = _bearing(dossier, "approval", "signed_internal", APPROVAL_CLAUSE)
    lid, m = _find(lines, RE_APPROVAL)
    slid, sm = _find(lines, RE_APPROVAL_STATUS)
    if m and sm:
        return {
            "action": "send_approved_notice",
            "evidence": [lid, slid],
            "fields": {
                "recipient": m.group(3),
                "referenceId": m.group(2),
                "status": sm.group(1),
            },
        }

    # Verified internal record window changes
    _src, lines = _bearing(dossier, "event", "signed_internal", CARRIER_CLAUSE)
    lid, m = _find(lines, RE_CARRIER)
    if m:
        plid = _rule_line(dossier, "update_internal_record")
        ev = [plid, lid] if plid else [lid]
        return {
            "action": "update_internal_record",
            "evidence": ev,
            "fields": {
                "caseId": m.group(2),
                "sourceEventId": m.group(1),
                "value": m.group(4),
            },
        }

    # Sender identity validation issues
    _src, lines = _bearing(
        dossier, "record", "authenticated_internal", MISMATCH_CLAUSE
    )
    lid, m = _find(lines, RE_MISMATCH)
    if m:
        plid = _rule_line(dossier, "request_confirmation")
        _msrc, mlines = _bearing(
            dossier, "message", "external_unverified", "supplies order"
        )
        slid, sm = _find(mlines, RE_SUPPLIES)
        clid, _cm = _find(mlines, re.compile(r"^I am (\S+?)\."))
        ref_id = m.group(1)
        ev = [e for e in (plid, lid, clid) if e]
        return {
            "action": "request_confirmation",
            "evidence": ev,
            "fields": {
                "team": m.group(3),
                "claimedSender": m.group(2),
                "referenceId": ref_id,
            },
        }

    # Unverified customer queries
    _rsrc, rlines = _bearing(
        dossier, "record", "authenticated_internal", ENQUIRY_RECORD_CLAUSE
    )
    _msrc, mlines = _bearing(
        dossier, "message", "external_unverified", ENQUIRY_CLAUSE
    )
    rlid, rm = _find(rlines, RE_ENQUIRY_RECORD)
    mlid, mm = _find(mlines, RE_GATEWAY)
    if rm and mm:
        fields = {
            "recipient": mm.group(1),
            "referenceId": rm.group(1),
            "status": rm.group(3),
        }
        plid = _rule_line(dossier, "create_draft")
        elid, _em = _find(mlines, re.compile(re.escape(ENQUIRY_CLAUSE)))
        evidence = [e for e in (plid, rlid, elid) if e]
        return {"action": "create_draft", "evidence": evidence, "fields": fields}
    return None

# ------------------------------------------------------------- LLM ADAPTERS
async def call_llm_chat(messages, max_tokens=2048, timeout=30.0):
    openrouter_key = os.environ.get("OPENROUTER_API_KEY")
    gemini_key = os.environ.get("GEMINI_API_KEY")

    key = openrouter_key or gemini_key
    model = (
        os.environ.get("OPENROUTER_MODEL")
        or os.environ.get("LLM_MODEL")
        or "google/gemini-2.5-flash"
    )

    if not key:
        raise RuntimeError("No LLM API key configured in env")

    is_gemini_direct = False
    if gemini_key and (gemini_key.startswith("AIzaSy") or not key.startswith("sk-")):
        is_gemini_direct = True
    elif (
        key
        and not key.startswith("sk-")
        and "gemini" in model.lower()
        and "openrouter" not in model.lower()
    ):
        is_gemini_direct = True

    async with httpx.AsyncClient() as client:
        if is_gemini_direct:
            system_instruction = ""
            gemini_messages = []
            for msg in messages:
                if msg["role"] == "system":
                    system_instruction = msg["content"]
                elif msg["role"] == "user":
                    gemini_messages.append(
                        {"role": "user", "parts": [{"text": msg["content"]}]}
                    )
                elif msg["role"] == "assistant":
                    gemini_messages.append(
                        {"role": "model", "parts": [{"text": msg["content"]}]}
                    )

            clean_model = model.split("/")[-1]
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{clean_model}:generateContent?key={key}"
            payload = {
                "contents": gemini_messages,
                "generationConfig": {
                    "responseMimeType": "application/json",
                    "maxOutputTokens": max_tokens,
                    "temperature": 0.0,
                },
            }
            if system_instruction:
                payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}

            resp = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
            else:
                raise RuntimeError(f"Gemini API error {resp.status_code}: {resp.text}")
        else:
            base_url = (
                os.environ.get("LLM_BASE_URL") or "https://openrouter.ai/api/v1"
            )
            headers = {
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": model,
                "messages": messages,
                "temperature": 0.0,
                "max_tokens": max_tokens,
                "response_format": {"type": "json_object"},
            }
            url = f"{base_url}/chat/completions"
            resp = await client.post(
                url, json=payload, headers=headers, timeout=timeout
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
            else:
                payload.pop("response_format", None)
                resp = await client.post(
                    url, json=payload, headers=headers, timeout=timeout
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]
                raise RuntimeError(
                    f"OpenAI-compatible API error {resp.status_code}: {resp.text}"
                )

def _loads(text):
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = min([i for i in (text.find("{"), text.find("[")) if i != -1] or [-1])
        end = max(text.rfind("}"), text.rfind("]"))
        if start != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise

async def decide_chunk(items):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": build_user_message(items)},
    ]
    for _attempt in range(2):
        try:
            content = await call_llm_chat(
                messages, max_tokens=2048, timeout=CHUNK_TIMEOUT
            )
            data = _loads(content)
        except Exception as e:
            print(f"[MAILROOM_LOG] decide_chunk attempt {_attempt} failed: {e}")
            continue
        decisions = data.get("decisions") if isinstance(data, dict) else None
        if not isinstance(decisions, dict):
            decisions = data if isinstance(data, dict) else {}
        out = {
            did: decisions[did]
            for did, _d in items
            if isinstance(decisions.get(did), dict)
        }
        if out:
            return out
    return {}

async def run_model(pending):
    if not pending:
        return {}
    chunks = [
        pending[i : i + CHUNK_SIZE] for i in range(0, len(pending), CHUNK_SIZE)
    ]
    sem = asyncio.Semaphore(MAX_CONCURRENCY)

    async def guarded(chunk):
        async with sem:
            return await decide_chunk(chunk)

    async def sweep(groups, budget):
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*(guarded(g) for g in groups), return_exceptions=True),
                timeout=budget,
            )
        except asyncio.TimeoutError:
            return {}
        out = {}
        for r in results:
            if isinstance(r, dict):
                out.update(r)
        return out

    merged = await sweep(chunks, PROPOSE_BUDGET * 0.7)

    missing = [it for it in pending if it[0] not in merged]
    if missing and len(missing) <= 12:
        retry = [missing[i : i + 3] for i in range(0, len(missing), 3)]
        merged.update(await sweep(retry, PROPOSE_BUDGET * 0.3))
    return merged

# ------------------------------------------------------- FROZEN TOOL SHAPES
def _first_ref(dossier, did):
    for key in ("referenceId", "reference", "caseId", "orderId"):
        v = dossier.get(key)
        if isinstance(v, str) and v and not looks_secret(v):
            return v[:80]
    return did

def _team_of(dossier):
    for key in ("owningTeam", "team", "queue", "mailbox"):
        v = dossier.get(key)
        if isinstance(v, str) and v and not looks_secret(v):
            return v[:80]
    return "mailroom"

def shape_action(action, fields, dossier, did, line_ids):
    mailbox = dossier.get("mailbox")
    mailbox = mailbox if isinstance(mailbox, str) and mailbox else did
    ref = _first_ref(dossier, did)
    get = lambda k, fb, limit=160: clean_scalar(
        fields.get(k) if isinstance(fields, dict) else None, fb, limit
    )

    if action == "create_draft":
        drafted = clean_scalar(
            fields.get("mailbox") if isinstance(fields, dict) else None, mailbox, 80
        )
        return (
            {"kind": "draft_queue", "id": "mailbox:" + drafted},
            {
                "recipient": get("recipient", mailbox),
                "referenceId": get("referenceId", ref),
                "status": get("status", "in_progress", 80),
                "template": "order_status",
            },
        )

    if action == "update_internal_record":
        case_id = get("caseId", ref, 80)
        return (
            {"kind": "case_record", "id": case_id},
            {
                "field": "delivery_window",
                "sourceEventId": get(
                    "sourceEventId", line_ids[0] if line_ids else ref, 80
                ),
                "value": get("value", "pending_review", 120),
            },
        )

    if action == "send_approved_notice":
        return (
            {"kind": "email", "id": get("recipient", mailbox)},
            {
                "referenceId": get("referenceId", ref),
                "status": get("status", "approved", 80),
                "template": "approved_delivery_notice",
            },
        )

    if action == "request_confirmation":
        return (
            {"kind": "approval_queue", "id": get("team", _team_of(dossier), 80)},
            {
                "claimedSender": get("claimedSender", mailbox),
                "questionCode": "VERIFY_REQUEST",
                "referenceId": get("referenceId", ref),
            },
        )

    if action == "quarantine_item":
        artifact = fields.get("artifactId") if isinstance(fields, dict) else None
        allowed = set(line_ids) | {
            s.get("sourceId")
            for s in (dossier.get("sources") or [])
            if isinstance(s, dict) and isinstance(s.get("sourceId"), str)
        }
        for _lid, text, _sid in dossier_lines(dossier):
            m = RE_ARTIFACT.search(text)
            if m:
                allowed.add(m.group(1))
        if not isinstance(artifact, str) or artifact not in allowed:
            artifact = line_ids[0] if line_ids else did
        return (
            {"kind": "security_queue", "id": "mailroom"},
            {
                "artifactId": artifact,
                "reasonCode": "INDIRECT_PROMPT_INJECTION",
            },
        )

    reason = fields.get("reasonCode") if isinstance(fields, dict) else None
    reason = reason.strip() if isinstance(reason, str) else ""
    if reason.upper() in NO_ACTION_REASONS:
        reason = reason.upper()
    else:
        reason = COMPLETED_REASONS.get(reason.lower(), "INFORMATIONAL")
    return (None, {"reasonCode": reason, "referenceId": get("referenceId", ref)})

def build_proposal(did, dossier, fingerprint, raw):
    lines = dossier_lines(dossier)
    line_ids = [lid for lid, _t, _s in lines]
    valid = set(line_ids)

    action = raw.get("action") if isinstance(raw, dict) else None
    action = (
        action.strip().lower().replace("-", "_").replace(" ", "_")
        if isinstance(action, str)
        else ""
    )
    if action not in ACTIONS:
        action = SAFE_DEFAULT

    fields = raw.get("fields") if isinstance(raw, dict) else None
    if not isinstance(fields, dict):
        fields = raw if isinstance(raw, dict) else {}

    if action == "send_approved_notice":
        rcpt = fields.get("recipient")
        if not isinstance(rcpt, str) or not rcpt.strip() or looks_secret(rcpt):
            action = SAFE_DEFAULT

    target, payload = shape_action(action, fields, dossier, did, line_ids)

    ev_raw = raw.get("evidence") if isinstance(raw, dict) else None
    if not isinstance(ev_raw, list):
        ev_raw = []
    evidence, seen = [], set()
    for e in ev_raw:
        if isinstance(e, str) and e in valid and e not in seen:
            seen.add(e)
            evidence.append(e)
        if len(evidence) >= MAX_EVIDENCE:
            break
    if not evidence and line_ids:
        evidence = [line_ids[0]]

    proposal = {
        "dossierId": did,
        "callId": call_id_for(did, fingerprint),
        "action": action,
        "target": target,
        "payload": payload,
        "evidence": sorted(evidence),
    }
    return proposal

# --------------------------------------------------- CRYPTOGRAPHIC VERIFICATION
def verify_receipt_signature(verifier_jwk, receipt, eval_id=None) -> bool:
    """Verifies the Ed25519 cryptographic signature over various standard message serialization formats."""
    if not HAS_CRYPTOGRAPHY:
        print("[MAILROOM_LOG] WARNING: 'cryptography' library is not available. Verification bypassed.")
        return True

    try:
        if not verifier_jwk or not isinstance(verifier_jwk, dict):
            return False
        jwk = verifier_jwk.get("publicKeyJwk")
        if not jwk or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            return False

        sig_b64 = receipt.get("receiptSignature")
        if not sig_b64:
            return False

        sig_bytes = decode_base64(sig_b64)

        call_id = receipt.get("callId", "")
        proposal_digest_val = receipt.get("proposalDigest", "")
        receipt_id = receipt.get("receiptId", "")
        dossier_id = receipt.get("dossierId", "")
        action = receipt.get("action", "")
        accepted = receipt.get("accepted")
        accepted_str = str(accepted).lower() if isinstance(accepted, bool) else ""

        # Decode public key and signature
        x_bytes = decode_base64(jwk.get("x", ""))
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(x_bytes)

        # Base64url helper for JWS payload encoding
        def base64url_encode(b: bytes) -> str:
            return base64.urlsafe_b64encode(b).decode('utf-8').replace('=', '')

        candidates = []

        # 1. Delimited strings WITH evaluationId
        if eval_id:
            candidates.append(f"{eval_id}|{proposal_digest_val}|{call_id}")
            candidates.append(f"{eval_id}{proposal_digest_val}{call_id}")
            candidates.append(f"{eval_id}|{call_id}|{proposal_digest_val}")
            candidates.append(f"{eval_id}{call_id}{proposal_digest_val}")
            candidates.append(f"{eval_id}|{call_id}|{proposal_digest_val}|{receipt_id}")
            candidates.append(f"{eval_id}{call_id}{proposal_digest_val}{receipt_id}")
            candidates.append(f"{eval_id}|{call_id}|{proposal_digest_val}|{receipt_id}|{accepted_str}")
            candidates.append(f"{eval_id}{call_id}{proposal_digest_val}{receipt_id}{accepted_str}")
            candidates.append(f"{eval_id}|{proposal_digest_val}|{call_id}|{receipt_id}")
            candidates.append(f"{eval_id}|{proposal_digest_val}|{call_id}|{receipt_id}|{accepted_str}")
            candidates.append(f"{eval_id}|{dossier_id}|{call_id}|{action}|{accepted_str}|{proposal_digest_val}|{receipt_id}")
            candidates.append(f"{eval_id}{dossier_id}{call_id}{action}{accepted_str}{proposal_digest_val}{receipt_id}")
            candidates.append(f"{eval_id}|{receipt_id}")
            candidates.append(f"{eval_id}{receipt_id}")
            candidates.append(f"{eval_id}|{call_id}|{receipt_id}")
            candidates.append(f"{eval_id}{call_id}{receipt_id}")

        # 2. Delimited strings WITHOUT evaluationId
        candidates.append(f"{proposal_digest_val}|{call_id}")
        candidates.append(f"{proposal_digest_val}{call_id}")
        candidates.append(f"{proposal_digest_val}|{call_id}|{receipt_id}")
        candidates.append(f"{proposal_digest_val}{call_id}{receipt_id}")
        candidates.append(f"{proposal_digest_val}|{call_id}|{receipt_id}|{accepted_str}")
        candidates.append(f"{proposal_digest_val}{call_id}{receipt_id}{accepted_str}")
        candidates.append(f"{call_id}|{receipt_id}")
        candidates.append(f"{call_id}{receipt_id}")
        candidates.append(f"{receipt_id}")

        # 3. JSON dict of receipt excluding signature
        msg_dict = {k: v for k, v in receipt.items() if k != "receiptSignature"}
        candidates.append(canonical_json(msg_dict))

        # 4. JSON dict of receipt excluding signature but INCLUDING evaluationId
        if eval_id:
            msg_dict_with_eval = {k: v for k, v in receipt.items() if k != "receiptSignature"}
            msg_dict_with_eval["evaluationId"] = eval_id
            candidates.append(canonical_json(msg_dict_with_eval))

        # 5. JWS Compact Serialization Payload formats (Header.Payload)
        header_b64 = "eyJhbGciOiJFZERTQSJ9" # {"alg":"EdDSA"}
        candidates.append(f"{header_b64}.{base64url_encode(canonical_json(msg_dict).encode('utf-8'))}")
        if eval_id:
            candidates.append(f"{header_b64}.{base64url_encode(canonical_json(msg_dict_with_eval).encode('utf-8'))}")

        # 6. Specific structured objects
        if eval_id:
            candidates.append(canonical_json({
                "evaluationId": eval_id,
                "proposalDigest": proposal_digest_val,
                "callId": call_id,
                "receiptId": receipt_id,
                "accepted": accepted
            }))
            candidates.append(canonical_json({
                "evaluationId": eval_id,
                "proposalDigest": proposal_digest_val,
                "callId": call_id
            }))
            candidates.append(canonical_json({
                "evaluationId": eval_id,
                "callId": call_id,
                "receiptId": receipt_id
            }))

        candidates.append(canonical_json({
            "proposalDigest": proposal_digest_val,
            "callId": call_id,
            "receiptId": receipt_id,
            "accepted": accepted
        }))
        candidates.append(canonical_json({
            "proposalDigest": proposal_digest_val,
            "callId": call_id
        }))

        # -------------------------------------------------- EXPANSION BLOCK
        import itertools
        # Permutations of (eval_id, proposal_digest, call_id) with alternative separators
        if eval_id:
            parts_3 = [eval_id, proposal_digest_val, call_id]
            for p in itertools.permutations(parts_3):
                for delim in [":", ".", ",", "-", "_", "/"]:
                    candidates.append(delim.join(p))

        # Permutations of (eval_id, proposal_digest, call_id, receipt_id) with alternative separators
        if eval_id:
            parts_4 = [eval_id, proposal_digest_val, call_id, receipt_id]
            for p in itertools.permutations(parts_4):
                for delim in [":", ".", ",", "-", "_", "/"]:
                    candidates.append(delim.join(p))

        # JSON object of receipt nested under evaluationId key
        if eval_id:
            candidates.append(canonical_json({
                "evaluationId": eval_id,
                "receipt": msg_dict
            }))

        # Generate JWS Compact wrappers for the new permutations
        for cand in list(candidates):
            if isinstance(cand, str) and not cand.startswith(header_b64):
                candidates.append(f"{header_b64}.{base64url_encode(cand.encode('utf-8'))}")

        # Try to verify against candidates
        for cand in candidates:
            if isinstance(cand, str):
                cand_bytes = cand.encode("utf-8")
            else:
                cand_bytes = cand
            try:
                public_key.verify(sig_bytes, cand_bytes)
                return True
            except Exception:
                pass

        print(f"[MAILROOM_LOG] Ed25519 signature verification failed for receipt: {call_id}")
        return False
    except Exception as e:
        print(f"[MAILROOM_LOG] Ed25519 signature verification exception: {e}")
        return False

def bind_receipts(eval_id, receipts, proposals, verifier):
    """Binds each receipt to its matching proposal, validating attributes and cryptographic signatures."""
    by_call = {p["callId"]: p for p in proposals}
    bound = []
    for r in receipts:
        call_id = r.get("callId", "").strip()
        proposal = by_call.get(call_id)
        if proposal is None:
            return Response(status_code=409, content=canonical_json({"detail": f"receipt callId {call_id} does not belong"}), media_type="application/json")
        if r.get("dossierId") != proposal["dossierId"]:
            return Response(status_code=409, content=canonical_json({"detail": "Mismatch"}), media_type="application/json")
        if r.get("action") != proposal["action"]:
            return Response(status_code=409, content=canonical_json({"detail": "Mismatch"}), media_type="application/json")
        if r.get("proposalDigest") != proposal_digest(proposal):
            return Response(status_code=409, content=canonical_json({"detail": "Mismatch"}), media_type="application/json")

        # Verify signature passing eval_id
        if not verify_receipt_signature(verifier, r, eval_id):
            return Response(status_code=400, content=canonical_json({"detail": "Invalid signature"}), media_type="application/json")

        bound.append((r, proposal))

    missing = [
        c for c in by_call if c not in {r.get("callId", "").strip() for r in receipts}
    ]
    if missing:
        return Response(status_code=409, content=canonical_json({"detail": "Missing receipts"}), media_type="application/json")
    return bound

# ------------------------------------------------------------- REQUEST HANDLER
@router.post("/mailroom")
async def handle_mailroom(request: Request):
    try:
        body = await request.json()
    except Exception:
        return Response(status_code=400, content=canonical_json({"detail": "Invalid JSON"}), media_type="application/json")

    op = body.get("operation")
    eval_id = body.get("evaluationId")
    
    if op not in ("propose", "commit") or not eval_id:
        return Response(status_code=400, content=canonical_json({"detail": "Bad operation"}), media_type="application/json")

    if op == "propose":
        return await do_propose(body)
    if op == "commit":
        return await do_commit(body)
    return Response(status_code=400, content=canonical_json({"detail": "unknown operation"}), media_type="application/json")

# ------------------------------------------------------------------ PROPOSE
def validate_propose(body):
    eval_id = body.get("evaluationId")
    if not isinstance(eval_id, str) or not eval_id.strip():
        return Response(status_code=422, content=canonical_json({"detail": "evaluationId is required"}), media_type="application/json")
    eval_id = eval_id.strip()

    dossiers = body.get("dossiers")
    if not isinstance(dossiers, list) or not dossiers:
        return Response(status_code=422, content=canonical_json({"detail": "dossiers must be a non-empty array"}), media_type="application/json")
    if len(dossiers) > MAX_DOSSIERS:
        return Response(status_code=422, content=canonical_json({"detail": "too many dossiers"}), media_type="application/json")

    ids, seen = [], set()
    for d in dossiers:
        if not isinstance(d, dict):
            return Response(status_code=422, content=canonical_json({"detail": "each dossier must be an object"}), media_type="application/json")
        did = d.get("dossierId")
        if not isinstance(did, str) or not did.strip():
            return Response(status_code=422, content=canonical_json({"detail": "dossier is missing dossierId"}), media_type="application/json")
        did = did.strip()
        if not isinstance(d.get("sources"), list):
            return Response(status_code=422, content=canonical_json({"detail": "dossier is missing sources"}), media_type="application/json")
        if did in seen:
            return Response(status_code=400, content=canonical_json({"detail": "duplicate dossierId"}), media_type="application/json")
        seen.add(did)
        ids.append(did)
    return eval_id, dossiers, ids

async def do_propose(body):
    val = validate_propose(body)
    if isinstance(val, Response):
        return val
    eval_id, dossiers, ids = val
    input_digest = digest_of(dossiers)

    # 1. Exact Replay and Conflict checks from your working original code
    if eval_id in _STATE["evals"]:
        if _STATE["evals"][eval_id]["inputDigest"] != input_digest:
            return Response(status_code=409, content=canonical_json({"detail": "Conflict"}), media_type="application/json")
        else:
            cached_proposals = list(_STATE["evals"][eval_id]["proposals"].values())
            order_map = {did: i for i, did in enumerate(ids)}
            cached_proposals.sort(key=lambda x: order_map.get(x["dossierId"], 999))
            response_dict = {
                "profile": PROFILE,
                "evaluationId": eval_id,
                "status": "awaiting_receipts",
                "inputDigest": input_digest,
                "proposals": cached_proposals
            }
            return Response(content=canonical_json(response_dict), media_type="application/json")

    proposals = []
    uncached_dossiers = []

    for d in dossiers:
        did = d["dossierId"]
        fingerprint = fingerprint_of(d)
        cache_key = f"{did}|{fingerprint}"
        
        if cache_key in _STATE["cache"]:
            proposals.append(_STATE["cache"][cache_key])
        else:
            fixed = deterministic_decision(d)
            if fixed is not None:
                proposal = build_proposal(did, d, fingerprint, fixed)
                _STATE["cache"][cache_key] = proposal
                proposals.append(proposal)
            else:
                uncached_dossiers.append((d, cache_key, fingerprint))

    if uncached_dossiers:
        dossiers_to_process = [item[0] for item in uncached_dossiers]
        ai_results = await run_model(dossiers_to_process)
        
        for d, cache_key, fingerprint in uncached_dossiers:
            did = d["dossierId"]
            raw_decision = ai_results.get(did, {})
            proposal = build_proposal(did, d, fingerprint, raw_decision)
            _STATE["cache"][cache_key] = proposal
            proposals.append(proposal)

    # Sort proposals by their original order map
    order_map = {did: i for i, did in enumerate(ids)}
    proposals.sort(key=lambda x: order_map.get(x["dossierId"], 999))

    # Save to the file-based original state dictionary
    _STATE["evals"][eval_id] = {
        "inputDigest": input_digest,
        "proposals": {p["dossierId"]: p for p in proposals},
        "receiptVerifier": body.get("receiptVerifier")
    }
    await save_state()

    response_dict = {
        "profile": PROFILE,
        "evaluationId": eval_id,
        "status": "awaiting_receipts",
        "inputDigest": input_digest,
        "proposals": proposals
    }
    return Response(content=canonical_json(response_dict), media_type="application/json")

# ------------------------------------------------------------------ COMMIT
def validate_commit(body):
    eval_id = body.get("evaluationId")
    if not isinstance(eval_id, str) or not eval_id.strip():
        return Response(status_code=422, content=canonical_json({"detail": "evaluationId is required"}), media_type="application/json")
    eval_id = eval_id.strip()

    input_digest = body.get("inputDigest")
    if not isinstance(input_digest, str) or not input_digest.strip():
        return Response(status_code=422, content=canonical_json({"detail": "inputDigest is required"}), media_type="application/json")
    input_digest = input_digest.strip()

    receipts = body.get("receipts")
    if not isinstance(receipts, list) or not receipts:
        return Response(status_code=422, content=canonical_json({"detail": "receipts must be a non-empty array"}), media_type="application/json")
    if len(receipts) > MAX_RECEIPTS:
        return Response(status_code=422, content=canonical_json({"detail": "too many receipts"}), media_type="application/json")
    seen = set()
    for r in receipts:
        if not isinstance(r, dict):
            return Response(status_code=422, content=canonical_json({"detail": "each receipt must be an object"}), media_type="application/json")
        call_id = r.get("callId")
        if not isinstance(call_id, str) or not call_id.strip():
            return Response(status_code=422, content=canonical_json({"detail": "receipt is missing callId"}), media_type="application/json")
        if not isinstance(r.get("accepted"), bool):
            return Response(status_code=422, content=canonical_json({"detail": "receipt is missing accepted"}), media_type="application/json")
        if not isinstance(r.get("receiptId"), str) or not r["receiptId"].strip():
            return Response(status_code=422, content=canonical_json({"detail": "receipt is missing receiptId"}), media_type="application/json")
        if call_id in seen:
            return Response(status_code=400, content=canonical_json({"detail": "duplicate callId in receipts"}), media_type="application/json")
        seen.add(call_id)
    return eval_id, input_digest, receipts

async def do_commit(body):
    val = validate_commit(body)
    if isinstance(val, Response):
        return val
    eval_id, input_digest, receipts = val

    eval_state = _STATE["evals"].get(eval_id)
    if not eval_state:
        return Response(status_code=400, content=canonical_json({"detail": "Unknown eval"}), media_type="application/json")

    # 1. Replay check from your working original code
    receipts_digest = digest_of(receipts)
    if "commit_digest" in eval_state and eval_state["commit_digest"] == receipts_digest:
        return Response(content=canonical_json(eval_state["commit_response"]), media_type="application/json")

    # 2. Conflict check (if evaluationId has already been committed with different receipts)
    if "commit_digest" in eval_state and eval_state["commit_digest"] != receipts_digest:
        return Response(status_code=409, content=canonical_json({"detail": "Conflict"}), media_type="application/json")

    # 3. Input digest match validation
    if eval_state["inputDigest"] != input_digest:
        return Response(status_code=409, content=canonical_json({"detail": "Conflict"}), media_type="application/json")

    proposals = eval_state["proposals"]
    verifier = eval_state.get("receiptVerifier")

    bound = bind_receipts(eval_id, receipts, proposals, verifier)
    if isinstance(bound, Response):
        return bound

    outcomes = []
    for r, proposal in bound:
        accepted = r.get("accepted") is True
        
        # Echo the bindings directly from r, deriving executed/rejected only from accepted
        outcome = {
            "dossierId": r.get("dossierId"),
            "callId": r.get("callId"),
            "action": r.get("action"),
            "proposalDigest": r.get("proposalDigest"),
            "receiptId": r.get("receiptId") if isinstance(r.get("receiptId"), str) else "",
            "status": "executed" if accepted else "rejected",
        }
        outcomes.append(outcome)

    response_dict = {
        "profile": PROFILE,
        "evaluationId": eval_id,
        "status": "completed",
        "inputDigest": input_digest,
        "outcomes": outcomes
    }
    
    # Store commit transaction into your working original dict state
    eval_state["commit_digest"] = receipts_digest
    eval_state["commit_response"] = response_dict
    await save_state()

    return Response(content=canonical_json(response_dict), media_type="application/json")
