import os
import sqlite3
import json

DB_FILE = os.path.join(os.path.dirname(__file__), "mailroom.db")

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS evaluations (
            evaluation_id TEXT PRIMARY KEY,
            receipt_verifier TEXT NOT NULL,
            input_digest TEXT NOT NULL,
            response_json TEXT
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS dossier_cache (
            content_hash TEXT PRIMARY KEY,
            proposal_json TEXT NOT NULL
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS evaluation_proposals (
            evaluation_id TEXT,
            dossier_id TEXT,
            call_id TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            payload TEXT,
            evidence TEXT NOT NULL,
            proposal_digest TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            receipt_id TEXT,
            PRIMARY KEY (evaluation_id, dossier_id)
        )
        """)
        conn.commit()

# Call init_db on import to ensure DB is initialized
init_db()

def get_evaluation(evaluation_id: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM evaluations WHERE evaluation_id = ?", (evaluation_id,)).fetchone()
        if row:
            return dict(row)
        return None

def save_evaluation(evaluation_id: str, receipt_verifier: dict, input_digest: str, response_json: str = None):
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO evaluations (evaluation_id, receipt_verifier, input_digest, response_json) VALUES (?, ?, ?, ?)",
            (evaluation_id, json.dumps(receipt_verifier), input_digest, response_json)
        )
        conn.commit()

def get_cached_proposal(content_hash: str):
    with get_db() as conn:
        row = conn.execute("SELECT proposal_json FROM dossier_cache WHERE content_hash = ?", (content_hash,)).fetchone()
        if row:
            return json.loads(row["proposal_json"])
        return None

def save_cached_proposal(content_hash: str, proposal: dict):
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO dossier_cache (content_hash, proposal_json) VALUES (?, ?)",
            (content_hash, json.dumps(proposal))
        )
        conn.commit()

def get_proposal(evaluation_id: str, dossier_id: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM evaluation_proposals WHERE evaluation_id = ? AND dossier_id = ?", (evaluation_id, dossier_id)).fetchone()
        if row:
            d = dict(row)
            return {
                "dossierId": d["dossier_id"],
                "callId": d["call_id"],
                "action": d["action"],
                "target": json.loads(d["target"]) if d["target"] else None,
                "payload": json.loads(d["payload"]) if d["payload"] else None,
                "evidence": json.loads(d["evidence"]),
                "proposalDigest": d["proposal_digest"],
                "status": d["status"],
                "receiptId": d["receipt_id"]
            }
        return None

def save_proposal(evaluation_id: str, dossier_id: str, proposal: dict):
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO evaluation_proposals (evaluation_id, dossier_id, call_id, action, target, payload, evidence, proposal_digest, status, receipt_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                evaluation_id,
                dossier_id,
                proposal["callId"],
                proposal["action"],
                json.dumps(proposal["target"]) if proposal["target"] is not None else None,
                json.dumps(proposal["payload"]) if proposal["payload"] is not None else None,
                json.dumps(proposal["evidence"]),
                proposal["proposalDigest"],
                proposal.get("status", "pending"),
                proposal.get("receiptId", None)
            )
        )
        conn.commit()

def update_proposal_outcome(evaluation_id: str, dossier_id: str, status: str, receipt_id: str):
    with get_db() as conn:
        conn.execute(
            "UPDATE evaluation_proposals SET status = ?, receipt_id = ? WHERE evaluation_id = ? AND dossier_id = ?",
            (status, receipt_id, evaluation_id, dossier_id)
        )
        conn.commit()

def get_evaluation_proposals(evaluation_id: str):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM evaluation_proposals WHERE evaluation_id = ?", (evaluation_id,)).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            results.append({
                "dossierId": d["dossier_id"],
                "callId": d["call_id"],
                "action": d["action"],
                "target": json.loads(d["target"]) if d["target"] else None,
                "payload": json.loads(d["payload"]) if d["payload"] else None,
                "evidence": json.loads(d["evidence"]),
                "proposalDigest": d["proposal_digest"],
                "status": d["status"],
                "receiptId": d["receipt_id"]
            })
        return results
