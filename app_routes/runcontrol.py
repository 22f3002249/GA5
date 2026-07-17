import json
import re
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Any, Dict, List, Literal

router = APIRouter()

BUDGET_TOKENS = 42000
TRACE_ID_FIELD = "client_ts"


class Step(BaseModel):
    step_number: int
    tool: str
    args: Dict[str, Any]
    tokens_used: int


class RunRequest(BaseModel):
    budget_tokens: int = BUDGET_TOKENS
    steps: List[Step]


class Decision(BaseModel):
    decision: Literal["continue", "halt"]
    reason: str


def normalize_whitespace(s: str) -> str:
    # Collapse all whitespace runs to single spaces, strip ends
    return re.sub(r"\s+", " ", s).strip()


def canonicalize(obj: Any) -> Any:
    """
    Recursively canonicalize a JSON-like value for exact-match comparison:
    - dict keys sorted, TRACE_ID_FIELD dropped
    - string values: whitespace-only differences normalized
    - lists: elements canonicalized in order (order matters for lists)
    """
    if isinstance(obj, dict):
        result = {}
        for k in sorted(obj.keys()):
            if k == TRACE_ID_FIELD:
                continue
            result[k] = canonicalize(obj[k])
        return result
    elif isinstance(obj, list):
        return [canonicalize(v) for v in obj]
    elif isinstance(obj, str):
        return normalize_whitespace(obj)
    else:
        return obj


def canonical_key(tool: str, args: Dict[str, Any]) -> str:
    canon = canonicalize(args)
    return tool + "|" + json.dumps(canon, sort_keys=True, separators=(",", ":"))


@router.post("/run-control", response_model=Decision)
def run_control(req: RunRequest):
    steps = req.steps

    # --- Budget rule ---
    total_tokens = sum(s.tokens_used for s in steps)
    if total_tokens >= req.budget_tokens:
        return Decision(
            decision="halt",
            reason=f"Cumulative tokens_used ({total_tokens}) has reached the budget ({req.budget_tokens})."
        )

    if not steps:
        return Decision(decision="continue", reason="No steps taken yet; fresh run.")

    # --- Loop rule 1: same tool called 3+ times in a row with identical canonical args ---
    keys = [canonical_key(s.tool, s.args) for s in steps]
    tools = [s.tool for s in steps]

    run_length = 1
    for i in range(len(keys) - 1, 0, -1):
        if keys[i] == keys[i - 1]:
            run_length += 1
            if run_length >= 3:
                return Decision(
                    decision="halt",
                    reason=f"Same tool '{tools[i]}' called {run_length}+ times in a row with identical arguments."
                )
        else:
            break

    # --- Loop rule 2: 2-step cycle A,B,A,B,A,B for >=6 trailing steps ---
    n = len(keys)
    if n >= 6:
        trailing = keys[-6:]
        a, b = trailing[0], trailing[1]
        if a != b:
            is_cycle = all(
                trailing[i] == (a if i % 2 == 0 else b)
                for i in range(6)
            )
            if is_cycle:
                return Decision(
                    decision="halt",
                    reason="Detected a repeating 2-step A/B cycle over the last 6 steps with no progress."
                )

    return Decision(
        decision="continue",
        reason=f"Under budget ({total_tokens}/{req.budget_tokens}) and no loop detected."
    )
