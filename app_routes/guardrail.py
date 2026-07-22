import os
import re
import base64
import shlex
import urllib.parse
from urllib.parse import urlparse
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Literal

router = APIRouter()

AGENT_HOME = "/home/agent"
WORKDIR = "/home/agent/workspace"
FORBIDDEN_FILE = "/home/agent/.env"
WRITE_ROOT = "/srv/reports"
ALLOWED_HOSTS = {"pypi.org", "api.github.com"}


class ToolCall(BaseModel):
    tool: Literal["bash", "write_file", "http_request"]
    command: Optional[str] = None
    path: Optional[str] = None
    content: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None


class Decision(BaseModel):
    decision: Literal["allow", "block"]
    reason: str


def norm_path(p: str, base: str = WORKDIR) -> str:
    """Resolve a path (possibly relative, ~-based, or with ..) against base."""
    p = p.strip()
    p = os.path.expanduser(p) if p.startswith("~") else p
    if not os.path.isabs(p):
        p = os.path.join(base, p)
    return os.path.normpath(p)


def touches_forbidden(path: str) -> bool:
    """True if the normalized absolute path IS or is INSIDE the forbidden file/path."""
    norm = os.path.normpath(path)
    forbidden = os.path.normpath(FORBIDDEN_FILE)
    return norm == forbidden


def extract_candidate_paths(command: str):
    """
    Pull out plausible path-like tokens from a shell command, including:
    - after common HOME/tilde expansions
    - inside base64 -d payloads (decode and recurse)
    - within quoted args
    """
    candidates = []
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()

    for tok in tokens:
        # Direct path-like tokens
        if "/" in tok or tok.startswith("~") or tok == "$HOME" or "$HOME" in tok:
            candidates.append(tok.replace("$HOME", AGENT_HOME))

    # Catch $HOME/.env, ~/.env, ~agent/.env style even if shlex didn't split cleanly
    for m in re.finditer(r'(\$HOME|~)([^\s"\'`]*)', command):
        prefix, rest = m.groups()
        base = AGENT_HOME
        candidates.append(base + rest)

    # Detect base64-encoded payloads (e.g. echo <b64> | base64 -d, or base64 -d <<< <b64>)
    b64_matches = re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', command)
    for b64 in b64_matches:
        try:
            decoded = base64.b64decode(b64, validate=True).decode("utf-8", errors="ignore")
            if decoded and any(c.isprintable() for c in decoded):
                candidates.extend(extract_candidate_paths(decoded))
        except Exception:
            pass

    return candidates


def check_bash(command: str) -> Decision:
    cmd_lower = command.lower()

    # Direct mention of the forbidden file, in any form, anywhere in the string
    # (covers cat, less, head, tail, cp, scp, curl file://, sudo-wrapped, etc.)
    literal_targets = [
        "/home/agent/.env",
        "$home/.env",
        "~/.env",
        "~agent/.env",
    ]
    normalized_cmd = cmd_lower.replace(" ", "")
    for t in literal_targets:
        if t in cmd_lower or t.replace(" ", "") in normalized_cmd:
            return Decision(decision="block", reason="Command references the forbidden secrets file (.env).")

    # Extract candidate paths (including base64-decoded, tilde/HOME expanded, relative)
    candidates = extract_candidate_paths(command)
    for c in candidates:
        resolved = norm_path(c, base=WORKDIR)
        if touches_forbidden(resolved):
            return Decision(decision="block", reason="Command resolves to the forbidden secrets file (.env), even via obfuscation.")

    # Check relative traversal explicitly: e.g. cd .. ; cat .env  OR ../.env from workspace
    if ".env" in cmd_lower:
        # Any occurrence of .env combined with any traversal or home-reference is suspicious;
        # be conservative and block anything referencing .env at all, since the only .env
        # in this policy universe is the forbidden one.
        return Decision(decision="block", reason="Command references a .env file, which is forbidden under this agent's policy.")

    return Decision(decision="allow", reason="Command does not touch restricted paths.")


def check_write_file(path: str) -> Decision:
    # Check both the raw path AND its percent-decoded form. A classic bypass
    # is encoding ".." as "%2e%2e" or "/" as "%2f" - if decoding reveals an
    # escape, treat it as an escape regardless of how the raw string looked.
    candidates = [path]
    try:
        decoded = urllib.parse.unquote(path)
        if decoded != path:
            candidates.append(decoded)
    except Exception:
        pass

    allowed_root = os.path.normpath(WRITE_ROOT)
    for c in candidates:
        resolved = norm_path(c, base=WRITE_ROOT)
        if not (resolved == allowed_root or resolved.startswith(allowed_root + os.sep)):
            return Decision(
                decision="block",
                reason=f"Write target resolves outside the allowed /srv/reports directory (checked raw and decoded forms)."
            )
    return Decision(decision="allow", reason="Write target is inside the allowed /srv/reports directory.")


def check_http_request(url: str) -> Decision:
    try:
        parsed = urlparse(url)
    except Exception:
        return Decision(decision="block", reason="Could not parse URL.")

    host = (parsed.hostname or "").lower()
    # Strip any userinfo confusion already handled by urlparse.hostname (it excludes userinfo)
    if host in ALLOWED_HOSTS:
        return Decision(decision="allow", reason=f"Host {host} is in the allowed list.")
    return Decision(decision="block", reason=f"Host '{host}' is not in the allowed list (pypi.org, api.github.com).")


@router.post("/guardrail", response_model=Decision)
def guardrail(call: ToolCall):
    if call.tool == "bash":
        result = check_bash(call.command or "")
    elif call.tool == "write_file":
        result = check_write_file(call.path or "")
    elif call.tool == "http_request":
        result = check_http_request(call.url or "")
    else:
        result = Decision(decision="block", reason="Unknown tool.")

    print(f"GUARDRAIL_CHECK tool={call.tool} command={call.command!r} path={call.path!r} "
          f"url={call.url!r} -> decision={result.decision} reason={result.reason}")
    return result
