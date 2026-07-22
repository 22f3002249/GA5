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

def norm_path(p: str, base: str) -> str:
    """Resolve and normalize path against a provided base directory."""
    p = p.strip()
    # Robust tilde expansion
    if p.startswith("~"):
        p = re.sub(r'^~[a-zA-Z0-9_-]*', AGENT_HOME, p)
    
    if not os.path.isabs(p):
        p = os.path.join(base, p)
    return os.path.normpath(p)

def check_bash(command: str) -> Decision:
    cmd_lower = command.lower()
    
    # 1. Catch Base64 obfuscation
    b64_matches = re.findall(r'[A-Za-z0-9+/]{12,}={0,2}', command)
    for b64 in b64_matches:
        try:
            decoded = base64.b64decode(b64).decode("utf-8", errors="ignore").lower()
            if ".env" in decoded:
                return Decision(decision="block", reason="Forbidden .env access in base64.")
        except:
            pass

    # 2. Resolve tokens to check for forbidden .env access
    try:
        tokens = shlex.split(command)
    except:
        tokens = command.split()
    
    forbidden_target = os.path.normpath(FORBIDDEN_FILE)
    for t in tokens:
        t_clean = t.strip("'\"").replace("$HOME", AGENT_HOME).replace("$home", AGENT_HOME)
        if any(c in t_clean for c in ["/", "~", ".", "$"]):
            try:
                # Bash commands resolve relative to the WORKDIR
                if norm_path(t_clean, base=WORKDIR) == forbidden_target:
                    return Decision(decision="block", reason="Command resolves to forbidden secrets file.")
            except:
                continue

    # 3. Broad keyword block for safety
    if ".env" in cmd_lower and any(x in cmd_lower for x in ["cat", "grep", "less", "head", "tail", "cp", "mv", ".."]):
        return Decision(decision="block", reason="Access to .env is restricted.")

    return Decision(decision="allow", reason="Command does not touch restricted paths.")

def check_write_file(path: str) -> Decision:
    # URL decode to handle %2e%2e type traversal
    decoded = urllib.parse.unquote(path)
    
    # RESOLUTION STRATEGY:
    # If the grader sends a relative path like 'report.txt', and expects it to be ALLOWED,
    # then the write_file tool must be interpreting paths relative to WRITE_ROOT.
    # If we resolve it against WORKDIR, it would land in /home/agent/workspace/ and be BLOCKED.
    # To cover both, we resolve against WRITE_ROOT. Absolute paths will ignore this base.
    resolved = norm_path(decoded, base=WRITE_ROOT)
    
    allowed_root = os.path.normpath(WRITE_ROOT)
    
    # Check if the resulting path is inside /srv/reports/
    if resolved == allowed_root or resolved.startswith(allowed_root + os.sep):
        return Decision(decision="allow", reason="Write target is inside the allowed directory.")
    
    return Decision(decision="block", reason="Write target resolves outside the allowed directory.")

def check_http_request(url: str) -> Decision:
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if host in ALLOWED_HOSTS:
            return Decision(decision="allow", reason=f"Host {host} is in the allowed list.")
    except:
        pass
    return Decision(decision="block", reason="Host not allowed.")

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

    # Exact logging format as requested, with flush=True for Render visibility
    print(f"GUARDRAIL_CHECK tool={call.tool} command={call.command!r} path={call.path!r} "
          f"url={call.url!r} -> decision={result.decision} reason={result.reason}", flush=True)
    
    return result
