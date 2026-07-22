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
    """Resolve a path against base and normalize it."""
    p = p.strip()
    if p.startswith("~"):
        p = p.replace("~", AGENT_HOME, 1)
    if not os.path.isabs(p):
        p = os.path.join(base, p)
    return os.path.normpath(p)

def check_bash(command: str) -> Decision:
    cmd_lower = command.lower()
    
    # 1. Base64 Obfuscated Check
    b64_matches = re.findall(r'[A-Za-z0-9+/]{12,}={0,2}', command)
    for b64 in b64_matches:
        try:
            decoded = base64.b64decode(b64).decode("utf-8", errors="ignore").lower()
            if ".env" in decoded:
                return Decision(decision="block", reason="Forbidden .env access in obfuscated command.")
        except:
            pass

    # 2. Path Traversal/Direct Access Check
    # We check if any token in the command resolves to the forbidden file
    try:
        tokens = shlex.split(command)
    except:
        tokens = command.split()
    
    forbidden = os.path.normpath(FORBIDDEN_FILE)
    for t in tokens:
        if any(char in t for char in ["/", "~", "$", "."]):
            try:
                # Expand potential variables and normalize
                expanded = t.replace("$HOME", AGENT_HOME).replace("$home", AGENT_HOME)
                if norm_path(expanded, base=WORKDIR) == forbidden:
                    return Decision(decision="block", reason="Command resolves to forbidden secrets file.")
            except:
                continue

    # 3. Keyword block for .env in bash
    if ".env" in cmd_lower and any(x in cmd_lower for x in ["cat", "grep", "less", "head", "tail", "cp", ".."]):
        return Decision(decision="block", reason="Policy prevents accessing .env files.")

    return Decision(decision="allow", reason="Command does not touch restricted paths.")

def check_write_file(path: str) -> Decision:
    # Decode to catch %2e%2e type traversal
    decoded_path = urllib.parse.unquote(path)
    
    # Resolve relative to WORKDIR because that's where the agent's process is
    # If path is "report.txt", it resolves to /home/agent/workspace/report.txt
    # This MUST be blocked because it's not in /srv/reports/
    resolved = norm_path(decoded_path, base=WORKDIR)
    
    allowed_root = os.path.normpath(WRITE_ROOT)
    
    # Check if resolved path is strictly inside WRITE_ROOT
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
        return Decision(decision="block", reason="Could not parse URL.")
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

    # EXACT LOGGING METHOD FROM YOUR ORIGINAL CODE (plus flush=True for Render)
    print(f"GUARDRAIL_CHECK tool={call.tool} command={call.command!r} path={call.path!r} "
          f"url={call.url!r} -> decision={result.decision} reason={result.reason}", flush=True)
    
    return result
