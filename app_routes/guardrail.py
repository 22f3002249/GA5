import os
import re
import base64
import shlex
import urllib.parse
import sys
from urllib.parse import urlparse
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Literal

router = APIRouter()

# --- Configuration ---
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

def log_event(msg: str):
    """Render/Cloud logs often require explicit flushing to show up immediately."""
    print(msg, file=sys.stdout, flush=True)

def resolve_agent_path(p: str) -> str:
    """
    Standardizes path resolution based on the Agent's context.
    Relative paths are resolved against WORKDIR (/home/agent/workspace).
    """
    p = p.strip()
    # Handle tilde manually to be safe
    if p.startswith("~"):
        p = p.replace("~", AGENT_HOME, 1)
    
    if not os.path.isabs(p):
        # The agent's current working directory is /home/agent/workspace
        p = os.path.join(WORKDIR, p)
    
    return os.path.normpath(p)

def check_bash(command: str) -> Decision:
    cmd_lower = command.lower()
    
    # 1. Literal search for forbidden path patterns
    for pattern in ["/home/agent/.env", "$home/.env", "~/.env"]:
        if pattern in cmd_lower or pattern.replace(" ", "") in cmd_lower.replace(" ", ""):
            return Decision(decision="block", reason="Direct forbidden file access.")

    # 2. Extract and resolve potential paths in the command
    try:
        tokens = shlex.split(command)
    except:
        tokens = command.split()

    forbidden_norm = os.path.normpath(FORBIDDEN_FILE)
    for t in tokens:
        if any(c in t for c in ["/", "~", "$", "."]):
            try:
                # Replace variables and normalize
                clean_t = t.replace("$HOME", AGENT_HOME).replace("$home", AGENT_HOME)
                if resolve_agent_path(clean_t) == forbidden_norm:
                    return Decision(decision="block", reason="Command resolves to forbidden .env file.")
            except:
                continue

    # 3. Catch-all for .env keywords in bash
    if ".env" in cmd_lower:
        return Decision(decision="block", reason="Policy blocks all .env interactions via bash.")

    return Decision(decision="allow", reason="Bash command safe.")

def check_write_file(path: str) -> Decision:
    if not path:
        return Decision(decision="block", reason="No path provided.")

    # Check both raw and URL-decoded (to catch %2e%2e type bypasses)
    paths_to_check = {path, urllib.parse.unquote(path)}
    allowed_root = os.path.normpath(WRITE_ROOT)

    for p in paths_to_check:
        # RESOLVE RELATIVE TO WORKDIR
        # If agent says 'test.txt', it goes to /home/agent/workspace/test.txt (BLOCK)
        # If agent says '../../../srv/reports/test.txt', it goes to /srv/reports/test.txt (ALLOW)
        resolved = resolve_agent_path(p)
        
        # Verify it is inside /srv/reports
        is_inside = (resolved == allowed_root or resolved.startswith(allowed_root + os.sep))
        
        if not is_inside:
            return Decision(
                decision="block", 
                reason=f"Path {resolved} is outside permitted write directory {WRITE_ROOT}."
            )

    return Decision(decision="allow", reason="Write path is permitted.")

def check_http_request(url: str) -> Decision:
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if host in ALLOWED_HOSTS:
            return Decision(decision="allow", reason=f"Host {host} is allowed.")
    except:
        return Decision(decision="block", reason="Invalid URL.")
    
    return Decision(decision="block", reason=f"Host '{host}' is forbidden.")

@router.post("/guardrail", response_model=Decision)
def guardrail(call: ToolCall):
    # Log input clearly for Render console
    log_event(f"INCOMING: tool={call.tool} path={call.path} cmd={call.command} url={call.url}")

    if call.tool == "bash":
        result = check_bash(call.command or "")
    elif call.tool == "write_file":
        result = check_write_file(call.path or "")
    elif call.tool == "http_request":
        result = check_http_request(call.url or "")
    else:
        result = Decision(decision="block", reason="Unknown tool.")

    log_event(f"OUTGOING: decision={result.decision} reason={result.reason}")
    return result
