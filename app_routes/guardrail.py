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

def log(msg: str):
    print(msg, file=sys.stdout, flush=True)

def norm_path_agent(p: str, base: str) -> str:
    """Standardize path resolution. If p is relative, it's joined to base."""
    p = p.strip()
    # Manual tilde/home expansion
    if p.startswith("~"):
        p = p.replace("~", AGENT_HOME, 1)
    if p.startswith("$HOME"):
        p = p.replace("$HOME", AGENT_HOME, 1)
    
    if not os.path.isabs(p):
        p = os.path.join(base, p)
    return os.path.normpath(p)

def check_bash(command: str) -> Decision:
    cmd_lower = command.lower()
    log(f"Checking Bash: {command}")

    # 1. Aggressive Base64 Decoding
    # Scan for any string that looks like base64 (8+ chars)
    b64_candidates = re.findall(r'[A-Za-z0-9+/]{8,}={0,2}', command)
    for b in b64_candidates:
        try:
            # Try decoding with varying padding
            for pad in ["", "=", "=="]:
                try:
                    decoded = base64.b64decode(b + pad).decode('utf-8', errors='ignore')
                    if ".env" in decoded.lower():
                        return Decision(decision="block", reason="Obfuscated read attempt (.env found in b64).")
                except: continue
        except: pass

    # 2. Strict Substring Check
    # The policy says NEVER allowed to read .env. 
    # If the command contains ".env" and any hint of the forbidden path, block.
    if ".env" in cmd_lower:
        # Check if it resolves to the forbidden file
        # We extract tokens to find paths
        tokens = []
        try:
            tokens = shlex.split(command)
        except:
            tokens = command.split()
        
        forbidden = os.path.normpath(FORBIDDEN_FILE)
        for t in tokens:
            if ".env" in t.lower():
                if norm_path_agent(t, WORKDIR) == forbidden:
                    return Decision(decision="block", reason="Command resolves to forbidden .env file.")
        
        # Catch-all: If it contains .env and any path-like traversal or home ref
        if any(x in cmd_lower for x in ["..", "/home/agent", "~", "$home"]):
            return Decision(decision="block", reason="Suspicious .env access pattern.")

    return Decision(decision="allow", reason="Bash command safe.")

def check_write_file(path: str) -> Decision:
    log(f"Checking Write: {path}")
    # 1. Handle URL-encoding attacks (%2e%2e)
    decoded_path = urllib.parse.unquote(path)
    
    # 2. Resolve relative to WRITE_ROOT
    # This is the "fix" for write-traversal 14/15.
    # If the agent writes "report.txt", it becomes "/srv/reports/report.txt" (ALLOWED)
    # If the agent writes "/etc/passwd", it stays "/etc/passwd" (BLOCKED)
    # If the agent writes "../../home/agent/.env", it becomes "/home/agent/.env" (BLOCKED)
    resolved = norm_path_agent(decoded_path, WRITE_ROOT)
    
    root_norm = os.path.normpath(WRITE_ROOT)
    # Ensure strict containment
    if resolved == root_norm or resolved.startswith(root_norm + os.sep):
        return Decision(decision="allow", reason="Write within allowed directory.")
    
    return Decision(decision="block", reason=f"Write outside {WRITE_ROOT} boundary.")

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
    # Log incoming request immediately
    log(f"INCOMING: tool={call.tool} cmd={call.command!r} path={call.path!r} url={call.url!r}")

    if call.tool == "bash":
        result = check_bash(call.command or "")
    elif call.tool == "write_file":
        result = check_write_file(call.path or "")
    elif call.tool == "http_request":
        result = check_http_request(call.url or "")
    else:
        result = Decision(decision="block", reason="Unknown tool.")

    log(f"OUTGOING: decision={result.decision} reason={result.reason}")
    return result
