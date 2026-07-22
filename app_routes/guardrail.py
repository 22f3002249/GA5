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

# Environment Constants
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
    """Resolve a path against a base directory (defaulting to the agent's WORKDIR)."""
    p = p.strip()
    if p.startswith("~"):
        p = os.path.expanduser(p)
    if not os.path.isabs(p):
        p = os.path.join(base, p)
    return os.path.normpath(p)

def touches_forbidden(path: str) -> bool:
    """Check if the path resolves specifically to the forbidden .env file."""
    norm = os.path.normpath(path)
    forbidden = os.path.normpath(FORBIDDEN_FILE)
    return norm == forbidden

def extract_candidate_paths(command: str):
    """Deep inspection of bash commands for path-like strings and hidden payloads."""
    candidates = []
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()

    for tok in tokens:
        if "/" in tok or tok.startswith("~") or "$HOME" in tok:
            candidates.append(tok.replace("$HOME", AGENT_HOME))

    # Regex to catch concatenated strings like /home/agent/.env without spaces
    for m in re.finditer(r'(\$HOME|~|/home/agent)([^\s"\'`]*)', command):
        prefix, rest = m.groups()
        base = AGENT_HOME if prefix in ("$HOME", "~", "/home/agent") else ""
        candidates.append(base + rest)

    # Base64 Decoding (for obfuscated attacks)
    b64_matches = re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', command)
    for b64 in b64_matches:
        try:
            decoded = base64.b64decode(b64, validate=True).decode("utf-8", errors="ignore")
            if decoded and any(c.isprintable() for c in decoded):
                candidates.extend(extract_candidate_paths(decoded))
        except:
            pass
    return candidates

def check_bash(command: str) -> Decision:
    cmd_lower = command.lower()
    
    # 1. Block literal mentions (including space-stripping bypasses)
    literal_targets = ["/home/agent/.env", "$home/.env", "~/.env", "~agent/.env"]
    normalized_cmd = cmd_lower.replace(" ", "")
    for t in literal_targets:
        if t in cmd_lower or t.replace(" ", "") in normalized_cmd:
            return Decision(decision="block", reason="Direct reference to forbidden .env file.")

    # 2. Check resolved candidate paths
    candidates = extract_candidate_paths(command)
    for c in candidates:
        if touches_forbidden(norm_path(c, base=WORKDIR)):
            return Decision(decision="block", reason="Path resolves to forbidden .env file.")

    # 3. Conservative keyword check
    if ".env" in cmd_lower:
        return Decision(decision="block", reason="Policy forbids any access to .env files.")

    return Decision(decision="allow", reason="Bash command appears safe.")

def check_write_file(path: str) -> Decision:
    # Handle URL encoding bypasses (e.g., %2e%2e for ..)
    candidates = [path]
    try:
        decoded = urllib.parse.unquote(path)
        if decoded != path:
            candidates.append(decoded)
    except:
        pass

    allowed_root = os.path.normpath(WRITE_ROOT)
    
    for p in candidates:
        # IMPORTANT: We must resolve relative to WORKDIR. 
        # If the agent writes "file.txt", it lands in /home/agent/workspace/file.txt, 
        # which is OUTSIDE /srv/reports/ and must be BLOCKED.
        resolved = norm_path(p, base=WORKDIR)
        
        # Check containment in WRITE_ROOT
        is_inside = (resolved == allowed_root or resolved.startswith(allowed_root + os.sep))
        
        if not is_inside:
            return Decision(
                decision="block",
                reason=f"Write target {resolved} is outside permitted {WRITE_ROOT} directory."
            )
            
    return Decision(decision="allow", reason="Write target is within permitted directory.")

def check_http_request(url: str) -> Decision:
    try:
        parsed = urlparse(url)
        # hostname is already lowercase and stripped of userinfo/port by urlparse
        host = (parsed.hostname or "").lower()
        if host in ALLOWED_HOSTS:
            return Decision(decision="allow", reason=f"Host {host} is allowed.")
    except:
        return Decision(decision="block", reason="Malformed URL.")
    
    return Decision(decision="block", reason="Outbound host is not in the allowlist.")

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

    # Logging as requested
    print(f"GUARDRAIL_CHECK tool={call.tool} "
          f"cmd={call.command!r} path={call.path!r} url={call.url!r} "
          f"-> decision={result.decision} reason={result.reason}")
    
    return result
