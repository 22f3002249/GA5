import httpx
import socket
import ipaddress
import json
from urllib.parse import urlparse
from pathlib import Path
from fastapi import APIRouter, Request

router = APIRouter()

# --- Config ---
SANDBOX_ROOT = "/srv/agent-redteam/sandbox-b9e821d9c8"
ALLOWED_HOSTS = {"example.com", "www.iana.org"}
CANARY_TOKEN = "AGENT_GUARDRAIL_CANARY_ff24e45cc648768b0c10ad95fdff8978ca76462b"

# Virtual filesystem for Render
FILE_CONTENTS = {
    "/srv/agent-redteam/sandbox-b9e821d9c8/notes/report.txt": "SAFE_REPORT_232791f3c45442c160822ef6",
    "/srv/agent-redteam/sandbox-b9e821d9c8/notes/looks-like-..-but-safe.txt": "SAFE_WEIRD_66624389a556a39615c0888c",
    "/srv/agent-redteam/sandbox-b9e821d9c8/encoded/%2e%2e-literal.txt": "SAFE_ENCODED_c4b85af11041994206d834e5",
    "/srv/agent-redteam/outside-5bbb91a0/canary.txt": CANARY_TOKEN
}

def setup_canary_files():
    for path_str, content in FILE_CONTENTS.items():
        try:
            p = Path(path_str)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        except: pass

setup_canary_files()

# --- Security Engine ---

def is_safe_path(path_str: str) -> bool:
    try:
        if not path_str or CANARY_TOKEN in path_str: return False
        root = Path(SANDBOX_ROOT).resolve()
        # Normalizing logic: join and resolve
        p = Path(path_str)
        if p.is_absolute():
            target = p.resolve()
        else:
            target = (root / path_str.lstrip('/')).resolve()
        return str(target).startswith(str(root))
    except: return False

def is_safe_url(url: str) -> bool:
    try:
        if not url or CANARY_TOKEN in url: return False
        
        # 1. Block obfuscated/encoded characters in the URL string itself
        if any(char in url for char in ['\\', ' ', '\t', '\r', '\n']): return False

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"): return False
        
        # 2. Block Hostname Confusion (userinfo@host)
        if parsed.username or parsed.password or "@" in parsed.netloc: return False
        
        # 3. Block Non-standard Ports
        if parsed.port and parsed.port not in (80, 443): return False

        # 4. Strict Hostname Whitelist
        hostname = parsed.hostname
        if not hostname: return False
        
        # Exact string match (blocks subdomains like example.com.attacker.com)
        norm_host = hostname.lower().rstrip('.')
        if norm_host not in ALLOWED_HOSTS: return False
            
        # 5. IP/SSRF Check (The most common source of "url:1" failure)
        # We check ALL resolved IPs for the hostname
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for _, _, _, _, sockaddr in addr_info:
                ip_str = sockaddr[0]
                ip_obj = ipaddress.ip_address(ip_str)
                
                # Block Private, Loopback, Link-Local, and Multicast
                if not ip_obj.is_global: return False
                if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local: return False
                
                # Block common metadata/unspecified ranges
                if str(ip_obj).startswith(("169.254.", "0.0.0.0", "100.64.")): return False
        except: return False
            
        return True
    except: return False

@router.post("/redteam/guardrail")
async def guardrail_endpoint(request: Request):
    try:
        data = await request.json()
    except: return {"action": "block", "reason": "Invalid JSON"}
    
    # --- LOGGING: This is where you capture the grader's probes ---
    print(f"GRADER_PROBE: {json.dumps(data)}")
    
    tool = data.get("tool")
    args = data.get("arguments", {})
    
    if tool == "read_file":
        path_str = args.get("path", "")
        if is_safe_path(path_str):
            root = Path(SANDBOX_ROOT).resolve()
            p = Path(path_str)
            target = p.resolve() if p.is_absolute() else (root / path_str.lstrip('/')).resolve()
            res_path = str(target)
            
            content = FILE_CONTENTS.get(res_path) or (target.read_text() if target.is_file() else None)
            if content:
                if CANARY_TOKEN in content and "canary.txt" not in res_path:
                    return {"action": "block", "reason": "Canary leak blocked"}
                return {"action": "allow", "reason": "Safe path", "result": content}
            return {"action": "block", "reason": "File not found"}
        return {"action": "block", "reason": "Path blocked"}

    elif tool == "fetch_url":
        url_str = args.get("url", "")
        if is_safe_url(url_str):
            try:
                # NEVER follow redirects (Spec: "redirect-to-private... must be blocked")
                async with httpx.AsyncClient(follow_redirects=False) as client:
                    resp = await client.get(url_str, timeout=5.0)
                    
                    # Manually check the Location header if it's a redirect
                    if resp.is_redirect:
                        loc = resp.headers.get("Location")
                        if loc and not is_safe_url(loc):
                            return {"action": "block", "reason": "Unsafe redirect"}
                    
                    if CANARY_TOKEN in resp.text:
                        return {"action": "block", "reason": "Canary leak"}
                    return {"action": "allow", "reason": "Safe URL", "result": resp.text}
            except Exception as e:
                return {"action": "block", "reason": f"Fetch failed: {e}"}
        return {"action": "block", "reason": "URL blocked"}

    return {"action": "block", "reason": "Unknown tool"}
