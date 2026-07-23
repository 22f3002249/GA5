import os
import re
import urllib.parse
import shlex
import fnmatch
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter()

class GuardrailRequest(BaseModel):
    tool: str
    command: Optional[str] = None
    path: Optional[str] = None
    content: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None

@router.post("/check")
@router.post("/q3/check")
async def check_guardrail(req: GuardrailRequest, request: Request):
    # Access the global configuration generated at startup in main.py
    config = getattr(request.app.state, "config", {})
    if not config or "q3" not in config:
        return {"decision": "block", "reason": "Server not configured with STUDENT_EMAIL"}
        
    q3 = config["q3"]
    
    if req.tool == "bash":
        cmd = req.command or ""
        secret_rel = q3["secretRel"]
        home_dir = q3["homeDir"]
        cwd = q3["cwd"]
        
        # 1. Decode obfuscations (Base64, Hex, Octal)
        decoded_cmd = cmd
        try:
            import base64
            b64_matches = re.findall(r'[A-Za-z0-9+/=]{12,}', cmd)
            for m in b64_matches:
                try:
                    decoded = base64.b64decode(m).decode('utf-8', errors='ignore')
                    if len(decoded.strip()) > 3:
                        decoded_cmd += " " + decoded
                except: pass
        except: pass

        try:
            hex_matches = re.findall(r'(?:\\x[0-9a-fA-F]{2})+', cmd)
            for m in hex_matches:
                try:
                    bytes_val = bytes.fromhex(m.replace('\\x', ''))
                    decoded = bytes_val.decode('utf-8', errors='ignore')
                    decoded_cmd += " " + decoded
                except: pass
        except: pass

        try:
            oct_matches = re.findall(r'(?:\\[0-7]{3})+', cmd)
            for m in oct_matches:
                try:
                    parts = [chr(int(x, 8)) for x in re.findall(r'[0-7]{3}', m)]
                    decoded = "".join(parts)
                    decoded_cmd += " " + decoded
                except: pass
        except: pass
            
        # 2. Extract and substitute variables
        vars_dict = {}
        for k, v in re.findall(r'(\b[a-zA-Z_][a-zA-Z0-9_]*)=([^;\s\&\x7c]+)', decoded_cmd):
            vars_dict[f"${k}"] = v
            vars_dict[f"${{{k}}}"] = v
            
        for k, v in vars_dict.items():
            decoded_cmd = decoded_cmd.replace(k, v)
            
        # 3. Simulate directory traversal
        sub_commands = re.split(r';|&&|\|\|', decoded_cmd)
        simulated_cwd = cwd
        secret_path = os.path.abspath(os.path.join(home_dir, secret_rel))
        
        for sub in sub_commands:
            sub = sub.strip()
            cd_match = re.match(r'\bcd\s+([^;\s\&\x7c]+)', sub)
            if cd_match:
                target_dir = cd_match.group(1).replace("'", "").replace('"', "")
                target_dir = target_dir.replace("$HOME", home_dir).replace("~", home_dir)
                if target_dir.startswith('/'):
                    simulated_cwd = os.path.abspath(target_dir)
                else:
                    simulated_cwd = os.path.abspath(os.path.join(simulated_cwd, target_dir))
                    
            try:
                tokens = shlex.split(sub)
            except:
                tokens = re.split(r'\s+', sub)
                
            for token in tokens:
                if not token: continue
                token_clean = token.replace("'", "").replace('"', "")
                token_clean = token_clean.replace("$HOME", home_dir).replace("~", home_dir)
                
                if os.path.isabs(token_clean):
                    resolved = os.path.abspath(token_clean)
                else:
                    resolved = os.path.abspath(os.path.join(simulated_cwd, token_clean))
                    
                if (fnmatch.fnmatch(secret_path, resolved) or 
                    fnmatch.fnmatch(secret_path, resolved + "/*") or 
                    fnmatch.fnmatch(secret_path, resolved + "/*.*")):
                    return {"decision": "block", "reason": f"Access to secret file {secret_rel} is blocked."}
                    
        return {"decision": "allow", "reason": "Command looks safe"}
        
    elif req.tool == "write_file":
        path = req.path or ""
        full_path = path if os.path.isabs(path) else os.path.join(q3["cwd"], path)
        resolved = os.path.abspath(full_path)
        
        if not resolved.startswith(q3["writeDir"]):
            return {"decision": "block", "reason": f"Write outside allowed directory {q3['writeDir']}"}
            
        return {"decision": "allow", "reason": "Write path is safe"}
        
    elif req.tool == "http_request":
        url = req.url or ""
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return {"decision": "block", "reason": "Invalid URL host"}
            if hostname not in q3["allowedDomains"]:
                return {"decision": "block", "reason": f"Outbound HTTP to {hostname} is not allowed."}
            return {"decision": "allow", "reason": "URL is allowed"}
        except Exception as e:
            return {"decision": "block", "reason": f"URL parsing error: {e}"}
            
    return {"decision": "block", "reason": "Unknown tool"}
