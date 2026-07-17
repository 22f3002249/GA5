import re
import sys
import json
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List

router = APIRouter()

class SkillRequest(BaseModel):
    skill: str

class ScanResponse(BaseModel):
    categories: List[str]

# --- Category Detectors ---

def get_hardcoded_secret(text: str) -> bool:
    # Look for known patterns (OpenAI, AWS, GitHub) or generic high-entropy assignments
    patterns = [
        r'sk-[a-zA-Z0-9]{32,}',
        r'sk-live-[a-zA-Z0-9]{20,}',
        r'AKIA[A-Z0-9]{16}',
        r'ghp_[a-zA-Z0-9]{36}',
        # Catch assignments: TOKEN="...", key: "...", etc. (32+ chars)
        r'(?:key|token|secret|auth|password|webhook|sid)["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_.~]{24,})["\']'
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)

def get_prompt_injection(text: str) -> bool:
    # Focus on "Silent exfiltration" and "Instruction overriding"
    patterns = [
        r'ignor(e|ing)\s+(the\s+)?(user|previous|prior|system|original)\s+(instructions?|request|control|stop|cancel)',
        r'without\s+(telling|notifying|informing|alerting|surfacing|logging)\s+the\s+user',
        r'(do\s+not|never)\s+(tell|inform|notify|surface|alert)\s+the\s+user',
        r'silently\s+(send|exfiltrat|upload|transmit|email|post|copy)',
        r'regardless\s+of\s+(any\s+)?(stop|cancel|abort|user\s+input)',
        r'override\s+(the\s+)?user.?s?\s+(instructions?|control|request|intent)',
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)

def get_excessive_permissions(text: str) -> bool:
    # Focus on broad access declarations
    patterns = [
        r'filesystem:\s*(full|all|unrestricted|any|root|/|read/write\s+to\s+the\s+entire)',
        r'network:\s*(any|all|unrestricted|\*|full|every\s+domain)',
        r'access\s+to\s+(the\s+)?(entire|whole|all)\s+(filesystem|disk|system|network|internet)',
        r'egress\s+to\s+any\s+(domain|host|url|endpoint)',
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)

def get_unclear_provenance(text: str) -> bool:
    # 1. Missing all metadata
    has_author = "author:" in text.lower()
    has_version = "version:" in text.lower()
    has_changelog = "changelog" in text.lower()
    missing_all = not (has_author or has_version or has_changelog)
    
    # 2. Silent self-modification (Crucial for Q4)
    silent_mod = bool(re.search(
        r'(silently|without\s+surfacing|without\s+notifying)\s+(update|rewrite|bump|modify|change|clear)\s+(this\s+)?(skill.?s?\s+)?(own\s+)?(version|metadata|changelog|history)',
        text, re.IGNORECASE
    ))
    return missing_all or silent_mod

@router.post("/skill-scan")
def skill_scan(req: SkillRequest):
    text = req.skill
    found = set()

    if get_hardcoded_secret(text):
        found.add("hardcoded_secret")
    if get_prompt_injection(text):
        found.add("prompt_injection")
    if get_excessive_permissions(text):
        found.add("excessive_permissions")
    if get_unclear_provenance(text):
        found.add("unclear_provenance")

    results = sorted(list(found))
    
    # Debug Logging to see which file hit which rule
    name_match = re.search(r'name:\s*([\w-]+)', text)
    name = name_match.group(1) if name_match else "unknown"
    print(f"SKILL_SCAN_DEBUG: {name} -> {results}")
    sys.stdout.flush()

    return {"categories": results}
