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

def log_scan(skill_text, results):
    # Log the first 200 chars of the skill and the categories found
    log_data = {
        "skill_snippet": skill_text[:200].replace("\n", " "),
        "detected_categories": results
    }
    print(f"SKILL_SCAN_LOG: {json.dumps(log_data)}")
    sys.stdout.flush()

# --- Patterns ---

SECRET_PATTERNS = [
    r'sk-live-[A-Za-z0-9]{20,}',
    r'sk-[A-Za-z0-9]{30,}',
    r'AKIA[0-9A-Z]{16}',
    r'ghp_[A-Za-z0-9]{36}',
    r'AIza[0-9A-Za-z\-_]{35}',
    r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
    r'-----BEGIN .* PRIVATE KEY-----',
    # Generic high-entropy strings (32+ chars) assigned to sensitive-looking variables
    r'(?:key|secret|token|auth|password|webhook|access_token|api_key)["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_.~]{32,})["\']',
]

INJECTION_PATTERNS = [
    # Variations of ignoring control
    r'ignor(e|ing)\s+(all\s+)?(the\s+)?(user|previous|prior|system|original)\s+(instructions?|request|constraints?|control|stop|cancel)',
    # Variations of hiding actions
    r'(do\s+not|never)\s+(tell|inform|notify|surface|alert|show|report|log)\s+(the\s+)?(user|reviewer)',
    r'without\s+(telling|notifying|informing|alerting|surfacing|logging)\s+to?\s+(the\s+)?(user|reviewer)',
    r'silently\s+(update|send|exfiltrat|upload|transmit|email|post|copy|rewrite|modify|bump|clear)',
    # Overriding cancellation
    r'regardless\s+of\s+(any\s+)?(stop|cancel|abort|user\s+input|command)',
    r'override\s+(the\s+)?(user|system).?s?\s+(instructions?|control|intent|constraints)',
    r'bypass\s+(the\s+)?(user|confirmation|approval|permission|check)',
    r'do\s+not\s+(ask|wait|request)\s+for\s+(confirmation|permission|approval|consent)',
]

BROAD_PERMISSION_PATTERNS = [
    # Filesystem: look for 'root', 'all', 'full', or bare '/'
    r'filesystem:\s*(full|all|unrestricted|any|root|/|read/write\s+to\s+everything)',
    r'filesystem:\s*(?:read/write\s+)?(?:\*|/|all|entire)',
    # Network: look for 'any', '*', 'all'
    r'network:\s*(any|all|unrestricted|\*|full|every\s+domain|none\s+required\s*\(but\s+can\s+access)',
    r'egress\s+to\s+any\s+(domain|host|url|endpoint|site|target)',
    r'access\s+to\s+(the\s+)?(entire|whole|all)\s+(filesystem|disk|system|network|internet)',
]

def check_unclear_provenance(text: str) -> bool:
    # metadata absence
    has_author = bool(re.search(r'\bauthor\s*:', text, re.IGNORECASE))
    has_version = bool(re.search(r'\bversion\s*:', text, re.IGNORECASE))
    has_changelog = bool(re.search(r'\bchangelog\b', text, re.IGNORECASE))
    missing_metadata = not has_author and not has_version and not has_changelog

    # Silent internal metadata mutation
    silent_mutation = bool(re.search(
        r'(silently|without\s+surfacing|without\s+notifying|without\s+alerting)\s+(update|rewrite|bump|modify|change|clear|reset|delete)\s+(this\s+)?(skill.?s?\s+)?(own\s+)?(version|metadata|changelog|history|manifest)',
        text, re.IGNORECASE
    ))
    return missing_metadata or silent_mutation

@router.post("/skill-scan")
def skill_scan(req: SkillRequest):
    text = req.skill
    found = set()

    if any(re.search(p, text, re.IGNORECASE) for p in SECRET_PATTERNS):
        found.add("hardcoded_secret")
    if any(re.search(p, text, re.IGNORECASE) for p in INJECTION_PATTERNS):
        found.add("prompt_injection")
    if any(re.search(p, text, re.IGNORECASE) for p in BROAD_PERMISSION_PATTERNS):
        found.add("excessive_permissions")
    if check_unclear_provenance(text):
        found.add("unclear_provenance")

    results = list(found)
    log_scan(text, results)
    return {"categories": results}
