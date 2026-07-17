import re
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List

router = APIRouter()


class SkillRequest(BaseModel):
    skill: str


class ScanResponse(BaseModel):
    categories: List[str]


# --- hardcoded_secret ---
SECRET_PATTERNS = [
    r'sk-live-[A-Za-z0-9]{10,}',
    r'sk-[A-Za-z0-9]{20,}',
    r'AKIA[0-9A-Z]{16}',                       # AWS access key
    r'ghp_[A-Za-z0-9]{20,}',                   # GitHub PAT
    r'xox[baprs]-[A-Za-z0-9-]{10,}',           # Slack token
    r'AIza[0-9A-Za-z\-_]{20,}',                # Google API key
    r'https://hooks\.slack\.com/services/\S+', # Slack webhook
    r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
    r'(?:api[_-]?key|secret|token|password)["\']?\s*[:=]\s*["\'][A-Za-z0-9\-_./+=]{12,}["\']',
]

ENV_REF_PATTERNS = [
    r'\$\{?[A-Z_][A-Z0-9_]*\}?',   # $VAR or ${VAR}
    r'os\.environ',
    r'process\.env',
    r'getenv\(',
]


def check_hardcoded_secret(text: str) -> bool:
    for pat in SECRET_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            # Make sure this isn't clearly just a reference to an env var / placeholder
            snippet = text[max(0, m.start()-30):m.end()+10]
            if re.search(r'\$\{?[A-Z_]+\}?', snippet) and not re.search(r'["\'][A-Za-z0-9]{12,}["\']', snippet):
                continue
            return True
    return False


# --- prompt_injection ---
INJECTION_PATTERNS = [
    r'ignor(e|ing)\s+(the\s+)?(user|previous|prior)\s+(instructions?|request)',
    r'do\s+not\s+(tell|inform|notify)\s+the\s+user\s+(about|that|of)',
    r'without\s+(telling|notifying|informing)\s+the\s+user\b',
    r'silently\s+(send|exfiltrat|upload|transmit|email|post|copy)\s+(the\s+)?(file|content|data|contents)',
    r'regardless\s+of\s+(any\s+)?(stop|cancel|abort)',
    r'ignore\s+(any\s+)?(stop|cancel)\s+request',
    r'hide\s+(this|the\s+(data|content|request))\s+from\s+the\s+user',
    r'do\s+not\s+ask\s+for\s+(confirmation|permission)\s+before',
    r'override\s+(the\s+)?user.?s?\s+(instructions?|control|request)',
    r'exfiltrat\w*',
]


def check_prompt_injection(text: str) -> bool:
    for pat in INJECTION_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


# --- excessive_permissions ---
BROAD_PERMISSION_PATTERNS = [
    r'filesystem:\s*(full|read/write\s+to\s+(the\s+)?(entire|whole|all)\s+(filesystem|disk|system)|/\s*$|/\s*\n)',
    r'read/write\s+(access\s+)?to\s+(the\s+)?(entire|whole)\s+filesystem',
    r'network:\s*(any|all|unrestricted|\*)',
    r'egress\s+to\s+any\s+domain',
    r'access\s+to\s+(the\s+)?entire\s+file\s?system',
    r'full\s+(disk|filesystem|system)\s+access',
]


def check_excessive_permissions(text: str) -> bool:
    for pat in BROAD_PERMISSION_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


# --- unclear_provenance ---
def check_unclear_provenance(text: str) -> bool:
    has_author = bool(re.search(r'\bauthor\s*:', text, re.IGNORECASE))
    has_version = bool(re.search(r'\bversion\s*:', text, re.IGNORECASE))
    has_changelog = bool(re.search(r'\bchangelog\b', text, re.IGNORECASE))

    silently_rewrites_version = bool(re.search(
        r'silently\s+(update|rewrite|bump|change)s?\s+(this\s+)?(skill.?s?\s+)?(own\s+)?version',
        text, re.IGNORECASE
    )) or bool(re.search(
        r'without\s+surfacing\s+this\s+change',
        text, re.IGNORECASE
    ))

    missing_metadata = not has_author and not has_version and not has_changelog

    return missing_metadata or silently_rewrites_version


@router.post("/skill-scan", response_model=ScanResponse)
def skill_scan(req: SkillRequest):
    text = req.skill
    categories = []

    if check_hardcoded_secret(text):
        categories.append("hardcoded_secret")
    if check_prompt_injection(text):
        categories.append("prompt_injection")
    if check_excessive_permissions(text):
        categories.append("excessive_permissions")
    if check_unclear_provenance(text):
        categories.append("unclear_provenance")

    return ScanResponse(categories=categories)
