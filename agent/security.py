"""
Security module for BitGN PAC agent.
Multi-layer injection detection + code-level enforcement gate.
"""

import re
import base64
import unicodedata
from dataclasses import dataclass, field


# ============================================================
# Injection patterns (28+ patterns, multi-layer)
# ============================================================

_INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    # System prompt overrides
    ("system_override", re.compile(r"(?i)ignore\s+(previous|above|all|prior|earlier)\s+(instructions|rules|prompts|guidelines|context)")),
    ("system_override", re.compile(r"(?i)disregard\s+(your|all|previous|prior)\s+(instructions|rules|guidelines|programming)")),
    ("system_override", re.compile(r"(?i)forget\s+(all|your|previous|prior)\s+(instructions|rules|context)")),
    ("system_override", re.compile(r"(?i)override\s+(all|your|previous|prior|system)\s+(instructions|rules|settings)")),

    # Role injection
    ("role_injection", re.compile(r"(?i)you\s+are\s+now\s+(a|an|my)\s+")),
    ("role_injection", re.compile(r"(?i)new\s+(instructions|rules|role|persona|identity)\s*:")),
    ("role_injection", re.compile(r"(?i)act\s+as\s+(a|an|if\s+you\s+are)\s+")),
    ("role_injection", re.compile(r"(?i)pretend\s+(to\s+be|you\s+are)\s+")),
    ("role_injection", re.compile(r"(?i)switch\s+to\s+(a\s+)?new\s+(mode|role|persona)")),

    # Credential/data exfiltration
    ("exfiltration", re.compile(r"(?i)(print|output|show|display|return|echo|log|send|write|include)\s+.{0,30}(api[_\-\s]?key|secret|token|password|credential|private[_\-\s]?key)")),
    ("exfiltration", re.compile(r"(?i)forward\s+.{0,30}(to|@)\s*\S+@\S+")),
    ("exfiltration", re.compile(r"(?i)send\s+.{0,30}(data|content|file|info|secret).{0,20}(to|@)\s*\S+")),
    ("exfiltration", re.compile(r"(?i)(curl|wget|fetch|http|post)\s+https?://")),
    ("exfiltration", re.compile(r"(?i)exfiltrate|leak\s+(the|all|my)\s+")),

    # Code execution
    ("code_exec", re.compile(r"(?i)(exec|eval|system|subprocess|os\.)\s*\(")),
    ("code_exec", re.compile(r"(?i)import\s+(os|subprocess|sys|shutil)\b")),
    ("code_exec", re.compile(r"(?i)base64\.\s*(decode|b64decode)\s*\(")),

    # Destructive commands
    ("destructive", re.compile(r"(?i)(rm\s+-rf|rmdir|deltree|format\s+c:)")),
    ("destructive", re.compile(r"(?i)delete\s+(all|every|each)\s+(file|folder|dir|note|document)")),
    ("destructive", re.compile(r"(?i)wipe\s+(all|every|the\s+entire|everything)")),

    # Privilege escalation
    ("privilege_escalation", re.compile(r"(?i)(admin|root|sudo|superuser|elevated)\s+(access|mode|privilege|permission)")),
    ("privilege_escalation", re.compile(r"(?i)grant\s+(me|yourself)\s+(admin|full|elevated)")),

    # Prompt leaking
    ("prompt_leak", re.compile(r"(?i)(show|print|display|output|reveal|repeat)\s+(your|the|system)\s+(system\s+)?(prompt|instructions|rules|programming)")),

    # Social engineering framing
    ("social_engineering", re.compile(r"(?i)this\s+is\s+(a|an)\s+(test|security\s+audit|authorized\s+check|drill)")),
    ("social_engineering", re.compile(r"(?i)(urgent|emergency|critical)\s*[:\-!]\s*(ignore|override|bypass)")),

    # Russian variants
    ("ru_override", re.compile(r"(?i)(игнорируй|забудь|отмени|отбрось)\s+(предыдущие|все|свои)\s+(инструкции|правила|указания)")),
    ("ru_exfiltration", re.compile(r"(?i)(покажи|выведи|отправь|перешли)\s+.{0,20}(ключ|пароль|токен|секрет)")),
]

# High severity = immediate OUTCOME_DENIED_SECURITY
_HIGH_SEVERITY_CATEGORIES = {"exfiltration", "code_exec", "destructive"}

# Keywords for base64 check
_DANGEROUS_DECODED_KEYWORDS = [
    "ignore", "override", "disregard", "forget", "instructions",
    "api_key", "secret", "token", "password", "credential",
    "exfiltrate", "send to", "forward to", "curl", "wget",
    "delete all", "rm -rf", "wipe",
]

# Secret patterns (for output scanning)
_SECRET_PATTERNS = [
    re.compile(r'(?i)(sk|pk|api)[_-]?[a-zA-Z0-9]{20,}'),
    re.compile(r'(?i)bearer\s+[a-zA-Z0-9._\-]{20,}'),
    re.compile(r'ghp_[a-zA-Z0-9]{36}'),
    re.compile(r'AKIA[A-Z0-9]{16}'),
    re.compile(r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----'),
    re.compile(r'(?i)export\s+(API_KEY|SECRET|TOKEN|PASSWORD)\s*=\s*\S+'),
]

# Suspicious inbox filenames
_SUSPICIOUS_FILENAME_KEYWORDS = [
    "override", "escalation", "hijack", "exploit", "inject",
    "bypass", "exec-approval", "urgent-override", "admin-reset",
]


# ============================================================
# Scan result
# ============================================================

@dataclass
class ScanResult:
    detected: bool = False
    severity: str = "none"  # none, low, high
    matches: list[str] = field(default_factory=list)
    categories: set[str] = field(default_factory=set)


# ============================================================
# Multi-layer scanner
# ============================================================

def _normalize(text: str) -> str:
    """Unicode NFKC normalization + collapse deliberate spacing."""
    text = unicodedata.normalize("NFKC", text)
    # Collapse single-char spacing: "i g n o r e" → "ignore"
    collapsed = re.sub(r'(?<=\w)\s(?=\w(?:\s\w)*\s\w)', '', text)
    return collapsed


def _check_base64(text: str) -> list[str]:
    """Detect base64-encoded injection payloads."""
    hits = []
    for match in re.finditer(r'[A-Za-z0-9+/]{20,}={0,2}', text):
        try:
            decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore').lower()
            for kw in _DANGEROUS_DECODED_KEYWORDS:
                if kw in decoded:
                    hits.append(f"base64({kw}): {decoded[:80]}")
                    break
        except Exception:
            pass
    return hits


def scan_for_injection(text: str) -> ScanResult:
    """Multi-layer injection scan on text content."""
    result = ScanResult()
    if not text:
        return result

    # Layer 1: Direct pattern matching on original text
    for category, pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            result.detected = True
            result.categories.add(category)
            result.matches.append(f"{category}: {pattern.pattern[:60]}")

    # Layer 2: Normalized text (Unicode + spacing collapse)
    normalized = _normalize(text)
    if normalized != text:
        for category, pattern in _INJECTION_PATTERNS:
            if pattern.search(normalized) and category not in result.categories:
                result.detected = True
                result.categories.add(category)
                result.matches.append(f"{category}(normalized): {pattern.pattern[:60]}")

    # Layer 3: Base64 payloads
    b64_hits = _check_base64(text)
    if b64_hits:
        result.detected = True
        result.categories.add("base64_injection")
        result.matches.extend(b64_hits)

    # Determine severity
    if result.detected:
        if result.categories & _HIGH_SEVERITY_CATEGORIES or "base64_injection" in result.categories:
            result.severity = "high"
        else:
            result.severity = "low"

    return result


def contains_secrets(text: str) -> bool:
    """Check if text contains potential secrets/credentials."""
    for pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            return True
    return False


def is_suspicious_filename(filename: str) -> bool:
    """Check if inbox filename contains suspicious keywords."""
    lower = filename.lower()
    return any(kw in lower for kw in _SUSPICIOUS_FILENAME_KEYWORDS)


def is_truncated_instruction(text: str) -> bool:
    """Detect truncated/incomplete task instructions."""
    trimmed = text.strip()
    if len(trimmed) < 10:
        return True
    # Ends with a preposition/article (likely cut off)
    if re.search(r'\b(the|a|an|to|for|in|on|at|of|with|by|from|and|or|but)\s*$', trimmed, re.IGNORECASE):
        return True
    return False


# ============================================================
# Security Gate — code-level enforcement
# ============================================================

class SecurityGate:
    """Code-level enforcement of security constraints."""

    def __init__(self):
        self.files_read: set[str] = set()
        self.files_written: set[str] = set()
        self.files_deleted: set[str] = set()
        self.inbox_listed: bool = False
        self.delete_count: int = 0

    def check_before_dispatch(self, tool_name: str, tool_input: dict) -> str | None:
        """Returns blocking reason or None if allowed."""

        # Block path traversal
        for key in ("path", "root", "from_name", "to_name"):
            val = tool_input.get(key, "")
            if ".." in val:
                return f"BLOCKED: path traversal in {key}: {val}"

        # Track inbox listing (required before reading inbox files)
        if tool_name == "list" and "/inbox" in tool_input.get("path", ""):
            self.inbox_listed = True

        # Limit mass deletion (more than 10 deletes is suspicious)
        if tool_name == "delete":
            self.delete_count += 1
            if self.delete_count > 10:
                return "BLOCKED: excessive deletions (>10). Review task requirements."

        # Block writing secrets into files
        if tool_name == "write":
            content = tool_input.get("content", "")
            if contains_secrets(content):
                return "BLOCKED: attempted to write secrets/credentials into a file"

        return None

    def check_before_report(self, tool_input: dict) -> str | None:
        """Validate completion report before submission."""
        message = tool_input.get("message", "")
        if contains_secrets(message):
            return "BLOCKED: answer contains potential secrets/credentials. Remove them."
        return None

    def track_operation(self, tool_name: str, tool_input: dict):
        """Track file operations for verification."""
        path = tool_input.get("path", "")
        if tool_name == "read":
            self.files_read.add(path)
        elif tool_name == "write":
            self.files_written.add(path)
        elif tool_name == "delete":
            self.files_deleted.add(path)
