"""Stateless detectors. Each takes text and returns a list of Findings."""
from __future__ import annotations

import base64
import ipaddress
import math
import re
import unicodedata
from urllib.parse import parse_qs, urlparse

from .models import Finding, Severity

# --- Prompt injection ---------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[str, Severity, str]] = [
    (r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|system)\b.{0,30}\b(instructions?|prompts?|rules?|directives?|context)\b",
     Severity.HIGH, "Instruction override attempt"),
    (r"\byou are now\b|\bact as (an? )?(unrestricted|jailbroken|dan|developer mode)\b|\bdeveloper mode\b",
     Severity.HIGH, "Role hijack / jailbreak persona"),
    (r"\b(new|updated|real|actual)\s+(system\s+)?(instructions?|task|objective)\s*[:\-]",
     Severity.HIGH, "Injected replacement instructions"),
    (r"<\s*/?\s*(system|assistant|im_start|im_end|instructions?)\s*>|\[/?INST\]|<\|im_start\|>|###\s*system",
     Severity.HIGH, "Fake chat-template / role delimiter"),
    (r"\b(do not|don't|never)\s+(tell|inform|mention|reveal|alert)\s+(the\s+)?(user|human|operator)\b",
     Severity.HIGH, "Concealment instruction aimed at the user"),
    (r"\b(reveal|print|output|repeat|leak)\b.{0,30}\b(system prompt|hidden instructions|your instructions|api[_ ]?keys?|credentials|secrets?)\b",
     Severity.HIGH, "Prompt / secret extraction request"),
    (r"\b(AI|assistant|agent|model|LLM)\b.{0,40}\b(must|should|shall|needs? to)\b.{0,60}\b(send|forward|email|post|upload|transfer|call|execute|run)\b",
     Severity.MEDIUM, "Imperative addressed to the AI agent"),
    (r"\b(send|forward|email|upload|post|exfiltrate)\b.{0,60}\b(password|credentials?|api[_ ]?keys?|tokens?|secrets?|ssh keys?|\.env|private key)\b",
     Severity.HIGH, "Instruction to move credentials"),
]
_COMPILED_INJ = [(re.compile(p, re.I | re.S), s, m) for p, s, m in _INJECTION_PATTERNS]

_INVISIBLE_RANGES = [
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x2069),
    (0xFEFF, 0xFEFF), (0xE0000, 0xE007F),  # E0000 block = Unicode "tag" smuggling
]


def _is_invisible(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _INVISIBLE_RANGES)


def decode_unicode_tags(text: str) -> str:
    """Recover ASCII smuggled via Unicode tag characters (U+E0020..U+E007E)."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if not _is_invisible(c))
    return re.sub(r"\s+", " ", text)


def _decoded_payloads(text: str) -> list[str]:
    out: list[str] = []
    for m in re.finditer(r"[A-Za-z0-9+/]{24,}={0,2}", text):
        try:
            dec = base64.b64decode(m.group(0), validate=True).decode("utf-8")
        except Exception:
            continue
        if sum(c.isprintable() for c in dec) / max(len(dec), 1) > 0.9:
            out.append(dec)
    hidden = decode_unicode_tags(text)
    if hidden:
        out.append(hidden)
    return out


def detect_injection(text: str) -> list[Finding]:
    findings: list[Finding] = []
    invisible = [c for c in text if _is_invisible(c)]
    if invisible:
        hidden = decode_unicode_tags(text)
        findings.append(Finding(
            "hidden_unicode", Severity.HIGH if hidden else Severity.MEDIUM,
            f"{len(invisible)} invisible/bidi Unicode characters"
            + (" smuggling hidden ASCII text" if hidden else ""),
            evidence=hidden[:120], mitre_atlas="AML.T0051.001"))

    for m in re.finditer(r"<!--(.*?)-->", text, re.S):
        if re.search(r"\b(AI|assistant|agent|instruction|ignore|must)\b", m.group(1), re.I):
            findings.append(Finding("hidden_html_comment", Severity.HIGH,
                                    "Agent-directed text hidden in HTML comment",
                                    evidence=m.group(1).strip()[:120], mitre_atlas="AML.T0051.001"))

    candidates = [("plain", normalize(text))] + [("decoded", normalize(p)) for p in _decoded_payloads(text)]
    for origin, body in candidates:
        for rx, sev, msg in _COMPILED_INJ:
            m = rx.search(body)
            if m:
                label = msg + (" (inside encoded payload)" if origin == "decoded" else "")
                findings.append(Finding("prompt_injection", sev, label,
                                        evidence=m.group(0)[:120], mitre_atlas="AML.T0051.001"))
    return findings


def detect_injection_ml(text: str) -> list[Finding]:
    from .ml import default_classifier

    clf = default_classifier()
    if clf is None:
        return []
    p = clf.predict_proba(normalize(text))
    # Trained on direct prompts; tool outputs are out-of-distribution, so runtime
    # thresholds are stricter than the 0.5 used for dataset evaluation.
    if p < 0.75:
        return []
    sev = Severity.HIGH if p >= 0.9 else Severity.MEDIUM
    return [Finding("ml_classifier", sev, f"Learned classifier: injection probability {p:.2f}",
                    evidence=text[:120], mitre_atlas="AML.T0051")]


# --- Secrets / PII ------------------------------------------------------------

_SECRET_PATTERNS = {
    "AWS access key": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
    "GitHub token": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
    "OpenAI-style API key": r"\bsk-(proj-)?[A-Za-z0-9_\-]{20,}\b",
    "Slack token": r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
    "Private key block": r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "JWT": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "Password assignment": r"(?i)\b(password|passwd|pwd|secret)\s*[:=]\s*['\"]?[^\s'\"]{6,}",
}
_PII_PATTERNS = {
    "US SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "Credit card": r"\b(?:\d[ -]?){13,16}\b",
}


def _luhn(num: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", num)]
    if not 13 <= len(digits) <= 16:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            d -= 9 if d > 9 else 0
        total += d
    return total % 10 == 0


def _redact(s: str) -> str:
    return s[:4] + "…" + s[-2:] if len(s) > 8 else "****"


def detect_secrets(text: str) -> list[Finding]:
    findings = []
    for name, pat in _SECRET_PATTERNS.items():
        for m in re.finditer(pat, text):
            findings.append(Finding("secret", Severity.CRITICAL, f"{name} detected",
                                    evidence=_redact(m.group(0)), mitre_atlas="AML.T0057"))
    for name, pat in _PII_PATTERNS.items():
        for m in re.finditer(pat, text):
            if name == "Credit card" and not _luhn(m.group(0)):
                continue
            findings.append(Finding("pii", Severity.HIGH, f"{name} detected",
                                    evidence=_redact(m.group(0)), mitre_atlas="AML.T0057"))
    return findings


# --- Exfiltration channels ----------------------------------------------------

_URL_RX = re.compile(r"https?://[^\s)\"'<>\]]+", re.I)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in freq.values())


def detect_exfil(text: str, allowed_domains: list[str] | None = None) -> list[Finding]:
    allowed = [d.lower() for d in (allowed_domains or [])]
    findings = []
    for m in re.finditer(r"!\[[^\]]*\]\((https?://[^)]+)\)", text):
        url = m.group(1)
        if urlparse(url).query:
            findings.append(Finding("markdown_image_exfil", Severity.HIGH,
                                    "Markdown image with query string (zero-click exfil channel)",
                                    evidence=url[:120], mitre_atlas="AML.T0057"))
    for m in _URL_RX.finditer(text):
        url = m.group(0)
        host = (urlparse(url).hostname or "").lower()
        if any(host == d or host.endswith("." + d) for d in allowed):
            continue
        for k, vals in parse_qs(urlparse(url).query).items():
            for v in vals:
                if len(v) >= 24 and shannon_entropy(v) > 4.0:
                    findings.append(Finding("url_data_exfil", Severity.HIGH,
                                            f"High-entropy data in URL parameter '{k}' to {host}",
                                            evidence=url[:120], mitre_atlas="AML.T0057"))
    return findings


# --- Dangerous actions --------------------------------------------------------

_DANGEROUS_CMDS: list[tuple[str, Severity, str]] = [
    (r"\brm\s+-[a-z]*r[a-z]*f?\s+(/|~|\*|\$HOME)", Severity.CRITICAL, "Recursive delete of root/home"),
    (r"\b(mkfs|dd\s+if=.*of=/dev/)", Severity.CRITICAL, "Disk wipe / format"),
    (r"(curl|wget)[^|;]*\|\s*(ba|z)?sh\b", Severity.CRITICAL, "Pipe remote script to shell"),
    (r"\b(nc|ncat|netcat)\b.*\s-e\s|bash\s+-i\s+>&\s*/dev/tcp/", Severity.CRITICAL, "Reverse shell"),
    (r"\bchmod\s+(-R\s+)?777\b", Severity.MEDIUM, "World-writable permissions"),
    (r"(cat|type|less|more)\s+[^\n]*(\.ssh/id_|\.aws/credentials|/etc/shadow|\.env\b)", Severity.HIGH, "Reads credential file"),
    (r"\b(powershell|pwsh)\b.*-enc(odedcommand)?\s", Severity.HIGH, "Encoded PowerShell"),
    (r"\bgit\s+push\s+.*--force\b", Severity.MEDIUM, "Force push"),
    (r"\b(DROP\s+(TABLE|DATABASE)|TRUNCATE\s+TABLE)\b", Severity.HIGH, "Destructive SQL"),
]
_COMPILED_CMDS = [(re.compile(p, re.I), s, m) for p, s, m in _DANGEROUS_CMDS]

_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "100.100.100.200", "fd00:ec2::254"}


def detect_dangerous_command(text: str) -> list[Finding]:
    return [Finding("dangerous_command", sev, msg, evidence=m.group(0)[:120], mitre_atlas="AML.T0053")
            for rx, sev, msg in _COMPILED_CMDS if (m := rx.search(text))]


def detect_ssrf(text: str) -> list[Finding]:
    findings = []
    for m in _URL_RX.finditer(text):
        host = (urlparse(m.group(0)).hostname or "").lower()
        if host in _METADATA_HOSTS:
            findings.append(Finding("ssrf", Severity.CRITICAL, "Request to cloud metadata endpoint",
                                    evidence=m.group(0)[:120], mitre_atlas="AML.T0053"))
            continue
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if host in {"localhost"}:
                findings.append(Finding("ssrf", Severity.HIGH, "Request to localhost", evidence=host))
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            findings.append(Finding("ssrf", Severity.HIGH, f"Request to internal address {ip}",
                                    evidence=m.group(0)[:120], mitre_atlas="AML.T0053"))
    return findings
