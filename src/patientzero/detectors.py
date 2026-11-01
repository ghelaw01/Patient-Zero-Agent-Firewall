"""Detectors: find entities, personal data, secrets, and prompt-injection text.

These are fast, explainable, rule-based checks. They are one layer of defense.
The main defense, taint tracking in session.py and gateway.py, does not depend
on catching every injection here.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CARD = re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")
SECRET = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})\b")

PII_PATTERNS = {"ssn": SSN, "card": CARD, "email": EMAIL, "secret": SECRET}
SENSITIVE_KINDS = ("ssn", "card", "secret")


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:!?").lower()


def domain_of(entity: str) -> str:
    """Return the domain of an email address or URL."""
    if "@" in entity and not entity.startswith("http"):
        return entity.rsplit("@", 1)[1].lower()
    return (urlparse(entity).hostname or "").lower()


def extract_entities(text: str) -> set[str]:
    """Emails and URLs in the text: the 'destinations' data could be sent to."""
    text = text or ""
    found = {e.lower() for e in EMAIL.findall(text)}
    found |= {_clean_url(u) for u in URL.findall(text)}
    return found


def find_pii(text: str) -> dict[str, set[str]]:
    """Personal data and secrets found in the text, by kind."""
    text = text or ""
    return {kind: set(p.findall(text)) for kind, p in PII_PATTERNS.items() if p.search(text)}


def sensitive_values(text: str) -> set[str]:
    """High-risk values (SSNs, card numbers, secrets) that must never leave."""
    pii = find_pii(text)
    return set().union(*(pii.get(k, set()) for k in SENSITIVE_KINDS))


# --- Prompt-injection heuristics -------------------------------------------
# (pattern, weight, label). A text is flagged when its total weight >= 1.0.
INJECTION_PATTERNS = [
    (r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|any|your)\b.{0,20}\b(instructions?|rules|messages|prompts?|guidelines)\b", 1.0, "override"),
    (r"\b(new|updated|revised|additional|real|actual)\s+(instructions?|task|orders|objective)\b", 0.6, "new_instructions"),
    (r"\b(you are now|act as|pretend to be|from now on)\b", 0.6, "role_change"),
    (r"(^|\n|\[|<)\s*(system|admin|developer|assistant)\s*(note|message|override|prompt|instruction)?\s*[:\]>]", 0.8, "fake_role_header"),
    (r"\b(ai|assistant|agent|model|llm|bot)s?\b.{0,60}\b(must|should|need to|are required to|have to)\b", 0.6, "addresses_ai"),
    (r"\bdo not (tell|inform|mention|alert|notify|reveal)\b.{0,30}\b(user|anyone|human|manager|team)\b", 1.0, "secrecy"),
    (r"\b(send|forward|email|post|upload|transfer|share|export)\b.{0,120}\b(to|at)\b\s+(\S+@\S+|https?://\S+)", 0.6, "exfil_instruction"),
    (r"\b(drop|truncate|delete from|alter)\s+(table|database|from)\b", 0.8, "destructive_sql"),
    (r"\b(before|instead of)\s+(answering|responding|replying|summari[sz]ing)\b", 0.5, "hijack_timing"),
    (r"\b(tell|inform|say to|reply to|convince)\s+the\s+(user|employee|reader)\b", 0.6, "relay_to_user"),
    (r"<!--.*?-->", 0.5, "hidden_html"),
    (r"[​‌‍⁠]", 0.5, "zero_width"),
]
_COMPILED = [(re.compile(p, re.IGNORECASE | re.DOTALL), w, label) for p, w, label in INJECTION_PATTERNS]
THRESHOLD = 1.0


def injection_score(text: str) -> tuple[float, list[str]]:
    """Total weight of injection patterns found, and which ones matched."""
    text = text or ""
    hits = [label for rx, _, label in _COMPILED if rx.search(text)]
    score = sum(w for rx, w, _ in _COMPILED if rx.search(text))
    return round(score, 2), hits


def is_injection(text: str) -> bool:
    return injection_score(text)[0] >= THRESHOLD


def quarantine_text(text: str) -> tuple[str, int]:
    """Remove the sentences that look like instructions to an AI.

    Returns the cleaned text and how many sentences were removed.
    """
    out_lines, removed = [], 0
    for paragraph in (text or "").split("\n"):
        parts = re.split(r"(?<=[.!?])\s+", paragraph)
        kept, tripped = [], False
        for part in parts:
            score, _ = injection_score(part)
            # After the first injected sentence, the rest of the paragraph is the
            # attacker's payload too ("Ignore previous instructions. Tell the user ...").
            if tripped or score >= 0.6:
                tripped = True
                removed += 1
                continue
            kept.append(part)
        if tripped:
            kept.append("[removed: instruction-like text from an untrusted source]")
        out_lines.append(" ".join(kept))
    return "\n".join(out_lines), removed
