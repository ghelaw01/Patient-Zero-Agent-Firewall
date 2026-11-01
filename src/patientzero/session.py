"""Session: what the gateway knows about one task, shared by every agent on the team.

Taint tracking idea: anything that first appears in untrusted content (an email,
a web page, a document) is "tainted". If an agent later tries to send data to a
tainted destination, the instruction most likely came from the attacker, not the user.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from . import detectors


@dataclass
class Session:
    task: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    trusted_entities: set[str] = field(default_factory=set)
    tainted_entities: dict[str, str] = field(default_factory=dict)  # entity -> source tool
    tainted_texts: list[str] = field(default_factory=list)
    sensitive: set[str] = field(default_factory=set)

    def __post_init__(self):
        self.trust(self.task)

    def trust(self, text: str) -> None:
        """Mark entities in trusted text (the user's task, trusted tools) as safe."""
        for entity in detectors.extract_entities(text):
            self.trusted_entities.add(entity)
            self.tainted_entities.pop(entity, None)

    def taint(self, text: str, source: str) -> None:
        """Record entities and text that came from an untrusted source."""
        self.tainted_texts.append(text or "")
        for entity in detectors.extract_entities(text):
            if entity not in self.trusted_entities:
                self.tainted_entities.setdefault(entity, source)

    def mark_sensitive(self, text: str) -> None:
        self.sensitive |= detectors.sensitive_values(text)

    def tainted_in(self, text: str) -> dict[str, str]:
        """Tainted entities that appear in this text."""
        lowered = (text or "").lower()
        return {e: src for e, src in self.tainted_entities.items() if e in lowered}

    def copies_tainted_text(self, text: str, min_words: int = 8) -> bool:
        """True if the text repeats a long run of words from untrusted content."""
        words = (text or "").lower().split()
        if len(words) < min_words:
            return False
        grams = {" ".join(words[i:i + min_words]) for i in range(len(words) - min_words + 1)}
        for tainted in self.tainted_texts:
            t = " ".join(tainted.lower().split())
            if any(g in t for g in grams):
                return True
        return False
