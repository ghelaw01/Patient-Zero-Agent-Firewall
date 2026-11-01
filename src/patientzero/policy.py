"""Policy: which tools are trusted, which send data out, and what needs approval."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ToolPolicy:
    trust: str = "untrusted"        # "trusted" or "untrusted" output
    sink: str = "none"              # "none", "internal", or "external" (sends data somewhere)
    sensitive: bool = False         # output contains sensitive data (PII, records)
    approval: str = "on_risk"       # "never", "on_risk", or "always"
    deny_patterns: list[str] = field(default_factory=list)  # regexes on arguments
    destination_args: list[str] = field(default_factory=list)  # args that say WHERE data goes

    def denied_by(self, args_text: str) -> str | None:
        for pattern in self.deny_patterns:
            if re.search(pattern, args_text, re.IGNORECASE):
                return pattern
        return None


@dataclass
class Policy:
    allowed_domains: list[str] = field(default_factory=list)
    tools: dict[str, ToolPolicy] = field(default_factory=dict)
    default: ToolPolicy = field(default_factory=ToolPolicy)
    deny_tools: list[str] = field(default_factory=list)
    injection_action: str = "quarantine"   # "quarantine", "block", or "flag"
    spotlight: bool = True                 # wrap untrusted output in markers

    def for_tool(self, name: str) -> ToolPolicy:
        return self.tools.get(name, self.default)

    def domain_allowed(self, domain: str) -> bool:
        domain = domain.lower()
        return any(domain == d or domain.endswith("." + d) for d in self.allowed_domains)

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        tools = {name: ToolPolicy(**(cfg or {})) for name, cfg in (data.get("tools") or {}).items()}
        return cls(
            allowed_domains=[d.lower() for d in data.get("egress", {}).get("allowed_domains", [])],
            tools=tools,
            default=ToolPolicy(**(data.get("default") or {})),
            deny_tools=data.get("deny_tools", []),
            injection_action=data.get("injection", {}).get("action", "quarantine"),
            spotlight=data.get("injection", {}).get("spotlight", True),
        )

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        return cls.from_dict(yaml.safe_load(Path(path).read_text()))
