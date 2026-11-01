"""Patient Zero: stop one poisoned document from hijacking your whole AI agent team."""
from .agents import Agent, Team
from .audit import AuditLog, verify
from .gateway import Gateway, approve_all, cli_approver, deny_risky
from .llm import make_model
from .policy import Policy
from .session import Session

__version__ = "0.1.0"
__all__ = ["Agent", "Team", "AuditLog", "verify", "Gateway", "approve_all", "cli_approver",
           "deny_risky", "make_model", "Policy", "Session"]
