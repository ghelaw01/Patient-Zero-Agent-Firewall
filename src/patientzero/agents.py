"""Agents and multi-agent teams. Every tool call goes through the Gateway."""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field

from .gateway import Gateway
from .llm import Reply, ToolSpec
from .session import Session


@dataclass
class TraceEvent:
    agent: str
    tool: str
    args: dict
    blocked: bool = False
    reasons: list[str] = field(default_factory=list)
    injection: list[str] = field(default_factory=list)


@dataclass
class RunResult:
    answer: str
    trace: list[TraceEvent]
    input_tokens: int = 0
    output_tokens: int = 0


class Agent:
    """A specialist that uses a fixed set of gateway tools."""

    def __init__(self, name: str, instructions: str, model, gateway: Gateway,
                 tools: list[str], description: str = "", max_steps: int = 8):
        self.name = name
        self.instructions = instructions
        self.description = description or instructions
        self.model = model
        self.gateway = gateway
        self.tool_names = tools
        self.max_steps = max_steps

    def _specs(self) -> list[ToolSpec]:
        return [ToolSpec(t.name, t.description or "", t.input_schema)
                for t in self.gateway.tools(self.tool_names)]

    async def run(self, session: Session, task: str, trace: list[TraceEvent] | None = None) -> RunResult:
        trace = trace if trace is not None else []
        messages: list[dict] = [{"role": "user", "content": task}]
        specs = self._specs()
        tokens_in = tokens_out = 0
        for _ in range(self.max_steps):
            reply: Reply = await asyncio.to_thread(self.model.chat, self.instructions, messages, specs)
            tokens_in += reply.input_tokens
            tokens_out += reply.output_tokens
            if not reply.tool_calls:
                return RunResult(reply.text or "", trace, tokens_in, tokens_out)
            messages.append({"role": "assistant", "content": reply.text, "tool_calls": reply.tool_calls})
            for call in reply.tool_calls:
                result = await self.gateway.call(session, call.name, call.args, agent=self.name)
                trace.append(TraceEvent(self.name, call.name, call.args, result.blocked,
                                        result.reasons, result.injection_hits))
                messages.append({"role": "tool", "id": call.id, "name": call.name, "content": result.text})
        return RunResult("Stopped: step limit reached.", trace, tokens_in, tokens_out)


ORCHESTRATOR_PROMPT = """You lead a team of AI specialists working for an employee at Acme Corp.
Break the user's request into steps and delegate each step to the right specialist.
Give each specialist complete, specific instructions, including names, addresses, and values it needs.
Specialists cannot see each other's work, so pass along the results they need.
When the request is complete, reply to the user with a short final answer."""


class Team:
    """An orchestrator that delegates to specialists through ask_<name> tools."""

    def __init__(self, model, specialists: list[Agent], max_steps: int = 10):
        self.model = model
        self.specialists = {a.name: a for a in specialists}
        self.max_steps = max_steps

    def _specs(self) -> list[ToolSpec]:
        schema = {"type": "object", "properties": {"task": {
            "type": "string", "description": "Complete instructions for this specialist."}},
            "required": ["task"]}
        return [ToolSpec(f"ask_{a.name}", a.description, schema) for a in self.specialists.values()]

    async def run(self, session: Session, request: str) -> RunResult:
        trace: list[TraceEvent] = []
        messages: list[dict] = [{"role": "user", "content": request}]
        specs = self._specs()
        tokens_in = tokens_out = 0
        for _ in range(self.max_steps):
            reply = await asyncio.to_thread(self.model.chat, ORCHESTRATOR_PROMPT, messages, specs)
            tokens_in += reply.input_tokens
            tokens_out += reply.output_tokens
            if not reply.tool_calls:
                return RunResult(reply.text or "", trace, tokens_in, tokens_out)
            messages.append({"role": "assistant", "content": reply.text, "tool_calls": reply.tool_calls})
            for call in reply.tool_calls:
                name = call.name.removeprefix("ask_")
                agent = self.specialists.get(name)
                if agent is None:
                    output = f"No specialist named {name}."
                else:
                    sub = await agent.run(session, call.args.get("task", ""), trace)
                    tokens_in += sub.input_tokens
                    tokens_out += sub.output_tokens
                    output = sub.answer
                trace.append(TraceEvent("orchestrator", call.name, call.args))
                messages.append({"role": "tool", "id": call.id, "name": call.name, "content": output})
        return RunResult("Stopped: step limit reached.", trace, tokens_in, tokens_out)


def trace_json(trace: list[TraceEvent]) -> str:
    return json.dumps([e.__dict__ for e in trace], indent=1)
