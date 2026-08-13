"""Shared data model for all of "Bezpiecznik".

One source of truth: adapters and subagents produce `Finding`, and the report consumes them.
"""
from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TargetType(str, Enum):
    WEB_APP = "web-app"
    AI_ASSISTANT = "ai-assistant"
    BOTH = "both"


class Target(BaseModel):
    """A single test target (host/URL/AI endpoint)."""

    url: str
    type: TargetType
    # Chatbot endpoint (if ai-assistant) — for the AI layer.
    llm_endpoint: Optional[str] = None
    auth_header: Optional[str] = None  # e.g. "Authorization: Bearer ..."
    notes: str = ""


class Scope(BaseModel):
    """Engagement scope + authorization status. The gate for active actions."""

    engagement: str = "unnamed"
    in_scope: list[str] = Field(default_factory=list)   # allowed domains/URLs/IPs/endpoints
    out_of_scope: list[str] = Field(default_factory=list)
    authorized: bool = False                            # written consent confirmed?
    allow_destructive: bool = False                     # DoS/flooding/DROP etc.
    window: str = ""                                    # testing time window
    contact: str = ""                                   # escalation
    created_at: float = Field(default_factory=time.time)


class Evidence(BaseModel):
    request: Optional[str] = None
    response: Optional[str] = None
    payload: Optional[str] = None
    log_path: Optional[str] = None


class Finding(BaseModel):
    """A single finding — shared across web and AI."""

    id: str = Field(default_factory=lambda: _uid("FND"))
    title: str
    severity: Severity = Severity.INFO
    # Standards mappings (research/02):
    owasp: Optional[str] = None       # e.g. "A05:2025 Injection" / "LLM01:2025 Prompt Injection"
    cwe: Optional[str] = None         # e.g. "CWE-89"
    atlas: Optional[str] = None       # e.g. "AML.T0051"
    cvss_v4: Optional[float] = None
    cvss_vector: Optional[str] = None

    target: Optional[str] = None
    component: Optional[str] = None   # endpoint / tool / layer
    source_tool: str = "manual"       # who reported it (garak/sqlmap/chat_attacker/...)

    description: str = ""
    impact: str = ""
    recommendation: str = ""
    reproduction: str = ""      # step-by-step how to REPRODUCE (human-readable, visible PoC)
    evidence: Evidence = Field(default_factory=Evidence)
    tags: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)


# ---- Conversational layer (multi-turn AI tests) ----

Role = Literal["system", "user", "assistant", "tool"]


class Message(BaseModel):
    role: Role
    content: str
    # optional tool calls (tool-calling)
    tool_calls: Optional[list[dict[str, Any]]] = None
    name: Optional[str] = None  # tool name for role="tool"


class JudgeVerdict(str, Enum):
    SUCCESS = "success"     # target broke policy / leaked
    PROGRESS = "progress"   # partial progress, worth continuing
    REFUSAL = "refusal"     # hard refusal
    UNCLEAR = "unclear"


class Judgement(BaseModel):
    verdict: JudgeVerdict
    confidence: float = 0.0
    rationale: str = ""


class Conversation(BaseModel):
    """Conversation history with the target chatbot (for attacker/judge)."""

    id: str = Field(default_factory=lambda: _uid("CONV"))
    goal: str = ""                       # attack goal, e.g. "extract the canary"
    messages: list[Message] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    succeeded: bool = False

    def add(self, role: Role, content: str, **kw: Any) -> None:
        self.messages.append(Message(role=role, content=content, **kw))


class Report(BaseModel):
    engagement: str
    target: Target
    scope: Scope
    findings: list[Finding] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out
