"""LLM provider abstraction.

Shared interface `LLM.chat(messages, tools=?)` with backends:
  - Ollama (locally, qwen3.5:9b by default) — endpoint /api/chat
  - OpenAI-compatible (optional, for a stronger orchestrator)

Used by the "Bezpiecznik" orchestrator and the attacker/judge subagents.
Dependency: httpx.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

import httpx

from .config import LLMConfig


@dataclass
class LLMReply:
    content: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def has_tool_calls(self) -> bool:
        return bool(self.tool_calls)


def _to_dicts(messages: list[Any]) -> list[dict[str, Any]]:
    """Accepts a pydantic Message or plain dicts."""
    out: list[dict[str, Any]] = []
    for m in messages:
        if hasattr(m, "model_dump"):
            d = m.model_dump(exclude_none=True)
        else:
            d = dict(m)
        # Ollama wants the minimal shape {role, content, [tool_calls], [name]}
        msg = {"role": d["role"], "content": d.get("content", "")}
        if d.get("tool_calls"):
            msg["tool_calls"] = d["tool_calls"]
        if d.get("name"):
            msg["name"] = d["name"]
        out.append(msg)
    return out


class LLM:
    """LLM client. A single reusable object (holds an httpx connection)."""

    def __init__(self, cfg: Optional[LLMConfig] = None):
        self.cfg = cfg or LLMConfig()
        self._client = httpx.Client(timeout=self.cfg.timeout_s)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "LLM":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # --- Public API ---

    def chat(
        self,
        messages: list[Any],
        tools: Optional[list[dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        think: Optional[bool] = None,
    ) -> LLMReply:
        if self.cfg.provider == "ollama":
            return self._chat_ollama(messages, tools, temperature, think)
        if self.cfg.provider == "openai":
            return self._chat_openai(messages, tools, temperature)
        raise ValueError(f"Unknown LLM provider: {self.cfg.provider}")

    def complete(self, prompt: str, **kw: Any) -> str:
        """Convenience: a single user prompt → text."""
        return self.chat([{"role": "user", "content": prompt}], **kw).content

    def chat_stream(
        self,
        messages: list[Any],
        tools: Optional[list[dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        think: Optional[bool] = None,
    ) -> Iterator[str]:
        """Streams the response token-by-token (yields text fragments).
        Returns (via StopIteration.value) the full LLMReply with content + tool_calls.
        For provider != ollama: falls back to a single chunk."""
        if self.cfg.provider != "ollama":
            reply = self.chat(messages, tools, temperature, think)
            if reply.content:
                yield reply.content
            return reply
        payload: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": _to_dicts(messages),
            "stream": True,
            "think": self.cfg.think if think is None else think,
            "options": {"temperature": self.cfg.temperature if temperature is None else temperature},
        }
        if tools:
            payload["tools"] = tools
        content_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        with self._client.stream("POST", f"{self.cfg.host}/api/chat", json=payload) as r:
            r.raise_for_status()
            for line in r.iter_lines():
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                msg = data.get("message", {}) or {}
                chunk = msg.get("content", "") or ""
                if chunk:
                    content_parts.append(chunk)
                    yield chunk
                if msg.get("tool_calls"):
                    tool_calls = msg["tool_calls"]
                if data.get("done"):
                    break
        return LLMReply(content="".join(content_parts), tool_calls=tool_calls, raw={})

    # --- Backends ---

    def _chat_ollama(
        self,
        messages: list[Any],
        tools: Optional[list[dict[str, Any]]],
        temperature: Optional[float],
        think: Optional[bool],
    ) -> LLMReply:
        payload: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": _to_dicts(messages),
            "stream": False,
            "think": self.cfg.think if think is None else think,
            "options": {
                "temperature": self.cfg.temperature if temperature is None else temperature,
            },
        }
        if tools:
            payload["tools"] = tools
        r = self._client.post(f"{self.cfg.host}/api/chat", json=payload)
        r.raise_for_status()
        data = r.json()
        msg = data.get("message", {}) or {}
        return LLMReply(
            content=msg.get("content", "") or "",
            tool_calls=msg.get("tool_calls", []) or [],
            raw=data,
        )

    def _chat_openai(
        self,
        messages: list[Any],
        tools: Optional[list[dict[str, Any]]],
        temperature: Optional[float],
    ) -> LLMReply:
        base = self.cfg.api_base or "https://api.openai.com/v1"
        headers = {"Authorization": f"Bearer {self.cfg.api_key or ''}"}
        payload: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": _to_dicts(messages),
            "temperature": self.cfg.temperature if temperature is None else temperature,
        }
        if tools:
            payload["tools"] = tools
        r = self._client.post(f"{base}/chat/completions", json=payload, headers=headers)
        r.raise_for_status()
        data = r.json()
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {}) or {}
        return LLMReply(
            content=msg.get("content") or "",
            tool_calls=msg.get("tool_calls", []) or [],
            raw=data,
        )

    def health(self) -> bool:
        """Quick provider availability check."""
        try:
            if self.cfg.provider == "ollama":
                r = self._client.get(f"{self.cfg.host}/api/tags")
                return r.status_code == 200
            return bool(self.cfg.api_key)
        except httpx.HTTPError:
            return False
