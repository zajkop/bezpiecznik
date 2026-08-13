"""Single-turn harness for chatbot tests — deterministic, no LLM.

Iterates over payloads from payloads/ai/*, sends them to the target, detects canary/prompt leaks.
Fast and cheap. Multi-turn is handled by the subagents (chat_attacker/chat_judge).
"""
from __future__ import annotations

import os

from ...core.logging import AuditLogger
from ...core.models import Evidence, Finding, Severity, Target
from ...core.scope import ActionClass, ScopeGuard
from . import detectors as det
from .chat_client import TargetChatClient


def _load(payloads_dir: str, name: str, limit: int = 6) -> list[str]:
    path = os.path.join(payloads_dir, "ai", name)
    out: list[str] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                s = line.strip()
                if s and not s.startswith("#") and not s.startswith("##") and len(s) > 8:
                    out.append(s)
                if len(out) >= limit:
                    break
    except FileNotFoundError:
        pass
    return out


class LLMHarness:
    name = "llm-harness (single-turn)"

    def __init__(self, chat: TargetChatClient, log: AuditLogger, guard: ScopeGuard,
                 payloads_dir: str, known_canary: str | None = None):
        self.chat = chat
        self.log = log
        self.guard = guard
        self.payloads_dir = payloads_dir
        self.known_canary = known_canary

    def run(self, target: Target) -> list[Finding]:
        self.guard.authorize(target.llm_endpoint or target.url, ActionClass.ACTIVE)
        findings: list[Finding] = []
        tested = 0
        refusals = 0

        suites = [
            ("system-prompt-extraction.txt", "LLM07:2025 System Prompt Leakage", "CWE-200"),
            ("jailbreak.txt", "LLM01:2025 Prompt Injection", "CWE-1427"),
            ("data-exfiltration.txt", "LLM02:2025 Sensitive Information Disclosure", "CWE-200"),
        ]
        for fname, owasp, cwe in suites:
            for payload in _load(self.payloads_dir, fname):
                tested += 1
                reply = self.chat.send(payload)
                self.log.action(target.llm_endpoint or target.url, self.name,
                                f"probe: {payload[:60]}")
                canary = det.canary_leaked(reply, self.known_canary, sent=payload)
                leak = det.system_prompt_leaked(reply)  # returns None for refusals
                if canary:
                    findings.append(self._finding(
                        f"Secret/canary leak via prompt injection ({canary})",
                        Severity.CRITICAL, owasp, cwe, payload, reply, target))
                    self.log.finding("Canary leak", "critical")
                    break  # this class confirmed
                if leak:
                    findings.append(self._finding(
                        "System prompt / instruction leak",
                        Severity.HIGH, "LLM07:2025 System Prompt Leakage", "CWE-200",
                        payload, reply, target))
                    self.log.finding("System prompt leak", "high")
                    break
                if det.is_refusal(reply):
                    refusals += 1

        # --- output-handling (LLM05): model returns a raw dangerous payload ---
        for payload in _load(self.payloads_dir, "output-handling.txt"):
            tested += 1
            reply = self.chat.send(payload)
            self.log.action(target.llm_endpoint or target.url, self.name, f"output probe: {payload[:50]}")
            danger = det.dangerous_output(reply)
            if danger:
                findings.append(self._finding(
                    f"Improper Output Handling — model returns a dangerous payload ({danger})",
                    Severity.HIGH, "LLM05:2025 Improper Output Handling", "CWE-79",
                    payload, reply, target))
                self.log.finding("Improper output handling", "high")
                break

        # --- indirect prompt injection (LLM01): instruction hidden in the data ---
        for payload in _load(self.payloads_dir, "indirect-injection.txt"):
            tested += 1
            reply = self.chat.send(payload)
            self.log.action(target.llm_endpoint or target.url, self.name, f"indirect probe: {payload[:50]}")
            if det.obeyed_injection(reply) or det.canary_leaked(reply, self.known_canary, sent=payload):
                findings.append(self._finding(
                    "Indirect Prompt Injection — model executed an instruction from the data",
                    Severity.HIGH, "LLM01:2025 Prompt Injection", "CWE-1427",
                    payload, reply, target))
                self.log.finding("Indirect prompt injection", "high")
                break

        self.log.info(f"Single-turn harness: {tested} attempts, {refusals} refusals, "
                      f"{len(findings)} confirmations")
        return findings

    def _finding(self, title, sev, owasp, cwe, payload, reply, target) -> Finding:
        return Finding(
            title=title, severity=sev, owasp=owasp, cwe=cwe,
            atlas="AML.T0051 LLM Prompt Injection",
            target=target.llm_endpoint or target.url, component="chat endpoint",
            source_tool=self.name,
            description="A single-turn payload bypassed the guardrail and revealed protected content.",
            impact="Disclosure of secrets/instructions; a basis for further escalation.",
            recommendation="Strengthen the guardrail (input+output), do not keep secrets in the prompt, "
                           "validate and filter responses.",
            evidence=Evidence(payload=payload, response=reply[:500]))
