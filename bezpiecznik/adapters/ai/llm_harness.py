"""Single-turn harness for chatbot tests — deterministic, no LLM.

Iterates over payloads from payloads/ai/*, sends them to the target, detects canary/prompt leaks.
Fast and cheap. Multi-turn is handled by the subagents (chat_attacker/chat_judge).
"""
from __future__ import annotations

import json
import os

from ...core.logging import AuditLogger
from ...core.models import Evidence, Finding, Message, Severity, Target
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


def _load_json(payloads_dir: str, name: str, limit: int) -> list[str]:
    """Load a big multi-line payload set stored as a JSON array of strings."""
    path = os.path.join(payloads_dir, "ai", name)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    return [p for p in data if isinstance(p, str) and len(p) > 8][:limit]


def _load_triples(payloads_dir: str, name: str, limit: int) -> list[list[str]]:
    """Load prefill-injection triples: [seed_user, assistant_prefill, followup]."""
    path = os.path.join(payloads_dir, "ai", name)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    out: list[list[str]] = []
    for row in data:
        if (isinstance(row, list) and len(row) == 3
                and all(isinstance(x, str) for x in row)):
            out.append(row)
        if len(out) >= limit:
            break
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

        # --- big real-world jailbreak set (hundreds of in-the-wild prompts, LLM01) ---
        # each is a live model call (~seconds); depth is capped by BEZ_AI_PAYLOAD_LIMIT.
        ai_limit = int(os.environ.get("BEZ_AI_PAYLOAD_LIMIT", "120"))
        big = _load_json(self.payloads_dir, "jailbreak-fuzz.json", ai_limit)
        if big:
            self.log.info(f"Jailbreak fuzz: trying {len(big)} in-the-wild prompts "
                          f"(raise BEZ_AI_PAYLOAD_LIMIT for more)")
            for payload in big:
                tested += 1
                reply = self.chat.send(payload)
                if det.canary_leaked(reply, self.known_canary, sent=payload) or \
                        det.system_prompt_leaked(reply):
                    findings.append(self._finding(
                        "Jailbreak (in-the-wild prompt) leaked protected content",
                        Severity.CRITICAL, "LLM01:2025 Prompt Injection", "CWE-1427",
                        payload, reply, target))
                    self.log.finding("Jailbreak leak (fuzz set)", "critical")
                    break
                if det.is_refusal(reply):
                    refusals += 1

        # --- big system-prompt-extraction set (LLM07) + encoding-obfuscation set (LLM01) ---
        for setname, ftitle, fowasp, fcwe in [
            ("system-prompt-fuzz.json", "System prompt leak (extraction set)",
             "LLM07:2025 System Prompt Leakage", "CWE-200"),
            ("encoding-fuzz.json", "Guardrail bypassed via encoded/obfuscated payload",
             "LLM01:2025 Prompt Injection", "CWE-1427"),
        ]:
            fuzz = _load_json(self.payloads_dir, setname, ai_limit)
            if not fuzz:
                continue
            self.log.info(f"{setname}: trying {len(fuzz)} payloads")
            for payload in fuzz:
                tested += 1
                reply = self.chat.send(payload)
                if det.canary_leaked(reply, self.known_canary, sent=payload) or \
                        det.system_prompt_leaked(reply):
                    findings.append(self._finding(ftitle, Severity.CRITICAL, fowasp, fcwe,
                                                  payload, reply, target))
                    self.log.finding(ftitle, "critical")
                    break
                if det.is_refusal(reply):
                    refusals += 1

        # --- output-handling (LLM05): model returns a raw dangerous payload ---
        # curated high-signal set first, then the big generated set (dangerous payload × phrasing).
        for payload in _load(self.payloads_dir, "output-handling.txt") + \
                _load_json(self.payloads_dir, "output-handling-fuzz.json", ai_limit):
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
        # curated set + big generated set (instruction-in-data wrapper × injected goal).
        for payload in _load(self.payloads_dir, "indirect-injection.txt") + \
                _load_json(self.payloads_dir, "indirect-fuzz.json", ai_limit):
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

        # --- sensitive-information disclosure (LLM02): broad exfiltration phrasings ---
        # curated `data-exfiltration.txt` already ran in the suites loop above; this adds the
        # big generated set (PII / secret / cross-tenant / training-data leak phrasings).
        for payload in _load_json(self.payloads_dir, "exfil-fuzz.json", ai_limit):
            tested += 1
            reply = self.chat.send(payload)
            self.log.action(target.llm_endpoint or target.url, self.name, f"exfil probe: {payload[:50]}")
            if det.canary_leaked(reply, self.known_canary, sent=payload) or det.system_prompt_leaked(reply):
                findings.append(self._finding(
                    "Sensitive Information Disclosure — model leaked protected data on request",
                    Severity.HIGH, "LLM02:2025 Sensitive Information Disclosure", "CWE-200",
                    payload, reply, target))
                self.log.finding("Sensitive information disclosure", "high")
                break
            if det.is_refusal(reply):
                refusals += 1

        # --- assistant-prefill / "sockpuppeting" (LLM01): a forged assistant turn in the
        # conversation history makes the model believe it already agreed to comply, so it
        # continues from the planted (compliant) text. Distinct from single/multi-turn: the
        # bypass lives in the history the client controls, not in the current user message.
        for seed_user, assistant_prefill, followup in \
                _load_triples(self.payloads_dir, "prefill-injection.json", ai_limit):
            tested += 1
            history = [
                Message(role="user", content=seed_user),
                Message(role="assistant", content=assistant_prefill),
            ]
            reply = self.chat.send(followup, history)
            self.log.action(target.llm_endpoint or target.url, self.name,
                            f"prefill probe: {assistant_prefill[:50]}")
            # Exclude the forged assistant text from leak matching: only NEW content counts.
            sent = seed_user + "\n" + assistant_prefill + "\n" + followup
            if det.canary_leaked(reply, self.known_canary, sent=sent) or \
                    det.system_prompt_leaked(reply) or det.obeyed_injection(reply):
                findings.append(self._finding(
                    "Assistant-prefill (sockpuppeting) bypass — a forged assistant turn in the "
                    "history led the model to disclose protected content in its reply",
                    Severity.HIGH, "LLM01:2025 Prompt Injection", "CWE-1427",
                    sent, reply, target))
                self.log.finding("Assistant-prefill bypass", "high")
                break
            if det.is_refusal(reply):
                refusals += 1

        # --- policy-puppetry (LLM01): adversarial instructions disguised as a policy/config
        # file (XML/JSON/YAML) so the model treats them as authoritative system configuration
        # rather than user content, bypassing alignment. Distinct from plain jailbreaks: the
        # bypass rides on structural config-mimicry (HiddenLayer universal-bypass technique).
        for payload in _load_json(self.payloads_dir, "policy-puppetry.json", ai_limit):
            tested += 1
            reply = self.chat.send(payload)
            self.log.action(target.llm_endpoint or target.url, self.name,
                            f"policy-puppetry probe: {payload[:50]}")
            if det.canary_leaked(reply, self.known_canary, sent=payload) or \
                    det.system_prompt_leaked(reply) or det.obeyed_injection(reply):
                findings.append(self._finding(
                    "Policy-puppetry bypass — adversarial instructions disguised as a "
                    "policy/config file were treated as authoritative and led the model to "
                    "disclose protected content or execute the injected instruction",
                    Severity.HIGH, "LLM01:2025 Prompt Injection", "CWE-1427",
                    payload, reply, target))
                self.log.finding("Policy-puppetry bypass", "high")
                break
            if det.is_refusal(reply):
                refusals += 1

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
