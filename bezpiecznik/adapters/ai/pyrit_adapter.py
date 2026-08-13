"""Wrapper for PyRIT (Microsoft) — orchestration of multi-turn attacks (Crescendo/PAIR).

Graceful degradation: no pyrit → empty result with a note. The native equivalent of this
function is subagents/chat_attacker.py (multi-turn on a local Qwen) — works without PyRIT.

Installation: pip install pyrit
Note: PyRIT is a heavy SDK; this wrapper configures a local Ollama as attacker+target.
"""
from __future__ import annotations

from ...core.config import LLMConfig
from ...core.logging import AuditLogger
from ...core.models import Evidence, Finding, Severity, Target


def pyrit_available() -> bool:
    try:
        import pyrit  # noqa: F401
        return True
    except ImportError:
        return False


class PyritAdapter:
    name = "pyrit"

    def __init__(self, log: AuditLogger, llm_cfg: LLMConfig):
        self.log = log
        self.llm_cfg = llm_cfg

    def run(self, target: Target, objective: str, max_turns: int = 6) -> list[Finding]:
        if not pyrit_available():
            self.log.info("PyRIT not installed — skipped (pip install pyrit). "
                          "Multi-turn is covered by the native chat-attacker (Crescendo/PAIR on Qwen).")
            return []
        try:
            return self._run_crescendo(target, objective, max_turns)
        except Exception as e:  # noqa: BLE001
            self.log.info(f"PyRIT: orchestration error ({e}) — falling back to the native chat-attacker")
            return []

    def _run_crescendo(self, target: Target, objective: str, max_turns: int) -> list[Finding]:
        """Integration with PyRIT: local Ollama (OpenAI-compatible) as attacker/scorer,
        REST/HTTP target as the objective. Requires pyrit to be installed; the API is versioned,
        which is why the whole thing is wrapped in try/except by run()."""
        from pyrit.orchestrator import CrescendoOrchestrator
        from pyrit.prompt_target import OpenAIChatTarget

        endpoint = target.llm_endpoint or (target.url.rstrip("/") + "/api/chat")
        # Ollama exposes an OpenAI-compatible API under /v1 — use it for attacker/scorer.
        ollama_openai = self.llm_cfg.host.rstrip("/") + "/v1"
        adversarial = OpenAIChatTarget(endpoint=ollama_openai, api_key="ollama",
                                       model_name=self.llm_cfg.model)
        objective_target = OpenAIChatTarget(endpoint=endpoint, api_key="none",
                                            model_name="target-chatbot")
        orchestrator = CrescendoOrchestrator(
            objective_target=objective_target,
            adversarial_chat=adversarial,
            scoring_target=adversarial,
            max_turns=max_turns,
        )
        self.log.action(endpoint, self.name, f"PyRIT Crescendo: {objective[:60]}")
        result = orchestrator.run_attack(objective=objective)  # API depends on the PyRIT version
        achieved = bool(getattr(result, "achieved_objective", False))
        if achieved:
            return [Finding(
                title=f"PyRIT Crescendo achieved the objective: {objective[:80]}",
                severity=Severity.CRITICAL, owasp="LLM01:2025 Prompt Injection", cwe="CWE-1427",
                atlas="AML.T0051 LLM Prompt Injection",
                target=endpoint, component="chat endpoint (PyRIT multi-turn)", source_tool=self.name,
                description=f"The Crescendo orchestrator (PyRIT) broke the objective after multi-turn escalation.",
                impact="Guardrail bypassed by an adaptive conversational attack.",
                recommendation="Conversation-context-aware guardrails; multi-turn monitoring.",
                evidence=Evidence(payload=objective, response=str(result)[:400]))]
        return []
