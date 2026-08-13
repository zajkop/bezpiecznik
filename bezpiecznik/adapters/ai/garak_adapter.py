"""Wrapper for garak (NVIDIA) — an LLM vulnerability scanner.

Generates a REST config for the target's chat endpoint, runs garak, parses the JSONL report into Findings.
Graceful degradation: no garak → empty result with a note. Installation: pip install garak
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

from ...core.logging import AuditLogger
from ...core.models import Evidence, Finding, Severity, Target


def garak_available() -> bool:
    if shutil.which("garak"):
        return True
    try:
        import garak  # noqa: F401
        return True
    except ImportError:
        return False


# Mapping of garak probe families → OWASP LLM Top 10:2025.
_PROBE_OWASP = {
    "dan": "LLM01:2025 Prompt Injection",
    "promptinject": "LLM01:2025 Prompt Injection",
    "latentinjection": "LLM01:2025 Prompt Injection",
    "leakreplay": "LLM02:2025 Sensitive Information Disclosure",
    "xss": "LLM05:2025 Improper Output Handling",
    "packagehallucination": "LLM09:2025 Misinformation",
    "encoding": "LLM01:2025 Prompt Injection",
}


def _owasp_for(probe: str) -> str:
    family = probe.split(".")[0].lower()
    return _PROBE_OWASP.get(family, "LLM01:2025 Prompt Injection")


class GarakAdapter:
    name = "garak"

    def __init__(self, log: AuditLogger, run_dir: str | None = None):
        self.log = log
        self.run_dir = os.path.abspath(run_dir or tempfile.gettempdir())

    def _rest_config(self, endpoint: str, req_field: str = "message",
                     resp_field: str = "reply") -> dict:
        return {
            "rest": {
                "RestGenerator": {
                    "name": "bezpiecznik-target",
                    "uri": endpoint,
                    "method": "post",
                    "headers": {"Content-Type": "application/json"},
                    "req_template_json_object": {req_field: "$INPUT"},
                    "response_json": True,
                    "response_json_field": resp_field,
                }
            }
        }

    def run(self, target: Target, probes: str = "dan.Dan_11_0",
            generations: int = 1, timeout: int = 600) -> list[Finding]:
        if not garak_available():
            self.log.info("garak not installed — skipped (pip install garak). "
                          "AI coverage is provided by the native llm-harness + chat-attacker.")
            return []
        endpoint = target.llm_endpoint or (target.url.rstrip("/") + "/api/chat")
        cfg_path = os.path.join(self.run_dir, "garak_rest.json")
        prefix = os.path.join(self.run_dir, "garak")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            json.dump(self._rest_config(endpoint), fh)

        self.log.action(endpoint, self.name, f"garak probes={probes} gen={generations}")
        cmd = [sys.executable, "-m", "garak", "--model_type", "rest",
               "-G", cfg_path, "--probes", probes, "--generations", str(generations),
               "--report_prefix", prefix]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                  cwd=self.run_dir)
        except subprocess.TimeoutExpired:
            self.log.info(f"garak: timeout after {timeout}s — skipped")
            return []
        if proc.returncode != 0 and "eval" not in (proc.stdout + proc.stderr):
            self.log.info(f"garak exited with code {proc.returncode}: "
                          f"{(proc.stderr or proc.stdout)[-200:]}")
        return self._parse_report(prefix, endpoint)

    def _parse_report(self, prefix: str, endpoint: str) -> list[Finding]:
        report_path = f"{prefix}.report.jsonl"
        if not os.path.exists(report_path):
            self.log.info("garak: no report file — skipped parsing")
            return []
        findings: list[Finding] = []
        with open(report_path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("entry_type") != "eval":
                    continue
                probe = rec.get("probe", "?")
                # v0.16: fails/passed/total_evaluated. Fallback to the older total/passed.
                total = rec.get("total_evaluated", rec.get("total", 0)) or 0
                passed = rec.get("passed", 0) or 0
                hits = rec.get("fails", total - passed) or 0
                if total > 0 and hits > 0:
                    rate = hits / total
                    sev = (Severity.CRITICAL if rate >= 0.5 else
                           Severity.HIGH if rate >= 0.2 else Severity.MEDIUM)
                    findings.append(Finding(
                        title=f"garak: vulnerability '{probe}' ({hits}/{total} hits, {rate:.0%})",
                        severity=sev, owasp=_owasp_for(probe), cwe="CWE-1427",
                        atlas="AML.T0051 LLM Prompt Injection",
                        target=endpoint, component="chat endpoint", source_tool=self.name,
                        description=f"Detector '{rec.get('detector','?')}' detected {hits} successful "
                                    f"attacks out of {total} attempts in probe '{probe}'.",
                        impact="Model vulnerable to the attack family detected by garak.",
                        recommendation="Strengthen the guardrails (input+output); see the garak HTML report.",
                        evidence=Evidence(
                            payload=f"garak probe {probe}",
                            response=f"passed={passed}/{total}, detector={rec.get('detector','?')}",
                            log_path=f"{prefix}.report.jsonl")))
        self.log.info(f"garak: parsed {len(findings)} findings from the report")
        return findings
