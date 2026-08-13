"""Configuration for "Bezpiecznik".

Secrets NEVER go into the repo — we read them from ENV. Default values chosen for
the operator's local setup (Ollama + qwen3.5:9b).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class LLMConfig:
    """LLM provider settings. Local Ollama by default."""

    provider: str = _env("BEZ_LLM_PROVIDER", "ollama")  # "ollama" | "openai"
    host: str = _env("BEZ_LLM_HOST", "http://localhost:11434")
    model: str = _env("BEZ_LLM_MODEL", "qwen3.5:9b")
    # model "thinking" mode — sometimes helpful for the judge, disable for fast turns
    think: bool = _env_bool("BEZ_LLM_THINK", False)
    temperature: float = float(_env("BEZ_LLM_TEMP", "0.7"))
    timeout_s: int = int(_env("BEZ_LLM_TIMEOUT", "120"))
    # for API providers (optional):
    api_key_env: str = "BEZ_LLM_API_KEY"
    api_base: str = _env("BEZ_LLM_API_BASE", "")

    @property
    def api_key(self) -> str | None:
        return os.environ.get(self.api_key_env)


@dataclass
class HTTPConfig:
    """Settings for outbound traffic to targets."""

    # Test-traffic tag — so the client's SOC can tell us apart from a real attack.
    user_agent: str = _env("BEZ_UA", "Bezpiecznik-Pentest/0.1 (authorized-test)")
    # gentle pace by default — don't accidentally take the target down
    rate_limit_rps: float = float(_env("BEZ_RPS", "2"))
    timeout_s: int = int(_env("BEZ_HTTP_TIMEOUT", "30"))
    verify_tls: bool = _env_bool("BEZ_VERIFY_TLS", True)
    # OOB endpoint (Burp Collaborator / interactsh) for confirming blind vulnerabilities
    oob_domain: str = _env("BEZ_OOB", "")


@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    http: HTTPConfig = field(default_factory=HTTPConfig)
    # directory for run artifacts (logs, evidence, reports)
    workdir: str = _env("BEZ_WORKDIR", "./runs")
    # path to the payload library
    payloads_dir: str = _env("BEZ_PAYLOADS", os.path.join(os.path.dirname(__file__), "..", "..", "payloads"))


def load_config() -> Config:
    return Config()
