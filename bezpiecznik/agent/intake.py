"""Initial intake: collects target + type + scope + consent → Scope/Target.

Interactive mode (input()) and programmatic mode (from_dict) for automated/demo runs.
"""
from __future__ import annotations

from ..core.models import Scope, Target, TargetType


def target_from_dict(d: dict) -> Target:
    return Target(
        url=d["url"],
        type=TargetType(d.get("type", "web-app")),
        llm_endpoint=d.get("llm_endpoint"),
        auth_header=d.get("auth_header"),
        notes=d.get("notes", ""),
    )


def scope_from_dict(d: dict) -> Scope:
    return Scope(
        engagement=d.get("engagement", "unnamed"),
        in_scope=d.get("in_scope", []),
        out_of_scope=d.get("out_of_scope", []),
        authorized=bool(d.get("authorized", False)),
        allow_destructive=bool(d.get("allow_destructive", False)),
        window=d.get("window", ""),
        contact=d.get("contact", ""),
    )


def interactive_intake() -> tuple[Target, Scope]:
    print("=== Bezpiecznik — initial intake ===")
    url = input("Target URL (e.g. http://127.0.0.1:8000): ").strip()
    t = input("Type [web-app / ai-assistant / both]: ").strip() or "web-app"
    llm_ep = None
    if t in ("ai-assistant", "both"):
        llm_ep = input("Chatbot endpoint (e.g. http://127.0.0.1:8000/api/chat): ").strip() or None
    authorized = input("Do you have WRITTEN consent to test this target? [y/N]: ").strip().lower() == "y"
    destructive = False
    if authorized:
        destructive = input("Allow DESTRUCTIVE tests (DoS/flooding)? [y/N]: ").strip().lower() == "y"

    from urllib.parse import urlparse
    host = urlparse(url).hostname or url
    target = Target(url=url, type=TargetType(t), llm_endpoint=llm_ep)
    scope = Scope(engagement="interactive", in_scope=[host], authorized=authorized,
                  allow_destructive=destructive)
    if not authorized:
        print("⚠️  No confirmed consent — only passive actions are allowed.")
    return target, scope
