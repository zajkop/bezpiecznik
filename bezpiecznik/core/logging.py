"""Run audit and logging.

Every active action is logged (what/when/which payload) — for reproducibility and accountability.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Optional


class AuditLogger:
    def __init__(self, workdir: str, run_id: Optional[str] = None, echo: bool = True):
        self.run_id = run_id or time.strftime("run-%Y%m%d-%H%M%S")
        self.dir = os.path.join(workdir, self.run_id)
        os.makedirs(self.dir, exist_ok=True)
        self.path = os.path.join(self.dir, "audit.jsonl")
        self.echo = echo

    def event(self, kind: str, **fields: Any) -> None:
        rec = {"ts": round(time.time(), 3), "kind": kind, **fields}
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if self.echo:
            self._print(kind, fields)

    def _print(self, kind: str, fields: dict[str, Any]) -> None:
        colors = {"action": "\033[36m", "finding": "\033[33m", "blocked": "\033[31m",
                  "info": "\033[90m", "error": "\033[31m"}
        c = colors.get(kind, "")
        r = "\033[0m" if c else ""
        summary = fields.get("summary") or fields.get("title") or fields.get("target") or ""
        print(f"{c}[{kind}]{r} {summary}", file=sys.stderr)

    def action(self, target: str, tool: str, summary: str, **kw: Any) -> None:
        self.event("action", target=target, tool=tool, summary=summary, **kw)

    def finding(self, title: str, severity: str, **kw: Any) -> None:
        self.event("finding", title=title, severity=severity, summary=f"[{severity}] {title}", **kw)

    def blocked(self, target: str, reason: str) -> None:
        self.event("blocked", target=target, summary=f"BLOCKED {target}: {reason}", reason=reason)

    def info(self, summary: str, **kw: Any) -> None:
        self.event("info", summary=summary, **kw)

    def error(self, summary: str, **kw: Any) -> None:
        self.event("error", summary=summary, **kw)
