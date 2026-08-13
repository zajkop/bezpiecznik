"""CLI entrypoint.

  python -m bezpiecznik          → AUTO mode (intake → full pipeline → report)
  python -m bezpiecznik chat     → CONVERSATIONAL mode (talk with the agent, tool-calling on Qwen)
"""
from __future__ import annotations

import sys

from .cli import interactive_cli
from .intake import interactive_intake
from .orchestrator import Orchestrator
from .tools import BezpiecznikSession


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if argv and argv[0] == "chat":
        session = BezpiecznikSession()
        try:
            interactive_cli(session)
        finally:
            session.close()
        return 0

    print("Bezpiecznik — authorized pentesting agent (web + AI/LLM)\n")
    target, scope = interactive_intake()
    orch = Orchestrator()
    try:
        report, paths = orch.auto_run(target, scope)
    finally:
        orch.close()
    print(f"\nFindings: {len(report.findings)} | MD report: {paths['md']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
