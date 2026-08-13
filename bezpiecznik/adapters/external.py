"""Helper for running external tools with graceful degradation.

If the binary is not installed → we return a 'skipped' status instead of crashing the run.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class ToolResult:
    tool: str
    available: bool
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    skipped_reason: str = ""

    @property
    def ok(self) -> bool:
        return self.available and self.returncode == 0


def which(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_tool(tool: str, args: list[str], timeout: int = 300, input_text: str | None = None) -> ToolResult:
    if not which(tool):
        return ToolResult(tool=tool, available=False,
                          skipped_reason=f"'{tool}' is not installed (skipped)")
    try:
        proc = subprocess.run(
            [tool, *args], capture_output=True, text=True, timeout=timeout, input=input_text,
        )
        return ToolResult(tool=tool, available=True, returncode=proc.returncode,
                          stdout=proc.stdout, stderr=proc.stderr)
    except subprocess.TimeoutExpired:
        return ToolResult(tool=tool, available=True, returncode=124,
                          stderr=f"timeout after {timeout}s")
    except Exception as e:  # noqa: BLE001
        return ToolResult(tool=tool, available=True, returncode=-1, stderr=str(e))
