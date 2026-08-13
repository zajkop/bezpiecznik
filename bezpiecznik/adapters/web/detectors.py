"""Success detectors for web tests — deterministic (no LLM)."""
from __future__ import annotations

import re

# SQL error signatures (error-based SQLi) — multiple engines.
SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlite3?\.(OperationalError|Warning)",
    r"SQLite/JDBCDriver",
    r"SQL error:",
    r"SQLITE_ERROR",
    r"unrecognized token",
    r"no such column",
    r"incomplete input",
    r"near \".*\": syntax error",
    r"near .{0,18}: syntax error",   # tolerates HTML-encoded quotes (&quot;/&#39;)
    r"pg_query\(\)",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wmysqli?_",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark",
]

# Markers of successful command injection (output of typical commands).
CMD_MARKERS = [
    r"uid=\d+\(.*?\)\s+gid=\d+",       # id
    r"root:.*?:0:0:",                   # cat /etc/passwd
    r"\bLinux\b.*\d+\.\d+\.\d+",       # uname -a
]

# Path traversal markers (reading known files).
TRAVERSAL_MARKERS = [
    r"root:.*?:0:0:",                   # /etc/passwd
    r"\[extensions\]",                  # win.ini
    r"for 16-bit app support",          # win.ini
]


def sql_error(text: str) -> str | None:
    for pat in SQL_ERRORS:
        if re.search(pat, text, re.IGNORECASE):
            return pat
    return None


def cmd_injected(text: str) -> str | None:
    for pat in CMD_MARKERS:
        if re.search(pat, text):
            return pat
    return None


def traversal_ok(text: str) -> str | None:
    for pat in TRAVERSAL_MARKERS:
        if re.search(pat, text, re.IGNORECASE):
            return pat
    return None


def reflected(text: str, payload: str) -> bool:
    """XSS reflection: payload appears in the response UN-escaped."""
    if payload in text:
        # if the escaped variant is present too but the raw one occurs — reflection exists.
        return True
    return False


def escaped_variant(payload: str) -> str:
    return (payload.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))
