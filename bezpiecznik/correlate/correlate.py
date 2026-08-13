"""Finding correlation: deduplication + CVSS 4.0 scoring (simplified) + prioritization."""
from __future__ import annotations

from ..core.models import Finding, Severity

# Simplified severity → approximate CVSS 4.0 mapping (when a tool doesn't provide a vector).
_SEV_CVSS = {
    Severity.CRITICAL: 9.3,
    Severity.HIGH: 8.1,
    Severity.MEDIUM: 5.8,
    Severity.LOW: 3.4,
    Severity.INFO: 0.0,
}
_SEV_ORDER = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2,
              Severity.LOW: 1, Severity.INFO: 0}


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.component or f.target, f.cwe or f.title.split()[0], f.owasp)
        cur = seen.get(key)
        if cur is None or _SEV_ORDER[f.severity] > _SEV_ORDER[cur.severity]:
            seen[key] = f
    return list(seen.values())


def score(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        if f.cvss_v4 is None:
            f.cvss_v4 = _SEV_CVSS[f.severity]
    return findings


def correlate(findings: list[Finding]) -> list[Finding]:
    out = score(dedupe(findings))
    out.sort(key=lambda f: (_SEV_ORDER[f.severity], f.cvss_v4 or 0), reverse=True)
    return out
