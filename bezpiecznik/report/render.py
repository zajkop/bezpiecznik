"""Report generator: JSON (machine-readable) + Markdown (human-readable). Template from research/02."""
from __future__ import annotations

import json
import os
import time

from ..core.models import Report, Severity

_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def write_json(report: Report, path: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(report.model_dump_json(indent=2))
    return path


def render_markdown(report: Report) -> str:
    counts = report.by_severity()
    lines: list[str] = []
    lines.append(f"# Security test report — {report.engagement}")
    lines.append("")
    lines.append(f"- **Target:** {report.target.url} ({report.target.type.value})")
    lines.append(f"- **Date:** {time.strftime('%Y-%m-%d %H:%M', time.localtime(report.generated_at))}")
    lines.append(f"- **Authorization:** {'confirmed' if report.scope.authorized else 'NONE'}"
                 f" | destructive: {'yes' if report.scope.allow_destructive else 'no'}")
    lines.append("")

    # Executive summary
    total = len(report.findings)
    crit = counts["critical"] + counts["high"]
    lines.append("## Executive summary")
    lines.append("")
    lines.append(f"Detected **{total}** findings, including **{crit}** at high/critical risk. "
                 f"Immediate response recommended for the 🔴/🟠 items below.")
    lines.append("")

    # Severity table
    lines.append("## Severity breakdown")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for s in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {_SEV_EMOJI[s]} {s} | {counts[s]} |")
    lines.append("")

    # Summary table
    lines.append("## Findings (summary)")
    lines.append("")
    lines.append("| # | Severity | Title | OWASP | Component |")
    lines.append("|---|---|---|---|---|")
    for i, f in enumerate(report.findings, 1):
        lines.append(f"| {i} | {_SEV_EMOJI[f.severity.value]} {f.severity.value} | {f.title} "
                     f"| {f.owasp or '-'} | `{f.component or '-'}` |")
    lines.append("")

    # Details
    lines.append("## Technical details")
    lines.append("")
    for i, f in enumerate(report.findings, 1):
        lines.append(f"### {i}. {_SEV_EMOJI[f.severity.value]} [{f.severity.value.upper()}] {f.title}")
        lines.append("")
        lines.append(f"- **ID:** {f.id}")
        meta = " / ".join(x for x in [f.owasp, f.cwe, f.atlas] if x)
        lines.append(f"- **Mapping:** {meta or '-'}")
        lines.append(f"- **CVSS 4.0 (approx.):** {f.cvss_v4}")
        lines.append(f"- **Component:** `{f.component or '-'}`  |  **Source:** {f.source_tool}")
        lines.append(f"- **Target:** {f.target or '-'}")
        lines.append("")
        if f.description:
            lines.append(f"**Description:** {f.description}")
            lines.append("")
        if f.impact:
            lines.append(f"**Impact:** {f.impact}")
            lines.append("")
        if f.evidence and (f.evidence.payload or f.evidence.request or f.evidence.response):
            lines.append("**Evidence (PoC):**")
            lines.append("```")
            if f.evidence.payload:
                lines.append(f"payload : {f.evidence.payload}")
            if f.evidence.request:
                lines.append(f"request : {f.evidence.request}")
            if f.evidence.response:
                resp = f.evidence.response.replace("\n", " ")[:300]
                lines.append(f"response: {resp}")
            lines.append("```")
            lines.append("")
        if f.reproduction:
            lines.append("**How to reproduce:**")
            lines.append("")
            lines.append("```")
            lines.append(f.reproduction)
            lines.append("```")
            lines.append("")
        if f.recommendation:
            lines.append(f"**Recommendation:** {f.recommendation}")
            lines.append("")
    return "\n".join(lines)


def write_markdown(report: Report, path: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(report))
    return path


_SEV_HEX = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
            "low": "#3e63dd", "info": "#8b8d98"}


def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_html(report: Report) -> str:
    counts = report.by_severity()
    gen = time.strftime("%Y-%m-%d %H:%M", time.localtime(report.generated_at))
    chips = "".join(
        f'<span class="chip" style="background:{_SEV_HEX[s]}">{s}: {counts[s]}</span>'
        for s in ("critical", "high", "medium", "low", "info") if counts[s])
    cards = []
    for i, f in enumerate(report.findings, 1):
        hx = _SEV_HEX[f.severity.value]
        meta = " / ".join(x for x in [f.owasp, f.cwe, f.atlas] if x)
        ev = f.evidence
        ev_html = ""
        if ev and (ev.payload or ev.request or ev.response):
            parts = []
            if ev.payload:
                parts.append(f"payload : {_esc(ev.payload)}")
            if ev.request:
                parts.append(f"request : {_esc(ev.request)}")
            if ev.response:
                parts.append(f"response: {_esc(ev.response[:400])}")
            ev_html = f'<pre class="ev">{chr(10).join(parts)}</pre>'
        repro_html = (f'<div class="repro"><b>How to reproduce:</b><pre>{_esc(f.reproduction)}</pre></div>'
                      if f.reproduction else "")
        cards.append(f"""
        <div class="card" style="border-left:5px solid {hx}">
          <div class="ctitle"><span class="sev" style="background:{hx}">{f.severity.value}</span>
            <span class="num">#{i}</span> {_esc(f.title)}</div>
          <div class="cmeta">{_esc(meta)} · CVSS {f.cvss_v4} · <code>{_esc(f.component or '-')}</code>
            · {_esc(f.source_tool)}</div>
          <p>{_esc(f.description)}</p>
          <p><b>Impact:</b> {_esc(f.impact)}</p>
          {repro_html}
          {ev_html}
          <p class="rec"><b>Recommendation:</b> {_esc(f.recommendation)}</p>
        </div>""")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Report — {_esc(report.engagement)}</title>
<style>
:root{{color-scheme:light dark}}
body{{font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0e1116;color:#e6e6e6}}
.wrap{{max-width:960px;margin:0 auto;padding:32px 20px}}
h1{{font-size:24px;margin:0 0 4px}} .sub{{color:#8b8d98;margin:0 0 20px}}
.chips{{margin:16px 0}} .chip{{color:#fff;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600;margin-right:6px}}
.card{{background:#161b22;border-radius:10px;padding:16px 18px;margin:14px 0}}
.ctitle{{font-size:16px;font-weight:600;margin-bottom:6px}}
.sev{{color:#fff;padding:1px 8px;border-radius:6px;font-size:11px;text-transform:uppercase;margin-right:6px}}
.num{{color:#8b8d98}} .cmeta{{color:#8b8d98;font-size:12px;margin-bottom:8px}}
code{{background:#0e1116;padding:1px 5px;border-radius:4px}}
pre{{background:#0e1116;padding:10px;border-radius:6px;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-word}}
.repro{{background:#0d2818;border:1px solid #1a5c38;border-radius:6px;padding:8px 12px;margin:8px 0}}
.repro pre{{background:transparent;padding:4px 0}}
.rec{{color:#7ee2b8}}
</style></head><body><div class="wrap">
<h1>🛡 Security test report — {_esc(report.engagement)}</h1>
<p class="sub">Target: {_esc(report.target.url)} ({report.target.type.value}) · {gen} ·
authorization: {'confirmed' if report.scope.authorized else 'NONE'}</p>
<div class="chips">{chips or '<span class="chip" style="background:#8b8d98">no findings</span>'}</div>
<p>Detected <b>{len(report.findings)}</b> findings.</p>
{''.join(cards)}
</div></body></html>"""


def write_html(report: Report, path: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(report))
    return path
