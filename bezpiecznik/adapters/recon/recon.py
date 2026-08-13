"""Recon: fingerprint + discovery. Natively + optionally nmap/ffuf if available."""
from __future__ import annotations

import json
import os
import re
from urllib.parse import urlparse

from ...core.http import HttpClient
from ...core.logging import AuditLogger
from ...core.models import Evidence, Finding, Severity, Target
from ...core.scope import ActionClass, ScopeGuard
from ..external import run_tool, which


class ReconAdapter:
    name = "recon"

    def __init__(self, http: HttpClient, log: AuditLogger, guard: ScopeGuard, payloads_dir: str):
        self.http = http
        self.log = log
        self.guard = guard
        self.payloads_dir = payloads_dir
        self.routes: list[str] = []   # client hash-routes from SPA-recon (for DOM-XSS)

    def run(self, target: Target) -> tuple[list[Finding], list[tuple[str, str]]]:
        """Returns (findings, seeds) — seeds are (path, parameter) for the web scanner."""
        base = target.url.rstrip("/")
        self.guard.authorize(base, ActionClass.PASSIVE)
        findings: list[Finding] = []
        seeds: set[tuple[str, str]] = set()

        # 1) Fingerprint from the homepage
        r = self.http.get(base + "/")
        self.log.action(base, self.name, "GET / (fingerprint)")
        srv = r.header("Server")
        self.log.info(f"Server: {srv or '(none)'} | status {r.status} | {len(r.text)}B")

        # 2) Extract parameterized links from the HTML (?a=b)
        for m in re.finditer(r'href=["\']([^"\']+)["\']', r.text, re.IGNORECASE):
            href = m.group(1)
            u = urlparse(href)
            if u.query:
                path = u.path if u.path.startswith("/") else "/" + u.path
                for pair in u.query.split("&"):
                    if "=" in pair:
                        seeds.add((path, pair.split("=", 1)[0]))

        # 3) Extract parameters from FORMS (action + field names). Catches e.g. the 'search' field.
        seeds |= self._parse_forms(r.text)

        # 3.5–5) SPA-recon + ffuf + nmap are INDEPENDENT → run them IN PARALLEL (cuts recon ~3x).
        import concurrent.futures as _cf

        active = self.guard.check(base, ActionClass.ACTIVE)

        def _spa() -> tuple[set[tuple[str, str]], list[str]]:
            if not active:
                self.log.info("SPA-recon skipped (no ACTIVE authorization)")
                return set(), []
            from .spa_recon import SpaRecon
            s, _e, r = SpaRecon(self.log).discover(base)
            return s, sorted(r)

        with _cf.ThreadPoolExecutor(max_workers=3) as ex:
            f_spa = ex.submit(_spa)
            f_ffuf = ex.submit(self._ffuf_discovery, base)
            f_nmap = ex.submit(self._nmap, target)
            spa_seeds, self.routes = f_spa.result()
            seeds |= spa_seeds
            seeds |= f_ffuf.result()
            findings += f_nmap.result()

        self.log.info(f"Recon: found {len(seeds)} entry points (path,param)")
        return findings, sorted(seeds)

    def _parse_forms(self, html: str) -> set[tuple[str, str]]:
        """Extracts (action_path, field_name) from forms — GET and POST."""
        seeds: set[tuple[str, str]] = set()
        for fm in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, re.IGNORECASE | re.DOTALL):
            attrs, body = fm.group(1), fm.group(2)
            am = re.search(r'action\s*=\s*["\']?([^"\'>\s]+)', attrs, re.IGNORECASE)
            action = am.group(1) if am else "/"
            path = urlparse(action).path or "/"
            if not path.startswith("/"):
                path = "/" + path
            for nm in re.finditer(r'<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["\']?([\w\-\[\]]+)',
                                  body, re.IGNORECASE):
                name = nm.group(1)
                # skip non-text/noise fields
                if name.lower() not in {"submit", "csrf", "_token", "button"}:
                    seeds.add((path, name))
        if seeds:
            self.log.info(f"Recon: extracted {len(seeds)} fields from forms: "
                          + ", ".join(sorted({f'{p}?{n}' for p, n in seeds})[:8]))
        return seeds

    def _ffuf_discovery(self, base: str) -> set[tuple[str, str]]:
        seeds: set[tuple[str, str]] = set()
        wl = os.path.join(self.payloads_dir, "vendor", "SecLists",
                          "Discovery", "Web-Content", "common.txt")
        if not which("ffuf") or not os.path.exists(wl):
            self.log.info("ffuf/SecLists unavailable — skipping content discovery")
            return seeds
        res = run_tool("ffuf", ["-u", f"{base}/FUZZ", "-w", wl, "-mc", "200,301,302,403",
                                "-of", "json", "-o", "-", "-s"], timeout=120)
        if res.ok and res.stdout.strip():
            self.log.action(base, "ffuf", "content discovery")
            try:
                data = json.loads(res.stdout)
                for r in data.get("results", [])[:50]:
                    self.log.info(f"ffuf: /{r.get('input',{}).get('FUZZ','')} [{r.get('status')}]")
            except json.JSONDecodeError:
                pass
        return seeds

    def _nmap(self, target: Target) -> list[Finding]:
        host = urlparse(target.url).hostname or target.url
        if not which("nmap"):
            self.log.info("nmap unavailable — skipping service scan")
            return []
        # only local/private hosts in this demo; enforce scope
        self.guard.authorize(target.url, ActionClass.ACTIVE)
        res = run_tool("nmap", ["-sT", "-Pn", "-T4", "--top-ports", "20", host], timeout=60)
        out: list[Finding] = []
        if res.ok:
            self.log.action(host, "nmap", "top-20 port scan (-T4)")
            open_ports = re.findall(r"^(\d+)/tcp\s+open\s+(\S+)", res.stdout, re.MULTILINE)
            if open_ports:
                self.log.info("nmap open ports: " +
                              ", ".join(f"{p}/{s}" for p, s in open_ports))
        else:
            self.log.info(f"nmap: {res.skipped_reason or res.stderr[:120]}")
        return out
