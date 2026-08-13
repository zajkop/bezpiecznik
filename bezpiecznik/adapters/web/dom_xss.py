"""DOM-based XSS scanner via a headless browser.

The classic "reflected" detector (searching for the payload in the server response) does not catch
DOM-XSS, because the payload executes JS on the client side (it does not come back in the server HTML).
This scanner loads the page in Chromium with the payload and checks whether the JS REALLY executed
(marker in window + intercepted dialog). It tests injections in: SPA hash-route, fragment and query string.

Graceful degradation: no playwright → empty list with a note.
"""
from __future__ import annotations

from urllib.parse import quote

from ...core.logging import AuditLogger
from ...core.models import Evidence, Finding, Severity, Target
from ...core.scope import ActionClass, ScopeGuard

MARKER = "BZDOMXSS7"

# Payloads set window.<MARKER>=1. The 3 most effective contexts (faster than the full set).
_PAYLOADS = [
    f'<img src=x onerror="window.{MARKER}=1">',
    f'<iframe src="javascript:parent.{MARKER}=1">',
    f'<svg onload="window.{MARKER}=1">',
]


def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


class DomXssScanner:
    name = "dom-xss (headless)"

    def __init__(self, log: AuditLogger, guard: ScopeGuard,
                 max_routes: int = 4, max_params: int = 4):
        self.log = log
        self.guard = guard
        self.max_routes = max_routes
        self.max_params = max_params

    def scan(self, target: Target, routes: list[str], params: list[str]) -> list[Finding]:
        if not playwright_available():
            self.log.info("DOM-XSS: playwright not installed — skipping")
            return []
        base = target.url.rstrip("/")
        self.guard.authorize(base, ActionClass.ACTIVE)
        # build a list of injection points (URL templates with a {PL} placeholder)
        params = params[: self.max_params] or ["q", "search", "query", "id"]
        routes = (routes or [])[: self.max_routes]
        placements: list[tuple[str, str]] = []  # (description, url_template)
        for r in routes:
            for p in params:
                placements.append((f"#{r}?{p}", f"{base}/#{r}?{p}={{PL}}"))
        for p in params:
            placements.append((f"?{p}", f"{base}/?{p}={{PL}}"))
        placements.append(("#fragment", f"{base}/#{{PL}}"))

        try:
            return self._run(base, placements)
        except Exception as e:  # noqa: BLE001
            self.log.info(f"DOM-XSS: headless error ({repr(e)[:120]}) — skipping")
            return []

    def _run(self, base: str, placements: list[tuple[str, str]]) -> list[Finding]:
        from playwright.sync_api import sync_playwright

        findings: list[Finding] = []
        hit_placements: set[str] = set()
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            for desc, template in placements:
                if desc in hit_placements:
                    continue
                for payload in _PAYLOADS:
                    url = template.replace("{PL}", quote(payload, safe=""))
                    page = browser.new_page(ignore_https_errors=True)
                    fired = {"v": False}
                    page.on("dialog", lambda d, f=fired: (f.__setitem__("v", True), d.dismiss()))
                    executed = False
                    try:
                        page.goto(url, wait_until="domcontentloaded", timeout=10000)
                        page.wait_for_timeout(1300)
                        executed = bool(page.evaluate(f"() => window.{MARKER} === 1")) or fired["v"]
                    except Exception:  # noqa: BLE001
                        executed = fired["v"]
                    finally:
                        page.close()
                    self.log.action(base, self.name, f"DOM-XSS probe {desc}")
                    if executed:
                        hit_placements.add(desc)
                        findings.append(self._finding(base, desc, template, payload))
                        self.log.finding(f"DOM-based XSS ({desc})", "high")
                        break  # this location confirmed
            browser.close()
        self.log.info(f"DOM-XSS: tested {len(placements)} locations, "
                      f"confirmed {len(findings)}")
        return findings

    def _finding(self, base: str, desc: str, template: str, payload: str) -> Finding:
        vis = template.replace("{PL}", quote('<img src=x onerror="alert(document.domain)">', safe=""))
        repro = (
            "HOW TO REPRODUCE (visible proof):\n"
            f"1. Paste into a browser:\n   {vis}\n"
            "2. The script will execute in the DOM → an alert() with the domain = DOM-XSS proof.\n"
            "The scanner confirmed execution by setting window." + MARKER + "=1 in headless Chromium "
            "(the payload executed JS on the client side — which is why a plain 'reflected' scanner does not see it).")
        return Finding(
            title=f"DOM-based XSS ({desc})", severity=Severity.HIGH,
            owasp="A05:2025 Injection", cwe="CWE-79",
            target=template.replace("{PL}", quote(payload, safe="")),
            component=desc, source_tool=self.name,
            description="The payload executed JavaScript on the client side (a DOM sink reads data "
                        "from the URL/hash without sanitization). Confirmed by real execution in the browser.",
            impact="JS execution in the victim's context (session hijacking, actions on their behalf).",
            recommendation="Sanitize data from location.hash/search before inserting into the DOM; "
                           "avoid innerHTML/bypassSecurityTrust; deploy CSP.",
            reproduction=repro,
            evidence=Evidence(payload=payload,
                              request=template.replace("{PL}", quote(payload, safe=""))))
