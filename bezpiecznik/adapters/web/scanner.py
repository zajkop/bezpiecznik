"""Native web scanner (pure Python) — requires no external binaries.

Tests: SQLi (error-based + boolean), reflected XSS, command injection,
path traversal, open redirect, IDOR, missing security headers.
Deterministic detection (detectors.py). Payloads partly from payloads/web/*.
"""
from __future__ import annotations

import os
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ...core.http import HttpClient, Response
from ...core.logging import AuditLogger
from ...core.models import Evidence, Finding, Severity, Target
from ...core.scope import ActionClass, ScopeGuard
from . import detectors as det


def _set_param(base_url: str, path: str, param: str, value: str, extra: dict | None = None) -> str:
    u = urlparse(base_url)
    q = {param: value}
    if extra:
        q.update(extra)
    return urlunparse((u.scheme, u.netloc, path, "", urlencode(q), ""))


def _load_payloads(payloads_dir: str, name: str, limit: int = 8) -> list[str]:
    path = os.path.join(payloads_dir, "web", name)
    out: list[str] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                s = line.rstrip("\n")
                if s and not s.startswith("#") and not s.startswith("##"):
                    out.append(s)
                if len(out) >= limit:
                    break
    except FileNotFoundError:
        pass
    return out


class WebScanner:
    name = "web-scanner (native)"

    def __init__(self, http: HttpClient, log: AuditLogger, guard: ScopeGuard, payloads_dir: str):
        self.http = http
        self.log = log
        self.guard = guard
        self.payloads_dir = payloads_dir

    def scan(self, target: Target, seeds: list[tuple[str, str]]) -> list[Finding]:
        """seeds: list of (path, parameter_name) to test."""
        base = target.url.rstrip("/")
        self.guard.authorize(base, ActionClass.ACTIVE)
        findings: list[Finding] = []

        findings += self._security_headers(base)

        for path, param in seeds:
            self.guard.authorize(base, ActionClass.ACTIVE)
            findings += self._sqli(base, path, param)
            findings += self._xss(base, path, param)
            findings += self._cmdi(base, path, param)
            findings += self._traversal(base, path, param)
            findings += self._ssti(base, path, param)
            findings += self._crlf(base, path, param)
            findings += self._time_sqli(base, path, param)
            if param.lower() in {"url", "uri", "fetch", "link", "src", "dest", "u",
                                 "target", "feed", "callback", "path", "next", "return", "redirect"}:
                findings += self._open_redirect(base, path, param)
                findings += self._ssrf(base, path, param)
            if param.lower() in {"user", "username", "uid", "cn", "dn", "login"}:
                findings += self._ldap(base, path, param)
            if param.lower() in {"id", "uid", "user", "user_id", "pid"}:
                findings += self._idor(base, path, param)
        return findings

    def _report(self, findings: list[Finding], f: Finding) -> None:
        self.log.finding(f.title, f.severity.value, target=f.target, owasp=f.owasp)
        findings.append(f)

    # ---- individual tests ----

    def _security_headers(self, base: str) -> list[Finding]:
        r = self.http.get(base + "/")
        self.log.action(base, self.name, "GET / (header analysis)")
        missing = [h for h in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options")
                   if not r.header(h)]
        out: list[Finding] = []
        if missing:
            f = Finding(
                title=f"Missing security headers: {', '.join(missing)}",
                severity=Severity.LOW, owasp="A02:2025 Security Misconfiguration",
                cwe="CWE-693", target=base + "/", component="response headers",
                source_tool=self.name,
                description="The response does not set key defensive headers.",
                impact="Increases the risk of clickjacking, MIME-sniffing and XSS.",
                recommendation="Add CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff.",
                evidence=Evidence(request=f"GET {base}/",
                                  response="; ".join(f"{k}: {v}" for k, v in r.headers.items())),
            )
            self._report(out, f)
        srv = r.header("Server")
        if srv and any(ch.isdigit() for ch in srv):
            f = Finding(title=f"Server version disclosure in the Server header: {srv}",
                        severity=Severity.INFO, owasp="A02:2025 Security Misconfiguration",
                        cwe="CWE-200", target=base + "/", source_tool=self.name,
                        description="The Server header discloses the version — makes CVE hunting easier.",
                        recommendation="Hide/generalize the Server header.",
                        evidence=Evidence(response=f"Server: {srv}"))
            self._report(out, f)
        return out

    def _baseline(self, base: str, path: str, param: str) -> Response:
        return self.http.get(_set_param(base, path, param, "1"))

    def _sqli(self, base: str, path: str, param: str) -> list[Finding]:
        out: list[Finding] = []
        # 1) error-based: single apostrophe
        url = _set_param(base, path, param, "1'")
        r = self.http.get(url)
        self.log.action(base, self.name, f"SQLi probe {path}?{param}=1'")
        sig = det.sql_error(r.text)
        if sig:
            self._report(out, Finding(
                title=f"SQL Injection (error-based) in parameter '{param}'",
                severity=Severity.CRITICAL, owasp="A05:2025 Injection", cwe="CWE-89",
                target=url, component=f"{path}?{param}", source_tool=self.name,
                description=f"Injecting an apostrophe triggers a SQL error (signature: {sig}).",
                impact="Possible database read/modification, authentication bypass.",
                recommendation="Use parameterized queries (prepared statements).",
                evidence=Evidence(payload="1'", request=f"GET {url}", response=r.text[:400])))
            return out  # confirmed, no need for boolean
        # 2) boolean-based: differentiating a TRUE vs FALSE condition (resistant to false positives).
        #    Real SQLi: "1 OR 1=1" (true) and "1 AND 1=2" (false) give DIFFERENT responses.
        #    Non-SQL (e.g. ping): both variants fail the same way → no difference → no report.
        r_true = self.http.get(_set_param(base, path, param, "1 OR 1=1"))
        r_false = self.http.get(_set_param(base, path, param, "1 AND 1=2"))
        r_base = self._baseline(base, path, param)
        differ = abs(len(r_true.text) - len(r_false.text))
        if (r_true.status == 200 and r_false.status == 200
                and differ > 20
                and len(r_true.text) > len(r_false.text)          # true returns more
                and len(r_true.text) >= len(r_base.text)           # and no less than baseline
                and "usage:" not in r_true.text.lower()            # not CLI tool output
                and det.sql_error(r_true.text) is None):
            self._report(out, Finding(
                title=f"SQL Injection (boolean-based) in parameter '{param}'",
                severity=Severity.HIGH, owasp="A05:2025 Injection", cwe="CWE-89",
                target=_set_param(base, path, param, "1 OR 1=1"),
                component=f"{path}?{param}", source_tool=self.name,
                description="A true condition (1 OR 1=1) and a false one (1 AND 1=2) give different "
                            "responses — a classic symptom of SQL injection.",
                impact="Reading data from the database (blind SQLi).",
                recommendation="Parameterized queries; type validation.",
                evidence=Evidence(payload="1 OR 1=1 / 1 AND 1=2",
                                  response=f"len(true)={len(r_true.text)} len(false)={len(r_false.text)} "
                                           f"len(base)={len(r_base.text)}")))
        return out

    def _xss(self, base: str, path: str, param: str) -> list[Finding]:
        out: list[Finding] = []
        marker = "bzX9"
        payloads = [f"<script>{marker}()</script>", f"\"><svg onload={marker}()>"] + \
                   _load_payloads(self.payloads_dir, "xss.txt", limit=4)
        for p in payloads:
            url = _set_param(base, path, param, p)
            r = self.http.get(url)
            if p in r.text and det.escaped_variant(p) != p and det.escaped_variant(p) not in r.text:
                self.log.action(base, self.name, f"XSS probe {path}?{param}")
                vis_url = _set_param(base, path, param, "<script>alert(document.domain)</script>")
                repro = (
                    "HOW TO REPRODUCE (visible proof):\n"
                    f"1. Paste this URL into a browser:\n   {vis_url}\n"
                    "2. The page will execute the injected script → an alert() with the domain pops up = XSS proof.\n"
                    "Why the scanner's marker was 'invisible': the scanner detects the vulnerability with a safe "
                    f"payload '{p}' (the bzX9() function call does not exist → the script executes, but "
                    "WITHOUT a visible effect and without a popup). The <script> tag by itself displays nothing; "
                    "only alert()/console reveal the execution. Alternatively, open the dev console (F12) "
                    "with the marker — you will see ReferenceError: bzX9 is not defined (proof that the JS ran).")
                self._report(out, Finding(
                    title=f"Reflected XSS in parameter '{param}'",
                    severity=Severity.HIGH, owasp="A05:2025 Injection", cwe="CWE-79",
                    target=url, component=f"{path}?{param}", source_tool=self.name,
                    description="Payload reflected in the response without HTML encoding (HTML body context).",
                    impact="JS execution in the victim's context (session theft, phishing).",
                    recommendation="Context-encode the output (HTML-encode); deploy CSP.",
                    reproduction=repro,
                    evidence=Evidence(payload=p, request=f"GET {url}", response=r.text[:300])))
                break
        return out

    def _cmdi(self, base: str, path: str, param: str) -> list[Finding]:
        out: list[Finding] = []
        for p in ["127.0.0.1;id", "127.0.0.1| id", "1;id"]:
            url = _set_param(base, path, param, p)
            r = self.http.get(url)
            sig = det.cmd_injected(r.text)
            if sig:
                self.log.action(base, self.name, f"CMDi probe {path}?{param}")
                self._report(out, Finding(
                    title=f"OS Command Injection in parameter '{param}'",
                    severity=Severity.CRITICAL, owasp="A05:2025 Injection", cwe="CWE-78",
                    target=url, component=f"{path}?{param}", source_tool=self.name,
                    description=f"Injected command executed (signature: {sig}).",
                    impact="Remote code execution on the server (RCE).",
                    recommendation="Do not build commands from input; use safe APIs/allowlist.",
                    evidence=Evidence(payload=p, request=f"GET {url}", response=r.text[:300])))
                break
        return out

    def _traversal(self, base: str, path: str, param: str) -> list[Finding]:
        out: list[Finding] = []
        deep = "../" * 14
        for p in [deep + "etc/passwd", "..%2f" * 14 + "etc%2fpasswd",
                  "....//" * 14 + "etc/passwd", "../../../../../../etc/passwd"]:
            url = _set_param(base, path, param, p)
            r = self.http.get(url)
            sig = det.traversal_ok(r.text)
            if sig:
                self.log.action(base, self.name, f"Traversal probe {path}?{param}")
                self._report(out, Finding(
                    title=f"Path Traversal / LFI in parameter '{param}'",
                    severity=Severity.HIGH, owasp="A01:2025 Broken Access Control", cwe="CWE-22",
                    target=url, component=f"{path}?{param}", source_tool=self.name,
                    description="Reading a file outside the application directory (/etc/passwd).",
                    impact="Leak of system/configuration files, potentially RCE.",
                    recommendation="Canonicalize and validate paths; allowlist files.",
                    evidence=Evidence(payload=p, request=f"GET {url}", response=r.text[:300])))
                break
        return out

    def _open_redirect(self, base: str, path: str, param: str) -> list[Finding]:
        out: list[Finding] = []
        evil = "https://evil.example/x"
        url = _set_param(base, path, param, evil)
        r = self.http.get(url)
        loc = r.header("Location") or ""
        if r.status in (301, 302, 303, 307, 308) and evil in loc:
            self.log.action(base, self.name, f"Open redirect {path}?{param}")
            self._report(out, Finding(
                title=f"Open Redirect in parameter '{param}'",
                severity=Severity.MEDIUM, owasp="A01:2025 Broken Access Control", cwe="CWE-601",
                target=url, component=f"{path}?{param}", source_tool=self.name,
                description="The application redirects to an arbitrary external URL.",
                impact="Phishing, filter bypass, OAuth token theft.",
                recommendation="Allowlist redirect targets; use relative paths.",
                evidence=Evidence(payload=evil, response=f"HTTP {r.status} Location: {loc}")))
        return out

    def _ssti(self, base: str, path: str, param: str) -> list[Finding]:
        out: list[Finding] = []
        # Low collision-risk marker: 1337*1337 = 1787569.
        probes = [("{{1337*1337}}", "1787569"), ("${1337*1337}", "1787569"),
                  ("#{1337*1337}", "1787569"), ("{{7*'7'}}", "7777777")]
        # make sure the marker does not appear in the baseline (by accident)
        base_txt = self._baseline(base, path, param).text
        for payload, marker in probes:
            if marker in base_txt:
                continue
            url = _set_param(base, path, param, payload)
            r = self.http.get(url)
            if marker in r.text and payload not in r.text:  # computed, not just reflected
                self.log.action(base, self.name, f"SSTI probe {path}?{param}")
                self._report(out, Finding(
                    title=f"Server-Side Template Injection in parameter '{param}'",
                    severity=Severity.CRITICAL, owasp="A05:2025 Injection", cwe="CWE-1336",
                    target=url, component=f"{path}?{param}", source_tool=self.name,
                    description=f"A template expression was evaluated ({payload} → {marker}).",
                    impact="Usually leads to RCE on the server (depending on the template engine).",
                    recommendation="Do not render input as a template; sandbox the engine; escaping.",
                    evidence=Evidence(payload=payload, request=f"GET {url}", response=r.text[:250])))
                break
        return out

    def _ssrf(self, base: str, path: str, param: str) -> list[Finding]:
        out: list[Finding] = []
        # file:// → read /etc/passwd (unambiguous marker). http to metadata will not work locally.
        for payload in ["file:///etc/passwd", "file:/etc/passwd"]:
            url = _set_param(base, path, param, payload)
            r = self.http.get(url)
            if det.traversal_ok(r.text):
                self.log.action(base, self.name, f"SSRF probe {path}?{param}")
                self._report(out, Finding(
                    title=f"Server-Side Request Forgery in parameter '{param}'",
                    severity=Severity.HIGH, owasp="A01:2025 Broken Access Control", cwe="CWE-918",
                    target=url, component=f"{path}?{param}", source_tool=self.name,
                    description="The server fetches an arbitrary resource specified by the attacker "
                                "(here: file:///etc/passwd). Also susceptible to cloud metadata access.",
                    impact="Access to internal services, cloud metadata (IAM role theft), files.",
                    recommendation="Allowlist hosts/schemes; block file:// and internal ranges "
                                   "(169.254.169.254, localhost, RFC1918).",
                    evidence=Evidence(payload=payload, request=f"GET {url}", response=r.text[:250])))
                return out
        return out

    def _crlf(self, base: str, path: str, param: str) -> list[Finding]:
        out: list[Finding] = []
        marker = "bzcrlf9"
        payload = f"en\r\nX-Injected: {marker}"
        url = _set_param(base, path, param, payload)
        r = self.http.get(url)
        if (r.header("X-Injected") or "").strip() == marker:
            self.log.action(base, self.name, f"CRLF probe {path}?{param}")
            self._report(out, Finding(
                title=f"CRLF / HTTP Response Splitting in parameter '{param}'",
                severity=Severity.HIGH, owasp="A05:2025 Injection", cwe="CWE-113",
                target=url, component=f"{path}?{param}", source_tool=self.name,
                description="CRLF injection (%0d%0a) creates a new response header.",
                impact="Header injection, cache poisoning, XSS via Set-Cookie, response splitting.",
                recommendation="Strip/encode CR and LF from data that ends up in response headers.",
                evidence=Evidence(payload=payload, request=f"GET {url}",
                                  response=f"header X-Injected: {marker} appeared in the response")))
        return out

    def _time_sqli(self, base: str, path: str, param: str) -> list[Finding]:
        out: list[Finding] = []
        base_r = self._baseline(base, path, param)
        baseline_ms = base_r.elapsed_ms
        # time-delay payloads for various engines (RANDOMBLOB=SQLite, SLEEP=MySQL, pg_sleep=PG)
        # dual-OR forces evaluation of both heavy LIKEs (AND binds tighter than OR → bypasses short-circuit)
        payloads = [
            ("1 AND 1=LIKE('ABC',UPPER(HEX(RANDOMBLOB(120000000)))) "
             "OR 1=LIKE('ABD',UPPER(HEX(RANDOMBLOB(120000000))))"),    # SQLite (~2.8s)
            "1 AND SLEEP(3)",                                           # MySQL
            "1'||pg_sleep(3)--",                                        # PostgreSQL
            "1;SELECT pg_sleep(3)--",
        ]
        for p in payloads:
            r = self.http.get(_set_param(base, path, param, p))
            # threshold: >2.5s AND noticeably slower than baseline (reduces false positives)
            if r.elapsed_ms > 2500 and r.elapsed_ms > baseline_ms + 2000:
                self.log.action(base, self.name, f"time-SQLi {path}?{param} ({r.elapsed_ms:.0f}ms)")
                self._report(out, Finding(
                    title=f"SQL Injection (time-based blind) in parameter '{param}'",
                    severity=Severity.CRITICAL, owasp="A05:2025 Injection", cwe="CWE-89",
                    target=_set_param(base, path, param, p), component=f"{path}?{param}",
                    source_tool=self.name,
                    description=f"The delaying payload extended the response to {r.elapsed_ms:.0f}ms "
                                f"(baseline {baseline_ms:.0f}ms) — time-based blind SQLi.",
                    impact="Full character-by-character database read (blind), authentication bypass.",
                    recommendation="Parameterized queries; type validation.",
                    evidence=Evidence(payload=p,
                                      response=f"time: {r.elapsed_ms:.0f}ms vs baseline {baseline_ms:.0f}ms")))
                break
        return out

    def _ldap(self, base: str, path: str, param: str) -> list[Finding]:
        out: list[Finding] = []
        normal = self.http.get(_set_param(base, path, param, "admin"))
        inj = self.http.get(_set_param(base, path, param, "*)(uid=*))"))
        star = self.http.get(_set_param(base, path, param, "*"))
        # injecting LDAP metacharacters returns significantly more than a concrete value
        bigger = max(len(inj.text), len(star.text))
        if (normal.status == 200 and bigger > len(normal.text) * 1.4 and bigger > len(normal.text) + 20):
            self.log.action(base, self.name, f"LDAP probe {path}?{param}")
            self._report(out, Finding(
                title=f"Possible LDAP Injection in parameter '{param}'",
                severity=Severity.HIGH, owasp="A05:2025 Injection", cwe="CWE-90",
                target=_set_param(base, path, param, "*)(uid=*))"), component=f"{path}?{param}",
                source_tool=self.name,
                description="LDAP filter metacharacters (*)(uid=*) return significantly more records "
                            "than a concrete value — a symptom of LDAP filter injection.",
                impact="Authentication bypass, enumeration/leak of directory entries.",
                recommendation="Escape LDAP metacharacters (RFC 4515) in input data.",
                evidence=Evidence(payload="*)(uid=*))",
                                  response=f"len(normal)={len(normal.text)} len(inj)={bigger}")))
        return out

    def _idor(self, base: str, path: str, param: str) -> list[Finding]:
        out: list[Finding] = []
        r1 = self.http.get(_set_param(base, path, param, "1"))
        r2 = self.http.get(_set_param(base, path, param, "2"))
        if (r1.status == 200 and r2.status == 200 and r1.text and r2.text
                and r1.text != r2.text and "unauthor" not in r2.text.lower()
                and "forbidden" not in r2.text.lower()):
            self.log.action(base, self.name, f"IDOR probe {path}?{param}")
            self._report(out, Finding(
                title=f"Possible IDOR/BOLA in parameter '{param}'",
                severity=Severity.HIGH, owasp="A01:2025 Broken Access Control", cwe="CWE-639",
                target=_set_param(base, path, param, "2"), component=f"{path}?{param}",
                source_tool=self.name,
                description="Changing the identifier returns another object's data without access control.",
                impact="Access to other users' data (API1:2023 BOLA).",
                recommendation="Enforce object-level authorization per request.",
                evidence=Evidence(payload="id=2",
                                  response=r2.text[:250])))
        return out
