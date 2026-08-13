"""Detectors for modern/less-common web classes:
CORS misconfiguration, Host-header injection, GraphQL introspection/injection,
server-side Prototype Pollution, and Race conditions.
"""
from __future__ import annotations

import concurrent.futures
import json

import httpx

from ...core.http import HttpClient
from ...core.logging import AuditLogger
from ...core.models import Evidence, Finding, Severity, Target
from ...core.scope import ActionClass, ScopeGuard

EVIL_ORIGIN = "https://evil.example"


class ModernScanner:
    name = "modern-scanner (native)"

    def __init__(self, http: HttpClient, log: AuditLogger, guard: ScopeGuard):
        self.http = http
        self.log = log
        self.guard = guard

    def scan(self, target: Target, *, cors_paths: list[str] | None = None,
             host_paths: list[str] | None = None, graphql_paths: list[str] | None = None,
             merge_paths: list[str] | None = None, race: dict | None = None) -> list[Finding]:
        base = target.url.rstrip("/")
        self.guard.authorize(base, ActionClass.ACTIVE)
        findings: list[Finding] = []
        for p in (cors_paths if cors_paths is not None else ["/"]):
            findings += self._cors(base, p)
        for p in (host_paths if host_paths is not None else ["/"]):
            findings += self._host_header(base, p)
        for p in (graphql_paths if graphql_paths is not None else ["/graphql"]):
            findings += self._graphql(base, p)
        for p in (merge_paths or []):
            findings += self._prototype_pollution(base, p)
        if race:
            findings += self._race(base, race)
        return findings

    def _report(self, out: list[Finding], f: Finding) -> None:
        self.log.finding(f.title, f.severity.value, owasp=f.owasp)
        out.append(f)

    def _cors(self, base: str, path: str) -> list[Finding]:
        out: list[Finding] = []
        r = self.http.get(f"{base}{path}", headers={"Origin": EVIL_ORIGIN})
        acao = (r.header("Access-Control-Allow-Origin") or "").strip()
        acac = (r.header("Access-Control-Allow-Credentials") or "").strip().lower()
        reflected = acao == EVIL_ORIGIN
        wildcard_creds = acao == "*" and acac == "true"
        if reflected or wildcard_creds:
            self.log.action(base, self.name, f"CORS probe {path}")
            sev = Severity.HIGH if (reflected and acac == "true") else Severity.MEDIUM
            self._report(out, Finding(
                title=f"CORS misconfiguration at {path}",
                severity=sev, owasp="A05:2025 Security Misconfiguration", cwe="CWE-942",
                target=f"{base}{path}", component=path, source_tool=self.name,
                description=("The response reflects an arbitrary Origin in Access-Control-Allow-Origin"
                             + (" together with Allow-Credentials: true" if acac == "true" else "")
                             + "." if reflected else "Access-Control-Allow-Origin: * with credentials."),
                impact="A malicious site can read authenticated responses cross-origin (data theft).",
                recommendation="Allowlist trusted origins; never reflect Origin with credentials; avoid '*' with credentials.",
                reproduction=f"curl -H 'Origin: {EVIL_ORIGIN}' {base}{path} -i  # see Access-Control-Allow-Origin reflect it",
                evidence=Evidence(payload=f"Origin: {EVIL_ORIGIN}",
                                  response=f"ACAO: {acao} | ACAC: {acac}")))
        return out

    def _host_header(self, base: str, path: str) -> list[Finding]:
        out: list[Finding] = []
        evil = "evil.example"
        r = self.http.get(f"{base}{path}", headers={"X-Forwarded-Host": evil, "Host": evil})
        loc = r.header("Location") or ""
        if evil in r.text or evil in loc:
            self.log.action(base, self.name, f"Host-header probe {path}")
            self._report(out, Finding(
                title=f"Host Header Injection at {path}",
                severity=Severity.MEDIUM, owasp="A05:2025 Security Misconfiguration", cwe="CWE-644",
                target=f"{base}{path}", component=path, source_tool=self.name,
                description="The application reflects the client-supplied Host/X-Forwarded-Host header "
                            "into the response (e.g. links).",
                impact="Password-reset poisoning, cache poisoning, phishing links pointing to an attacker host.",
                recommendation="Use a fixed, server-side canonical host; validate Host against an allowlist.",
                reproduction=f"curl -H 'X-Forwarded-Host: {evil}' {base}{path}  # see {evil} in the response",
                evidence=Evidence(payload=f"X-Forwarded-Host: {evil}", response=(r.text or loc)[:200])))
        return out

    def _graphql(self, base: str, path: str) -> list[Finding]:
        out: list[Finding] = []
        q = {"query": "{__schema{types{name}}}"}
        r = self.http.post(f"{base}{path}", headers={"Content-Type": "application/json"},
                          content=json.dumps(q))
        if "__schema" in r.text and ("types" in r.text or "name" in r.text):
            self.log.action(base, self.name, f"GraphQL introspection {path}")
            self._report(out, Finding(
                title=f"GraphQL introspection enabled at {path}",
                severity=Severity.MEDIUM, owasp="A05:2025 Security Misconfiguration", cwe="CWE-200",
                target=f"{base}{path}", component=path, source_tool=self.name,
                description="The GraphQL endpoint answers introspection queries, exposing the full schema.",
                impact="Full schema/type disclosure aids further attacks (hidden fields, mutations, injection).",
                recommendation="Disable introspection in production; enforce authz per field; rate-limit.",
                reproduction=f"curl -X POST {base}{path} -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}'",
                evidence=Evidence(payload=json.dumps(q), response=r.text[:250])))
        return out

    def _prototype_pollution(self, base: str, path: str) -> list[Finding]:
        out: list[Finding] = []
        hdr = {"Content-Type": "application/json"}
        polluted = self.http.post(f"{base}{path}", headers=hdr,
                                 content=json.dumps({"__proto__": {"admin": True}}))
        benign = self.http.post(f"{base}{path}", headers=hdr, content=json.dumps({"name": "x"}))
        # pollution took effect if the polluted request flips a property the benign one does not
        if ('"admin": true' in polluted.text.lower().replace(" ", " ")
                or '"admin":true' in polluted.text.lower()) and \
           ('"admin":true' not in benign.text.lower().replace(" ", "")):
            self.log.action(base, self.name, f"Prototype pollution {path}")
            self._report(out, Finding(
                title=f"Prototype Pollution at {path}",
                severity=Severity.HIGH, owasp="A08:2025 Software or Data Integrity Failures", cwe="CWE-1321",
                target=f"{base}{path}", component=path, source_tool=self.name,
                description="A __proto__ key in the JSON body pollutes object properties server-side "
                            "(an unsafe recursive merge), changing application behavior (e.g. admin flag).",
                impact="Privilege escalation, denial of service, or RCE depending on downstream gadgets.",
                recommendation="Reject __proto__/constructor/prototype keys; use null-prototype objects; safe merge.",
                reproduction=f"curl -X POST {base}{path} -d '{{\"__proto__\":{{\"admin\":true}}}}'",
                evidence=Evidence(payload='{"__proto__":{"admin":true}}', response=polluted.text[:200])))
        return out

    def _race(self, base: str, race: dict) -> list[Finding]:
        out: list[Finding] = []
        path = race.get("path")
        if not path:
            return out
        reset = race.get("reset_path")
        n = int(race.get("concurrency", 15))
        body = race.get("body") or "{}"
        success_token = race.get("success_token", "redeemed")
        if reset:
            self.http.post(f"{base}{reset}", content="{}")
        # true concurrency: a dedicated client without the scanner's rate-limit throttle
        def fire(_i: int) -> str:
            try:
                with httpx.Client(timeout=15, verify=False) as c:
                    return c.post(f"{base}{path}", content=body,
                                  headers={"Content-Type": "application/json"}).text
            except httpx.HTTPError:
                return ""
        self.log.action(base, self.name, f"Race probe {path} x{n} concurrent")
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            results = list(ex.map(fire, range(n)))
        wins = sum(1 for t in results if success_token in t)
        if wins > 1:  # a single-use action succeeded more than once → the limit was raced
            self._report(out, Finding(
                title=f"Race Condition at {path} (limit bypassed {wins}x)",
                severity=Severity.HIGH, owasp="A04:2025 Insecure Design", cwe="CWE-362",
                target=f"{base}{path}", component=path, source_tool=self.name,
                description=f"Firing {n} concurrent requests let a single-use action succeed {wins} times — "
                            "a check-then-act TOCTOU race with no locking.",
                impact="Business-logic abuse: multi-redeem coupons, over-withdrawal, limit bypass.",
                recommendation="Atomic DB constraints / SELECT ... FOR UPDATE / idempotency keys / locks.",
                reproduction=f"Fire ~{n} concurrent POST {base}{path} — more than one succeeds.",
                evidence=Evidence(payload=f"{n} concurrent requests",
                                  response=f"{wins} succeeded (expected 1)")))
        return out
