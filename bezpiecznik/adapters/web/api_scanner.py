"""API scanner: BOLA (path-based), excessive data exposure, XXE.

Mapping: OWASP API Security Top 10:2023 (API1 BOLA, API3 excessive data exposure)
and OWASP A05:2025 (XXE as injection).
"""
from __future__ import annotations

import json

from ...core.http import HttpClient
from ...core.logging import AuditLogger
from ...core.models import Evidence, Finding, Severity, Target
from ...core.scope import ActionClass, ScopeGuard
from . import detectors as det

# Fields whose presence in an API response suggests excessive data exposure.
SENSITIVE_FIELDS = ["password", "passwd", "ssn", "pesel", "secret", "token", "api_key",
                    "apikey", "credit_card", "card_number", "role", "is_admin", "private_key"]

XXE_PAYLOAD = ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM '
               '"file:///etc/passwd">]><root>&xxe;</root>')


class ApiScanner:
    name = "api-scanner (native)"

    def __init__(self, http: HttpClient, log: AuditLogger, guard: ScopeGuard):
        self.http = http
        self.log = log
        self.guard = guard

    def scan(self, target: Target, rest_resources: list[str], xml_endpoints: list[str]) -> list[Finding]:
        """rest_resources: base collection paths, e.g. '/api/orders' (we append /{id}).
        xml_endpoints: paths accepting XML (POST), e.g. '/xml'."""
        base = target.url.rstrip("/")
        self.guard.authorize(base, ActionClass.ACTIVE)
        findings: list[Finding] = []
        for res in rest_resources:
            findings += self._bola(base, res)
            findings += self._excessive_exposure(base, res)
        for ep in xml_endpoints:
            findings += self._xxe(base, ep)
        return findings

    def _bola(self, base: str, resource: str) -> list[Finding]:
        out: list[Finding] = []
        r1 = self.http.get(f"{base}{resource}/1")
        r2 = self.http.get(f"{base}{resource}/2")
        if (r1.status == 200 and r2.status == 200 and r1.text and r2.text
                and r1.text != r2.text
                and "unauthor" not in r2.text.lower() and "forbidden" not in r2.text.lower()):
            self.log.action(base, self.name, f"BOLA probe {resource}/{{id}}")
            self._report(out, Finding(
                title=f"Broken Object Level Authorization (BOLA) w {resource}/{{id}}",
                severity=Severity.HIGH, owasp="API1:2023 BOLA", cwe="CWE-639",
                target=f"{base}{resource}/2", component=f"{resource}/{{id}}", source_tool=self.name,
                description="Access to an object after changing the identifier in the path without access control.",
                impact="Reading/manipulating other users' data — the most common API vulnerability.",
                recommendation="Enforce object-level authorization per request (owner == requester).",
                evidence=Evidence(payload=f"{resource}/1 vs {resource}/2", response=r2.text[:250])))
        return out

    def _excessive_exposure(self, base: str, resource: str) -> list[Finding]:
        out: list[Finding] = []
        r = self.http.get(f"{base}{resource}/1")
        try:
            data = json.loads(r.text)
        except json.JSONDecodeError:
            return out
        blob = json.dumps(data).lower()
        found = [f for f in SENSITIVE_FIELDS if f'"{f}"' in blob]
        if found:
            self.log.action(base, self.name, f"exposure probe {resource}/1")
            self._report(out, Finding(
                title=f"Excessive data exposure in {resource}/{{id}}: {', '.join(found)}",
                severity=Severity.HIGH, owasp="API3:2023 Broken Object Property Level Authorization",
                cwe="CWE-213", target=f"{base}{resource}/1", component=f"{resource}/{{id}}",
                source_tool=self.name,
                description=f"The API response contains sensitive fields: {', '.join(found)}.",
                impact="Leak of confidential object properties (passwords, roles, PII) to the client.",
                recommendation="Return only the needed fields (allowlist/DTO); do not serialize entire entities.",
                evidence=Evidence(response=r.text[:300])))
        return out

    def _xxe(self, base: str, endpoint: str) -> list[Finding]:
        out: list[Finding] = []
        r = self.http.post(f"{base}{endpoint}",
                           headers={"Content-Type": "application/xml"}, content=XXE_PAYLOAD)
        if det.traversal_ok(r.text):
            self.log.action(base, self.name, f"XXE probe POST {endpoint}")
            self._report(out, Finding(
                title=f"XML External Entity (XXE) in POST {endpoint}",
                severity=Severity.CRITICAL, owasp="A05:2025 Injection", cwe="CWE-611",
                target=f"{base}{endpoint}", component=endpoint, source_tool=self.name,
                description="The XML parser expands external entities — reading a file (file:///etc/passwd).",
                impact="Reading server files, SSRF, potentially DoS (billion laughs).",
                recommendation="Disable external entity expansion and DTDs in the XML parser.",
                evidence=Evidence(payload=XXE_PAYLOAD, response=r.text[:250])))
        return out

    def _report(self, out: list[Finding], f: Finding) -> None:
        self.log.finding(f.title, f.severity.value, owasp=f.owasp)
        out.append(f)
