# 03 — Playbook: web application and API testing

Mapping: **OWASP Top 10:2025** + **OWASP WSTG v4.2** + **OWASP API Security Top 10:2023**.
Payloads in [`payloads/web/`](../payloads/web/) and [`payloads/vendor/PayloadsAllTheThings/`](../payloads/vendor/PayloadsAllTheThings/).

> Always [00-authorization-and-scope.md](00-authorization-and-scope.md) first. The tests below are active.

## Phase 0 — Recon and surface mapping

| Goal | How | Tools |
|---|---|---|
| Subdomains / hosts | passively + actively | subfinder, amass, `crt.sh` |
| Live services | HTTP(S) probe, tech fingerprint | httpx, whatweb, Wappalyzer |
| Content / endpoints | crawl + directory brute-force | katana, gau, ffuf + `SecLists/Discovery/Web-Content` |
| Ports / services | scan | nmap (`-sV -sC`) |
| Hidden parameters | discovery | Arjun, `x8`, `SecLists` param lists |
| Headers / methods | analysis | curl, `nmap http-methods`, ZAP |

## OWASP Top 10:2025 — tests per category

### A01:2025 — Broken Access Control (including IDOR, SSRF*)
*In 2025 SSRF was absorbed into this category.
- **IDOR / BOLA:** change object identifiers (`/api/users/1001` → `1002`), UUIDs, hashes; also test parameters in the body and the JWT `sub`.
- **Privilege escalation:** access to admin functionality as a user (forced URL, hidden `role` fields).
- **Path traversal:** `../../etc/passwd` and encoded variants → `payloads/web/path-traversal.txt`.
- **SSRF:** force a server request to `http://169.254.169.254/` (cloud metadata), `http://localhost:<port>` → `payloads/web/ssrf.txt`.
- **Missing function-level authz (API5:2023):** call admin endpoints without the role.
- WSTG-ATHZ, WSTG-INPV-19 (SSRF).

### A02:2025 — Security Misconfiguration
- Default credentials, open panels (`/admin`, `/actuator`, `/.git/`, `/server-status`).
- Redundant HTTP methods (`PUT`, `TRACE`), directory listing, verbose errors.
- Security headers (CSP, HSTS, X-Frame-Options) — missing = clickjacking/MITM.
- CORS misconfiguration (`Access-Control-Allow-Origin: *` with credentials) → `payloads/web/cors.md`.
- Sensitive files: `.env`, backups, `.DS_Store`, source maps → ffuf + `SecLists`.

### A03:2025 — Software Supply Chain Failures (NEW)
- SCA of dependencies: `pip-audit`, `npm audit`, trivy, grype, syft, OWASP Dependency-Check.
- Dependency confusion / typosquatting (internal packages that can be published publicly).
- CI/CD integrity, unsigned artifacts, `postinstall` scripts.
- Lockfile poisoning, compromise of third-party JS (missing SRI).

### A04:2025 — Cryptographic Failures
- TLS: weak protocols/ciphers (testssl.sh, `nmap --script ssl-enum-ciphers`).
- Sensitive data in plaintext (HTTP, tokens in the URL, no encryption at-rest).
- Weak password hashing (MD5/SHA1 without salt), predictable IVs, ECB.
- Padding oracle, JWT `alg:none` / weak secret → JWT section below.

### A05:2025 — Injection
The richest part of the payloads. Test every entry point (query, body, headers, cookie, JSON, XML).
- **SQLi:** `payloads/web/sqli.txt`; automation: sqlmap. Variants: error-based, boolean/time-blind, UNION, stacked.
- **XSS** (reflected/stored/DOM): `payloads/web/xss.txt`; Ostrowski polyglot.
- **Command injection:** `payloads/web/command-injection.txt` (`; id`, `| whoami`, `$(...)`, backticks).
- **SSTI** (template): `payloads/web/ssti.txt` (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`) → RCE per engine.
- **NoSQL injection:** `{"$gt":""}`, `{"$ne":null}` → `payloads/vendor/PayloadsAllTheThings/NoSQL Injection`.
- **LDAP / XPath / GraphQL / CRLF / XXE / SSI:** the relevant directories in PayloadsAllTheThings.
- WSTG-INPV-*.

### A06:2025 — Insecure Design
- Threat modeling: no rate limits on critical flows, no server-side validation.
- Abuse of business logic (coupons, transfers, workflow) → see Business Logic below.
- No anti-automation mechanisms where they are needed.

### A07:2025 — Authentication Failures
- Brute force / credential stuffing: `SecLists/Passwords/Common-Credentials`, `Usernames`.
- Weak password policy, no lockout/MFA, user enumeration (different messages/timing).
- Login bypass (SQLi in the login, `admin'--`), weak "forgot password" (predictable token).
- Session fixation, no session invalidation after a password change.
- WSTG-ATHN, WSTG-SESS.

### A08:2025 — Software or Data Integrity Failures
- Insecure deserialization (Java/PHP/Python pickle/.NET) → `payloads/vendor/PayloadsAllTheThings/Insecure Deserialization`.
- Unsigned updates, loading code from untrusted sources.
- CI/CD integrity (overlaps with A03).

### A09:2025 — Security Logging & Alerting Failures
- Are successful/failed logins, permission changes, admin logins being logged?
- Can an alert be triggered (and does it arrive)? Log injection / forging.
- (Usually a "white-box" test / in collaboration with the blue team).

### A10:2025 — Mishandling of Exceptional Conditions (NEW)
- Incorrect exception handling → crash, fail-open (authorization denial turns into access), stack trace leak.
- Race conditions / TOCTOU → `payloads/vendor/PayloadsAllTheThings/Race Condition`.
- Unhandled errors leading to DoS or an inconsistent state.

## OWASP API Security Top 10:2023 — additional API tests

| Code | Name | Test |
|---|---|---|
| API1 | Broken Object Level Authorization (BOLA) | like IDOR — the most common API vulnerability |
| API2 | Broken Authentication | weak JWTs, no token expiry, keys in the repo |
| API3 | Broken Object Property Level Authorization | mass assignment / excessive data exposure |
| API4 | Unrestricted Resource Consumption | no rate limit/pagination → DoS, cost-based |
| API5 | Broken Function Level Authorization | a user calls admin functions |
| API6 | Unrestricted Access to Sensitive Business Flows | automation of critical flows (purchases, registrations) |
| API7 | SSRF | as above |
| API8 | Security Misconfiguration | like A02 |
| API9 | Improper Inventory Management | shadow/zombie APIs, old `/v1` versions |
| API10 | Unsafe Consumption of APIs | blind trust in third-party responses |

## Cross-cutting topics (separate payload directories)

- **JWT:** `alg:none`, weak HS256 secret (brute: `SecLists`), RS256→HS256 confusion, `kid` injection → `payloads/vendor/PayloadsAllTheThings/JSON Web Token`.
- **CSRF:** missing/bypassed token, SameSite → `Cross-Site Request Forgery`.
- **File upload:** webshell, polyglot, bypassing extension/MIME filters → `Upload Insecure Files`.
- **Open Redirect, Clickjacking, Prototype Pollution, Request Smuggling, Race Condition** — each has a directory in PayloadsAllTheThings.
- **Business Logic:** race conditions on payments, price/quantity manipulation (negative), bypassing workflow steps.

## "Workflow" summary for the agent

```
recon (httpx/ffuf/nmap) 
  → automatic scan (nuclei + ZAP baseline) 
  → manual analysis per WSTG per category 
  → targeted payloads from payloads/web/* and vendor/PayloadsAllTheThings/* 
  → PoC confirmation (sqlmap/Burp/manual) 
  → OWASP2025/CWE/CVSS4.0 mapping 
  → report (template from 02)
```
