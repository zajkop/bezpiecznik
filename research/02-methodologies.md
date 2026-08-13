# 02 — Security testing methodologies

This document describes *how* to conduct a test (the process), independently of *what* we are testing
(the catalog of vulnerabilities is in [03](03-web-app-methodology.md) and [04](04-ai-llm-methodology.md)).

## 1. Overarching process — PTES (7 phases)

The industry end-to-end standard. Every "Bezpiecznik" engagement goes through these phases:

1. **Pre-engagement Interactions** — scope, RoE, consent, goals, time window → [00-authorization-and-scope.md](00-authorization-and-scope.md).
2. **Intelligence Gathering (Recon)** — OSINT, attack-surface enumeration, fingerprinting.
3. **Threat Modeling** — what assets, what realistic threat scenarios (who would attack us and why).
4. **Vulnerability Analysis** — identifying vulnerabilities (scanning + manual analysis).
5. **Exploitation** — confirming a vulnerability with a real (controlled) PoC.
6. **Post-Exploitation** — impact: escalation, pivoting, access to data (within scope). Mapping to MITRE ATT&CK.
7. **Reporting** — documenting, severity, recommendations.

## 2. Technical standard — NIST SP 800-115

A government guide; complementary to PTES. Four phases: **Planning → Discovery →
Attack → Reporting**, with an emphasis on repeatability and evidence documentation.

## 3. Detailed methodology — OWASP WSTG v4.2 (web)

The actual "test-by-test playbook". Each test has a `WSTG-<CAT>-<NN>` identifier. Categories:

| Code | Category | Example test |
|---|---|---|
| INFO | Information Gathering | server fingerprinting, application mapping |
| CONF | Configuration & Deploy Mgmt | backup files, admin panels, HTTP methods |
| IDNT | Identity Management | user enumeration, registration |
| ATHN | Authentication | brute force, bypass, weak "remember me" |
| ATHZ | Authorization | IDOR, privilege escalation, path traversal |
| SESS | Session Management | fixation, predictable tokens, CSRF |
| INPV | Input Validation | SQLi, XSS, SSTI, SSRF, injection (including GraphQL) |
| ERRH | Error Handling | stack traces, information leaks |
| CRYP | Cryptography | weak TLS, padding oracle |
| BUSL | Business Logic | flow bypass, race condition |
| CLNT | Client-side | DOM XSS, clickjacking, postMessage |
| APIT | API Testing | REST/GraphQL specifics |

The v4.2 checklist (xlsx) in the OWASP/wstg repo is good for coverage and for a "what was tested" report.

## 4. AI methodology — MITRE ATLAS + OWASP GenAI Red Teaming

For AI/LLM systems, classic methodologies are not enough. The AI layer uses:

- **MITRE ATLAS** — adversary tactics against ML: Reconnaissance, Resource Development,
  Initial Access, **ML Model Access**, Execution, Persistence, Defense Evasion,
  Discovery, Collection, **ML Attack Staging**, Exfiltration, Impact. Map findings to ATLAS TTPs.
- **OWASP GenAI Red Teaming Guide** — 4 dimensions: model, implementation (app/RAG), system
  (infra/agent), process (governance). Test each dimension, not just the model itself.
- **NIST AI 600-1** — a list of GenAI risks (including CBRN, confabulation, data leakage) for threat modeling.

Detailed AI playbook → [04-ai-llm-methodology.md](04-ai-llm-methodology.md).

## 5. Post-exploitation — MITRE ATT&CK

After gaining access, describe the steps and impact in ATT&CK language (Enterprise/Cloud/Containers):
tactics TA0001–TA0040. It helps the defense map to detections and lets you show real impact.

## 6. Classification and scoring of findings

- **Severity:** CVSS **v4.0** (base + threat + environmental).
- **Weakness class:** CWE-ID.
- **Risk mapping:** OWASP Top 10:2025 / API Top 10:2023 / LLM Top 10:2025 / ATLAS TTP.
- **Remediation priority:** a combination of severity × exploitability × business impact.

## 7. Reporting {#raportowanie}

Template for a single finding (used by the agent in JSON output and in the MD report):

```
### [SEVERITY] Concise title
- ID: FND-001
- Category: OWASP A05:2025 Injection / CWE-89 / (ATLAS AML.T00xx if AI)
- Endpoint / component: POST /api/search
- CVSS 4.0: 8.6 (vector: ...)

**Description:** what the vulnerability is.
**Evidence (PoC):** exact steps + payload + request/response (secrets redacted).
**Impact:** what the attacker actually achieves.
**Recommendation:** a concrete fix + link to the OWASP Cheat Sheet.
**Evidence:** paths to logs/screenshots.
```

Structure of the overall report:
1. **Executive Summary** (for management — business risk, no jargon).
2. **Scope and methodology** (what, when, how, which standards).
3. **Findings summary** (table: severity → count).
4. **Technical details** (findings per the template above).
5. **Appendices** (logs, wordlists, tool configuration — reproducibility).

## 8. Phase → tools map (summary)

| Phase | Web/API | AI/LLM |
|---|---|---|
| Recon | nmap, httpx, ffuf, katana, subfinder | model fingerprinting, enumeration of `/v1/chat/*` endpoints |
| Vuln analysis | nuclei, ZAP, Burp, nikto | garak, promptfoo |
| Exploitation | sqlmap, Burp Intruder, manual | PyRIT (multi-turn), manual jailbreaks |
| Reporting | own aggregator → JSON/MD | the same aggregator, ATLAS/LLM Top 10 mapping |

Full stack → [05-tooling.md](05-tooling.md).
