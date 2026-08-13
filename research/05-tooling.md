# 05 — Recommended tooling stack

Philosophy: **the "Bezpiecznik" agent orchestrates mature, proven tools** — it does not reimplement
scanners in Python from scratch. We write our own code only where a ready-made option is missing (glue,
result aggregation, LLM-specific orchestration).

## A. AI / LLM red teaming (the core for "Bezpiecznik")

| Tool | Role | Why | Installation |
|---|---|---|---|
| **garak** (NVIDIA) | LLM vulnerability scanner | 37+ probe modules (dan, promptinject, leakreplay, packagehallucination, xss…), easily extensible | `pip install garak` |
| **PyRIT** (Microsoft) | Multi-turn/multimodal attack orchestration | Crescendo, conversational jailbreaks, integration with targets; proven in MS production | `pip install pyrit` |
| **promptfoo** | Red team + eval in CI/CD | 50+ vulnerability types, mapping to OWASP/NIST/**MITRE ATLAS**/EU AI Act, reports | `npm install -g promptfoo` |
| **deepteam** | LLM red-team framework based on the OWASP LLM Top 10 | Ready-made scenarios for the standard | `pip install deepteam` |
| **Giskard** | Quality + security testing of models/RAG | Automatic problem detection, good for RAG | `pip install giskard` |
| **LLM Guard / Guardrails AI** | DEFENSIVE layer (mitigation reference) | For remediation recommendations, not for attack | `pip install llm-guard` |

**Minimal set:** garak + PyRIT (offense) → promptfoo (regression in CI) → LLM Guard (defense in the report).

## B. Web / API — recon and mapping

| Tool | Role |
|---|---|
| **nmap** | port/service scanning, NSE scripts |
| **httpx** (ProjectDiscovery) | HTTP probe, fingerprinting, statuses at scale |
| **subfinder / amass** | subdomain enumeration |
| **katana / gau / waybackurls** | crawling and URL collection |
| **ffuf / feroxbuster** | directory/parameter fuzzing (with SecLists) |
| **Arjun / x8** | discovery of hidden parameters |
| **whatweb / Wappalyzer** | technology fingerprinting |

## C. Web / API — vulnerability scanning and exploitation

| Tool | Role |
|---|---|
| **Burp Suite** (Pro/Community) | proxy, Intruder, Repeater — the core of manual work |
| **OWASP ZAP** | free proxy/scanner, baseline automation, API |
| **nuclei** (+ nuclei-templates) | template-based scanning (CVE, misconfig, exposures) |
| **sqlmap** | automatic SQLi exploitation |
| **nikto** | quick scan of web server misconfiguration |
| **testssl.sh** | TLS/SSL audit |
| **dalfox** | automatic XSS |
| **commix** | automatic command injection |
| **jwt_tool** | attacks on JWT |

## D. Supply chain / SCA (OWASP A03:2025, LLM03)

| Tool | Role |
|---|---|
| **trivy** | scanning of images, IaC, dependencies, secrets |
| **grype + syft** | SBOM + dependency vulnerabilities |
| **OWASP Dependency-Check** | SCA per ecosystem |
| **pip-audit / npm audit** | quick dependency audit |
| **picklescan / modelscan** | scanning of poisoned ML models (LLM03) |
| **gitleaks / trufflehog** | secret leakage in the repo |

## E. Post-exploitation / reporting

- **MITRE ATT&CK Navigator** — technique mapping.
- **Faraday / Dradis / DefectDojo** — aggregation and management of findings (optional).
- **Own aggregator** (to be built) → JSON + Markdown per the template from [02](02-methodologies.md#raportowanie).

## F. Environment

- **Kali Linux / Parrot OS** — distributions with preconfigured tooling.
- **Docker** — tool isolation (some have ready-made images).
- **Python venv** — for garak/PyRIT/promptfoo, dependency isolation.

## A note on "reinventing the wheel"

The previous version of the plan wanted to write its own recon-scanner and payload-delivery in Python.
That's a mistake: `nmap`/`ffuf`/`nuclei`/`garak`/`PyRIT` do it better and are maintained.
The value of the "Bezpiecznik" agent = **orchestration + correlation + reporting**, not a copy of a scanner.
