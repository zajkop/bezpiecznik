# 01 — Sources, standards and references (verified 2026-08)

All entries checked for currency as of August 2026. Where a new edition has been released,
we point to it explicitly (a common mistake: citing the 2021/2023 version as "the latest").

## A. Vulnerability standards (what to test)

### Web / API
| Standard | Current version | Notes | Link |
|---|---|---|---|
| **OWASP Top 10** | **2025** (final, November 2025) | First update since 2021. New: A03 Software Supply Chain Failures, A10 Mishandling of Exceptional Conditions | https://owasp.org/Top10/ |
| **OWASP API Security Top 10** | **2023** | Still the current edition; BOLA (API1) is No. 1 | https://owasp.org/API-Security/ |
| **OWASP WSTG** (Web Security Testing Guide) | **v4.2** (stable) | The actual step-by-step testing methodology, WSTG-XXXX identifiers | https://owasp.org/www-project-web-security-testing-guide/ |
| **OWASP ASVS** (Application Security Verification Standard) | v4.0.3 (v5.0 in progress) | Verification requirements — good for a "secure by design" checklist | https://owasp.org/www-project-application-security-verification-standard/ |
| **OWASP Cheat Sheet Series** | rolling | Condensed mitigations per topic | https://cheatsheetseries.owasp.org/ |
| **CWE** (MITRE) | v4.x | Weakness classification; map every finding to a CWE-ID | https://cwe.mitre.org/ |
| **CVSS** | **v4.0** | Severity scoring (v4.0 replaces 3.1) | https://www.first.org/cvss/ |

### AI / LLM
| Standard | Current version | Notes | Link |
|---|---|---|---|
| **OWASP Top 10 for LLM Applications** | **2025** | LLM01–LLM10; the 2025 version (not "AI01–AI04") | https://genai.owasp.org/ |
| **OWASP GenAI Security Project** | rolling | Umbrella project: Agentic AI threats, red teaming guide, LLM Top 10 | https://genai.owasp.org/ |
| **MITRE ATLAS** | rolling | The equivalent of ATT&CK for attacks on ML/AI systems — tactics and techniques | https://atlas.mitre.org/ |
| **NIST AI RMF 1.0** | 2023 | AI risk management framework | https://www.nist.gov/itl/ai-risk-management-framework |
| **NIST AI 600-1** (Generative AI Profile) | 2024 | GenAI profile for the AI RMF — concrete GenAI risks | https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf |
| **EU AI Act** | 2024 (phased rollout) | Compliance obligations, high-risk systems | https://artificialintelligenceact.eu/ |

## B. Methodologies (how to conduct a test)

| Methodology | Scope | Link |
|---|---|---|
| **PTES** (Penetration Testing Execution Standard) | 7 phases end-to-end: pre-engagement → reporting | http://www.pentest-standard.org/ |
| **NIST SP 800-115** | Technical guide to security testing (government standard) | https://csrc.nist.gov/pubs/sp/800/115/final |
| **OSSTMM 3** | "Operational security" measurement — RAV metrics | https://www.isecom.org/OSSTMM.3.pdf |
| **MITRE ATT&CK** | Database of adversary tactics/techniques (post-exploitation, kill-chain) | https://attack.mitre.org/ |
| **OWASP Firmware / Mobile / IoT Testing Guides** | Extensions for other platforms | https://owasp.org/ |
| **OWASP GenAI Red Teaming Guide** | Red-team methodology for GenAI/agentic systems | https://genai.owasp.org/ |

## C. Payload repositories (downloaded to `payloads/vendor/`)

| Repo | Contents | License | Status |
|---|---|---|---|
| **PayloadsAllTheThings** (swisskyrepo) | Curated payloads + bypasses for ~60 classes of web/API vulnerabilities, including `Prompt Injection` | MIT-ish (see repo) | ✅ downloaded |
| **SecLists** (danielmiessler) | Wordlists: fuzzing, discovery, usernames, passwords | MIT | ✅ downloaded (sparse: Fuzzing, Discovery/Web-Content, Usernames, Passwords) |
| **L1B3RT4S** (elder-plinius) | Per-vendor jailbreaks (OpenAI, Anthropic, Google, Meta, Mistral…) | see repo | ✅ downloaded |
| **JailbreakBench** | JBB-Behaviors benchmark (100 misuse behaviors + 100 benign), NeurIPS 2024 | MIT | ✅ downloaded |
| **garak** (NVIDIA) | LLM vulnerability scanner + a rich probe database: `dan`, `autodan`, `gcg`, `harmbench`, `inthewild_jailbreak_llms.json` | Apache-2.0 | ✅ downloaded |

Additional sources to consider (not downloaded, worth adding as needed):
- **FuzzDB** — https://github.com/fuzzdb-project/fuzzdb (fault-injection primitives)
- **HarmBench** — https://github.com/centerforaisafety/HarmBench (standardized red-team eval)
- **AdvBench** (from the llm-attacks/GCG repo) — harmful behaviors/strings
- **HackAPrompt dataset** — the largest collection of adversarial prompts from the competition
- **Nuclei templates** — https://github.com/projectdiscovery/nuclei-templates (template-based vulnerability scanning)

## D. Tooling ecosystem (details in [05-tooling.md](05-tooling.md))

- **AI red team:** garak (NVIDIA), PyRIT (Microsoft), promptfoo, deepteam, Giskard
- **Web/API:** Burp Suite, OWASP ZAP, nuclei, ffuf, httpx, nmap, sqlmap, nikto, Nuclei
- **Supply chain / SCA:** trivy, grype, syft, `pip-audit`, `npm audit`, OWASP Dependency-Check

## E. Bug bounty / practice (to calibrate against real-world techniques)

- HackerOne Hacktivity, PortSwigger Web Security Academy (free labs + payloads),
  PentesterLab, HackTricks (https://book.hacktricks.xyz/) — an encyclopedia of offensive techniques.

---
*Link and version verification: 2026-08-13. AI standards change quickly — check genai.owasp.org and atlas.mitre.org quarterly.*
