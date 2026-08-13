# Payloads — index, provenance and rules of use

> ⚠️ **For authorized testing only.** See [../research/00-authorization-and-scope.md](../research/00-authorization-and-scope.md).
> The payloads contain test markers (e.g. `SSN 123-45-6789`, `4111-1111-1111-1111`) — these are **synthetic
> data**, not real. Do not use real PII. Replace the `YOUR-COLLABORATOR` placeholders
> with your own OOB endpoint (Burp Collaborator / interactsh).

## Structure

```
payloads/
├── web/          # consolidated, canonical web payloads (per vulnerability)
├── ai/           # consolidated AI/LLM payloads (per technique)
└── vendor/       # full source repositories (downloaded), updatable
```

### `web/` — consolidated
| File | Vulnerability | OWASP 2025 |
|---|---|---|
| `sqli.txt` | SQL Injection | A05 |
| `xss.txt` | Cross-Site Scripting | A05 |
| `command-injection.txt` | OS Command Injection | A05 |
| `ssti.txt` | Server-Side Template Injection | A05 |
| `path-traversal.txt` | Path Traversal / LFI | A01/A05 |
| `ssrf.txt` | Server-Side Request Forgery | A01 |
| `xxe-nosqli-misc.txt` | XXE, NoSQLi, LDAP, Open Redirect, CRLF | A05/A01 |

### `ai/` — consolidated
| File | Technique | OWASP LLM 2025 |
|---|---|---|
| `jailbreak.txt` | Prompt injection / jailbreak (direct) | LLM01 |
| `indirect-injection.txt` | Indirect prompt injection (RAG/tool/email) | LLM01 |
| `system-prompt-extraction.txt` | System prompt leakage | LLM07 |
| `data-exfiltration.txt` | Sensitive info disclosure | LLM02/LLM08 |
| `output-handling.txt` | Improper output handling → web vulns | LLM05 |
| `encoding-bypass.txt` | Filter bypasses via encoding | LLM01 |

### `vendor/` — full sources (downloaded 2026-08-13)
| Directory | Repo | License | Contents |
|---|---|---|---|
| `PayloadsAllTheThings/` | swisskyrepo/PayloadsAllTheThings | see repo | ~60 classes of web/API vulnerabilities + `Prompt Injection` |
| `SecLists/` | danielmiessler/SecLists | MIT | Fuzzing, Discovery/Web-Content, Usernames, Passwords (sparse) |
| `L1B3RT4S/` | elder-plinius/L1B3RT4S | see repo | per-vendor jailbreaks (`OPENAI.mkd`, `ANTHROPIC.mkd`, …), `SYSTEMPROMPTS.mkd` |
| `jailbreakbench/` | JailbreakBench/jailbreakbench | MIT | JBB-Behaviors benchmark (NeurIPS 2024) |
| `garak/` | NVIDIA/garak | Apache-2.0 | LLM scanner + probe data: `data/dan/`, `data/gcg/`, `inthewild_jailbreak_llms.json`, `harmbench` |

## How to use (examples)

```bash
# Web directory fuzzing (ffuf + SecLists):
ffuf -u https://TARGET/FUZZ -w vendor/SecLists/Discovery/Web-Content/common.txt

# SQLi automation (sqlmap with a custom tamper list) — ONLY in scope:
sqlmap -u "https://TARGET/item?id=1" --batch --risk=2 --level=3

# LLM scan (garak) — ONLY an authorized endpoint:
python -m garak --model_type rest -G config.json --probes dan,promptinject,latentinjection

# Manual jailbreak test — iterate over the lines in ai/jailbreak.txt via your own harness
```

## Updating sources

```bash
# refresh the downloaded repos (run from the payloads/vendor directory):
for d in PayloadsAllTheThings L1B3RT4S jailbreakbench garak; do (cd "$d" && git pull --ff-only); done
(cd SecLists && git pull --ff-only)   # sparse checkout preserved
```

## Hygiene / safety
- Do not commit real secrets or customer data to this tree.
- OOB payloads (`YOUR-COLLABORATOR`) point at **your** controlled endpoint — never someone else's.
- Destructive tests (DoS, `DROP TABLE`, LLM flooding) — only with a written opt-in ([00](../research/00-authorization-and-scope.md)).
