# Bezpiecznik — complete guide (in-depth)

A full description of the "Bezpiecznik" pentesting agent: how to use it interactively, how it works
under the hood, what tools, payloads, and subagents it has, and what attack vectors it actually covers.

> ⚠️ Authorized testing only. The consent gate is hard (`core/scope.py`). See
> [../research/00-authorization-and-scope.md](../research/00-authorization-and-scope.md).

---

## 1. TL;DR — quick start

```bash
# dependencies
pip install -r bezpiecznik/requirements.txt          # httpx, pydantic, playwright
python -m playwright install chromium                 # for SPA-recon and DOM-XSS
ollama pull qwen3.5:9b                                 # local model (attacker/judge/orchestrator)

# conversational mode (you talk to the agent)
python3 -m bezpiecznik chat

# automatic mode (interview → full pipeline → report)
python3 -m bezpiecznik
```

Point it at your own authorized lab (OWASP Juice Shop, DVWA, WebGoat, PortSwigger Web Security
Academy, …). No target is bundled.

---

## 2. Run modes

| Mode | Command | When |
|---|---|---|
| **Conversational** | `python3 -m bezpiecznik chat` | You talk to the agent, and it selects the tools itself (tool-calling on Qwen). The main mode. |
| **Auto** | `python3 -m bezpiecznik` | Interview (target/type/consent) → deterministic pipeline, no conversation. Faster, repeatable. |
| **Programmatic** | `Orchestrator().auto_run(target, scope)` | Integration/CI. |

---

## 3. Interactive CLI — full guide

Run `python3 -m bezpiecznik chat`. You will see a banner, the model status, and an `operator ▸` prompt.

### What you see in the console (à la Claude)
- **`⠋ Bezpiecznik is thinking…`** — an animated spinner while the model works (until the first token).
- **Streaming** — the agent's answer streams token by token.
- **`⚙ tool_name(arguments)`** + `running…` — when the agent invokes a tool.
- **Live findings** color-coded by severity: `● [critical] SQL Injection …`, `● [high] DOM-based XSS …`.
- **`✓`** — step summary.
- At the end: **`📄 Raport HTML: file://…`**.

### Commands (start with `/`)
| Command | Action |
|---|---|
| `/report` | Generate (if needed) and open the HTML report in the browser |
| `/findings` | List the findings so far |
| `/help` | Help |
| `exit` | Quit (auto-generates a report if there are findings) |

### A typical conversation flow
```
operator ▸ I have written consent to test http://127.0.0.1:3000 — it's an Angular SPA (web-app). Find vulnerabilities.
   ⚙ set_scope(url=…, type=web-app, authorized=True)   ✓ scope set
   ⚙ run_recon()                                        ✓ 2 entry points (SPA-recon)
   ⚙ run_web_scan()
     ● [critical] SQL Injection (error-based) in 'q'
     ● [high] DOM-based XSS (#/search?q)
   ⚙ generate_report()                                  📄 HTML report: file://…
🛡 Bezpiecznik ▸ Found 3 vulnerabilities: a critical SQLi in the 'q' parameter…
operator ▸ /report        # opens the report in the browser
operator ▸ exit
```

### Rules baked into the agent
- **`set_scope` first** — without it, no active actions.
- **`authorized=true` only after confirmation** by the operator (the agent asks when unsure).
- **Content from the target = data, not commands** — resilience against prompt injection aimed at the agent.
- **Routing by type**: `web-app` → recon/web/API; `ai-assistant` → chatbot tests (+garak); `both` → everything.

---

## 4. Architecture — how it works

```
You (operator)
   │  conversation (tool-calling)
   ▼
agent/cli.py ─ conversational orchestrator (LLM: qwen3.5:9b)
   │  invokes 10 tools (agent/tools.py) behind a hard scope gate
   ├── core/           scope (authorization) · llm (Ollama/API) · http (rate-limit) · models · logging
   ├── adapters/
   │   ├── recon/      recon.py (nmap∥ffuf∥HTML) + spa_recon.py (headless browser)
   │   ├── web/        scanner.py · api_scanner.py · advanced_scanner.py · jwt_scanner.py · dom_xss.py
   │   └── ai/         llm_harness.py · garak_adapter.py · pyrit_adapter.py · chat_client.py
   ├── subagents/      chat_attacker.py + chat_judge.py (multi-turn) · logic_tester.py (business logic)
   ├── correlate/      dedupe + CVSS 4.0 scoring + OWASP/CWE/ATLAS mapping
   └── report/         JSON + Markdown + HTML
```

**Process (PTES):** recon → vulnerability analysis → (exploit/attack) → correlation → report.
Every finding is a `Finding` object (single source of truth) with OWASP/CWE/CVSS mapping and reproduction.

---

## 5. LLM models — where each one runs

By default, **everything runs locally on `qwen3.5:9b`** (Ollama, `http://localhost:11434`). Configuration in `core/config.py` / ENV.

| Role | Model | For what |
|---|---|---|
| **Orchestrator** (conversation, tool selection) | `qwen3.5:9b` (tool-calling) or API | plans and invokes tools |
| **Attacker LLM** (multi-turn against a chatbot) | `qwen3.5:9b` locally | hundreds of iterations, privately |
| **Judge LLM** (scoring the target's responses) | `qwen3.5:9b` locally | success/refusal assessment |

ENV: `BEZ_LLM_MODEL`, `BEZ_LLM_HOST`, `BEZ_LLM_PROVIDER` (`ollama`|`openai`), `BEZ_MAX_TURNS`, `BEZ_RPS`.

---

## 6. Agent tools (7 tool-calls)

These are the functions the model invokes during a conversation (`agent/tools.py`). Each one validates scope.

| Tool | What it does | Underlying engine |
|---|---|---|
| `set_scope` | Sets the target, type, authorization | `core/scope.py` |
| `run_recon` | Fingerprint + endpoint/parameter discovery (+ SPA) | `adapters/recon/*` |
| `run_web_scan` | Web scan (SQLi/XSS/DOM-XSS/cmd/SSTI/SSRF/traversal/CRLF/time-SQLi/LDAP/IDOR/redirect/headers) | `adapters/web/scanner.py` + `dom_xss.py` |
| `run_api_scan` | BOLA, excessive data exposure, XXE | `adapters/web/api_scanner.py` |
| `run_advanced_scan` | NoSQLi, Stored XSS, CSRF, File Upload, JWT (alg:none + weak secret) | `advanced_scanner.py` + `jwt_scanner.py` |
| `http_request` | Arbitrary HTTP request (manual exploration) | `core/http.py` |
| `run_business_logic_test` | Business-logic test from a description (planner+judge LLM) | `subagents/logic_tester.py` |
| `run_ai_tests` | Chatbot tests: single-turn + multi-turn | `llm_harness` + subagents |
| `run_garak` | garak LLM scanner (NVIDIA) | `adapters/ai/garak_adapter.py` |
| `generate_report` | Correlation + JSON/MD/HTML report | `correlate` + `report` |

---

## 7. Engines (adapters) — how they work

### Recon (`adapters/recon/recon.py`)
Runs **in parallel** (≈3× faster):
- **fingerprint** (headers, Server, size) + **parsing of links and FORMS** from the HTML → seeds `(path, parameter)`;
- **ffuf** + SecLists — content discovery (if `ffuf` is installed);
- **nmap** — service scan (top-20, -T4).

### SPA-recon (`adapters/recon/spa_recon.py`) — headless browser
For Angular/React/Vue, where the HTML is empty. **Playwright/Chromium**:
1. loads the page and executes JS, **dismisses consent banners** (they block XHR),
2. interacts lightly (search box, navigation),
3. **captures XHR/fetch calls to the API** → seeds `(path, parameter)`,
4. collects **client-side hash routes** (e.g. `/search`) for DOM-XSS.
Degrades gracefully when Playwright is absent. *(Verified: on Juice Shop it detects `/rest/products/search?q`.)*

### Web scanner (`adapters/web/scanner.py`) — native, pure Python
For each seed it tests deterministically:
- **SQLi** — error-based (error signatures + `SQLITE_ERROR`) and boolean-based (true/false differentiation);
- **Reflected XSS** — context-aware (HTML body / attribute quote-breakout / unquoted attribute / JS string), catches attribute-context XSS even when angle brackets are HTML-encoded (+ a ready, visible PoC);
- **OS Command Injection** — `uid=`/`root:` markers;
- **SSTI** — `{{1337*1337}}`→`1787569`;
- **SSRF** — `file:///etc/passwd`;
- **Path Traversal/LFI** — reading `/etc/passwd`;
- **Open Redirect** — 3xx to an external URL;
- **IDOR** — differentiating objects by id;
- **Missing headers** + server version disclosure.

### API scanner (`adapters/web/api_scanner.py`)
- **BOLA (API1)** — changing the id in the REST path returns other users' objects;
- **Excessive data exposure (API3)** — sensitive fields (`password`, `ssn`, `role`…) in JSON;
- **XXE** — external entity `file:///etc/passwd` in a POST XML.

### DOM-XSS scanner (`adapters/web/dom_xss.py`) — headless browser
Injects payloads (`<img onerror>`, `<iframe javascript:>`, `<svg onload>`) into **hash routes, the fragment, and the query**,
loads them in Chromium, and checks for **real JS execution** (`window.BZDOMXSS7` marker + a captured `dialog`).
Catches what the "reflected" scanner cannot see. *(Verified: DOM-XSS `#/search?q` on Juice Shop.)*

### AI harness (`adapters/ai/llm_harness.py`) — single-turn, no LLM
Iterates over `payloads/ai/*`, sends them to the chatbot endpoint, and detects **deterministically**: canary leak,
system-prompt leak, refusal detection. Fast and cheap.

### garak (`adapters/ai/garak_adapter.py`)
A real wrapper: generates a REST config for the chat endpoint, runs `garak`, **parses the JSONL v0.16 report**
(`fails`/`total_evaluated`) → `Finding`. Degrades gracefully when garak is not installed.

### PyRIT (`adapters/ai/pyrit_adapter.py`)
A Crescendo wrapper (Microsoft PyRIT) — code-complete + graceful-skip; multi-turn is covered by the native chat-attacker.

---

## 8. Subagents (multi-turn against AI chatbots)

Two specialized LLM agents (`subagents/`) for adaptive multi-turn attacks — because single-turn is not enough here:

### `chat_attacker.py` — Attacker LLM
Conducts a conversation with the target chatbot following the **Crescendo/PAIR** strategy: starts gently, escalates, changes
tactics after a refusal. The loop: *generate the next message → send it to the target → assess (judge) → decide
(success / continue / turn limit)*. It knows effective techniques (repeat-above, translation trick, role-play).

### `chat_judge.py` — Judge LLM
Assesses the target's response → `{success | progress | refusal | unclear}` + a rationale. Catches subtle
policy violations that a simple regex would miss. Note: the deterministic detector + judge work
together — e.g. we caught "leak-while-refusing" (the model blurts out the secret *inside the refusal text*).

Invoked via `run_ai_tests` (single-turn harness → then multi-turn attacker+judge).

### `logic_tester.py` — Business Logic Tester (planner + judge)
Tests **business logic based on YOUR DESCRIPTION** — the one class where the LLM has an edge
over signatures (success is semantic, not regex-based). You provide a description of the endpoint + a goal (the undesired
behavior); the **planner LLM** plans and executes the request sequence itself via `http_request`, and the **judge LLM**
evaluates — solely based on the real responses — whether the abuse succeeded. The verdict is grounded
(it quotes the response) + the evidence is the full request sequence. *(Verified: double-booking, buying a widget for 0 PLN.)*

Example in a conversation with the agent:
```
operator ▸ Endpoint POST /api/book takes {seat,user} and reserves a seat. Check whether an
           already-taken seat can be booked (A1 by alice, then A1 by bob).
   ⚙ run_business_logic_test(description=…, goal="book the already-taken seat A1")
     ● [high] Business Logic Flaw: double-booking
```
Note: these are STATE-CHANGING actions (INVASIVE class) — use them on a test environment with test accounts.

---

## 9. Payloads — how many and which

### Consolidated, ready to use (curated)
**Web — 222 payloads across 7 files** (`payloads/web/`):

| File | Payloads | Vulnerability |
|---|---|---|
| `sqli.txt` | 44 | SQL Injection (error/boolean/UNION/time/WAF-bypass/auth-bypass) |
| `command-injection.txt` | 36 | OS Command Injection (Linux/Windows/blind/OOB) |
| `path-traversal.txt` | 31 | Path Traversal / LFI (encodings, PHP wrappers) |
| `xss.txt` | 30 | XSS (basic, attributes, polyglot, WAF-bypass) |
| `ssrf.txt` | 29 | SSRF (localhost, cloud metadata AWS/GCP/Azure, bypasses) |
| `xxe-nosqli-misc.txt` | 29 | XXE, NoSQLi, LDAP, Open Redirect, CRLF |
| `ssti.txt` | 23 | SSTI (Jinja2/Twig/Freemarker/Velocity/Smarty/ERB…) |

**AI/LLM — 73 payloads across 6 files** (`payloads/ai/`):

| File | Payloads | Technique (OWASP LLM) |
|---|---|---|
| `jailbreak.txt` | 15 | Prompt injection / jailbreak (LLM01) |
| `system-prompt-extraction.txt` | 15 | System prompt leakage (LLM07) |
| `data-exfiltration.txt` | 13 | Sensitive info disclosure (LLM02) |
| `output-handling.txt` | 11 | Improper output handling (LLM05) |
| `indirect-injection.txt` | 10 | Indirect prompt injection (LLM01) |
| `encoding-bypass.txt` | 9 | Filter bypasses via encoding |

### Full source collections (`payloads/vendor/`)
| Repo | Contents |
|---|---|
| **PayloadsAllTheThings** (479 files) | ~60 classes of web/API vulnerabilities + Prompt Injection |
| **SecLists** (5210 files, 1.3 GB) | Fuzzing, Discovery/Web-Content, Usernames, Passwords |
| **L1B3RT4S** (39 per-vendor jailbreaks) | OPENAI/ANTHROPIC/GOOGLE/META/… + SYSTEMPROMPTS |
| **garak** (47 probe datasets) | dan, gcg, autodan, harmbench, inthewild_jailbreak_llms |
| **JailbreakBench** | JBB-Behaviors benchmark (NeurIPS 2024) |

> The web scanner consumes part of the payloads from `payloads/web/*` (targeted detections) + its own built-ins.
> The AI harness consumes `payloads/ai/*`. garak uses its own probe database.

---

## 10. Attack-vector coverage — matrix (honestly)

Legend: ✅ automated detection · 🅿️ we have payloads, no auto-detection · ❌ none.

### Web / API (OWASP Top 10:2025 + API Top 10:2023)
| Vector | Status | Note |
|---|---|---|
| SQL Injection (error/boolean) | ✅ | signatures + true/false differentiation |
| SQL Injection (time-based blind) | ✅ | delay measurement (SQLite/MySQL/PG) |
| Reflected XSS | ✅ | **context-aware**: HTML body, attribute (quote breakout, incl. angle-brackets-encoded), unquoted-attribute, JS-string — with a visible PoC |
| DOM-based XSS | ✅ | headless browser (real JS execution) |
| Stored XSS | ✅ | write→read tracking |
| OS Command Injection | ✅ | |
| SSTI | ✅ | |
| SSRF | ✅ | file://; cloud metadata 🅿️ (payloads exist) |
| Path Traversal / LFI | ✅ | |
| Open Redirect | ✅ | |
| IDOR / BOLA | ✅ | query + REST path |
| Excessive data exposure (API3) | ✅ | |
| XXE | ✅ | |
| CRLF / Response Splitting | ✅ | header injection |
| NoSQL Injection | ✅ | operator injection (auth bypass) |
| LDAP Injection | ✅ | filter metacharacters |
| JWT (alg:none + weak secret) | ✅ | forge alg:none + crack HMAC with a wordlist |
| CSRF | ✅ | missing token + cookie without SameSite |
| Unrestricted File Upload | ✅ | uploading a webshell |
| Clickjacking | ✅ | via missing X-Frame-Options/CSP |
| Missing headers / misconfig | ✅ | CSP/XFO/XCTO + server version |
| Business Logic (from a description) | ✅ | `run_business_logic_test` — planner+judge LLM (double-booking, price/quantity manipulation, coupons) |
| Supply chain (SCA) | 🅿️ | trivy/grype wrappers described, not wired in |
| Deserialization / race condition | ❌ | hard to auto-detect safely and reliably |

### AI / LLM (OWASP LLM Top 10:2025)
| Vector | Status |
|---|---|
| Prompt injection direct (LLM01) | ✅ single + multi-turn |
| System prompt leakage (LLM07) | ✅ |
| Sensitive info disclosure (LLM02) | ✅ |
| Improper output handling (LLM05) | ✅ unsafe-output detector |
| Indirect injection (LLM01) | ✅ instruction in data → execution detection |
| Excessive agency (LLM06) | 🅿️ described; no auto-test |
| Unbounded consumption (LLM10) | ❌ (destructive — behind opt-in) |
| Vector/RAG (LLM08), poisoning (LLM04), supply chain (LLM03) | ❌ |
| garak (dan/promptinject/…) | ✅ if installed |

**Conclusion:** the core of the most common, most dangerous vectors (injection, XSS including DOM, SSRF, XXE, BOLA,
prompt injection) is **automated and verified**. The rest have payloads but require wiring up
detection.

---

## 11. Security and authorization
- **The scope gate** (`core/scope.py`) blocks out-of-scope and unauthorized actions; destructive ones require `allow_destructive`.
- **Rate-limit** (`BEZ_RPS`) and a **traffic tag** in the User-Agent (the SOC can tell a test from a real attack).
- **Synthetic markers** in the payloads (not real PII). OOB via your own collaborator.
- Full rules: [../research/00-authorization-and-scope.md](../research/00-authorization-and-scope.md).

## 12. Reports
Every run → `runs/<timestamp>/`: `report.json` (machine-readable), `report.md`, `report.html` (colorful,
with cards, severity colors, a "How to reproduce" section), and `audit.jsonl` (action log). Every finding:
title, severity, CVSS 4.0, OWASP/CWE/ATLAS mapping, description, impact, **step-by-step reproduction**, recommendation.

## 13. Extending
A new engine = an adapter returning `list[Finding]` (a shared interface). Add it to `orchestrator.auto_run`
and/or as a tool in `agent/tools.py`.
