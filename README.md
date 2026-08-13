<div align="center">

<img src="assets/bezpiecznik.png" alt="Bezpiecznik" width="420"/>

# 🛡️ Bezpiecznik

**A local-first, LLM-driven penetration-testing agent for web apps _and_ AI chatbots.**

You talk to it in plain language. It picks the right tools, runs the tests, reasons about
the results, and writes you a report — all powered by a model running on **your own machine**.

<sub>_Bezpiecznik_ is Polish for "fuse / safety switch" — the thing that trips before something burns down.</sub>

<br/>

![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![LLM](https://img.shields.io/badge/LLM-local%20(Ollama)-brightgreen)
![Web](https://img.shields.io/badge/web-21%20vuln%20classes-orange)
![AI](https://img.shields.io/badge/AI%2FLLM-OWASP%20LLM%20Top%2010-purple)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Authorized use only](https://img.shields.io/badge/use-authorized%20testing%20only-red)

</div>

---

## ✨ What it is

Most scanners are dumb pattern-matchers; most "AI pentest" demos are just a chat wrapper.
**Bezpiecznik is both** — a deterministic scanner engine *and* an LLM agent, each used where it wins:

- 🧠 **The LLM** talks to you, plans the engagement, drives multi-turn attacks on chatbots, and
  reasons about business logic (where success is *semantic*, not a signature).
- ⚙️ **The deterministic engines** find injection, XSS, SSRF, XXE, JWT flaws and more with
  zero false-drama (true/false differential SQLi, real-browser DOM-XSS execution, timing-based blind SQLi…).
- 🔒 **Everything runs locally** on [Ollama](https://ollama.com) (`qwen3.5:9b` by default) — your
  targets, payloads and jailbreaks never leave your machine.

> ⚠️ **Authorized testing only.** Bezpiecznik performs active, sometimes state-changing requests.
> A hard authorization gate blocks any action outside an explicitly-approved scope. See
> [`research/00-authorization-and-scope.md`](research/00-authorization-and-scope.md). Testing systems
> without written permission is a crime in most jurisdictions.

---

## 🎬 What it feels like

```text
operator ▸ I have written consent to test https://shop.example (web-app, it's an Angular SPA). Find vulnerabilities.

  ⚙ set_scope(url=https://shop.example, type=web-app, authorized=True)   ✓ scope set
  ⚙ run_recon()                                                          ✓ SPA-recon captured /rest/products/search?q
  ⚙ run_web_scan()
    ● [critical] SQL Injection (error-based) in parameter 'q'
    ● [high]     DOM-based XSS (#/search?q)
    ● [low]      Missing security headers: Content-Security-Policy
  ⚙ generate_report()                                                    📄 Report: file://…/report.html

🛡 Bezpiecznik ▸ Found 3 issues. The critical one is an error-based SQLi in the product search API…
```

Live spinner while it thinks, streamed answers, findings appearing in real time, and a clean
HTML report at the end. Type `/report` to open it in your browser.

---

## 🚀 Quick start

```bash
# 1. Install
pip install -r bezpiecznik/requirements.txt      # httpx, pydantic, playwright
python -m playwright install chromium            # for SPA-recon & DOM-XSS
ollama pull qwen3.5:9b                            # the local brain (attacker / judge / orchestrator)

# 2. Talk to the agent
python3 -m bezpiecznik chat
```

Then just describe your **authorized** target:

> *"I'm authorized to test http://localhost:8080 — it's a web app with a chatbot at /api/chat. Find issues and show me how to reproduce them."*

Prefer a scripted, non-interactive run? Use `python3 -m bezpiecznik` (guided intake → full pipeline → report).

---

## 🧰 What's under the hood

<table>
<tr><th>Layer</th><th>What it does</th></tr>
<tr><td>🗣️ <b>Conversational agent</b></td><td>Tool-calling loop on <code>qwen3.5:9b</code>; picks tools, streams answers, asks you when unsure</td></tr>
<tr><td>🔎 <b>Recon</b></td><td>Fingerprint + form parsing, <b>SPA-recon</b> (headless Chromium captures XHR/API calls), nmap/ffuf — run in parallel</td></tr>
<tr><td>🌐 <b>Web scanner</b></td><td>SQLi (error/boolean/<b>time-blind</b>), reflected & <b>DOM-XSS</b>, cmd-injection, SSTI, SSRF, path traversal, CRLF, LDAP, IDOR, open redirect, headers</td></tr>
<tr><td>🧩 <b>API & advanced</b></td><td>BOLA, excessive data exposure, XXE, NoSQLi, Stored XSS, CSRF, file upload, <b>JWT</b> (alg:none + weak-secret cracking)</td></tr>
<tr><td>🤖 <b>AI / LLM testing</b></td><td>single-turn harness + <b>multi-turn attacker & judge</b> subagents (PAIR/Crescendo), garak wrapper, indirect injection, system-prompt leak</td></tr>
<tr><td>💼 <b>Business logic</b></td><td><b>Describe a rule, it tries to break it</b> — planner+judge plan HTTP sequences (double-booking, buy-for-0, coupon abuse)</td></tr>
<tr><td>📄 <b>Reporting</b></td><td>Correlated findings → JSON + Markdown + a styled HTML report with reproduction steps</td></tr>
</table>

<details>
<summary><b>🗺️ Architecture (click to expand)</b></summary>

```
You (operator)
   │  conversation (tool-calling)
   ▼
agent/cli.py ─ conversational orchestrator (LLM: qwen3.5:9b)
   │  invokes 10 tools (agent/tools.py) behind a hard scope gate
   ├── core/        scope · llm (Ollama/API) · http (rate-limited) · models · logging
   ├── adapters/
   │   ├── recon/   recon (nmap ∥ ffuf ∥ HTML) + spa_recon (headless browser)
   │   ├── web/     scanner · api_scanner · advanced_scanner · jwt_scanner · dom_xss
   │   └── ai/      llm_harness · garak · pyrit · chat_client
   ├── subagents/   chat_attacker + chat_judge (multi-turn) · logic_tester (business logic)
   ├── correlate/   dedupe + CVSS 4.0 scoring + OWASP/CWE/ATLAS mapping
   └── report/      JSON + Markdown + HTML
```
</details>

---

## 🎯 Coverage

<table>
<tr><th>Web / API</th><th>AI / LLM</th></tr>
<tr valign="top"><td>

SQLi (error / boolean / time-blind) · Reflected XSS · **DOM XSS** ·
Stored XSS · Command injection · SSTI · SSRF · Path traversal ·
Open redirect · IDOR / **BOLA** · Excessive data exposure · XXE ·
**CRLF** · **NoSQLi** · **LDAP** · **JWT** (alg:none + weak secret) ·
**CSRF** · **File upload** · Security misconfig · **Business logic**

</td><td>

Prompt injection (single + **multi-turn**) · System-prompt leakage ·
Sensitive info disclosure · Improper output handling ·
**Indirect injection** · garak probe suite

Mapped to **OWASP LLM Top 10:2025** & **MITRE ATLAS**.

</td></tr>
</table>

Full, honest coverage matrix (incl. what's *not* automated and why) in the
[**in-depth guide**](bezpiecznik/GUIDE.md#10--attack-vector-cover).

---

## 📚 Documentation

| Doc | What's inside |
|---|---|
| [**bezpiecznik/GUIDE.md**](bezpiecznik/GUIDE.md) | In-depth guide: every tool, subagent, payload set & coverage matrix |
| [**bezpiecznik/README.md**](bezpiecznik/README.md) | Package README: install, config, module map |
| [research/](research/) | Methodology: [authorization](research/00-authorization-and-scope.md) · [sources](research/01-sources.md) · [methodologies](research/02-methodologies.md) · [web](research/03-web-app-methodology.md) · [AI/LLM](research/04-ai-llm-methodology.md) · [tooling](research/05-tooling.md) |
| [payloads/](payloads/README.md) | Curated web (222) & AI (73) payloads + provenance |

---

## ⚙️ Configuration

All via environment variables (sensible local defaults):

| Variable | Default | Purpose |
|---|---|---|
| `BEZ_LLM_MODEL` | `qwen3.5:9b` | Ollama model (orchestrator / attacker / judge) |
| `BEZ_LLM_HOST` | `http://localhost:11434` | Ollama endpoint |
| `BEZ_LLM_PROVIDER` | `ollama` | `ollama` \| `openai` (use a stronger model for the planner/judge if you want) |
| `BEZ_RPS` | `2` | Request rate-limit toward the target |
| `BEZ_MAX_TURNS` | `6` | Max turns for multi-turn attacks |

---

## 🛑 Responsible use

Bezpiecznik is for **authorized** security testing, CTFs, and learning on systems you own or have
**written permission** to test. It ships **no bundled targets** — point it at your own lab
(e.g. OWASP Juice Shop, DVWA, PortSwigger Web Security Academy) or an authorized engagement.
The built-in scope gate refuses out-of-scope and destructive actions by default. You are responsible
for how you use it.

## 📜 License

MIT — see [LICENSE](LICENSE). Third-party payload collections retain their own licenses (see
[payloads/README.md](payloads/README.md)).

<div align="center"><sub>Built as a study in where deterministic tooling ends and LLM reasoning begins.</sub></div>
