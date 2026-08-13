# Bezpiecznik — pentesting agent (web + AI/LLM)

A conversational orchestrator that selects and runs security-testing tools,
correlates the results, and generates a report. The AI layer (attacker/judge multi-turn) runs on
a local **Ollama / qwen3.5:9b**.

> ⚠️ Authorized testing only. Consent gate: [core/scope.py](core/scope.py) +
> [../research/00-authorization-and-scope.md](../research/00-authorization-and-scope.md).

## Installation

```bash
pip install -r bezpiecznik/requirements.txt        # httpx, pydantic
ollama pull qwen3.5:9b                              # local model (attacker/judge/orchestrator)
# optional external tools (wrappers degrade gracefully when absent):
#   pip install garak ; brew install nmap sqlmap nikto ; nuclei ; ffuf
```

## Running

Point it at your **own authorized lab** (e.g. OWASP Juice Shop, DVWA, WebGoat, or a PortSwigger
Web Security Academy instance). No target is bundled.

**CONVERSATIONAL mode** (you talk to the agent; Qwen selects and invokes the tools itself via tool-calling):
```bash
python3 -m bezpiecznik chat
```

**AUTO mode** (asks for target/type/consent → full pipeline):
```bash
python3 -m bezpiecznik
```

**Programmatically:**
```python
from bezpiecznik.agent.orchestrator import Orchestrator
from bezpiecznik.core.models import Scope, Target, TargetType

scope = Scope(engagement="test", in_scope=["app.client.example"], authorized=True)
target = Target(url="https://app.client.example", type=TargetType.BOTH,
                llm_endpoint="https://app.client.example/api/chat")
orch = Orchestrator()
report, paths = orch.auto_run(target, scope)
orch.close()
```

## Configuration (ENV)

| Variable | Default | Description |
|---|---|---|
| `BEZ_LLM_MODEL` | `qwen3.5:9b` | Ollama model (attacker/judge) |
| `BEZ_LLM_HOST` | `http://localhost:11434` | Ollama endpoint |
| `BEZ_LLM_PROVIDER` | `ollama` | `ollama` \| `openai` |
| `BEZ_MAX_TURNS` | `6` | max turns in a multi-turn attack |
| `BEZ_RPS` | `2` | request rate-limit to the target |
| `BEZ_OOB` | `` | OOB domain (Collaborator/interactsh) |

## Architecture

See [GUIDE.md](GUIDE.md#4-architecture--how-it-works) — the "Architecture" section. In short:
`core` (llm/scope/http/models/logging) → `adapters` (recon/web/ai) →
`subagents` (chat_attacker/chat_judge + logic_tester on the LLM) → `correlate` → `report` → `agent` (orchestrator).

## What is implemented

| Module | Status | Note |
|---|---|---|
| Authorization gate (scope) | ✅ | hard, enforced before every action |
| Recon (native + nmap/ffuf) | ✅ | fingerprint, HTML crawl + form parsing, content discovery |
| **SPA-recon (headless browser)** | ✅ | Playwright/Chromium: executes JS, dismisses banners, captures XHR/fetch calls to the API → seeds. Finds endpoints in Angular/React/Vue that the HTML crawl cannot see |
| Web scanner (native) | ✅ | SQLi (error/boolean/**time-blind**), reflected XSS, **DOM-XSS**, cmd inj., **SSTI**, **SSRF**, traversal, **CRLF**, **LDAP**, open redirect, IDOR, headers |
| API scanner (native) | ✅ | **BOLA** (API1), **excessive data exposure** (API3), **XXE** |
| Advanced scanner (native) | ✅ | **NoSQLi**, **Stored XSS**, **CSRF**, **File upload**, **JWT** (alg:none + weak-secret cracking) |
| Business logic | ✅ | `run_business_logic_test` — planner+judge from a description |
| External web (sqlmap/nuclei/nikto) | ⚠️ wrapper | degrade gracefully when the binary is missing |
| AI single-turn (harness) | ✅ | payloads from `payloads/ai/*`; canary/prompt-leak/output-handling/indirect-injection detection |
| AI multi-turn (attacker+judge) | ✅ | Crescendo/PAIR on qwen3.5:9b |
| garak | ✅ | real wrapper: REST config + parsing of the v0.16 report |
| PyRIT | ⚠️ wrapper | code-complete + graceful-skip; the native chat-attacker covers multi-turn |
| Correlation + report | ✅ | dedupe, CVSS4.0, JSON + Markdown + HTML |
| AUTO orchestrator | ✅ | intake → web/AI routing → report |
| CONVERSATIONAL orchestrator | ✅ | tool-calling on qwen3.5:9b (`python -m bezpiecznik chat`) |

See the [in-depth guide](GUIDE.md) for the full attack-vector coverage matrix (including what is
*not* automated and why).
