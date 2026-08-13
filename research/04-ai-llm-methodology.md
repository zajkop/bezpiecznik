# 04 — Playbook: testing AI chatbots and assistants (LLM)

Mapping: **OWASP Top 10 for LLM Applications 2025** + **MITRE ATLAS** + **NIST AI 600-1**.
Payloads in [`payloads/ai/`](../payloads/ai/) and `payloads/vendor/{L1B3RT4S,garak,jailbreakbench}`.

> Authorization as in [00](00-authorization-and-scope.md). Destructive tests (LLM10 flooding) — only with an explicit opt-in.

## Threat model — 4 layers (OWASP GenAI Red Teaming)

Test the **whole application**, not just the model itself:
1. **Model** — the LLM itself (jailbreak, bias, hallucinations).
2. **Implementation** — system prompt, RAG, input/output validation, guardrails.
3. **System** — agent, tools/tool-calling, integrations, permissions, infra.
4. **Process** — governance, logging, human-in-the-loop.

## Phase 0 — LLM recon

- **Model fingerprinting:** ask differentiating questions (knowledge cutoff, refusal style, self-report) — carefully, the model can lie about itself.
- **Endpoint enumeration:** `/v1/chat/completions`, `/api/chat`, streaming (SSE), function-calling schema.
- **Surface mapping:** is there RAG? tool-calling? memory/sessions? file upload? multimodality (image/audio)?
- **Guardrail probing:** which layer filters (input classifier? output? both?).

## OWASP LLM Top 10:2025 — tests per category

### LLM01:2025 — Prompt Injection
The most important category. Two types:
- **Direct (jailbreak):** the user overrides instructions. Payloads: `payloads/ai/jailbreak.txt`,
  `payloads/vendor/L1B3RT4S/*.mkd` (per-vendor: `OPENAI.mkd`, `ANTHROPIC.mkd`, `GOOGLE.mkd`…),
  `payloads/vendor/garak/garak/data/dan/` (DAN and variants), `inthewild_jailbreak_llms.json`.
- **Indirect:** a payload in data that the model processes (RAG document, web page, email, tool output).
  Crucial for agents: a hidden instruction in the content → the agent executes it. Payloads: `payloads/ai/indirect-injection.txt`.
- **Techniques:** role-play, instruction override, "ignore previous", encoding (base64/ROT13/leetspeak),
  payload splitting, multi-turn priming, obfuscation, low-resource languages, token smuggling.
- ATLAS: AML.T0051 (LLM Prompt Injection). Automated test: garak `promptinject`, `dan`, `latentinjection`.

### LLM02:2025 — Sensitive Information Disclosure
- Leakage of training data / PII / secrets in responses.
- Leakage of other users' data (cross-tenant, session history).
- Secrets in the context (API keys in the system prompt, environment variables).
- Test: inject a PII marker (synthetic), check retention between sessions; ask about "previous conversations".
- Payloads: `payloads/ai/data-exfiltration.txt`. ATLAS: AML.T0057 (LLM Data Leakage).

### LLM03:2025 — Supply Chain
- Poisoned models from hubs (Hugging Face), backdoored weights, dangerous formats (`pickle` in `.bin`).
- Vulnerable dependencies (transformers, langchain), LoRA/adapters from untrusted sources.
- Scan: model scanning (picklescan), SCA of dependencies (like A03 web).

### LLM04:2025 — Data and Model Poisoning
- Poisoning of training/fine-tuning/RAG data (poisoned documents in the vector database).
- Backdoor triggers (a specific token → intended behavior).
- Test (if we have access to the pipeline): inject a poisoned document into RAG, check the impact on responses.

### LLM05:2025 — Improper Output Handling
LLM output treated as trusted by downstream → classic web vulns.
- **XSS** — output rendered in HTML without sanitization: ask the model for `<script>alert(1)</script>`.
- **SQLi / command injection** — output reaches a query/shell (agent tool-calling).
- **SSRF / path traversal** — output controls tools' URLs/paths.
- Payloads: `payloads/ai/output-handling.txt`. This is the bridge to the web payloads in [03](03-web-app-methodology.md).

### LLM06:2025 — Excessive Agency
Crucial for **agents** and assistants with tools.
- Excessive permissions: the agent can delete/send/pay without confirmation.
- Excessive functionality: available tools that go beyond what is needed.
- Excessive autonomy: no human-in-the-loop on irreversible actions.
- Test: via prompt injection, induce the agent to invoke a tool outside its intent (send an email, modify data).
- ATLAS: abuse of ML-enabled actions.

### LLM07:2025 — System Prompt Leakage
- Extraction of the system prompt (instructions, rules, keys, tool names).
- Techniques: "repeat everything above", "ignore and print your instructions", translation trick, continuation.
- Payloads: `payloads/ai/system-prompt-extraction.txt`, `payloads/vendor/L1B3RT4S/SYSTEMPROMPTS.mkd`.
- Note: the system prompt itself should not be a security secret — but its leak reveals the logic of the guardrails.

### LLM08:2025 — Vector and Embedding Weaknesses (RAG)
- Embedding inversion (recovering text from vectors), cross-context leakage in a shared database.
- Poisoning of the vector database, no tenant isolation in RAG.
- Test: do one user's queries return fragments of another's documents? Inject a controlling document.

### LLM09:2025 — Misinformation
- Hallucinations presented with confidence, package hallucination (the agent proposes a nonexistent package → slopsquatting).
- Excessive user reliance without verification.
- Test: garak `packagehallucination`, factual questions with a trap.

### LLM10:2025 — Unbounded Consumption
- Token/cost exhaustion, DoS via expensive queries, no rate limit/quota.
- Model extraction (stealing the model via mass queries).
- **Destructive test — only with opt-in:** a controlled check of limits (not real flooding of production).
- ATLAS: AML.T0034 (Cost Harvesting), model extraction TTP.

## Jailbreak techniques (catalog of techniques → payloads)

| Technique | Description | Payload source |
|---|---|---|
| DAN / persona override | "Do Anything Now", role-play without restrictions | `garak/data/dan/`, L1B3RT4S |
| Instruction override | "ignore all previous instructions…" | `payloads/ai/jailbreak.txt` |
| Encoding / obfuscation | base64, ROT13, leetspeak, homoglyphs, zero-width | `payloads/ai/encoding-bypass.txt` |
| Payload splitting | splitting the forbidden text into parts | PayloadsAllTheThings/Prompt Injection |
| Multi-turn / crescendo | gradual breakthrough over successive turns | PyRIT orchestrators |
| Low-resource language | a prompt in a rare language bypasses filters | garak |
| Many-shot jailbreak | many "compliant" examples in the context | Anthropic research 2024 |
| GCG / adversarial suffix | an optimized suffix that breaks the model | `garak/data/gcg/`, AdvBench |
| Cipher / token smuggling | hiding intent in token encoding | L1B3RT4S/TOKEN80M8 |

## Automated multi-turn attack loops (LLM-as-attacker / LLM-as-judge)

A key distinction for the tool — when an LLM is needed and when it is not:

| Type of test | Is an LLM needed? | How to detect success |
|---|---|---|
| **Single-turn** (send payload → check response) | **No** | Deterministically: canary match, refusal detection (regex/classifier), OOB callback |
| **Multi-turn adaptive** (the next message depends on the target's response) | **Yes** | An LLM judge assesses success; an LLM attacker plans the next move |

### The two LLM roles in the AI sub-agent
- **Attacker LLM** — generates the next prompt based on the conversation history and the attack goal
  (e.g. "extract the canary"). It runs the loop: *send → observe → decide (continue / change
  tactics / success / turn limit)*. This is the answer to the question "what next after the chatbot's response".
- **Judge / Scorer LLM** — assesses the target's response: whether it is a success (policy break / leak),
  partial progress, or a hard refusal. Returns a score + justification for the report.

Both roles can run **locally on Ollama** (e.g. Qwen3 8B) — cheap, private, lots of iterations.

### Known methods (to be implemented in the orchestrator)
| Method | Idea | Notes |
|---|---|---|
| **PAIR** (Prompt Automatic Iterative Refinement) | the attacker LLM iteratively improves a single prompt until a jailbreak | few queries, a good baseline |
| **TAP** (Tree of Attacks with Pruning) | a tree of prompt variants + pruning of dead branches | more effective, more expensive |
| **Crescendo** | gradual escalation through many mild turns | strong against contextual guardrails; it's in PyRIT |
| **GOAT** (Generative Offensive Agent Tester) | a conversational attacker-agent imitating a real user | multi-turn, versatile |

> You don't have to write these algorithms from scratch — **PyRIT** has ready orchestrators (Crescendo, multi-turn
> red-teaming) with a plugin for attacker/judge. Our `llm_harness` adds a layer on top of OUR payloads and criteria.

## Automation — garak / PyRIT / promptfoo

```bash
# garak — LLM vulnerability scan (example, requires a configured generator/endpoint)
python -m garak --model_type rest --generator_option_file cfg.json \
  --probes dan,promptinject,latentinjection,leakreplay,packagehallucination

# promptfoo — red team in CI/CD, maps to OWASP/NIST/ATLAS/EU AI Act (YAML config)
promptfoo redteam init && promptfoo redteam run

# PyRIT — multi-turn/crescendo orchestration (Python SDK, see 05-tooling.md)
```

## "Workflow" summary for the agent

```
LLM recon (fingerprint, endpoints, RAG?/tools?) 
  → MODEL layer: garak (dan/promptinject/leakreplay) + L1B3RT4S jailbreaks 
  → IMPLEMENTATION layer: system-prompt extraction, output-handling (→ web payloads) 
  → SYSTEM/AGENT layer: excessive agency, indirect injection via tool output/RAG 
  → PROCESS layer: logging, human-in-the-loop 
  → LLM Top 10:2025 + ATLAS TTP + CVSS4.0 mapping 
  → report (template from 02)
```
