"""Detectors for modern/less-common web classes:
CORS misconfiguration, Host-header injection, GraphQL introspection/injection,
server-side Prototype Pollution, and Race conditions.
"""
from __future__ import annotations

import concurrent.futures
import json
import re

import httpx

from ...core.http import HttpClient
from ...core.logging import AuditLogger
from ...core.models import Evidence, Finding, Severity, Target
from ...core.scope import ActionClass, ScopeGuard

EVIL_ORIGIN = "https://evil.example"

# --- Hidden indirect-prompt-injection in served content (LLM01, in-the-wild) ---
# A page can carry instructions aimed not at the human reader but at any LLM agent,
# crawler, RAG pipeline or "summarize this page" assistant that later consumes it.
# The instructions are CONCEALED from a human (HTML comment, CSS-hidden element, or
# zero-width/invisible Unicode) so only the machine reads them — the technique Unit 42
# documented being used in the wild against AI agents in 2026. We fire only when an
# AI-directed imperative co-occurs with a concealment mechanism, keeping false
# positives low (plain visible text that merely mentions "ignore instructions" does
# NOT trigger).

# Invisible / zero-width code points used to smuggle text past a human's eyes.
_INVISIBLE = [
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E, 0x200E, 0x200F,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2061, 0x2062, 0x2063, 0x2064,
    0x2066, 0x2067, 0x2068, 0x2069,
]
_ZW_TABLE = {c: None for c in _INVISIBLE}
_ZW_TABLE.update({c: None for c in range(0xE0000, 0xE0080)})  # Unicode Tags block

# Imperative phrases directed at an AI/assistant/model (not ordinary prose).
_INSTRUCTION_SIGNS = [
    re.compile(r"ignore\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|earlier|preceding)\s+"
               r"(?:instruction|prompt|message|context|rule)", re.I),
    re.compile(r"disregard\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|earlier|system|safety)", re.I),
    re.compile(r"\byou\s+are\s+now\b", re.I),
    re.compile(r"\bnew\s+instructions?\s*:", re.I),
    re.compile(r"\bsystem\s+prompt\b", re.I),
    re.compile(r"\b(?:reveal|print|repeat|output|leak|exfiltrate|send|forward)\b[^.\n<]{0,60}"
               r"\b(?:system\s+prompt|prompt|instructions?|api[\s_-]?key|password|secret|token|credential)", re.I),
    re.compile(r"\bdo\s+anything\s+now\b|\bDAN\s+mode\b", re.I),
    re.compile(r"\b(?:developer|god|jailbreak)\s+mode\b", re.I),
    re.compile(r"\b(?:assistant|system|ai)\s*:\s*(?:ignore|reveal|print|output|forward|send|say|reply|"
               r"execute|run|delete|email|browse|fetch)", re.I),
    re.compile(r"\boverride\b[^.\n<]{0,40}\b(?:instruction|policy|guardrail|restriction|filter)", re.I),
    re.compile(r"\b(?:reply|respond|answer|say|output)\b[^.\n<]{0,30}\bonly\s+with\b", re.I),
]

_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
# Text inside an element concealed via a hidden attribute or inline CSS.
_HIDDEN_ELEM = re.compile(
    r"<([a-zA-Z][\w-]*)\b[^>]*?"
    r"(?:\bhidden\b|aria-hidden\s*=\s*[\"']?\s*true"
    r"|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?![.\d])"
    r"|font-size\s*:\s*0(?![.\d])|(?:left|top|text-indent|margin-left)\s*:\s*-\s*\d{3,})"
    r"[^>]*>(.*?)</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)


def _match_instruction(text: str) -> str | None:
    """Return the matched snippet if the text carries an AI-directed instruction."""
    for pat in _INSTRUCTION_SIGNS:
        m = pat.search(text)
        if m:
            return m.group(0)
    return None


# --- Forged chat-template control tokens in served content (ChatInject, LLM01) ---
# Distinct from the concealment-based injection above: here the attack IS the
# presence of a model's chat-template role delimiters inside data that a downstream
# agent naively concatenates into its prompt template. The template renderer then
# treats the forged "<|im_start|>system" / "[INST]" / "<|start_header_id|>assistant"
# markers as real turn boundaries, letting attacker-controlled page/tool content
# escape the data sandbox and issue system/assistant turns (arXiv:2509.22830,
# "ChatInject"). These special-token strings essentially never occur in legitimate
# web content, so their presence is a strong, low-false-positive signal.

# High-specificity delimiters — a bare occurrence is enough to flag.
_CHAT_TEMPLATE_TOKENS = [
    "<|im_start|>", "<|im_end|>",                       # ChatML (OpenAI/Qwen)
    "<|start_header_id|>", "<|end_header_id|>", "<|eot_id|>",  # Llama 3
    "<<SYS>>", "<</SYS>>",                               # Llama 2
    "<start_of_turn>", "<end_of_turn>",                 # Gemma
    "<|system|>", "<|user|>", "<|assistant|>", "<|end|>",  # Phi / generic
]
# Softer markers (real words in normal prose) — flagged only when they introduce a
# forged privileged role, i.e. paired with a system/assistant role switch nearby.
_SOFT_ROLE_SWITCH = re.compile(
    r"(?:\[INST\]|###\s*Instruction\s*:|###\s*System\s*:|<\|prompter\|>)"
    r"[\s\S]{0,80}?"
    r"(?:###\s*Response\s*:|\bassistant\b|\bsystem\b|\[/INST\])",
    re.IGNORECASE)


def _match_chat_template(text: str) -> str | None:
    """Return a matched forged chat-template delimiter, if present."""
    for tok in _CHAT_TEMPLATE_TOKENS:
        if tok in text:
            return tok
    m = _SOFT_ROLE_SWITCH.search(text)
    if m:
        return re.sub(r"\s+", " ", m.group(0))[:60]
    return None


def _snippet(text: str, needle: str) -> str:
    """A short, single-line context window around the matched instruction."""
    flat = re.sub(r"\s+", " ", text).strip()
    i = flat.lower().find(needle.lower())
    if i < 0:
        return flat[:120]
    start = max(0, i - 20)
    return flat[start:start + 140]


# --- MCP tool poisoning in a served tool manifest (MCP03:2025, LLM01) ---
# A Model Context Protocol server advertises its tools via `tools/list`; each tool
# carries a free-text `description` and per-parameter descriptions that are fed
# verbatim into the agent's context. Tool poisoning plants adversarial instructions
# inside those descriptions (or parameter schemas) — hijacking the agent even when
# the poisoned tool is never called, and often concealing the directive from a human
# who only sees a short summary. Beyond the generic AI-directed imperatives and forged
# chat-template tokens we already match, tool poisoning has its own tell-tale side
# channels: the Invariant Labs `<IMPORTANT>` wrapper, "do not tell the user"
# secrecy directives, "before using this tool …" preambles, and instructions to read
# or exfiltrate sensitive local files (SSH keys, .env, ~/.cursor/mcp.json).
# Sources: OWASP MCP Top 10 MCP03:2025 (Tool Poisoning); Invariant Labs, "MCP Security
# Notification: Tool Poisoning Attacks"; MCPTox benchmark (arXiv:2508.14925).
_MCP_SIDECHANNEL = re.compile(
    r"<\s*IMPORTANT\s*>"
    r"|(?:do\s+not|don't|never)\s+(?:tell|mention|inform|notify|reveal\s+to|show|alert)\s+"
    r"(?:the\s+|this\s+)?(?:user|human|operator|caller)"
    r"|(?:without|do\s+not|don't)\s+(?:telling|informing|notifying|alerting)\s+"
    r"(?:the\s+)?(?:user|human)"
    r"|before\s+(?:using|calling|invoking|you\s+(?:use|call|invoke))\s+this\s+tool"
    r"|(?:read|cat|open|load|exfiltrate|send|forward|leak|upload|post)\b[^.\n]{0,50}?"
    r"(?:~/\.ssh|/etc/passwd|\.env\b|\.cursor/mcp\.json|mcp\.json|id_rsa"
    r"|api[\s_-]?key|secret|credential|access[\s_-]?token)",
    re.I,
)


def _find_tools(o: object) -> list[dict]:
    """Locate a list of tool definition dicts inside a parsed MCP/JSON response."""
    if isinstance(o, dict):
        for key in ("tools",):
            if isinstance(o.get(key), list):
                return [t for t in o[key] if isinstance(t, dict)]
        res = o.get("result")
        if isinstance(res, dict) and isinstance(res.get("tools"), list):
            return [t for t in res["tools"] if isinstance(t, dict)]
    if isinstance(o, list):
        return [t for t in o if isinstance(t, dict) and ("description" in t or "name" in t)]
    return []


def _parse_tools(text: str) -> list[dict]:
    """Parse tool definitions from a direct JSON body or an SSE `data:` stream."""
    if not text:
        return []
    objs: list[object] = []
    stripped = text.strip()
    try:
        objs.append(json.loads(stripped))
    except (ValueError, TypeError):
        for line in stripped.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                try:
                    objs.append(json.loads(line[5:].strip()))
                except (ValueError, TypeError):
                    pass
    tools: list[dict] = []
    for o in objs:
        tools.extend(_find_tools(o))
    return tools


def _walk_descriptions(node: object) -> list[str]:
    """Every `description` string value reachable inside a JSON-schema node."""
    out: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "description" and isinstance(v, str):
                out.append(v)
            else:
                out.extend(_walk_descriptions(v))
    elif isinstance(node, list):
        for it in node:
            out.extend(_walk_descriptions(it))
    return out


def _collect_descriptions(tool: dict) -> list[tuple[str, str]]:
    """(field, text) pairs an agent would ingest: name, description, param descriptions."""
    parts: list[tuple[str, str]] = []
    name = tool.get("name")
    if isinstance(name, str):
        parts.append(("name", name))
    desc = tool.get("description")
    if isinstance(desc, str):
        parts.append(("description", desc))
    schema = tool.get("inputSchema") or tool.get("input_schema") or tool.get("parameters")
    for d in _walk_descriptions(schema):
        parts.append(("parameter", d))
    return parts


def _mcp_signal(text: str) -> tuple[str, str] | None:
    """Classify a poisoning signal in one description, or None. Order = specificity."""
    deobf = text.translate(_ZW_TABLE)
    if deobf != text and not (_match_instruction(text) or _MCP_SIDECHANNEL.search(text)):
        m = _MCP_SIDECHANNEL.search(deobf)
        sign = _match_instruction(deobf) or (m.group(0) if m else None)
        if sign:
            return ("zero-width Unicode concealment", sign)
    sign = _match_instruction(text)
    if sign:
        return ("AI-directed instruction", sign)
    m = _MCP_SIDECHANNEL.search(text)
    if m:
        return ("hidden side-channel directive", m.group(0))
    ct = _match_chat_template(text)
    if ct:
        return ("forged chat-template token", ct)
    return None


class ModernScanner:
    name = "modern-scanner (native)"

    def __init__(self, http: HttpClient, log: AuditLogger, guard: ScopeGuard):
        self.http = http
        self.log = log
        self.guard = guard

    def scan(self, target: Target, *, cors_paths: list[str] | None = None,
             host_paths: list[str] | None = None, graphql_paths: list[str] | None = None,
             merge_paths: list[str] | None = None, race: dict | None = None,
             ai_inject_paths: list[str] | None = None,
             mcp_paths: list[str] | None = None) -> list[Finding]:
        base = target.url.rstrip("/")
        self.guard.authorize(base, ActionClass.ACTIVE)
        findings: list[Finding] = []
        for p in (cors_paths if cors_paths is not None else ["/"]):
            findings += self._cors(base, p)
        for p in (host_paths if host_paths is not None else ["/"]):
            findings += self._host_header(base, p)
        for p in (graphql_paths if graphql_paths is not None else ["/graphql"]):
            findings += self._graphql(base, p)
        for p in (merge_paths or []):
            findings += self._prototype_pollution(base, p)
        for p in (ai_inject_paths if ai_inject_paths is not None else ["/"]):
            findings += self._hidden_ai_injection(base, p)
        for p in (mcp_paths if mcp_paths is not None else ["/mcp", "/messages", "/sse"]):
            findings += self._mcp_tool_poisoning(base, p)
        if race:
            findings += self._race(base, race)
        return findings

    def _report(self, out: list[Finding], f: Finding) -> None:
        self.log.finding(f.title, f.severity.value, owasp=f.owasp)
        out.append(f)

    def _cors(self, base: str, path: str) -> list[Finding]:
        out: list[Finding] = []
        r = self.http.get(f"{base}{path}", headers={"Origin": EVIL_ORIGIN})
        acao = (r.header("Access-Control-Allow-Origin") or "").strip()
        acac = (r.header("Access-Control-Allow-Credentials") or "").strip().lower()
        reflected = acao == EVIL_ORIGIN
        wildcard_creds = acao == "*" and acac == "true"
        if reflected or wildcard_creds:
            self.log.action(base, self.name, f"CORS probe {path}")
            sev = Severity.HIGH if (reflected and acac == "true") else Severity.MEDIUM
            self._report(out, Finding(
                title=f"CORS misconfiguration at {path}",
                severity=sev, owasp="A05:2025 Security Misconfiguration", cwe="CWE-942",
                target=f"{base}{path}", component=path, source_tool=self.name,
                description=("The response reflects an arbitrary Origin in Access-Control-Allow-Origin"
                             + (" together with Allow-Credentials: true" if acac == "true" else "")
                             + "." if reflected else "Access-Control-Allow-Origin: * with credentials."),
                impact="A malicious site can read authenticated responses cross-origin (data theft).",
                recommendation="Allowlist trusted origins; never reflect Origin with credentials; avoid '*' with credentials.",
                reproduction=f"curl -H 'Origin: {EVIL_ORIGIN}' {base}{path} -i  # see Access-Control-Allow-Origin reflect it",
                evidence=Evidence(payload=f"Origin: {EVIL_ORIGIN}",
                                  response=f"ACAO: {acao} | ACAC: {acac}")))
        return out

    def _host_header(self, base: str, path: str) -> list[Finding]:
        out: list[Finding] = []
        evil = "evil.example"
        r = self.http.get(f"{base}{path}", headers={"X-Forwarded-Host": evil, "Host": evil})
        loc = r.header("Location") or ""
        if evil in r.text or evil in loc:
            self.log.action(base, self.name, f"Host-header probe {path}")
            self._report(out, Finding(
                title=f"Host Header Injection at {path}",
                severity=Severity.MEDIUM, owasp="A05:2025 Security Misconfiguration", cwe="CWE-644",
                target=f"{base}{path}", component=path, source_tool=self.name,
                description="The application reflects the client-supplied Host/X-Forwarded-Host header "
                            "into the response (e.g. links).",
                impact="Password-reset poisoning, cache poisoning, phishing links pointing to an attacker host.",
                recommendation="Use a fixed, server-side canonical host; validate Host against an allowlist.",
                reproduction=f"curl -H 'X-Forwarded-Host: {evil}' {base}{path}  # see {evil} in the response",
                evidence=Evidence(payload=f"X-Forwarded-Host: {evil}", response=(r.text or loc)[:200])))
        return out

    def _graphql(self, base: str, path: str) -> list[Finding]:
        out: list[Finding] = []
        q = {"query": "{__schema{types{name}}}"}
        r = self.http.post(f"{base}{path}", headers={"Content-Type": "application/json"},
                          content=json.dumps(q))
        if "__schema" in r.text and ("types" in r.text or "name" in r.text):
            self.log.action(base, self.name, f"GraphQL introspection {path}")
            self._report(out, Finding(
                title=f"GraphQL introspection enabled at {path}",
                severity=Severity.MEDIUM, owasp="A05:2025 Security Misconfiguration", cwe="CWE-200",
                target=f"{base}{path}", component=path, source_tool=self.name,
                description="The GraphQL endpoint answers introspection queries, exposing the full schema.",
                impact="Full schema/type disclosure aids further attacks (hidden fields, mutations, injection).",
                recommendation="Disable introspection in production; enforce authz per field; rate-limit.",
                reproduction=f"curl -X POST {base}{path} -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}'",
                evidence=Evidence(payload=json.dumps(q), response=r.text[:250])))
        return out

    def _hidden_ai_injection(self, base: str, path: str) -> list[Finding]:
        """Concealed indirect prompt injection served in the page content (LLM01).

        Flags text that carries an AI-directed instruction AND is hidden from a human
        reader (HTML comment, CSS/attribute-hidden element, or zero-width Unicode) — a
        payload aimed at any downstream LLM agent/crawler/RAG that consumes the page.
        """
        out: list[Finding] = []
        r = self.http.get(f"{base}{path}")
        ctype = (r.header("Content-Type") or "").lower()
        html = r.text or ""
        # Only meaningful for text/HTML responses.
        if "html" not in ctype and "text" not in ctype and not html.lstrip().startswith("<"):
            return out
        out += self._chat_template_injection(base, path, html)
        hits: list[tuple[str, str]] = []
        # 1) instruction concealed inside an HTML comment
        for m in _COMMENT.finditer(html):
            sign = _match_instruction(m.group(1))
            if sign:
                hits.append(("HTML comment", _snippet(m.group(1), sign)))
                break
        # 2) instruction concealed inside a CSS/attribute-hidden element
        for m in _HIDDEN_ELEM.finditer(html):
            sign = _match_instruction(m.group(2))
            if sign:
                hits.append(("CSS/attribute-hidden element", _snippet(m.group(2), sign)))
                break
        # 3) instruction smuggled with zero-width / invisible Unicode: it only surfaces
        #    once the invisible characters are stripped (and is not already visible raw).
        deobf = html.translate(_ZW_TABLE)
        if deobf != html and not _match_instruction(html):
            sign = _match_instruction(deobf)
            if sign:
                hits.append(("invisible Unicode (zero-width)", _snippet(deobf, sign)))
        if not hits:
            return out
        techniques = ", ".join(t for t, _ in hits)
        example = hits[0][1]
        self.log.action(base, self.name, f"Hidden AI-injection scan {path}")
        self._report(out, Finding(
            title=f"Indirect prompt injection hidden in page content at {path}",
            severity=Severity.HIGH, owasp="LLM01:2025 Prompt Injection", cwe="CWE-1427",
            target=f"{base}{path}", component=path, source_tool=self.name,
            description=("The page serves an AI-directed instruction concealed from a human reader "
                         f"({techniques}). A downstream LLM agent, crawler, RAG pipeline or "
                         "'summarize this page' assistant that ingests the content will read and may "
                         "obey it — classic indirect prompt injection served by the site itself "
                         "(e.g. via unsanitized user-generated content)."),
            impact="Hijacks any AI agent consuming the page: data exfiltration, tool abuse, "
                   "spoofed answers, or actions taken on the victim's behalf — with zero human clicks.",
            recommendation="Sanitize/neutralize user-generated and third-party content before it can "
                           "reach an LLM context; strip zero-width Unicode and hidden/comment text; "
                           "treat retrieved page content as untrusted data, never as instructions.",
            reproduction=f"curl -s {base}{path} | grep -aiE 'ignore .*instruction|system prompt|you are now'  "
                         f"# instruction is hidden ({techniques})",
            evidence=Evidence(payload=f"hidden instruction ({techniques})", response=example[:250])))
        return out

    def _chat_template_injection(self, base: str, path: str, html: str) -> list[Finding]:
        """Forged chat-template control tokens served in the page content (ChatInject, LLM01).

        Flags served content that carries a model's chat-template role delimiters
        (ChatML/Llama/Gemma/etc.). A downstream agent that concatenates this content
        into its prompt template has its turn boundaries forged by the data, letting
        the content issue system/assistant turns — escaping the data sandbox.
        """
        out: list[Finding] = []
        sign = _match_chat_template(html)
        if not sign:
            return out
        self.log.action(base, self.name, f"Chat-template injection scan {path}")
        self._report(out, Finding(
            title=f"Forged chat-template control tokens in page content at {path}",
            severity=Severity.HIGH, owasp="LLM01:2025 Prompt Injection", cwe="CWE-1427",
            target=f"{base}{path}", component=path, source_tool=self.name,
            description=("The page serves a model's chat-template role delimiter "
                         f"({sign!r}) inside its content. A downstream LLM agent, RAG "
                         "pipeline or tool that concatenates this content into its prompt "
                         "template will have the forged marker parsed as a real turn "
                         "boundary, letting attacker-controlled data open a spoofed "
                         "system/assistant turn — the ChatInject class (arXiv:2509.22830)."),
            impact="Attacker-controlled content escapes the data sandbox and injects "
                   "system/assistant instructions into any agent that ingests the page: "
                   "guardrail bypass, tool abuse, data exfiltration, spoofed answers.",
            recommendation="Strip/escape chat-template special tokens from retrieved and "
                           "user-generated content before it enters an LLM prompt; keep "
                           "untrusted data in a clearly delimited user turn, never rendered "
                           "as template control tokens.",
            reproduction=f"curl -s {base}{path} | grep -aoE '<\\|im_start\\|>|\\[INST\\]|<\\|start_header_id\\|>'  "
                         f"# forged delimiter {sign!r} in the served content",
            evidence=Evidence(payload=f"chat-template delimiter {sign!r}",
                              response=_snippet(html, sign)[:250])))
        return out

    def _mcp_tool_poisoning(self, base: str, path: str) -> list[Finding]:
        """MCP tool poisoning in a served tool manifest (MCP03:2025 / LLM01).

        Fetches an MCP `tools/list` (or a static tool manifest) and flags any tool
        whose description or parameter schema carries adversarial instructions — an
        AI-directed imperative, a forged chat-template token, a tool-poisoning side
        channel (`<IMPORTANT>` wrapper, "do not tell the user", "before using this
        tool", read/exfiltrate a secret file), or one of those smuggled with
        zero-width Unicode. These descriptions are fed verbatim into a consuming
        agent's context, so a poisoned tool hijacks the agent even if never called.
        """
        out: list[Finding] = []
        rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        r = self.http.post(f"{base}{path}",
                           headers={"Content-Type": "application/json",
                                    "Accept": "application/json, text/event-stream"},
                           content=json.dumps(rpc))
        tools = _parse_tools(r.text)
        # Static manifests are GET-only; probe GET only for manifest-shaped paths so
        # we never hang a GET on a live SSE stream.
        if not tools and (path.endswith(".json") or path.endswith("/tools")
                          or "manifest" in path or "well-known" in path):
            tools = _parse_tools(self.http.get(f"{base}{path}").text)
        if not tools:
            return out
        poisoned: list[tuple[str, str, str, str]] = []
        for tool in tools:
            tname = tool.get("name") if isinstance(tool.get("name"), str) else "<tool>"
            for field, text in _collect_descriptions(tool):
                sig = _mcp_signal(text)
                if sig:
                    poisoned.append((tname, field, sig[0], _snippet(text.translate(_ZW_TABLE), sig[1])))
                    break
        if not poisoned:
            return out
        self.log.action(base, self.name, f"MCP tool-poisoning scan {path}")
        names = ", ".join(sorted({p[0] for p in poisoned}))
        techniques = ", ".join(sorted({p[2] for p in poisoned}))
        tool0, field0, _, example = poisoned[0]
        self._report(out, Finding(
            title=f"MCP tool poisoning in the tool manifest at {path}",
            severity=Severity.HIGH, owasp="LLM01:2025 Prompt Injection", cwe="CWE-1427",
            target=f"{base}{path}", component=path, source_tool=self.name,
            description=(f"The MCP server at {path} advertises tool(s) whose {field0} carries "
                         f"adversarial instructions ({techniques}). Poisoned tool(s): {names}. "
                         "MCP tool descriptions and parameter schemas are fed verbatim into a "
                         "consuming agent's context, so the injected directive hijacks the agent "
                         "the moment the tool list is loaded — even if the poisoned tool is never "
                         "invoked (OWASP MCP03:2025 Tool Poisoning)."),
            impact="Any agent that connects to this MCP server can be silently redirected: secret "
                   "exfiltration (SSH keys, .env, tokens), unauthorized tool calls, spoofed answers, "
                   "or actions taken on the user's behalf — with the directive hidden from the human.",
            recommendation="Treat tool descriptions and parameter schemas as untrusted data; pin and "
                           "review tool definitions (hash on change); strip control tokens and hidden "
                           "directives; surface the full untruncated description to the user before "
                           "approval; isolate/allowlist MCP servers.",
            reproduction=(f"curl -s -X POST {base}{path} -H 'Content-Type: application/json' "
                          "-d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}'  "
                          f"# inspect the '{tool0}' tool {field0}"),
            evidence=Evidence(payload=f"poisoned {field0} of tool '{tool0}' ({techniques})",
                              response=example[:250])))
        return out

    def _prototype_pollution(self, base: str, path: str) -> list[Finding]:
        out: list[Finding] = []
        hdr = {"Content-Type": "application/json"}
        polluted = self.http.post(f"{base}{path}", headers=hdr,
                                 content=json.dumps({"__proto__": {"admin": True}}))
        benign = self.http.post(f"{base}{path}", headers=hdr, content=json.dumps({"name": "x"}))
        # pollution took effect if the polluted request flips a property the benign one does not
        if ('"admin": true' in polluted.text.lower().replace(" ", " ")
                or '"admin":true' in polluted.text.lower()) and \
           ('"admin":true' not in benign.text.lower().replace(" ", "")):
            self.log.action(base, self.name, f"Prototype pollution {path}")
            self._report(out, Finding(
                title=f"Prototype Pollution at {path}",
                severity=Severity.HIGH, owasp="A08:2025 Software or Data Integrity Failures", cwe="CWE-1321",
                target=f"{base}{path}", component=path, source_tool=self.name,
                description="A __proto__ key in the JSON body pollutes object properties server-side "
                            "(an unsafe recursive merge), changing application behavior (e.g. admin flag).",
                impact="Privilege escalation, denial of service, or RCE depending on downstream gadgets.",
                recommendation="Reject __proto__/constructor/prototype keys; use null-prototype objects; safe merge.",
                reproduction=f"curl -X POST {base}{path} -d '{{\"__proto__\":{{\"admin\":true}}}}'",
                evidence=Evidence(payload='{"__proto__":{"admin":true}}', response=polluted.text[:200])))
        return out

    def _race(self, base: str, race: dict) -> list[Finding]:
        out: list[Finding] = []
        path = race.get("path")
        if not path:
            return out
        reset = race.get("reset_path")
        n = int(race.get("concurrency", 15))
        body = race.get("body") or "{}"
        success_token = race.get("success_token", "redeemed")
        if reset:
            self.http.post(f"{base}{reset}", content="{}")
        # true concurrency: a dedicated client without the scanner's rate-limit throttle
        def fire(_i: int) -> str:
            try:
                with httpx.Client(timeout=15, verify=False) as c:
                    return c.post(f"{base}{path}", content=body,
                                  headers={"Content-Type": "application/json"}).text
            except httpx.HTTPError:
                return ""
        self.log.action(base, self.name, f"Race probe {path} x{n} concurrent")
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            results = list(ex.map(fire, range(n)))
        wins = sum(1 for t in results if success_token in t)
        if wins > 1:  # a single-use action succeeded more than once → the limit was raced
            self._report(out, Finding(
                title=f"Race Condition at {path} (limit bypassed {wins}x)",
                severity=Severity.HIGH, owasp="A04:2025 Insecure Design", cwe="CWE-362",
                target=f"{base}{path}", component=path, source_tool=self.name,
                description=f"Firing {n} concurrent requests let a single-use action succeed {wins} times — "
                            "a check-then-act TOCTOU race with no locking.",
                impact="Business-logic abuse: multi-redeem coupons, over-withdrawal, limit bypass.",
                recommendation="Atomic DB constraints / SELECT ... FOR UPDATE / idempotency keys / locks.",
                reproduction=f"Fire ~{n} concurrent POST {base}{path} — more than one succeeds.",
                evidence=Evidence(payload=f"{n} concurrent requests",
                                  response=f"{wins} succeeded (expected 1)")))
        return out
