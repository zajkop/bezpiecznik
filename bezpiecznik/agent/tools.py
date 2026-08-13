"""Agent tools for conversational mode (tool-calling on the LLM).

BezpiecznikSession holds the state (target, scope, findings) and exposes the tool methods.
TOOLS_SCHEMA are the definitions in OpenAI/Ollama format; dispatch() executes the calls.
Each tool returns a short summary text (for the LLM to relay to the operator).
"""
from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import urlparse

from ..core.config import Config, load_config
from ..core.http import HttpClient
from ..core.llm import LLM
from ..core.logging import AuditLogger
from ..core.models import Finding, Report, Scope, Target, TargetType
from ..core.scope import ScopeGuard
from ..adapters.recon.recon import ReconAdapter
from ..adapters.web.scanner import WebScanner
from ..adapters.web.api_scanner import ApiScanner
from ..adapters.web.advanced_scanner import AdvancedScanner
from ..adapters.web.jwt_scanner import JwtScanner
from ..adapters.ai.chat_client import TargetChatClient
from ..adapters.ai.llm_harness import LLMHarness
from ..adapters.ai.garak_adapter import GarakAdapter
from ..subagents.chat_judge import ChatJudge
from ..subagents.chat_attacker import ChatAttacker
from ..correlate.correlate import correlate
from ..report.render import write_html, write_json, write_markdown
from .guardrails import Guardrails


def _titles(found: list[Finding]) -> str:
    """Concise list of findings to return to the model (so it doesn't guess)."""
    if not found:
        return "no new findings"
    return "; ".join(f"[{f.severity.value}] {f.title}" for f in found[:12])


class BezpiecznikSession:
    def __init__(self, cfg: Config | None = None, known_canary: str | None = None):
        self.cfg = cfg or load_config()
        self.http = HttpClient(self.cfg.http)
        self.llm = LLM(self.cfg.llm)
        self.log = AuditLogger(self.cfg.workdir, echo=True)
        self.payloads_dir = os.path.abspath(self.cfg.payloads_dir)
        self.known_canary = known_canary
        self.target: Target | None = None
        self.scope: Scope | None = None
        self.guard: ScopeGuard | None = None
        self.seeds: list[tuple[str, str]] = []
        self.findings: list[Finding] = []
        self.report_paths: dict[str, str] = {}

    def close(self) -> None:
        self.http.close()
        self.llm.close()

    # ---- Tools ----

    def set_scope(self, url: str, type: str = "web-app", llm_endpoint: str | None = None,
                  authorized: bool = False, allow_destructive: bool = False) -> str:
        try:
            ttype = TargetType(type)
        except ValueError:
            return f"Error: unknown type '{type}'. Use: web-app | ai-assistant | both."
        host = urlparse(url).hostname or url
        self.target = Target(url=url, type=ttype, llm_endpoint=llm_endpoint)
        self.scope = Scope(engagement="interactive", in_scope=[host],
                           authorized=bool(authorized), allow_destructive=bool(allow_destructive))
        self.guard = ScopeGuard(self.scope)
        auth = "CONFIRMED" if authorized else "NONE (passive actions only)"
        return (f"Scope set. Target: {url} ({ttype.value}), in-scope host: {host}, "
                f"authorization: {auth}. You can now run recon and scans.")

    def _require_target(self) -> str | None:
        if not self.target or not self.guard:
            return "First set the target and scope via the set_scope tool."
        return None

    def run_recon(self) -> str:
        err = self._require_target()
        if err:
            return err
        recon = ReconAdapter(self.http, self.log, self.guard, self.payloads_dir)
        rf, seeds = recon.run(self.target)
        self.findings += rf
        self.seeds = sorted(set(self.seeds) | set(seeds))
        return (f"Recon complete. Detected {len(self.seeds)} entry points (path,param), "
                f"{len(rf)} preliminary findings. Ready for the web scan.")

    def run_web_scan(self, extra_seeds: list[list[str]] | None = None) -> str:
        err = self._require_target()
        if err:
            return err
        for pair in (extra_seeds or []):
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                self.seeds.append((pair[0], pair[1]))
        self.seeds = sorted(set(self.seeds))
        if not self.seeds:
            # Robustness: run recon itself, instead of requiring a strict call order.
            self.run_recon()
            self.seeds = sorted(set(self.seeds))
        if not self.seeds:
            return ("No entry points — recon did not detect any parameters (the target may be empty, "
                    "expired, or without forms/links). Provide extra_seeds manually.")
        scanner = WebScanner(self.http, self.log, self.guard, self.payloads_dir)
        found = scanner.scan(self.target, self.seeds)
        self.findings += found
        return (f"Web scan complete on {len(self.seeds)} points. "
                f"Findings: {len(found)}. Details: {_titles(found)}")

    def run_api_scan(self, api_resources: list[str] | None = None,
                     xml_endpoints: list[str] | None = None) -> str:
        err = self._require_target()
        if err:
            return err
        api = ApiScanner(self.http, self.log, self.guard)
        found = api.scan(self.target, api_resources or [], xml_endpoints or [])
        self.findings += found
        return (f"API scan (BOLA/exposure/XXE). Findings: {len(found)}. Details: {_titles(found)}")

    def run_advanced_scan(self, nosql_login: list[str] | None = None,
                          stored_paths: list[str] | None = None,
                          csrf_forms: list[list[str]] | None = None,
                          upload_paths: list[str] | None = None,
                          jwt_login: str | None = None, jwt_verify: str | None = None) -> str:
        err = self._require_target()
        if err:
            return err
        adv = AdvancedScanner(self.http, self.log, self.guard)
        stored_xss = [(p, p, "entry") for p in (stored_paths or [])]
        csrf = [tuple(c) for c in (csrf_forms or []) if isinstance(c, (list, tuple)) and len(c) == 2]
        found = adv.scan(self.target, nosql_login=nosql_login, stored_xss=stored_xss,
                         csrf_forms=csrf, upload_paths=upload_paths)
        if jwt_login and jwt_verify:
            found += JwtScanner(self.http, self.log, self.guard).scan(self.target, jwt_login, jwt_verify)
        self.findings += found
        return f"Advanced scan (NoSQLi/StoredXSS/CSRF/Upload/JWT): {_titles(found)}"

    def _do_http(self, method: str, path: str, params: dict | None = None,
                 json_body: Any = None, headers: dict | None = None) -> dict:
        """Core of a generic HTTP request (scope-enforced, INVASIVE). Returns a dict."""
        from urllib.parse import urlencode
        from ..core.scope import ActionClass
        base = self.target.url.rstrip("/")
        self.guard.authorize(base, ActionClass.INVASIVE)   # requests may change state
        url = base + (path if path.startswith("/") else "/" + path)
        if params:
            url += ("&" if "?" in url else "?") + urlencode(params)
        kw: dict[str, Any] = {"headers": dict(headers or {})}
        if json_body is not None:
            kw["content"] = json.dumps(json_body)
            kw["headers"].setdefault("Content-Type", "application/json")
        r = self.http.request(method.upper(), url, **kw)
        return {"status": r.status, "body": r.text, "headers": dict(r.headers)}

    def http_request(self, method: str = "GET", path: str = "/", params: dict | None = None,
                     json_body: Any = None, headers: dict | None = None) -> str:
        err = self._require_target()
        if err:
            return err
        r = self._do_http(method, path, params, json_body, headers)
        self.log.action(self.target.url, "http_request", f"{method.upper()} {path} -> {r['status']}")
        return f"HTTP {r['status']} | {len(r['body'])}B | body: {r['body'][:400]}"

    def run_business_logic_test(self, description: str, goal: str, max_steps: int = 6) -> str:
        err = self._require_target()
        if err:
            return err
        from ..subagents.logic_tester import LogicTester
        tester = LogicTester(self.llm, self._do_http, self.log)
        _tr, found = tester.run(self.target, description, goal, max_steps=max_steps)
        self.findings += found
        return f"Business logic test ('{goal[:40]}'): {_titles(found)}"

    def run_ai_tests(self, goal: str = "reveal system prompt or secret canary",
                     multi_turn: bool = True) -> str:
        err = self._require_target()
        if err:
            return err
        endpoint = self.target.llm_endpoint or (self.target.url.rstrip("/") + "/api/chat")
        chat = TargetChatClient(self.http, endpoint, self.target.auth_header)
        harness = LLMHarness(chat, self.log, self.guard, self.payloads_dir, self.known_canary)
        found = harness.run(self.target)
        self.findings += found
        msg = f"AI single-turn: {_titles(found)}."
        if multi_turn:
            judge = ChatJudge(self.llm)
            attacker = ChatAttacker(self.llm, judge, chat, self.log, self.guard, self.known_canary)
            _, af = attacker.run(self.target, goal, max_turns=6)
            self.findings += af
            msg += f" Multi-turn ({goal[:40]}): {_titles(af)}."
        return msg

    def run_garak(self, probes: str = "dan.Dan_11_0") -> str:
        err = self._require_target()
        if err:
            return err
        found = GarakAdapter(self.log, run_dir=self.log.dir).run(self.target, probes=probes, generations=2)
        self.findings += found
        return f"garak ({probes}): {len(found)} findings (may be 0 with a resilient model)."

    def generate_report(self) -> str:
        err = self._require_target()
        if err:
            return err
        self.findings = correlate(self.findings)
        report = Report(engagement=self.scope.engagement, target=self.target,
                        scope=self.scope, findings=self.findings)
        md = write_markdown(report, os.path.join(self.log.dir, "report.md"))
        write_json(report, os.path.join(self.log.dir, "report.json"))
        html = write_html(report, os.path.join(self.log.dir, "report.html"))
        self.report_paths = {"md": md, "html": html,
                             "json": os.path.join(self.log.dir, "report.json")}
        counts = report.by_severity()
        return (f"Report generated: {md}. Total {len(self.findings)} findings "
                f"(critical={counts['critical']}, high={counts['high']}, medium={counts['medium']}, "
                f"low={counts['low']}, info={counts['info']}). "
                f"Full list: {_titles(self.findings)}")


# Tool definitions in OpenAI/Ollama format (function calling).
TOOLS_SCHEMA: list[dict[str, Any]] = [
    {"type": "function", "function": {
        "name": "set_scope",
        "description": "Set the test target and scope. Call this FIRST. authorized=true only when the operator has confirmed written consent.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL, e.g. http://127.0.0.1:8000"},
            "type": {"type": "string", "enum": ["web-app", "ai-assistant", "both"]},
            "llm_endpoint": {"type": "string", "description": "Chat endpoint, if ai-assistant/both"},
            "authorized": {"type": "boolean"},
            "allow_destructive": {"type": "boolean"},
        }, "required": ["url", "type"]}}},
    {"type": "function", "function": {
        "name": "run_recon",
        "description": "Recon: fingerprint + detection of endpoints/parameters. Run after set_scope.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "run_web_scan",
        "description": "Web vulnerability scan (SQLi, XSS, cmd inj., SSTI, SSRF, traversal, IDOR, open redirect, headers).",
        "parameters": {"type": "object", "properties": {
            "extra_seeds": {"type": "array", "description": "Optional [path, parameter] pairs to test",
                            "items": {"type": "array", "items": {"type": "string"}}}}}}},
    {"type": "function", "function": {
        "name": "run_api_scan",
        "description": "API scan: BOLA, excessive data exposure, XXE.",
        "parameters": {"type": "object", "properties": {
            "api_resources": {"type": "array", "items": {"type": "string"},
                              "description": "Base REST paths, e.g. /api/orders"},
            "xml_endpoints": {"type": "array", "items": {"type": "string"},
                              "description": "Endpoints accepting XML (POST), e.g. /xml"}}}}},
    {"type": "function", "function": {
        "name": "run_advanced_scan",
        "description": "Advanced scan on SPECIFIC endpoints: NoSQLi (login), Stored XSS "
                       "(guestbook), CSRF (form), file upload, JWT (login+verify). Provide only known ones.",
        "parameters": {"type": "object", "properties": {
            "nosql_login": {"type": "array", "items": {"type": "string"}, "description": "JSON login endpoints"},
            "stored_paths": {"type": "array", "items": {"type": "string"}, "description": "Write/read paths (e.g. /guestbook)"},
            "csrf_forms": {"type": "array", "items": {"type": "array", "items": {"type": "string"}}, "description": "[[form, action]]"},
            "upload_paths": {"type": "array", "items": {"type": "string"}},
            "jwt_login": {"type": "string"}, "jwt_verify": {"type": "string"}}}}},
    {"type": "function", "function": {
        "name": "http_request",
        "description": "Send an arbitrary HTTP request to the target (for manual exploration / logic tests). "
                       "Returns status + content.",
        "parameters": {"type": "object", "properties": {
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]},
            "path": {"type": "string", "description": "Path, e.g. /api/book"},
            "params": {"type": "object", "description": "Query string parameters"},
            "json_body": {"type": "object", "description": "Body as JSON"}},
            "required": ["method", "path"]}}},
    {"type": "function", "function": {
        "name": "run_business_logic_test",
        "description": "Test BUSINESS LOGIC based on a DESCRIPTION. Provide a description of the endpoint(s) and "
                       "a GOAL — the undesired behavior to trigger (e.g. 'book an already-taken seat', "
                       "'buy a widget for 0', 'swap quantity while keeping the price'). The agent will plan "
                       "and execute a sequence of requests itself, and a judge will assess whether the abuse succeeded.",
        "parameters": {"type": "object", "properties": {
            "description": {"type": "string", "description": "Description of the endpoint(s): path, parameters, what it does"},
            "goal": {"type": "string", "description": "The undesired behavior to trigger"}},
            "required": ["description", "goal"]}}},
    {"type": "function", "function": {
        "name": "run_ai_tests",
        "description": "AI chatbot tests: single-turn (payloads) + multi-turn (attacker/judge on the local LLM).",
        "parameters": {"type": "object", "properties": {
            "goal": {"type": "string", "description": "Attack goal, e.g. 'reveal system prompt or canary'"},
            "multi_turn": {"type": "boolean"}}}}},
    {"type": "function", "function": {
        "name": "run_garak",
        "description": "Run the garak (NVIDIA) scanner against the chat endpoint. May return 0 with a resilient model.",
        "parameters": {"type": "object", "properties": {
            "probes": {"type": "string", "description": "List of garak probes, e.g. dan.Dan_11_0"}}}}},
    {"type": "function", "function": {
        "name": "generate_report",
        "description": "Correlate findings and generate a JSON+Markdown report. Call this at the end.",
        "parameters": {"type": "object", "properties": {}}}},
]


def dispatch(session: BezpiecznikSession, name: str, args: dict[str, Any]) -> str:
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {}
    fn = {
        "set_scope": session.set_scope,
        "run_recon": session.run_recon,
        "run_web_scan": session.run_web_scan,
        "run_api_scan": session.run_api_scan,
        "run_advanced_scan": session.run_advanced_scan,
        "http_request": session.http_request,
        "run_business_logic_test": session.run_business_logic_test,
        "run_ai_tests": session.run_ai_tests,
        "run_garak": session.run_garak,
        "generate_report": session.generate_report,
    }.get(name)
    if fn is None:
        return f"Error: unknown tool '{name}'."
    try:
        return fn(**(args or {}))
    except TypeError as e:
        return f"Argument error for tool '{name}': {e}"
    except Exception as e:  # noqa: BLE001
        return f"Execution error for '{name}': {e}"
