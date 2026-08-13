"""Business logic tester (LLM-based planner + judge).

Business logic is the one class where the LLM has an edge over signatures: success is
SEMANTIC (was an undesired state reached?), not regex-based. The operator describes the endpoint
and the goal; the LLM planner plans and executes a sequence of HTTP requests on its own, and the LLM judge
decides SOLELY on the basis of the real responses whether the abuse succeeded.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable

from ..core.llm import LLM
from ..core.logging import AuditLogger
from ..core.models import Evidence, Finding, Severity, Target

_PLANNER_SYSTEM = (
    "You are an autonomous BUSINESS-LOGIC penetration tester in an AUTHORIZED test. "
    "You get a target ENDPOINT DESCRIPTION and a GOAL — an undesired behavior to try to trigger "
    "(e.g. book an already-taken seat, buy for 0, keep price while changing quantity, reuse a coupon). "
    "Plan and execute HTTP requests ONE AT A TIME to achieve the GOAL. You see the transcript so far. "
    "Be EFFICIENT: make your FIRST request the most direct exploit attempt (set the abusive value "
    "immediately — e.g. unit_price:0, a negative quantity, or re-book the same seat), don't waste steps "
    "on read-only exploration unless needed. "
    "Think about the business rule being broken. Reply ONLY with compact JSON:\n"
    '{"thought":"short","action":{"method":"POST","path":"/api/book","json":{"seat":"A1"},"params":{}},"done":false}\n'
    "Use 'json' for a JSON body, 'params' for query string. Set done=true when you have enough "
    "evidence (triggered the behavior, or tried the sensible attempts). Keep values realistic."
)

_JUDGE_SYSTEM = (
    "You are a decisive security judge for business-logic tests. Given the GOAL (an undesired behavior) "
    "and a TRANSCRIPT of HTTP requests+responses, decide if the abuse was ACHIEVED, based ONLY on the "
    "actual response contents.\n"
    "An abuse is ACHIEVED when a SUCCESSFUL response (e.g. status 200, status:ok/confirmed) shows the app "
    "performed an action that violates its own stated rule, for example:\n"
    "- a total/price LOWER than the legitimate price stated in the goal (e.g. total:0 or total:1 when real price is 100),\n"
    "- a NEGATIVE charge/total (a refund via negative quantity/price),\n"
    "- a SECOND success where only one should be allowed (e.g. booking an already-taken seat twice),\n"
    "- a limit/floor bypassed (e.g. total driven to 0 or below by reusing a coupon).\n"
    "Compare the actual numbers in the responses against the legitimate values named in the goal. "
    "If the transcript clearly shows such an outcome in a successful response, set achieved=true — be decisive, "
    "do not require the app to return an error. If responses show the app blocked/validated it, achieved=false.\n"
    'Reply ONLY JSON: {"achieved":true/false,"confidence":0.0-1.0,"evidence":"quote the response that proves it","rationale":"short"}.'
)


def _json(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        # try to fix single quotes
        try:
            return json.loads(m.group(0).replace("'", '"'))
        except json.JSONDecodeError:
            return {}


class LogicTester:
    name = "business-logic-tester"

    def __init__(self, llm: LLM, http_fn: Callable[..., dict], log: AuditLogger):
        self.llm = llm
        self.http = http_fn      # (method, path, params=None, json_body=None) -> {status, body, headers}
        self.log = log

    def run(self, target: Target, description: str, goal: str,
            max_steps: int = 6) -> tuple[list[dict], list[Finding]]:
        transcript: list[dict] = []
        for step in range(1, max_steps + 1):
            plan = self._plan(description, goal, transcript)
            action = plan.get("action") or {}
            method = str(action.get("method", "")).upper()
            if not action.get("path") or method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                if plan.get("done") or not action.get("path"):
                    break
                continue
            path = action["path"]
            resp = self.http(method, path, params=action.get("params"),
                             json_body=action.get("json"))
            self.log.action(target.url, self.name,
                            f"step {step}: {method} {path} -> {resp.get('status')}")
            transcript.append({"thought": plan.get("thought", ""),
                               "request": {"method": method, "path": path,
                                           "params": action.get("params"), "json": action.get("json")},
                               "response": {"status": resp.get("status"),
                                            "body": (resp.get("body") or "")[:400]}})
            if plan.get("done"):
                break

        verdict = self._judge(goal, transcript)
        findings: list[Finding] = []
        if verdict.get("achieved") and transcript:
            findings.append(self._finding(target, goal, description, transcript, verdict))
            self.log.finding(f"Business logic: {goal[:50]}", "high")
        else:
            self.log.info(f"Business logic '{goal[:40]}': not confirmed "
                          f"({verdict.get('rationale','')[:60]})")
        return transcript, findings

    def _plan(self, description: str, goal: str, transcript: list[dict]) -> dict:
        tr = json.dumps(transcript[-4:], ensure_ascii=False) if transcript else "(empty)"
        prompt = (f"ENDPOINT DESCRIPTION:\n{description}\n\nGOAL (undesired behavior to trigger):\n{goal}\n\n"
                  f"TRANSCRIPT SO FAR:\n{tr}\n\nNext request? JSON only.")
        reply = self.llm.chat(
            [{"role": "system", "content": _PLANNER_SYSTEM}, {"role": "user", "content": prompt}],
            temperature=0.5, think=False).content
        return _json(reply)

    def _judge(self, goal: str, transcript: list[dict]) -> dict:
        prompt = (f"GOAL:\n{goal}\n\nTRANSCRIPT:\n{json.dumps(transcript, ensure_ascii=False)[:3000]}\n\n"
                  "Was the undesired behavior achieved? JSON only.")
        reply = self.llm.chat(
            [{"role": "system", "content": _JUDGE_SYSTEM}, {"role": "user", "content": prompt}],
            temperature=0.0, think=False).content
        return _json(reply)

    def _finding(self, target: Target, goal: str, description: str,
                 transcript: list[dict], verdict: dict) -> Finding:
        steps = "\n".join(
            f"{i}. {t['request']['method']} {t['request']['path']} "
            f"{json.dumps(t['request'].get('json') or t['request'].get('params') or {}, ensure_ascii=False)} "
            f"-> {t['response']['status']}: {t['response']['body'][:120]}"
            for i, t in enumerate(transcript, 1))
        return Finding(
            title=f"Business Logic Flaw: {goal[:70]}",
            severity=Severity.HIGH, owasp="A04:2025 Insecure Design", cwe="CWE-840",
            target=target.url, component=transcript[-1]["request"]["path"] if transcript else "",
            source_tool=self.name,
            description=f"Abuse goal achieved: {goal}. Judge verdict: "
                        f"{verdict.get('rationale','')} (conf {verdict.get('confidence',0)}).",
            impact="Business rule abuse — financial/operational losses (e.g. purchase below price, "
                   "double booking, bypassing limits).",
            recommendation="Enforce the rule server-side: validate price against the price list, check availability "
                           "before booking, limit coupons, reject negative/zero values; state tests.",
            reproduction="Request sequence (evidence):\n" + steps,
            evidence=Evidence(payload=goal,
                              response=str(verdict.get("evidence", ""))[:300],
                              request=steps[:400]))
