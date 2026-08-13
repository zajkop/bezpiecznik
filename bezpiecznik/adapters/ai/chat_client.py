"""Client for conversing with the TARGET (the chatbot under test).

Note: this is NOT our LLM (attacker/judge). It is an adapter to the victim's endpoint.
By default assumes the contract: POST <endpoint> {"message": str, "history": [{"role","content"}]}
→ {"reply": str}. Configurable for other APIs.
"""
from __future__ import annotations

import json
from typing import Optional

from ...core.http import HttpClient
from ...core.models import Message


class TargetChatClient:
    def __init__(self, http: HttpClient, endpoint: str, auth_header: Optional[str] = None):
        self.http = http
        self.endpoint = endpoint
        self.headers = {"Content-Type": "application/json"}
        if auth_header and ":" in auth_header:
            k, v = auth_header.split(":", 1)
            self.headers[k.strip()] = v.strip()

    def send(self, message: str, history: Optional[list[Message]] = None) -> str:
        payload = {
            "message": message,
            "history": [{"role": m.role, "content": m.content} for m in (history or [])],
        }
        r = self.http.post(self.endpoint, headers=self.headers, content=json.dumps(payload))
        try:
            data = json.loads(r.text)
        except json.JSONDecodeError:
            return r.text
        if not isinstance(data, dict):
            return r.text
        # handle various response shapes
        for key in ("reply", "response", "content"):
            if isinstance(data.get(key), str):
                return data[key]
        msg = data.get("message")
        if isinstance(msg, dict) and isinstance(msg.get("content"), str):
            return msg["content"]
        return r.text
