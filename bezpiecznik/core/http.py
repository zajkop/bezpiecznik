"""Rate-limited HTTP client for targets.

- Test-traffic tag in the User-Agent (so the SOC can tell us apart from a real attack).
- Gentle pace by default (don't accidentally take the target down).
- Does not raise exceptions on 4xx/5xx — returns a Response for analysis.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from .config import HTTPConfig


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float
    url: str

    def header(self, name: str) -> Optional[str]:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None


class HttpClient:
    def __init__(self, cfg: Optional[HTTPConfig] = None):
        self.cfg = cfg or HTTPConfig()
        self._client = httpx.Client(
            headers={"User-Agent": self.cfg.user_agent},
            timeout=self.cfg.timeout_s,
            verify=self.cfg.verify_tls,
            follow_redirects=False,
        )
        self._min_interval = 1.0 / self.cfg.rate_limit_rps if self.cfg.rate_limit_rps > 0 else 0.0
        self._last = 0.0

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        wait = self._min_interval - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

    def request(self, method: str, url: str, **kw: Any) -> Response:
        self._throttle()
        t0 = time.time()
        try:
            r = self._client.request(method, url, **kw)
            text = r.text
            status = r.status_code
            headers = dict(r.headers)
        except httpx.HTTPError as e:
            return Response(status=0, headers={}, text=f"[http-error] {e}",
                            elapsed_ms=(time.time() - t0) * 1000, url=url)
        return Response(status=status, headers=headers, text=text,
                        elapsed_ms=(time.time() - t0) * 1000, url=url)

    def get(self, url: str, **kw: Any) -> Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> Response:
        return self.request("POST", url, **kw)
