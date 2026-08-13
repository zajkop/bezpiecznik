"""Recon for SPAs (Angular/React/Vue) via a headless browser.

A classic HTML crawl extracts nothing from an SPA (content rendered in JS). This adapter
runs the page in Chromium (Playwright), executes JS, lightly interacts with it,
and CAPTURES XHR/fetch calls to the API — from which it builds seeds (path, parameter).

Graceful degradation: no playwright/chromium → returns empty seeds with a note.
Installation: pip install playwright && python -m playwright install chromium
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlparse


def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


class SpaRecon:
    name = "spa-recon (headless)"

    def __init__(self, log, nav_timeout_ms: int = 20000, marker: str = "bzscan"):
        self.log = log
        self.nav_timeout = nav_timeout_ms
        self.marker = marker

    def discover(self, base_url: str) -> tuple[set[tuple[str, str]], list[str], set[str]]:
        """Returns (seeds, endpoints, routes) — seeds=(path,param), endpoints=API,
        routes=client hash-routes (e.g. '/search') for DOM-XSS tests."""
        if not playwright_available():
            self.log.info("SPA-recon: playwright not installed — skipping "
                          "(pip install playwright && playwright install chromium)")
            return set(), [], set()
        try:
            return self._run(base_url)
        except Exception as e:  # noqa: BLE001
            self.log.info(f"SPA-recon: headless error ({repr(e)[:120]}) — skipping")
            return set(), [], set()

    def _run(self, base_url: str) -> tuple[set[tuple[str, str]], list[str], set[str]]:
        from playwright.sync_api import sync_playwright

        target_netloc = urlparse(base_url).netloc
        requests_seen: set[tuple[str, str]] = set()  # (method, url)
        routes: set[str] = set()

        def _record_route(url: str) -> None:
            frag = urlparse(url).fragment  # e.g. '/search?q=...'
            if frag:
                routes.add("/" + frag.split("?")[0].lstrip("/"))

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(ignore_https_errors=True)
            page.on("request", lambda r: requests_seen.add((r.method, r.url)))
            page.on("framenavigated", lambda f: _record_route(f.url))
            page.set_default_timeout(4000)

            page.goto(base_url, wait_until="load", timeout=self.nav_timeout)
            try:
                page.wait_for_load_state("networkidle", timeout=12000)
            except Exception:  # noqa: BLE001
                pass
            page.wait_for_timeout(3000)      # catch lazy XHR after the first render (SPA bootstrap)
            self._interact(page, base_url)
            page.wait_for_timeout(2000)      # catch XHR triggered by interaction
            _record_route(page.url)
            browser.close()

        seeds: set[tuple[str, str]] = set()
        endpoints: list[str] = []
        for method, url in requests_seen:
            u = urlparse(url)
            if u.netloc != target_netloc:
                continue  # same-origin only
            if u.path.startswith(("/socket.io", "/assets", "/resources")):
                continue
            path = u.path or "/"
            if u.query:
                endpoints.append(f"{method} {path}?{u.query}")
                # keep_blank_values=True — also catches 'q=' (empty), typical for SPA search boxes
                for k, _v in parse_qsl(u.query, keep_blank_values=True):
                    if k and k not in {"_", "t", "sid", "EIO", "transport"}:
                        seeds.add((path, k))
            elif "/rest/" in path or "/api/" in path:
                endpoints.append(f"{method} {path}")

        routes.discard("/")
        if seeds:
            self.log.info(f"SPA-recon: captured {len(endpoints)} API calls, "
                          f"extracted {len(seeds)} param-points: "
                          + ", ".join(sorted({f'{p}?{n}' for p, n in seeds})[:8]))
        else:
            self.log.info(f"SPA-recon: captured {len(endpoints)} API calls "
                          "(no GET parameters to fuzz)")
        if routes:
            self.log.info(f"SPA-recon: client routes: {', '.join(sorted(routes)[:8])}")
        return seeds, endpoints, routes

    def _interact(self, page, base_url: str) -> None:
        """Light interaction to trigger additional XHR: fill in text fields, click links."""
        # 00) close banners/consent dialogs (common SPA pattern — they block content/XHR loading).
        # Includes a Polish consent label so we also handle non-English sites; extend as needed.
        for lbl in ("dismiss", "Me want it!", "Got it", "Accept", "Zgadzam się"):
            try:
                page.click(f"button:has-text('{lbl}')", timeout=400)
                page.wait_for_timeout(250)
            except Exception:  # noqa: BLE001
                continue
        page.wait_for_timeout(800)   # catch XHR unblocked after closing the banners
        # 0) trigger the search UI (common pattern: a magnifier icon reveals the field)
        for sel in ("#searchQuery", "[aria-label*='search' i]", "[aria-label*='Search']",
                    ".mat-search_icon", "mat-icon:has-text('search')"):
            try:
                page.click(sel, timeout=1200)
                page.wait_for_timeout(400)
                break
            except Exception:  # noqa: BLE001
                continue
        # 1) search / text fields → type marker + Enter (triggers /search?q=…)
        try:
            inputs = page.query_selector_all(
                "input[type=text], input[type=search], input:not([type]), input[matInput]")
            for inp in inputs[:5]:
                try:
                    inp.fill(self.marker)
                    inp.press("Enter")
                    page.wait_for_timeout(800)
                except Exception:  # noqa: BLE001
                    continue
        except Exception:  # noqa: BLE001
            pass
        # 2) click a few in-app elements (SPA routing → new XHR)
        try:
            clickables = page.query_selector_all("a[href], button")
            clicked = 0
            for el in clickables:
                if clicked >= 6:
                    break
                try:
                    el.click(timeout=1500, no_wait_after=True)
                    page.wait_for_timeout(500)
                    clicked += 1
                except Exception:  # noqa: BLE001
                    continue
        except Exception:  # noqa: BLE001
            pass
