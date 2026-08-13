"""Authorization and scope gate (RoE).

Hard, non-bypassable rule: no active action starts without:
  1) confirmed authorization (Scope.authorized),
  2) a target that falls within in_scope and outside out_of_scope,
  3) (for destructive actions) Scope.allow_destructive.

See research/00-authorization-and-scope.md.
"""
from __future__ import annotations

import ipaddress
from enum import Enum
from urllib.parse import urlparse

from .models import Scope


class ActionClass(str, Enum):
    PASSIVE = "passive"        # OSINT, analysis of a single response — scope only
    ACTIVE = "active"          # scan, single payloads — consent + scope
    INVASIVE = "invasive"      # exploit, auth bypass — consent + scope
    DESTRUCTIVE = "destructive"  # DoS/flooding/DROP — additionally allow_destructive


class ScopeViolation(Exception):
    """Raised when an action violates the RoE. Never catch this just to proceed anyway."""


def _host_of(target: str) -> str:
    t = target.strip()
    if "://" not in t:
        t = "//" + t
    host = urlparse(t).hostname or target.strip()
    return host.lower()


def _matches(host: str, pattern: str) -> bool:
    """Match a host against a scope entry. Supports: exact host, *.domain, CIDR, bare IP."""
    p = pattern.strip().lower()
    if not p:
        return False
    # CIDR / IP
    try:
        net = ipaddress.ip_network(p, strict=False)
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    except ValueError:
        pass
    # subdomain wildcard: *.example.com
    if p.startswith("*."):
        base = p[2:]
        return host == base or host.endswith("." + base)
    # exact host match or domain suffix
    ph = _host_of(p)
    return host == ph or host.endswith("." + ph)


class ScopeGuard:
    """Enforces the RoE. Call `authorize(target, action)` BEFORE every operation on a target."""

    def __init__(self, scope: Scope):
        self.scope = scope

    def in_scope(self, target: str) -> bool:
        host = _host_of(target)
        if any(_matches(host, o) for o in self.scope.out_of_scope):
            return False
        return any(_matches(host, i) for i in self.scope.in_scope)

    def authorize(self, target: str, action: ActionClass) -> None:
        """Raises ScopeViolation if the action is not allowed. Otherwise: passes."""
        host = _host_of(target)

        # Passive: it's enough that the target is in scope (no invasive interaction).
        if action == ActionClass.PASSIVE:
            if not self.in_scope(target):
                raise ScopeViolation(f"Target out of scope (passive): {host}")
            return

        # Everything active requires written authorization.
        if not self.scope.authorized:
            raise ScopeViolation(
                f"No confirmed authorization — action '{action.value}' blocked. "
                f"Set Scope.authorized only after obtaining written consent."
            )
        if any(_matches(host, o) for o in self.scope.out_of_scope):
            raise ScopeViolation(f"Target is explicitly OUT-OF-SCOPE: {host}")
        if not self.in_scope(target):
            raise ScopeViolation(f"Target outside in_scope: {host}")

        if action == ActionClass.DESTRUCTIVE and not self.scope.allow_destructive:
            raise ScopeViolation(
                f"Destructive action requires an explicit opt-in (Scope.allow_destructive=True): {host}"
            )

    def check(self, target: str, action: ActionClass) -> bool:
        """Non-raising variant — returns True/False."""
        try:
            self.authorize(target, action)
            return True
        except ScopeViolation:
            return False
