from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from shadowstrike.models.domain import ScopePolicy


class ScopeViolation(ValueError):
    pass


class ScopeGuard:
    def __init__(self, policy: ScopePolicy):
        self.policy = policy
        self.allowed_networks = [ipaddress.ip_network(x, strict=False) for x in policy.allowed_cidrs]
        self.excluded_networks = [ipaddress.ip_network(x, strict=False) for x in policy.excluded_cidrs]

    @staticmethod
    def _host(target: str) -> str:
        parsed = urlparse(target if "://" in target else f"//{target}")
        return (parsed.hostname or target).strip("[]").lower().rstrip(".")

    @staticmethod
    def _domain_matches(host: str, rule: str) -> bool:
        rule = rule.lower().lstrip("*.").rstrip(".")
        return host == rule or host.endswith("." + rule)

    def allows(self, target: str) -> bool:
        host = self._host(target)
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if any(self._domain_matches(host, d) for d in self.policy.excluded_domains):
                return False
            return any(self._domain_matches(host, d) for d in self.policy.allowed_domains)
        if any(ip in net for net in self.excluded_networks):
            return False
        return any(ip in net for net in self.allowed_networks)

    def require(self, target: str) -> None:
        if not self.allows(target):
            raise ScopeViolation(f"Target is outside authorized scope: {target}")
