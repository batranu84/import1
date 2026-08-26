from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlparse

from shadowstrike.models.domain import Asset, Evidence


EXTERNAL_KINDS = {
    "domain",
    "ip-address",
    "dns-name",
    "network-service",
    "transport-endpoint",
    "transport-surface",
    "web-application",
    "web-endpoint",
    "javascript-resource",
    "javascript-dependency",
    "javascript-route",
    "api-schema",
    "api-operation",
    "graphql-endpoint",
    "websocket-reference",
    "email-contact",
}


@dataclass
class ExternalInventory:
    assets: list[Asset] = field(default_factory=list)
    by_kind: dict[str, list[Asset]] = field(default_factory=dict)
    service_ports: dict[str, list[int]] = field(default_factory=dict)
    web_origins: list[str] = field(default_factory=list)
    evidence_categories: dict[str, int] = field(default_factory=dict)

    @property
    def asset_count(self) -> int:
        return len(self.assets)

    @property
    def service_count(self) -> int:
        return len(self.by_kind.get("network-service", []))

    @property
    def transport_endpoint_count(self) -> int:
        return len(self.by_kind.get("transport-endpoint", []))

    @property
    def transport_surface_count(self) -> int:
        return len(self.by_kind.get("transport-surface", []))

    @property
    def web_count(self) -> int:
        return len(self.by_kind.get("web-application", []))

    @property
    def api_count(self) -> int:
        return sum(len(self.by_kind.get(kind, [])) for kind in ("api-schema", "api-operation", "graphql-endpoint"))


def _asset_key(asset: Asset) -> tuple[str, str]:
    value = asset.value.strip()
    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        value = f"{parsed.scheme.lower()}://{(parsed.hostname or '').lower()}"
        if parsed.port:
            value += f":{parsed.port}"
        if asset.kind not in {"web-application"}:
            value += parsed.path or "/"
    else:
        value = value.lower().rstrip(".")
    return asset.kind, value


def build_external_inventory(assets: list[Asset], evidence: list[Evidence]) -> ExternalInventory:
    deduped: dict[tuple[str, str], Asset] = {}
    by_kind: dict[str, list[Asset]] = defaultdict(list)
    services: dict[str, set[int]] = defaultdict(set)
    origins: set[str] = set()

    for asset in assets:
        if asset.kind not in EXTERNAL_KINDS:
            continue
        key = _asset_key(asset)
        if key not in deduped:
            deduped[key] = asset

    for asset in deduped.values():
        by_kind[asset.kind].append(asset)
        if asset.kind == "network-service":
            attrs = asset.attributes or {}
            host = str(attrs.get("host", "")).strip().lower()
            try:
                port = int(attrs.get("port"))
            except (TypeError, ValueError):
                host_port = asset.value.rsplit(":", 1)
                if len(host_port) != 2:
                    continue
                host = host or host_port[0].strip("[]").lower()
                try:
                    port = int(host_port[1])
                except ValueError:
                    continue
            if host:
                services[host].add(port)
        elif asset.kind == "web-application":
            parsed = urlparse(asset.value)
            if parsed.scheme and parsed.hostname:
                origin = f"{parsed.scheme.lower()}://{parsed.hostname.lower()}"
                if parsed.port:
                    origin += f":{parsed.port}"
                origins.add(origin)

    category_counts = Counter(item.category for item in evidence)
    return ExternalInventory(
        assets=list(deduped.values()),
        by_kind={k: sorted(v, key=lambda a: a.value) for k, v in by_kind.items()},
        service_ports={host: sorted(ports) for host, ports in services.items()},
        web_origins=sorted(origins),
        evidence_categories=dict(sorted(category_counts.items())),
    )
