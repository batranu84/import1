from __future__ import annotations

import ipaddress
from typing import Iterable

from shadowstrike.models.domain import Asset, AssessmentResult

SUBRESOURCE_KINDS = {
    "network-service", "transport-endpoint", "transport-surface", "web-endpoint",
    "javascript-resource", "javascript-dependency", "javascript-route", "api-operation",
}

def valid_host_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.is_unspecified or address.is_loopback or address.is_multicast:
        return False
    if address.version == 4 and str(address) in {"255.255.255.255", "0.0.0.0"}:
        return False
    return True

def primary_assets(assets: Iterable[Asset]) -> list[Asset]:
    return [a for a in assets if a.kind not in SUBRESOURCE_KINDS]

def valid_network_devices(assets: Iterable[Asset]) -> list[Asset]:
    return [a for a in assets if a.kind == "network-device" and valid_host_address(a.value)]

def confirmed_services(assets: Iterable[Asset], *, source: str | None = None) -> list[Asset]:
    out = []
    for a in assets:
        if a.kind != "network-service":
            continue
        if source is not None and a.source != source:
            continue
        state = str(a.attributes.get("service_state") or "confirmed").lower()
        if state == "confirmed":
            out.append(a)
    return out

def transport_observations(assets: Iterable[Asset]) -> list[Asset]:
    return [a for a in assets if a.kind in {"transport-endpoint", "transport-surface"}]

def inventory_summary(result: AssessmentResult) -> dict[str, int]:
    return {
        "primary_assets": len(primary_assets(result.assets)),
        "confirmed_services": len(confirmed_services(result.assets)),
        "transport_observations": len(transport_observations(result.assets)),
        "network_devices": len(valid_network_devices(result.assets)),
        "contacts": sum(1 for a in result.assets if a.kind == "email-contact"),
    }
