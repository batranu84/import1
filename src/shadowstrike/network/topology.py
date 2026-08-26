from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from shadowstrike.network.device import ShadowDevice


@dataclass
class ShadowTopology:
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)

    @classmethod
    def from_devices(cls, devices: Iterable[ShadowDevice], gateway: str | None = None) -> "ShadowTopology":
        """Build only relationships supported by direct observations.

        A flat-LAN reachability edge is labelled as such; it is not presented as a physical
        switch-port relationship. Stronger LLDP/FDB relationships can be added by sensors.
        """
        topology = cls()
        seen: set[str] = set()
        device_list = list(devices)
        for device in device_list:
            if device.ip in seen:
                continue
            topology.nodes.append({
                "id": device.ip,
                "label": device.hostname or device.ip,
                "kind": device.device_type,
                "ip": device.ip,
                "mac": device.mac,
                "vendor": device.vendor,
                "confidence": device.identity_confidence,
                "observation_state": device.observation_state,
            })
            seen.add(device.ip)
        if gateway and gateway not in seen:
            topology.nodes.append({
                "id": gateway, "label": gateway, "kind": "gateway/router", "ip": gateway,
                "confidence": "confirmed", "observation_state": "confirmed",
            })
            seen.add(gateway)

        if gateway:
            for device in device_list:
                if device.ip != gateway:
                    topology.add_link(
                        gateway, device.ip, "same-routed-lan",
                        evidence="route+positive-host-observation", confidence="observed",
                    )

        # Optional sensor-provided LLDP/FDB relationships are direct evidence and take
        # precedence over a generic routed-LAN relationship.
        for device in device_list:
            for link in device.metadata.get("topology_links", []) if device.metadata else []:
                source = str(link.get("source") or device.ip)
                target = str(link.get("target") or "")
                if target:
                    if target not in seen:
                        topology.nodes.append({
                            "id": target,
                            "label": str(link.get("target_label") or target),
                            "kind": "lldp-neighbor" if str(link.get("relation")) == "lldp-neighbor" else "observed-neighbor",
                            "description": link.get("target_description"),
                            "confidence": str(link.get("confidence") or "confirmed"),
                            "observation_state": "confirmed",
                        })
                        seen.add(target)
                    topology.add_link(
                        source, target, str(link.get("relation") or "connected"),
                        evidence=str(link.get("evidence") or "sensor"),
                        confidence=str(link.get("confidence") or "confirmed"),
                    )
                    if topology.edges:
                        topology.edges[-1]["local_port"] = link.get("local_port")
                        topology.edges[-1]["remote_port"] = link.get("remote_port")
        return topology

    def add_link(
        self,
        source: str,
        target: str,
        relation: str = "connected",
        *,
        evidence: str = "direct-observation",
        confidence: str = "confirmed",
    ) -> None:
        edge = {
            "source": source, "target": target, "relation": relation,
            "evidence": evidence, "confidence": confidence,
        }
        if edge not in self.edges:
            self.edges.append(edge)

    def export(self) -> dict[str, list[dict]]:
        return {"nodes": self.nodes, "edges": self.edges}
