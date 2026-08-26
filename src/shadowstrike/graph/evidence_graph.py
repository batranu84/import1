from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from shadowstrike.models.domain import Asset, Evidence, Finding


@dataclass(frozen=True)
class GraphNode:
    kind: str
    key: str
    label: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    relation: str


@dataclass
class EvidenceGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: set[GraphEdge] = field(default_factory=set)

    @staticmethod
    def _node_key(kind: str, key: str) -> str:
        return f"{kind}:{key}".lower()

    def add_node(self, kind: str, key: str, label: Optional[str] = None, metadata: Optional[dict[str, str]] = None) -> str:
        node_key = self._node_key(kind, key)
        self.nodes.setdefault(node_key, GraphNode(kind=kind, key=key, label=label or key, metadata=metadata or {}))
        return node_key

    def add_edge(self, source: str, target: str, relation: str) -> None:
        self.edges.add(GraphEdge(source=source, target=target, relation=relation))

    @classmethod
    def from_results(
        cls, assets: Iterable[Asset], evidence: Iterable[Evidence], findings: Iterable[Finding]
    ) -> "EvidenceGraph":
        graph = cls()
        asset_ids: dict[str, str] = {}
        asset_values: dict[str, str] = {}
        evidence_ids: dict[str, str] = {}

        asset_list = list(assets)
        for asset in asset_list:
            key = graph.add_node("asset", asset.value, f"{asset.kind}: {asset.value}", metadata={"asset_kind": asset.kind, "service_state": str(asset.attributes.get("service_state", "")), "inventory_class": str(asset.attributes.get("inventory_class", ""))})
            asset_ids[str(asset.id)] = key
            asset_values.setdefault(asset.value.lower(), key)
            source = graph.add_node("engine", asset.source)
            graph.add_edge(source, key, "discovered")

        # Add useful attack-surface relationships that do not depend on rendering every
        # individual evidence node. These are provenance/topology links, not exploit paths.
        for asset in asset_list:
            current = asset_ids[str(asset.id)]
            attrs = asset.attributes or {}
            resolved_from = str(attrs.get("resolved_from", "")).strip()
            if resolved_from:
                parent = asset_values.get(resolved_from.lower()) or graph.add_node("subject", resolved_from, resolved_from)
                graph.add_edge(parent, current, "resolves_to")
            if asset.kind == "network-service":
                host = asset.value.rsplit(":", 1)[0] if ":" in asset.value else asset.value
                parent = asset_values.get(host.lower()) or graph.add_node("subject", host, host)
                graph.add_edge(parent, current, "exposes")
            elif asset.kind == "email-contact":
                domain = str(attrs.get("domain", "")).strip()
                if domain:
                    parent = asset_values.get(domain.lower()) or graph.add_node("subject", domain, domain)
                    graph.add_edge(parent, current, "references_contact")
            elif asset.kind == "network-device":
                gateway = str(attrs.get("gateway", "")).strip()
                if gateway and gateway != asset.value:
                    parent = asset_values.get(gateway.lower()) or graph.add_node("network", gateway, f"gateway: {gateway}")
                    graph.add_edge(parent, current, "reachable_on_lan")
                sensor_id = str(attrs.get("sensor_id", "")).strip()
                if sensor_id:
                    sensor = graph.add_node("sensor", sensor_id, f"sensor: {sensor_id}")
                    graph.add_edge(sensor, current, "observed")
            elif asset.kind in {"web-application", "web-endpoint", "javascript-resource", "javascript-endpoint-reference"}:
                try:
                    from urllib.parse import urlparse
                    host = urlparse(asset.value).hostname
                except Exception:
                    host = None
                if host:
                    parent = asset_values.get(host.lower()) or graph.add_node("subject", host, host)
                    graph.add_edge(parent, current, "serves")

        for item in evidence:
            ekey = graph.add_node("evidence", str(item.id), item.summary)
            evidence_ids[str(item.id)] = ekey
            engine = graph.add_node("engine", item.engine)
            graph.add_edge(engine, ekey, "observed")
            if item.asset_id and str(item.asset_id) in asset_ids:
                graph.add_edge(asset_ids[str(item.asset_id)], ekey, "supported_by")

        for finding in findings:
            fkey = graph.add_node("finding", str(finding.id), finding.title)
            affected = asset_values.get(finding.affected_asset.lower())
            if affected is None:
                affected = graph.add_node("subject", finding.affected_asset, finding.affected_asset)
            graph.add_edge(affected, fkey, "affected_by")
            for evidence_id in finding.evidence_ids:
                ekey = evidence_ids.get(str(evidence_id))
                if ekey:
                    graph.add_edge(ekey, fkey, "supports")

        return graph

    def export(self) -> dict[str, list[dict[str, str]]]:
        return {
            "nodes": [vars(node) for node in self.nodes.values()],
            "edges": [vars(edge) for edge in sorted(self.edges, key=lambda e: (e.source, e.target, e.relation))],
        }
