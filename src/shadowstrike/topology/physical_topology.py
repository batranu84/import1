from dataclasses import dataclass, field


@dataclass
class PhysicalTopologyBuilder:
    """Builds evidence-backed topology nodes for physical assets."""

    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)

    def add_asset(self, asset_id: str, category: str, evidence=None, risk=None):
        node = {
            "id": asset_id,
            "kind": category,
            "evidence": list(evidence or []),
            "risk": risk,
        }
        if node not in self.nodes:
            self.nodes.append(node)
        return node

    def link(self, source: str, target: str, relation: str, evidence: str):
        edge = {
            "source": source,
            "target": target,
            "relation": relation,
            "evidence": evidence,
        }
        if edge not in self.edges:
            self.edges.append(edge)
        return edge

    def attach_physical(self, asset_id: str, category: str, parent: str | None = None, evidence=None, risk=None):
        self.add_asset(asset_id, category, evidence=evidence, risk=risk)
        if parent:
            self.link(parent, asset_id, "hosts", "physical asset observation")
        return self.export()

    def export(self):
        return {"nodes": self.nodes, "edges": self.edges}
