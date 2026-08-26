from dataclasses import dataclass

from shadowstrike.graph.evidence_graph import EvidenceGraph


@dataclass
class PhysicalGraphAdapter:
    """Maps physical asset intelligence into the evidence graph."""

    def attach(self, graph: EvidenceGraph, asset_key: str, assessment) -> None:
        physical = graph.add_node("physical-asset", asset_key, assessment.category)
        graph.add_edge(asset_key, physical, "classified_as")

        for item in assessment.evidence:
            evidence = graph.add_node("physical-evidence", item, item)
            graph.add_edge(physical, evidence, "supported_by")

        category = assessment.category.lower()
        if "camera" in category or "cctv" in category:
            graph.add_edge(physical, graph.add_node("class", "cctv", "CCTV"), "belongs_to")
        elif "iot" in category:
            graph.add_edge(physical, graph.add_node("class", "iot", "IoT"), "belongs_to")
        elif "ot" in category or "building" in category:
            graph.add_edge(physical, graph.add_node("class", "ot", "OT"), "belongs_to")
