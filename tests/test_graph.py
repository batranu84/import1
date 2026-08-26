from shadowstrike.graph.evidence_graph import EvidenceGraph
from shadowstrike.models.domain import Asset, Confidence, Evidence, Finding, Severity


def test_graph_links_evidence_to_finding():
    asset = Asset(kind="web-application", value="https://example.test", source="ShadowHTTP")
    evidence = Evidence(
        asset_id=asset.id,
        engine="ShadowHTTP",
        category="http",
        summary="HTTP 200",
    )
    finding = Finding(
        title="Fixture finding",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        affected_asset=asset.value,
        description="fixture",
        remediation="fixture",
        evidence_ids=[evidence.id],
    )
    graph = EvidenceGraph.from_results([asset], [evidence], [finding])
    exported = graph.export()
    relations = {edge["relation"] for edge in exported["edges"]}
    assert "discovered" in relations
    assert "supported_by" in relations
    assert "supports" in relations
    assert "affected_by" in relations
