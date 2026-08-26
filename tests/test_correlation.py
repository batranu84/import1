from shadowstrike.models.domain import Evidence
from shadowstrike.services.correlation import CorrelationEngine


def test_evidence_deduplication():
    engine = CorrelationEngine()
    e1 = Evidence(engine="x", category="dns", summary="same", raw={"a": 1})
    e2 = Evidence(engine="x", category="dns", summary="same", raw={"a": 1})
    normalized = engine.normalize_evidence([e1, e2])
    assert len(normalized) == 1
    assert normalized[0].fingerprint
