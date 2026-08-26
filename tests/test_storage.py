from pathlib import Path

from shadowstrike.models.domain import AssessmentRequest, AssessmentResult, ScopePolicy
from shadowstrike.storage.repository import AssessmentRepository


def test_repository_roundtrip(tmp_path: Path):
    repo = AssessmentRepository(tmp_path / "state.db")
    request = AssessmentRequest(
        name="fixture",
        targets=["example.test"],
        authorization_reference="LAB-1",
        scope=ScopePolicy(allowed_domains=["example.test"]),
    )
    result = AssessmentResult(name="fixture", profile="full", status="running")
    repo.save(request, result)
    loaded = repo.load(result.id)
    assert loaded is not None
    loaded_request, loaded_result = loaded
    assert loaded_request.authorization_reference == "LAB-1"
    assert loaded_result.id == result.id
    assert loaded_result.status == "running"
