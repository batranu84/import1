from shadowstrike.storage.repository import AssessmentRepository


def test_engine_checkpoint_roundtrip(tmp_path):
    repo = AssessmentRepository(tmp_path / "state.db")
    repo.save_engine_checkpoint("assessment-1", "ShadowScan", {"next_index": 42, "open_services": []})
    state = repo.load_engine_checkpoint("assessment-1", "ShadowScan")
    assert state["next_index"] == 42
    repo.clear_engine_checkpoint("assessment-1", "ShadowScan")
    assert repo.load_engine_checkpoint("assessment-1", "ShadowScan") is None
