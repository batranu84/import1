from fastapi.testclient import TestClient

from shadowstrike.api import app as app_module
from shadowstrike.api.app import app


def test_dashboard_and_health() -> None:
    client = TestClient(app)
    page = client.get("/")
    assert page.status_code == 200
    assert "SHADOWSTRIKE" in page.text
    assert "Start assessment" in page.text
    assert "Evidence Graph" in page.text
    assert "Settings" in page.text
    assert "Deep UDP + multicast discovery" in page.text
    assert "Specialist Nmap adapter" in page.text
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["version"] == "0.26.0"


def test_overview_and_system_settings() -> None:
    client = TestClient(app)
    overview = client.get("/overview")
    assert overview.status_code == 200
    assert "assessments" in overview.json()
    assert "active_task_count" in overview.json()

    runtime = client.get("/system/settings")
    assert runtime.status_code == 200
    data = runtime.json()
    assert data["runtime"]["version"] == "0.26.0"
    assert data["safety"]["scope_enforcement"] is True
    assert data["safety"]["load_testing_in_standard_profiles"] is False


def test_start_rejects_target_outside_scope() -> None:
    client = TestClient(app)
    response = client.post(
        "/assessments/start",
        json={
            "name": "scope-check",
            "targets": ["example.net"],
            "profile": "full",
            "authorization_reference": "TEST-AUTH",
            "scope": {
                "allowed_domains": ["example.com"],
                "allowed_cidrs": [],
                "excluded_domains": [],
                "excluded_cidrs": [],
                "max_requests_per_second": 10,
                "max_concurrency": 10,
                "allow_active_web": True,
                "allow_load_testing": False,
            },
        },
    )
    assert response.status_code == 400


def test_cancel_unknown_assessment_returns_404() -> None:
    client = TestClient(app)
    response = client.post("/assessments/00000000-0000-0000-0000-000000000000/cancel")
    assert response.status_code == 404


def test_background_worker_failure_is_persisted(tmp_path, monkeypatch) -> None:
    from shadowstrike.models.domain import AssessmentRequest, AssessmentResult, ModuleStatus, ScopePolicy
    from shadowstrike.storage.repository import AssessmentRepository

    repo = AssessmentRepository(tmp_path / "worker-failure.db")
    monkeypatch.setattr(app_module.orchestrator, "repository", repo)
    request = AssessmentRequest(
        name="worker-failure",
        targets=["example.test"],
        authorization_reference="LAB-WORKER",
        scope=ScopePolicy(allowed_domains=["example.test"]),
    )
    result = AssessmentResult(
        name=request.name,
        profile=request.profile,
        status="running",
        modules=[ModuleStatus(name="ShadowRecon")],
    )
    repo.save(request, result)

    app_module._record_background_failure(str(result.id), TypeError("fixture crash"))
    loaded = repo.load(result.id)
    assert loaded is not None
    failed = loaded[1]
    assert failed.status == "failed"
    assert failed.modules[0].state.value == "failed"
    assert "fixture crash" in (failed.modules[0].message or "")
