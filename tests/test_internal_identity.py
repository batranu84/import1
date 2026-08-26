from fastapi.testclient import TestClient

from shadowstrike.api import app as app_module
from shadowstrike.api.app import app
from shadowstrike.internal.identity import InternalIdentityService
from shadowstrike.models.domain import Asset, AssessmentRequest, AssessmentResult, Evidence, ScopePolicy
from shadowstrike.storage.repository import AssessmentRepository


def _identity_assets():
    dc = Asset(
        kind="network-device", value="10.40.0.10", source="ShadowLAN",
        attributes={
            "hostname": "dc01", "device_type": "domain-controller", "identity_confidence": "confirmed",
            "domain": "corp.example", "is_domain_controller": True,
        },
    )
    candidate = Asset(
        kind="network-device", value="10.40.0.11", source="ShadowLAN",
        attributes={"hostname": "srv01", "device_type": "server", "identity_confidence": "observed"},
    )
    services = []
    for host, ports in [("10.40.0.10", [53, 88, 389, 445, 3268]), ("10.40.0.11", [88, 135, 389, 445])]:
        for port in ports:
            services.append(Asset(
                kind="network-service", value=f"{host}:{port}", source="ShadowLAN",
                attributes={"host": host, "port": port},
            ))
    svc = Asset(
        kind="service-account", value="CORP\\svc_backup", source="authorized-directory-inventory",
        attributes={"domain": "corp.example", "service_account": True, "enabled": True, "password_never_expires": True},
    )
    stale = Asset(
        kind="ad-account", value="CORP\\old.user", source="authorized-directory-inventory",
        attributes={"domain": "corp.example", "enabled": True, "stale": True},
    )
    ev = Evidence(asset_id=svc.id, engine="DirectoryInventory", category="account-policy", summary="pwdNeverExpires=true")
    return [dc, candidate, svc, stale, *services], [ev]


def test_identity_summary_distinguishes_confirmed_and_candidate_dc():
    assets, evidence = _identity_assets()
    data = InternalIdentityService.summarize(assets, evidence)
    assert data["confirmed_domain_controllers"][0]["ip"] == "10.40.0.10"
    assert data["candidate_domain_controllers"][0]["ip"] == "10.40.0.11"
    assert data["domains"]["corp.example"] >= 1
    assert data["protocol_counts"] == {}
    assert data["candidate_protocol_counts"]["Kerberos"] == 2



def test_identity_protocol_counts_require_confirmed_protocol_evidence():
    assets, evidence = _identity_assets()
    kerberos = next(a for a in assets if a.kind == "network-service" and a.attributes.get("port") == 88)
    kerberos.attributes.update({
        "service_candidate": "Kerberos",
        "service_name": "kerberos",
        "service_state": "confirmed",
        "identity_basis": "kerberos-protocol-response",
    })
    data = InternalIdentityService.summarize(assets, evidence)
    assert data["protocol_counts"]["kerberos"] == 1
    assert data["candidate_protocol_counts"]["Kerberos"] == 2

def test_identity_findings_require_direct_configuration_evidence():
    assets, evidence = _identity_assets()
    derived, findings = InternalIdentityService.derive(assets, evidence)
    assert any(e.category == "internal-identity-summary" for e in derived)
    service_account = next(f for f in findings if "non-expiring" in f.title)
    assert service_account.validation_status == "observed-configuration"
    assert evidence[0].id in service_account.evidence_ids
    stale = next(f for f in findings if "Stale" in f.title)
    assert stale.confidence.value == "confirmed"


def test_ports_alone_do_not_create_vulnerability_findings():
    assets, evidence = _identity_assets()
    derived, findings = InternalIdentityService.derive(assets, evidence)
    assert all("LDAP" not in f.title and "SMB" not in f.title and "Kerberos" not in f.title for f in findings)


def test_internal_identity_api(tmp_path, monkeypatch):
    repo = AssessmentRepository(tmp_path / "identity-api.db")
    monkeypatch.setattr(app_module.orchestrator, "repository", repo)
    request = AssessmentRequest(
        name="internal", targets=["10.40.0.10"], profile="internal", mode="internal",
        authorization_reference="LAB-IDENTITY",
        scope=ScopePolicy(allowed_cidrs=["10.40.0.0/24"]),
    )
    result = AssessmentResult(name="internal", profile="internal", status="completed")
    result.assets, result.evidence = _identity_assets()
    repo.save(request, result)
    response = TestClient(app).get(f"/assessments/{result.id}/internal-identity")
    assert response.status_code == 200
    assert len(response.json()["confirmed_domain_controllers"]) == 1


def test_orchestrator_routes_shadowidentity_for_internal_mode():
    names = [e.name for e in app_module.orchestrator.internal_engines]
    assert "ShadowIdentity" in names
