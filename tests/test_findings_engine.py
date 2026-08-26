from shadowstrike.models.domain import Evidence
from shadowstrike.services.findings import FindingsEngine


def port(host: str, number: int, service: str) -> Evidence:
    return Evidence(
        engine="ShadowScan",
        category="port",
        summary=f"TCP/{number} accepted a connection on {host}",
        raw={"host": host, "port": number, "state": "open", "service_hint": service, "service_name": service, "service_state": "confirmed"},
    )


def test_service_exposure_creates_evidence_backed_findings() -> None:
    e1 = port("example.test", 21, "ftp")
    e2 = port("example.test", 143, "imap")
    e3 = port("example.test", 993, "imaps")
    findings = FindingsEngine().analyze([e1, e2, e3])
    titles = {f.title for f in findings}
    assert "FTP service reachable" in titles
    assert "Clear-text IMAP service reachable" in titles
    assert "Clear-text and encrypted mailbox protocols exposed together" in titles
    assert all(f.evidence_ids for f in findings)


def test_broad_surface_requires_eight_unique_ports() -> None:
    evidence = [port("host.test", p, "unknown") for p in (22, 25, 53, 80, 443, 465, 587, 993)]
    findings = FindingsEngine().analyze(evidence)
    assert any(f.title == "Broad TCP port reachability observed" for f in findings)


def test_dns_posture_only_flags_confirmed_absence() -> None:
    missing = Evidence(
        engine="ShadowDNS",
        category="dns-posture",
        summary="DMARC policy not observed",
        raw={"check": "DMARC", "host": "example.test", "present": False, "mail_domain": True},
    )
    present = Evidence(
        engine="ShadowDNS",
        category="dns-posture",
        summary="CAA posture",
        raw={"check": "CAA", "host": "example.test", "present": True},
    )
    findings = FindingsEngine().analyze([missing, present])
    assert [f.title for f in findings] == ["DMARC policy not observed"]


def test_unconfirmed_service_does_not_create_protocol_specific_finding() -> None:
    evidence = Evidence(
        engine="ShadowLAN", category="port", summary="TCP/21 open",
        raw={"host": "host.test", "port": 21, "state": "open", "service_state": "unconfirmed"},
    )
    findings = FindingsEngine().analyze([evidence])
    assert not any(f.title == "FTP service reachable" for f in findings)
