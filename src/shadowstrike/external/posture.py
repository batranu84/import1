from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.external.inventory import build_external_inventory
from shadowstrike.models.domain import Confidence, Evidence, Finding, Severity


MANAGEMENT_PORTS = {22, 23, 3389, 5900, 5985, 5986, 8080, 8443}
DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017}
CLEAR_TEXT_PORTS = {21, 23, 80, 110, 143}

MANAGEMENT_IDENTITIES = {
    "ssh", "telnet", "rdp", "ms-wbt-server", "vnc", "winrm", "winrm-http",
    "winrm-https", "wsman",
}
DATABASE_IDENTITIES = {
    "mssql", "ms-sql-s", "microsoft-sql-server", "oracle", "oracle-tns", "mysql",
    "postgresql", "postgres", "redis", "elasticsearch", "memcached", "mongodb", "mongo",
}
CLEAR_TEXT_IDENTITIES = {"ftp", "telnet", "http", "pop3", "imap"}


def _service_name(raw: dict) -> str:
    return str(raw.get("service_name") or raw.get("name") or "").strip().lower()


def _confirmed_service_index(
    assets: list,
    evidence: list[Evidence],
) -> tuple[dict[tuple[str, int], set[str]], dict[tuple[str, int], list[Evidence]]]:
    """Return service identities backed by explicit protocol/product confirmation.

    Port-number hints are intentionally ignored. Only records that explicitly declare
    ``service_state=confirmed`` may enter this index.
    """
    identities: dict[tuple[str, int], set[str]] = defaultdict(set)
    evidence_by_endpoint: dict[tuple[str, int], list[Evidence]] = defaultdict(list)

    for asset in assets:
        if getattr(asset, "kind", None) != "network-service":
            continue
        attrs = asset.attributes or {}
        if str(attrs.get("service_state") or "").lower() != "confirmed":
            continue
        host = str(attrs.get("host") or "").strip().lower()
        try:
            port = int(attrs.get("port"))
        except (TypeError, ValueError):
            continue
        name = _service_name(attrs)
        if host and name and name != "unknown":
            identities[(host, port)].add(name)

    for item in evidence:
        raw = item.raw or {}
        if str(raw.get("service_state") or "").lower() != "confirmed":
            continue
        host = str(raw.get("host") or "").strip().lower()
        try:
            port = int(raw.get("port"))
        except (TypeError, ValueError):
            continue
        name = _service_name(raw)
        if host and name and name != "unknown":
            endpoint = (host, port)
            identities[endpoint].add(name)
            evidence_by_endpoint[endpoint].append(item)
    return identities, evidence_by_endpoint


class ExternalPostureEngine(Engine):
    """Synthesize external evidence without promoting port heuristics to service identity."""

    name = "ShadowExternal"

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        del targets
        assets = context.assets or []
        evidence = context.evidence or []
        inventory = build_external_inventory(assets, evidence)
        output_evidence: list[Evidence] = []
        findings: list[Finding] = []

        summary = Evidence(
            engine=self.name,
            category="external-inventory-summary",
            summary=(
                f"External inventory: {inventory.asset_count} unique assets, "
                f"{inventory.service_count} protocol-confirmed services, {inventory.transport_endpoint_count} unverified transport endpoints, "
                f"{inventory.transport_surface_count} collapsed anomalous transport surfaces, {inventory.web_count} web applications, "
                f"{inventory.api_count} API artefacts"
            ),
            raw={
                "asset_count": inventory.asset_count,
                "service_count": inventory.service_count,
                "transport_endpoint_count": inventory.transport_endpoint_count,
                "transport_surface_count": inventory.transport_surface_count,
                "web_application_count": inventory.web_count,
                "api_artifact_count": inventory.api_count,
                "asset_kinds": {kind: len(items) for kind, items in inventory.by_kind.items()},
                "service_ports": inventory.service_ports,
                "web_origins": inventory.web_origins,
                "evidence_categories": inventory.evidence_categories,
                "service_count_semantics": "protocol-confirmed-application-services-only",
            },
        )
        output_evidence.append(summary)

        port_evidence: dict[tuple[str, int], list[Evidence]] = defaultdict(list)
        for item in evidence:
            if item.category != "port" or item.raw.get("state") != "open":
                continue
            host = str(item.raw.get("host", "")).strip().lower()
            try:
                port = int(item.raw.get("port"))
            except (TypeError, ValueError):
                continue
            if host:
                port_evidence[(host, port)].append(item)

        confirmed, identity_evidence = _confirmed_service_index(assets, evidence)
        anomaly_hosts = {
            str(item.raw.get("host") or "").strip().lower()
            for item in evidence
            if item.category == "tcp-acceptance-anomaly" and str(item.raw.get("host") or "").strip()
        }

        def candidate_observation(host: str, ports: list[int], group: str) -> None:
            if not ports or host in anomaly_hosts:
                return
            unresolved = [
                p for p in ports
                if not confirmed.get((host, p))
            ]
            if not unresolved:
                return
            output_evidence.append(Evidence(
                engine=self.name,
                category="service-candidate-surface",
                summary=f"{host} has {len(unresolved)} reachable TCP port(s) conventionally associated with {group}; protocol identity remains unverified",
                raw={
                    "host": host,
                    "group": group,
                    "ports": unresolved,
                    "reachability": "confirmed",
                    "service_identity": "unverified",
                    "promotion_to_finding": False,
                    "reason": "conventional-port-number-is-not-protocol-evidence",
                    "source_evidence_ids": [
                        str(ev.id) for port in unresolved for ev in port_evidence.get((host, port), [])
                    ],
                },
            ))

        def confirmed_endpoints(host: str, ports: list[int], allowed_names: set[str]) -> list[tuple[int, str]]:
            result: list[tuple[int, str]] = []
            for port in ports:
                for name in sorted(confirmed.get((host, port), set())):
                    if name in allowed_names:
                        result.append((port, name))
            return result

        observed_ports_by_host: dict[str, set[int]] = defaultdict(set)
        for (host, port), observations in port_evidence.items():
            if observations:
                observed_ports_by_host[host].add(port)
        for host, confirmed_ports in inventory.service_ports.items():
            observed_ports_by_host[host].update(confirmed_ports)

        for host, ports in observed_ports_by_host.items():
            management_ports = sorted(set(ports) & MANAGEMENT_PORTS)
            database_ports = sorted(set(ports) & DATABASE_PORTS)
            cleartext_ports = sorted(set(ports) & CLEAR_TEXT_PORTS)

            candidate_observation(host, management_ports, "administrative/management services")
            candidate_observation(host, database_ports, "database/data services")
            candidate_observation(host, cleartext_ports, "clear-text-capable protocols")

            management = confirmed_endpoints(host, management_ports, MANAGEMENT_IDENTITIES)
            databases = confirmed_endpoints(host, database_ports, DATABASE_IDENTITIES)
            cleartext = confirmed_endpoints(host, cleartext_ports, CLEAR_TEXT_IDENTITIES)

            if management:
                linked = [
                    ev.id for port, _name in management
                    for ev in [*port_evidence.get((host, port), []), *identity_evidence.get((host, port), [])]
                ]
                findings.append(Finding(
                    title="Internet-reachable administrative service confirmed",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=host,
                    description="Protocol-level evidence confirmed externally reachable administrative services: " + ", ".join(f"{name} TCP/{port}" for port, name in management) + ".",
                    remediation="Restrict administrative services to approved management networks or a secured access layer, and enforce strong authentication and transport security.",
                    evidence_ids=list(dict.fromkeys(linked)),
                    tags=["external", "attack-surface", "management", "protocol-confirmed", "evidence-backed"],
                ))

            if databases:
                linked = [
                    ev.id for port, _name in databases
                    for ev in [*port_evidence.get((host, port), []), *identity_evidence.get((host, port), [])]
                ]
                findings.append(Finding(
                    title="Internet-reachable database or data service confirmed",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=host,
                    description="Protocol/product evidence confirmed externally reachable data services: " + ", ".join(f"{name} TCP/{port}" for port, name in databases) + ".",
                    remediation="Restrict database and data services to trusted application/administration networks and require authentication plus encrypted transport.",
                    evidence_ids=list(dict.fromkeys(linked)),
                    tags=["external", "attack-surface", "database", "protocol-confirmed", "evidence-backed"],
                ))

            if cleartext:
                linked = [
                    ev.id for port, _name in cleartext
                    for ev in [*port_evidence.get((host, port), []), *identity_evidence.get((host, port), [])]
                ]
                findings.append(Finding(
                    title="Clear-text-capable protocol confirmed externally",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=host,
                    description="Protocol-level evidence confirmed externally reachable clear-text-capable services: " + ", ".join(f"{name} TCP/{port}" for port, name in cleartext) + ". This does not by itself prove that credentials or sensitive content are transmitted without encryption.",
                    remediation="Prefer encrypted-only protocols, enforce TLS before authentication, and remove obsolete clear-text listeners where they are not required.",
                    evidence_ids=list(dict.fromkeys(linked)),
                    tags=["external", "transport-security", "protocol-confirmed", "needs-configuration-validation"],
                ))

        http_by_origin: dict[str, list[Evidence]] = defaultdict(list)
        for item in evidence:
            if item.category != "http":
                continue
            raw_url = str(item.raw.get("url") or item.raw.get("final_url") or "")
            if not raw_url:
                marker = item.summary.split(" from ", 1)
                raw_url = marker[1].strip() if len(marker) == 2 else ""
            parsed = urlparse(raw_url)
            if parsed.scheme and parsed.hostname:
                origin = f"{parsed.scheme.lower()}://{parsed.hostname.lower()}"
                if parsed.port:
                    origin += f":{parsed.port}"
                http_by_origin[origin].append(item)

        for origin in inventory.web_origins:
            if not origin.startswith("http://"):
                continue
            linked = [item.id for item in http_by_origin.get(origin, [])]
            findings.append(Finding(
                title="Externally reachable web application observed over HTTP",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED if linked else Confidence.HIGH,
                affected_asset=origin,
                description="An HTTP application response was observed using unencrypted transport. This does not establish that sensitive workflows are exposed over HTTP, but the endpoint is part of the external attack surface.",
                remediation="Redirect HTTP to HTTPS and ensure sensitive cookies, authentication and application workflows are available only over TLS.",
                evidence_ids=linked or [summary.id],
                tags=["external", "web", "transport-security", "http-response-confirmed"],
                cwe="CWE-319",
            ))

        return EngineOutput(assets=[], evidence=output_evidence, findings=findings)
