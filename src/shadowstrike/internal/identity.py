from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any
from uuid import UUID

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Confidence, Evidence, Finding, Severity


class InternalIdentityService:
    """Passive Windows/Active Directory posture correlation.

    This layer performs no credential attacks and no additional target I/O. It only
    synthesizes identity-related observations already produced by authorized internal
    discovery/sensor stages. Port combinations are treated as role indicators, not proof
    of a domain role, unless direct metadata/evidence explicitly confirms that role.
    """

    IDENTITY_PORTS = {
        53: "DNS",
        88: "Kerberos",
        135: "MS RPC",
        389: "LDAP",
        445: "SMB",
        464: "Kerberos password change",
        636: "LDAPS",
        3268: "LDAP Global Catalog",
        3269: "LDAPS Global Catalog",
        3389: "RDP",
        5985: "WinRM HTTP",
        5986: "WinRM HTTPS",
    }
    DC_CORE_PORTS = {88, 389, 445}
    DC_SUPPORT_PORTS = {53, 135, 464, 3268, 3269}
    DIRECT_DC_ROLES = {"domain-controller", "domain_controller", "dc", "active-directory", "active_directory"}
    ACCOUNT_KINDS = {"identity-account", "ad-account", "directory-account", "service-account"}

    @staticmethod
    def _devices(assets: list[Asset]) -> list[Asset]:
        return [a for a in assets if a.kind == "network-device" and a.source == "ShadowLAN"]

    @staticmethod
    def _services(assets: list[Asset]) -> list[Asset]:
        return [a for a in assets if a.kind == "network-service" and a.source == "ShadowLAN"]

    @classmethod
    def _accounts(cls, assets: list[Asset]) -> list[Asset]:
        return [a for a in assets if a.kind in cls.ACCOUNT_KINDS]

    @staticmethod
    def _port(asset: Asset) -> int | None:
        raw = asset.attributes.get("port")
        if raw is None and ":" in asset.value:
            raw = asset.value.rsplit(":", 1)[-1]
        try:
            return int(raw) if raw is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _host(asset: Asset) -> str:
        host = str(asset.attributes.get("ip") or asset.attributes.get("host") or "").strip()
        if host:
            return host
        if ":" in asset.value:
            return asset.value.rsplit(":", 1)[0]
        return asset.value

    @staticmethod
    def _evidence_for_asset(evidence: list[Evidence], asset_id: UUID) -> list[Evidence]:
        return [e for e in evidence if e.asset_id == asset_id]

    @classmethod
    def _direct_dc(cls, device: Asset) -> bool:
        attrs = device.attributes
        role = str(attrs.get("role") or attrs.get("server_role") or attrs.get("device_type") or "").lower()
        if role in cls.DIRECT_DC_ROLES:
            return True
        return bool(attrs.get("is_domain_controller") is True or attrs.get("domain_controller") is True)

    @staticmethod
    def _domain_from_metadata(asset: Asset) -> str | None:
        for key in ("domain", "dns_domain", "ad_domain", "realm", "forest"):
            value = str(asset.attributes.get(key) or "").strip()
            if value:
                return value.rstrip(".").lower()
        return None

    @classmethod
    def summarize(cls, assets: list[Asset], evidence: list[Evidence]) -> dict[str, Any]:
        devices = cls._devices(assets)
        services = cls._services(assets)
        accounts = cls._accounts(assets)
        device_by_ip = {d.value: d for d in devices}

        service_map: defaultdict[str, set[int]] = defaultdict(set)
        identity_services: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for service in services:
            port = cls._port(service)
            if port not in cls.IDENTITY_PORTS:
                continue
            host = cls._host(service)
            service_map[host].add(port)
            attrs = service.attributes or {}
            state = str(attrs.get("service_state") or "unconfirmed").lower()
            confirmed_name = str(attrs.get("service_name") or "unknown") if state == "confirmed" else "unknown"
            identity_services[host].append({
                "port": port,
                "service": confirmed_name,
                "service_candidate": cls.IDENTITY_PORTS[port],
                "service_state": state,
                "identity_basis": attrs.get("identity_basis") or "conventional-port-candidate",
                "asset_id": str(service.id),
            })

        domain_controllers: list[dict[str, Any]] = []
        candidates: list[dict[str, Any]] = []
        domains: Counter[str] = Counter()

        all_hosts = set(service_map) | set(device_by_ip)
        for host in sorted(all_hosts):
            device = device_by_ip.get(host)
            ports = service_map.get(host, set())
            direct = bool(device and cls._direct_dc(device))
            candidate = cls.DC_CORE_PORTS.issubset(ports) and bool(ports & cls.DC_SUPPORT_PORTS)
            domain = cls._domain_from_metadata(device) if device else None
            if domain:
                domains[domain] += 1
            row = {
                "ip": host,
                "hostname": device.attributes.get("hostname") if device else None,
                "domain": domain,
                "ports": sorted(ports),
                "services": sorted({row["service"] for row in identity_services.get(host, []) if row.get("service_state") == "confirmed" and row.get("service") != "unknown"}),
                "service_candidates": [cls.IDENTITY_PORTS[p] for p in sorted(ports) if p in cls.IDENTITY_PORTS],
                "confidence": "confirmed" if direct else "candidate" if candidate else "observed",
                "basis": "direct role metadata" if direct else "service combination" if candidate else "identity-related service observation",
            }
            if direct:
                domain_controllers.append(row)
            elif candidate:
                candidates.append(row)

        service_accounts: list[dict[str, Any]] = []
        privileged_accounts: list[dict[str, Any]] = []
        stale_accounts: list[dict[str, Any]] = []
        for account in accounts:
            attrs = account.attributes
            row = {
                "name": account.value,
                "kind": account.kind,
                "domain": cls._domain_from_metadata(account),
                "enabled": attrs.get("enabled"),
                "privileged": bool(attrs.get("privileged") or attrs.get("admin") or attrs.get("high_privilege")),
                "service_account": bool(attrs.get("service_account") or account.kind == "service-account"),
                "password_never_expires": attrs.get("password_never_expires"),
                "last_logon": attrs.get("last_logon"),
                "stale": bool(attrs.get("stale") is True),
                "source": account.source,
            }
            if row["service_account"]:
                service_accounts.append(row)
            if row["privileged"]:
                privileged_accounts.append(row)
            if row["stale"]:
                stale_accounts.append(row)

        protocol_counts = Counter()
        candidate_protocol_counts = Counter()
        for rows in identity_services.values():
            for row in rows:
                candidate_protocol_counts[row["service_candidate"]] += 1
                if row.get("service_state") == "confirmed" and row.get("service") != "unknown":
                    protocol_counts[row["service"]] += 1

        return {
            "identity_host_count": len(identity_services),
            "confirmed_domain_controllers": domain_controllers,
            "candidate_domain_controllers": candidates,
            "domains": dict(domains),
            "identity_services": dict(identity_services),
            "protocol_counts": dict(protocol_counts),
            "candidate_protocol_counts": dict(candidate_protocol_counts),
            "account_inventory": {
                "count": len(accounts),
                "service_accounts": service_accounts,
                "privileged_accounts": privileged_accounts,
                "stale_accounts": stale_accounts,
            },
            "evidence_count": len(evidence),
            "basis": "passive correlation of existing authorized internal observations",
            "limitations": (
                "Service combinations indicate likely Windows/AD roles but are not treated as proof. "
                "No password guessing, Kerberos ticket extraction, credential relay, or privilege escalation is performed."
            ),
        }

    @classmethod
    def derive(cls, assets: list[Asset], evidence: list[Evidence]) -> tuple[list[Evidence], list[Finding]]:
        summary = cls.summarize(assets, evidence)
        derived: list[Evidence] = [Evidence(
            engine="ShadowIdentity",
            category="internal-identity-summary",
            summary=(
                f"Observed identity services on {summary['identity_host_count']} host(s), "
                f"with {len(summary['confirmed_domain_controllers'])} confirmed and "
                f"{len(summary['candidate_domain_controllers'])} candidate domain controller(s)"
            ),
            raw=summary,
        )]
        findings: list[Finding] = []

        # Findings are only created when direct evidence carries a posture property.
        # Presence of LDAP/SMB/Kerberos alone is inventory, not a vulnerability.
        for account in cls._accounts(assets):
            attrs = account.attributes
            if not bool(attrs.get("service_account") or account.kind == "service-account"):
                continue
            if attrs.get("password_never_expires") is not True:
                continue
            supporting = cls._evidence_for_asset(evidence, account.id)
            ev = Evidence(
                asset_id=account.id,
                engine="ShadowIdentity",
                category="service-account-password-policy",
                summary=f"Service account {account.value} observed with password-never-expires policy",
                raw={
                    "account": account.value,
                    "domain": cls._domain_from_metadata(account),
                    "password_never_expires": True,
                    "supporting_evidence_ids": [str(x.id) for x in supporting],
                },
            )
            derived.append(ev)
            findings.append(Finding(
                title="Service account configured with non-expiring password",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                affected_asset=account.value,
                description=(
                    "Authorized identity inventory evidence indicates that this service account is configured "
                    "with a non-expiring password. ShadowStrike does not test or recover the password."
                ),
                remediation=(
                    "Move the workload to a managed service account where supported, or establish controlled "
                    "credential rotation with least privilege and monitoring. Review dependencies before changing the policy."
                ),
                evidence_ids=[x.id for x in supporting] + [ev.id],
                tags=["internal", "identity", "active-directory", "service-account", "password-policy"],
                validation_status="observed-configuration",
                evidence_quality="corroborated" if supporting else "single-observation",
                technical_impact="A long-lived service credential can retain value for an extended period if exposed.",
                business_impact="Compromise of a long-lived service credential can increase persistence and remediation effort.",
                remediation_priority="P2 - high",
                priority_score=65,
                retest_status="not-retested",
                attack_path=["Internal identity plane", account.value, "Non-expiring service credential policy"],
            ))

        for account in cls._accounts(assets):
            attrs = account.attributes
            if not (attrs.get("stale") is True and attrs.get("enabled") is True):
                continue
            supporting = cls._evidence_for_asset(evidence, account.id)
            ev = Evidence(
                asset_id=account.id,
                engine="ShadowIdentity",
                category="stale-enabled-account",
                summary=f"Enabled stale account observed: {account.value}",
                raw={"account": account.value, "enabled": True, "stale": True},
            )
            derived.append(ev)
            findings.append(Finding(
                title="Stale identity account remains enabled",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                affected_asset=account.value,
                description=(
                    "Identity inventory evidence marks this account as stale while it remains enabled. "
                    "No authentication attempt was performed."
                ),
                remediation="Confirm ownership and business need, then disable or remove unused accounts through the organization's change process.",
                evidence_ids=[x.id for x in supporting] + [ev.id],
                tags=["internal", "identity", "account-hygiene"],
                validation_status="observed-configuration",
                evidence_quality="corroborated" if supporting else "single-observation",
                technical_impact="An unnecessary enabled identity increases the available authentication surface.",
                business_impact="Dormant accounts can increase unauthorized-access risk if credentials remain valid after ownership or need has changed.",
                remediation_priority="P3 - medium",
                priority_score=45,
                retest_status="not-retested",
                attack_path=["Internal identity plane", account.value, "Enabled stale account"],
            ))

        return derived, findings


class InternalIdentityEngine(Engine):
    """Passive AD/identity synthesis; performs no additional target I/O."""

    name = "ShadowIdentity"

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        if context.profile not in {"internal", "full"}:
            return EngineOutput(assets=[], evidence=[], findings=[])
        derived, findings = InternalIdentityService.derive(
            list(context.assets or []), list(context.evidence or [])
        )
        return EngineOutput(assets=[], evidence=derived, findings=findings)
