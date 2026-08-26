from __future__ import annotations

from collections import Counter
from urllib.parse import urlparse

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Evidence


class AdaptiveAssessmentEngine(Engine):
    """Evidence-driven assessment planner.

    This stage does not probe targets. It turns observations collected by earlier engines
    into explicit, scope-aware follow-up branches and a capability/coverage record. The
    planner is deliberately deterministic so an assessor can explain why a branch was
    activated, skipped, or blocked.
    """

    name = "ShadowAdaptive"

    _BRANCHES = {
        "active-directory": {"signals": {"kerberos", "ldap", "ldaps", "domain-controller", "smb"}, "checks": ["directory-posture", "smb-posture", "identity-correlation"]},
        "web-application": {"signals": {"http", "https", "web", "api"}, "checks": ["http-posture", "api-surface", "javascript-endpoints", "tls-posture"]},
        "network-infrastructure": {"signals": {"switch", "router", "firewall", "snmp", "access-point"}, "checks": ["management-plane", "snmp-inventory", "topology-correlation"]},
        "virtualization-containers": {"signals": {"docker", "kubernetes", "hypervisor", "esxi", "proxmox"}, "checks": ["management-surface", "platform-fingerprint", "segmentation-context"]},
        "physical-iot": {"signals": {"camera", "nvr", "iot", "onvif", "rtsp"}, "checks": ["device-fingerprint", "management-surface", "physical-topology"]},
    }

    @staticmethod
    def _tokens(context: EngineContext) -> set[str]:
        tokens: set[str] = set()
        for asset in context.assets or []:
            tokens.add(str(asset.kind).lower())
            tokens.add(str(asset.value).lower())
            for value in (asset.attributes or {}).values():
                if isinstance(value, (str, int, float)):
                    tokens.update(str(value).lower().replace("/", " ").replace("_", " ").split())
        for item in context.evidence or []:
            tokens.add(str(item.category).lower())
            tokens.update(str(item.summary).lower().replace("/", " ").replace("_", " ").split())
        return tokens

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        tokens = self._tokens(context)
        evidence: list[Evidence] = []
        assets: list[Asset] = []
        activated: list[str] = []
        for branch, spec in self._BRANCHES.items():
            matched = sorted(signal for signal in spec["signals"] if signal in tokens)
            state = "activated" if matched else "not-triggered"
            if matched:
                activated.append(branch)
            evidence.append(Evidence(
                engine=self.name,
                category="adaptive-assessment-branch",
                summary=f"Adaptive branch {branch}: {state}",
                raw={"branch": branch, "state": state, "signals": matched, "planned_checks": spec["checks"], "additional_probe_performed": False},
            ))

        # Candidate names discovered by previous engines are tracked explicitly. ScopeGuard
        # decides whether they may ever be touched; this stage never contacts them itself.
        candidates: dict[str, set[str]] = {}
        for item in context.evidence or []:
            raw = item.raw or {}
            for key in ("hostname", "host", "san", "sans", "redirect", "location", "endpoint"):
                value = raw.get(key)
                values = value if isinstance(value, list) else [value]
                for candidate in values:
                    if not isinstance(candidate, str) or not candidate.strip():
                        continue
                    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
                    host = (parsed.hostname or "").lower().rstrip(".")
                    if host and "." in host:
                        candidates.setdefault(host, set()).add(f"{item.engine}:{item.category}")
        for host, sources in sorted(candidates.items()):
            allowed = context.scope.allows(host)
            assets.append(Asset(kind="discovery-candidate", value=host, source=self.name, attributes={"scope_status": "authorized" if allowed else "blocked", "evidence_sources": sorted(sources)}))
            evidence.append(Evidence(engine=self.name, category="candidate-scope-decision", summary=f"Candidate {host} is {'authorized' if allowed else 'outside authorized scope'}", raw={"candidate": host, "authorized": allowed, "sources": sorted(sources), "contacted": False}))

        evidence.append(Evidence(
            engine=self.name,
            category="adaptive-assessment-summary",
            summary=f"Adaptive assessment activated {len(activated)} evidence-driven branch(es)",
            raw={"activated_branches": activated, "candidate_count": len(candidates), "policy": "evidence-driven; scope-gated; no probing by planner"},
        ))
        return EngineOutput(assets=assets, evidence=evidence, findings=[])
