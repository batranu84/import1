from __future__ import annotations

from collections import defaultdict
from statistics import pstdev
from urllib.parse import urlparse

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.engines.tcp import _banner_identity
from shadowstrike.models.domain import Confidence, Evidence, Finding, Severity


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}


def _service_name(raw: dict) -> str:
    return str(raw.get("service_name") or raw.get("name") or "").strip().lower()


def _endpoint_from_url(raw_url: str) -> tuple[str, int, str] | None:
    parsed = urlparse(raw_url)
    if not parsed.scheme or not parsed.hostname:
        return None
    scheme = parsed.scheme.lower()
    port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else None)
    if port is None:
        return None
    return parsed.hostname.lower(), int(port), scheme


class ExternalValidationEngine(Engine):
    """Cross-correlate existing external evidence without issuing new probes.

    Evidence fidelity rule: a conventional port number/service hint is never an independent
    identity signal. Service identity requires protocol/product evidence.
    """

    name = "ShadowValidate"

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        del targets
        evidence = context.evidence or []
        assets = context.assets or []
        out_evidence: list[Evidence] = []
        findings: list[Finding] = []

        port_by_endpoint: dict[tuple[str, int], list[Evidence]] = defaultdict(list)
        http_by_origin: dict[str, list[Evidence]] = defaultdict(list)
        http_by_endpoint: dict[tuple[str, int], list[Evidence]] = defaultdict(list)
        tls_by_endpoint: dict[tuple[str, int], list[Evidence]] = defaultdict(list)
        api_schema_by_origin: dict[str, list[Evidence]] = defaultdict(list)
        confirmed_identity: dict[tuple[str, int], dict[str, list[Evidence]]] = defaultdict(lambda: defaultdict(list))

        for item in evidence:
            raw = item.raw or {}
            if item.category == "port" and raw.get("state") == "open":
                host = str(raw.get("host", "")).strip().lower()
                try:
                    port = int(raw.get("port"))
                except (TypeError, ValueError):
                    continue
                if host:
                    endpoint = (host, port)
                    port_by_endpoint[endpoint].append(item)
                    if str(raw.get("service_state") or "").lower() == "confirmed":
                        name = _service_name(raw)
                        if name and name not in {"unknown", "tcpwrapped"}:
                            confirmed_identity[endpoint][name].append(item)
            elif item.category == "specialist-service-observation":
                host = str(raw.get("host", "")).strip().lower()
                try:
                    port = int(raw.get("port"))
                except (TypeError, ValueError):
                    continue
                name = _service_name(raw)
                if host and name and name not in {"unknown", "tcpwrapped"} and str(raw.get("service_state") or "").lower() == "confirmed":
                    confirmed_identity[(host, port)][name].append(item)
            elif item.category == "http":
                raw_url = str(raw.get("url") or raw.get("final_url") or "")
                if not raw_url:
                    marker = item.summary.split(" from ", 1)
                    raw_url = marker[1].strip() if len(marker) == 2 else ""
                endpoint = _endpoint_from_url(raw_url)
                if endpoint:
                    host, port, scheme = endpoint
                    origin = f"{scheme}://{host}" + (f":{port}" if port not in {80, 443} else "")
                    http_by_origin[origin].append(item)
                    http_by_endpoint[(host, port)].append(item)
                    confirmed_identity[(host, port)][scheme].append(item)
            elif item.category in {"tls", "tls-certificate"}:
                host = str(raw.get("host") or raw.get("hostname") or "").strip().lower()
                try:
                    port = int(raw.get("port") or 443)
                except (TypeError, ValueError):
                    port = 443
                if host:
                    tls_by_endpoint[(host, port)].append(item)
            elif item.category == "api-schema":
                raw_url = str(raw.get("url", ""))
                endpoint = _endpoint_from_url(raw_url)
                if endpoint:
                    host, port, scheme = endpoint
                    origin = f"{scheme}://{host}" + (f":{port}" if port not in {80, 443} else "")
                    api_schema_by_origin[origin].append(item)

        # Assets can carry protocol-confirmed identity from internal protocol probes or a
        # confidence-gated specialist adapter. Candidate hints are deliberately ignored.
        asset_by_endpoint: dict[tuple[str, int], list] = defaultdict(list)
        for asset in assets:
            if asset.kind not in {"network-service", "transport-endpoint"}:
                continue
            attrs = asset.attributes or {}
            host = str(attrs.get("host") or asset.value.rsplit(":", 1)[0]).strip("[]").lower()
            try:
                port = int(attrs.get("port") or asset.value.rsplit(":", 1)[1].split("/", 1)[0])
            except (TypeError, ValueError, IndexError):
                continue
            endpoint = (host, port)
            asset_by_endpoint[endpoint].append(asset)
            if str(attrs.get("service_state") or "").lower() == "confirmed":
                name = _service_name(attrs)
                if name and name not in {"unknown", "tcpwrapped"}:
                    # Asset identity is recorded via a correlation record below. Evidence IDs
                    # come from the endpoint indexes; no synthetic evidence ID is invented.
                    confirmed_identity[endpoint].setdefault(name, [])
            else:
                banner = str(attrs.get("banner") or "").strip()
                if banner:
                    name, _basis = _banner_identity(port, banner)
                    if name:
                        confirmed_identity[endpoint].setdefault(name, [])

        # Service identity correlation. An identity is confirmed only when at least one direct
        # protocol/product source exists. Port reachability and conventional port hints are not
        # counted as independent signals.
        confirmed_endpoints: set[tuple[str, int]] = set()
        for endpoint, names in sorted(confirmed_identity.items()):
            host, port = endpoint
            nonempty = {name: items for name, items in names.items() if name and name != "unknown"}
            if not nonempty:
                continue
            if len(nonempty) > 1:
                all_ids = list(dict.fromkeys(str(ev.id) for items in nonempty.values() for ev in items))
                out_evidence.append(Evidence(
                    engine=self.name,
                    category="service-identity-conflict",
                    summary=f"Conflicting service identities were observed for {host}:{port}; automatic promotion suppressed",
                    raw={
                        "host": host,
                        "port": port,
                        "identities": sorted(nonempty),
                        "source_evidence_ids": all_ids,
                        "identity_state": "conflict",
                        "promotion_suppressed": True,
                    },
                ))
                continue
            service_name, direct_items = next(iter(nonempty.items()))
            linked = [*port_by_endpoint.get(endpoint, []), *direct_items]
            if service_name in {"https"}:
                linked.extend(tls_by_endpoint.get(endpoint, []))
            linked_ids = list(dict.fromkeys(str(item.id) for item in linked))
            direct_categories = sorted(set(item.category for item in direct_items))
            signals = ["protocol/product-confirmation"]
            if port_by_endpoint.get(endpoint):
                signals.append("tcp-connect")
            if direct_categories:
                signals.extend(direct_categories)
            if service_name == "https" and tls_by_endpoint.get(endpoint):
                signals.append("tls-handshake")
            confirmed_endpoints.add(endpoint)
            target_asset = next(iter(asset_by_endpoint.get(endpoint, [])), None)
            out_evidence.append(Evidence(
                asset_id=target_asset.id if target_asset is not None else None,
                engine=self.name,
                category="service-identity-correlation",
                summary=f"{service_name} identity confirmed on {host}:{port} from protocol/product evidence",
                raw={
                    "host": host,
                    "port": port,
                    "service_name": service_name,
                    "identity_state": "confirmed",
                    "signals": sorted(set(signals)),
                    "source_evidence_ids": linked_ids,
                    "candidate_port_hint_used_as_identity": False,
                },
            ))

        # Detect suspicious TCP patterns that often indicate interception, tarpit/proxy behavior,
        # or generic connection acceptance. This is a coverage warning, not a vulnerability.
        ports_by_host: dict[str, list[Evidence]] = defaultdict(list)
        for (host, _port), items in port_by_endpoint.items():
            ports_by_host[host].extend(items)
        for host, items in ports_by_host.items():
            if len(items) < 5:
                continue
            unresolved = [item for item in items if (host, int(item.raw.get("port", -1))) not in confirmed_endpoints]
            if len(unresolved) < 5:
                continue
            null_banner_ratio = sum(1 for item in unresolved if not item.raw.get("banner")) / max(len(unresolved), 1)
            latencies = [float(item.raw.get("connect_latency_ms")) for item in unresolved if item.raw.get("connect_latency_ms") is not None]
            if len(latencies) < 5:
                continue
            spread = max(latencies) - min(latencies)
            deviation = pstdev(latencies) if len(latencies) > 1 else 0.0
            if null_banner_ratio >= 0.8 and spread <= 20.0:
                out_evidence.append(Evidence(
                    engine=self.name,
                    category="tcp-reachability-pattern-anomaly",
                    summary=f"{host} accepted connections on many ports with similar latency but without protocol confirmation",
                    raw={
                        "host": host,
                        "ports": sorted({int(item.raw.get("port")) for item in unresolved}),
                        "unconfirmed_endpoint_count": len(unresolved),
                        "null_banner_ratio": round(null_banner_ratio, 3),
                        "latency_min_ms": round(min(latencies), 2),
                        "latency_max_ms": round(max(latencies), 2),
                        "latency_spread_ms": round(spread, 2),
                        "latency_stddev_ms": round(deviation, 2),
                        "interpretation": "possible proxy/firewall/tarpit/generic-accept behavior; protocol validation required before service claims",
                        "finding_created": False,
                    },
                ))

        # HTTP posture based only on actually captured HTTP responses.
        for origin, items in http_by_origin.items():
            for item in items:
                headers = {str(k).lower(): str(v) for k, v in (item.raw.get("headers") or {}).items()}
                if not headers:
                    continue
                missing = [friendly for header, friendly in SECURITY_HEADERS.items() if header not in headers]
                posture = Evidence(
                    engine=self.name,
                    category="http-security-posture",
                    summary=f"HTTP security posture derived for {origin}: {len(missing)} recommended headers absent",
                    raw={
                        "origin": origin,
                        "missing_headers": missing,
                        "present_headers": [friendly for header, friendly in SECURITY_HEADERS.items() if header in headers],
                        "server_header_present": "server" in headers,
                        "source_evidence_ids": [str(item.id)],
                    },
                )
                out_evidence.append(posture)
                if origin.startswith("https://") and "HSTS" in missing:
                    findings.append(Finding(
                        title="HSTS not observed on HTTPS application",
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        affected_asset=origin,
                        description="An HTTPS response was observed without a Strict-Transport-Security header. This weakens browser-side enforcement of HTTPS for subsequent visits.",
                        remediation="Deploy an appropriate Strict-Transport-Security policy after confirming all required subdomains and workflows support HTTPS.",
                        evidence_ids=[item.id, posture.id],
                        tags=["external", "web", "headers", "transport-security", "correlated"],
                        cwe="CWE-319",
                    ))

        # API exposure scoring: inventory/exposure, not an exploitability claim.
        api_operations_by_schema: dict[str, int] = defaultdict(int)
        for asset in assets:
            if asset.kind == "api-operation":
                schema_url = str((asset.attributes or {}).get("schema_url", ""))
                if schema_url:
                    api_operations_by_schema[schema_url] += 1

        for origin, items in api_schema_by_origin.items():
            for item in items:
                schema_url = str(item.raw.get("url", ""))
                operation_count = max(int(item.raw.get("operation_count") or 0), api_operations_by_schema.get(schema_url, 0))
                exposure_score = 1
                if operation_count >= 10:
                    exposure_score += 1
                if operation_count >= 50:
                    exposure_score += 1
                out_evidence.append(Evidence(
                    engine=self.name,
                    category="api-exposure-posture",
                    summary=f"Publicly reachable API schema observed at {schema_url} with {operation_count} documented operations",
                    raw={
                        "origin": origin,
                        "schema_url": schema_url,
                        "operation_count": operation_count,
                        "exposure_score": exposure_score,
                        "score_scale": "1-3 attack-surface visibility only",
                        "source_evidence_ids": [str(item.id)],
                    },
                ))
                findings.append(Finding(
                    title="Externally reachable API schema documentation",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=schema_url or origin,
                    description="An API schema document was directly reachable and enumerated. This is an attack-surface visibility finding, not evidence of an authorization or data-access vulnerability.",
                    remediation="Confirm public schema exposure is intentional. If documentation is intended only for trusted users, restrict it at the application or access-control layer.",
                    evidence_ids=[item.id],
                    tags=["external", "api", "inventory", "attack-surface", "evidence-backed"],
                ))

        # CVE applicability support: strengthen only when the candidate's concrete endpoint has
        # a confirmed identity. A different service elsewhere on the same host cannot validate it.
        identity_by_endpoint: dict[tuple[str, int], list[Evidence]] = defaultdict(list)
        for item in out_evidence:
            if item.category != "service-identity-correlation" or item.raw.get("identity_state") != "confirmed":
                continue
            try:
                endpoint = (str(item.raw.get("host", "")).lower(), int(item.raw.get("port")))
            except (TypeError, ValueError):
                continue
            identity_by_endpoint[endpoint].append(item)

        for candidate in context.findings or []:
            if not candidate.cve_ids or "needs-validation" not in candidate.tags:
                continue
            affected = candidate.affected_asset.lower()
            host_part = affected.split("/", 1)[0]
            host = host_part
            port: int | None = None
            if host_part.count(":") == 1:
                maybe_host, maybe_port = host_part.rsplit(":", 1)
                try:
                    port = int(maybe_port)
                    host = maybe_host.strip("[]")
                except ValueError:
                    host = host_part.strip("[]")
            supporting = identity_by_endpoint.get((host, port), []) if port is not None else []
            if not supporting:
                continue
            candidate.tags = list(dict.fromkeys([*candidate.tags, "applicability-supported", "cross-engine-corroborated"]))
            if candidate.confidence == Confidence.PROBABLE:
                candidate.confidence = Confidence.HIGH
            candidate.evidence_ids = list(dict.fromkeys([*candidate.evidence_ids, *(item.id for item in supporting)]))
            out_evidence.append(Evidence(
                engine=self.name,
                category="vulnerability-applicability",
                summary=f"CVE candidate applicability strengthened by endpoint-specific service identity evidence for {candidate.affected_asset}",
                raw={
                    "finding_id": str(candidate.id),
                    "cve_ids": candidate.cve_ids,
                    "affected_asset": candidate.affected_asset,
                    "status": "applicability-supported-not-exploit-validated",
                    "supporting_evidence_ids": [str(item.id) for item in supporting],
                },
            ))

        out_evidence.append(Evidence(
            engine=self.name,
            category="external-validation-summary",
            summary=f"External validation produced {len(out_evidence)} evidence objects and {len(findings)} posture findings",
            raw={
                "service_correlations": sum(1 for e in out_evidence if e.category == "service-identity-correlation"),
                "service_identity_conflicts": sum(1 for e in out_evidence if e.category == "service-identity-conflict"),
                "tcp_pattern_anomalies": sum(1 for e in out_evidence if e.category == "tcp-reachability-pattern-anomaly"),
                "http_posture_records": sum(1 for e in out_evidence if e.category == "http-security-posture"),
                "api_posture_records": sum(1 for e in out_evidence if e.category == "api-exposure-posture"),
                "vulnerability_applicability_records": sum(1 for e in out_evidence if e.category == "vulnerability-applicability"),
                "candidate_port_hints_counted_as_identity": False,
            },
        ))
        return EngineOutput(assets=[], evidence=out_evidence, findings=findings)
