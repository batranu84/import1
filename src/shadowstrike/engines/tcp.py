from __future__ import annotations

import asyncio
import socket
import time
from collections import defaultdict
from statistics import pstdev
from typing import Optional

from shadowstrike.core.adaptive import AdaptiveConcurrency
from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Evidence

COMMON_PORTS = [22, 25, 53, 80, 110, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443]
EXTENDED_PORTS = sorted(set(COMMON_PORTS + [21, 23, 69, 88, 111, 135, 139, 161, 179, 427, 514, 873, 1080, 1521, 2049, 2375, 2376, 27017, 5000, 5001, 5672, 5900, 5985, 5986, 6443, 8000, 8006, 8081, 8883, 8888, 9000, 9090, 9200, 9300, 9443, 11211, 15672]))
STANDARD_PORTS = sorted(set(range(1, 1025)) | set(EXTENDED_PORTS))

SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "smtp-submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 2375: "docker", 2376: "docker-tls", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5672: "amqp", 5900: "vnc", 5985: "winrm", 5986: "winrm-tls",
    6379: "redis", 6443: "kubernetes-api", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 11211: "memcached", 15672: "rabbitmq-management", 27017: "mongodb",
}

GREETING_PORTS = {21, 22, 25, 110, 143, 587}


def _banner_identity(port: int, banner: str) -> tuple[str | None, str | None]:
    """Return a protocol identity only when received bytes actually support it."""
    text = banner.strip().lower()
    if not text:
        return None, None
    if text.startswith("ssh-") or "openssh" in text:
        return "ssh", "banner-protocol-signature"
    if port == 21 and (text.startswith("220") or "pure-ftpd" in text or "filezilla server" in text):
        return "ftp", "banner-protocol-signature"
    if port in {25, 587} and (text.startswith("220") or "esmtp" in text or "postfix" in text or "exim" in text):
        return ("smtp-submission" if port == 587 else "smtp"), "banner-protocol-signature"
    if port == 110 and (text.startswith("+ok") or "dovecot" in text):
        return "pop3", "banner-protocol-signature"
    if port == 143 and (text.startswith("*") or "dovecot" in text):
        return "imap", "banner-protocol-signature"
    return None, None


def _banner_service(port: int, banner: str) -> str:
    service, _basis = _banner_identity(port, banner)
    return service or "unknown"


def _port_ranges(ports: list[int]) -> list[str]:
    if not ports:
        return []
    ordered = sorted(set(int(p) for p in ports))
    ranges: list[str] = []
    start = prev = ordered[0]
    for port in ordered[1:]:
        if port == prev + 1:
            prev = port
            continue
        ranges.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = port
    ranges.append(str(start) if start == prev else f"{start}-{prev}")
    return ranges


def _acceptance_profile(observations: list[dict], attempted_ports: int) -> dict:
    accepted = len(observations)
    ratio = accepted / attempted_ports if attempted_ports else 0.0
    no_banner = sum(1 for item in observations if not item.get("banner"))
    no_banner_ratio = no_banner / accepted if accepted else 0.0
    latencies = [float(item.get("connect_latency_ms") or 0.0) for item in observations if item.get("connect_latency_ms") is not None]
    mean_latency = sum(latencies) / len(latencies) if latencies else 0.0
    latency_cv = (pstdev(latencies) / mean_latency) if len(latencies) >= 2 and mean_latency > 0 else None
    candidates = {str(item.get("service_candidate") or "unknown") for item in observations if str(item.get("service_candidate") or "unknown") != "unknown"}
    threshold = 16 if attempted_ports <= 64 else 64
    broad_acceptance = accepted >= threshold and ratio >= 0.75
    weak_application_evidence = no_banner_ratio >= 0.80
    similar_latency = latency_cv is not None and latency_cv <= 0.35
    many_unrelated_candidates = len(candidates) >= 6
    suspected_intermediary = broad_acceptance and weak_application_evidence and (similar_latency or many_unrelated_candidates or ratio >= 0.95)
    return {
        "attempted_ports": attempted_ports,
        "accepted_ports": accepted,
        "acceptance_ratio": round(ratio, 4),
        "no_banner_ratio": round(no_banner_ratio, 4),
        "mean_latency_ms": round(mean_latency, 2),
        "latency_coefficient_of_variation": round(latency_cv, 4) if latency_cv is not None else None,
        "candidate_protocol_count": len(candidates),
        "broad_acceptance": broad_acceptance,
        "suspected_intermediary_or_tarpit": suspected_intermediary,
        "signals": [
            name for name, enabled in (
                ("high-port-acceptance-ratio", broad_acceptance),
                ("little-or-no-application-data", weak_application_evidence),
                ("similar-connect-latency", similar_latency),
                ("many-unrelated-port-convention-candidates", many_unrelated_candidates),
            ) if enabled
        ],
    }


class TcpDiscoveryEngine(Engine):
    name = "ShadowScan"

    def __init__(self, ports: Optional[list[int]] = None, batch_size: int = 256):
        self.ports = ports
        self.batch_size = max(8, batch_size)

    def ports_for_profile(self, profile: str) -> list[int]:
        if self.ports is not None:
            return self.ports
        return STANDARD_PORTS if profile in {"full", "internal", "extended", "deep"} else COMMON_PORTS

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        assets: list[Asset] = []
        evidence: list[Evidence] = []
        ports = self.ports_for_profile(context.profile)
        controller = AdaptiveConcurrency(
            max_limit=context.scope.policy.max_concurrency,
            initial=min(32, context.scope.policy.max_concurrency),
        )
        tasks = [(context.scope._host(target), port) for target in targets for port in ports]
        attempted_by_host: dict[str, int] = defaultdict(int)
        for host, _port in tasks:
            attempted_by_host[host] += 1

        checkpoint = context.checkpoint_get() or {}
        start_index = min(int(checkpoint.get("next_index", 0)), len(tasks))
        recovered = checkpoint.get("open_services", []) if isinstance(checkpoint.get("open_services", []), list) else []
        started_all = time.monotonic()
        attempts = int(checkpoint.get("attempts", 0))
        successes = int(checkpoint.get("successes", 0))
        latency_total = float(checkpoint.get("latency_total", 0.0))
        open_services: list[dict] = []
        for item in recovered:
            if not isinstance(item, dict) or "host" not in item or "port" not in item:
                continue
            host, port = str(item["host"]), int(item["port"])
            candidate = str(item.get("service_candidate") or item.get("service_hint") or SERVICE_HINTS.get(port, "unknown"))
            service_name = str(item.get("service_name") or "unknown")
            service_state = str(item.get("service_state") or ("confirmed" if service_name != "unknown" else ("candidate" if candidate != "unknown" else "unknown")))
            open_services.append({
                "host": host,
                "resolved_ip": item.get("resolved_ip"),
                "address_family": item.get("address_family"),
                "port": port,
                "service_candidate": candidate,
                "service_hint": candidate,
                "service_name": service_name,
                "service_state": service_state,
                "identity_basis": item.get("identity_basis") or "conventional-port-candidate",
                "connect_latency_ms": float(item.get("connect_latency_ms", 0.0)),
                "banner": item.get("banner"),
                "recovered_from_checkpoint": True,
            })

        async def probe(host: str, port: int, sem: asyncio.Semaphore) -> tuple[bool, float]:
            nonlocal attempts, successes, latency_total
            context.scope.require(host)
            await context.limiter.wait()
            async with sem:
                attempts += 1
                started = asyncio.get_running_loop().time()
                try:
                    conn = asyncio.open_connection(host, port, family=socket.AF_UNSPEC)
                    reader, writer = await asyncio.wait_for(conn, timeout=context.timeout)
                except Exception:
                    latency = (asyncio.get_running_loop().time() - started) * 1000
                    controller.observe(False, latency)
                    return False, latency
                latency = (asyncio.get_running_loop().time() - started) * 1000
                successes += 1
                latency_total += latency
                controller.observe(True, latency)
                peer = writer.get_extra_info("peername")
                resolved_ip = str(peer[0]) if isinstance(peer, tuple) and peer else None
                sock = writer.get_extra_info("socket")
                family = getattr(sock, "family", None)
                address_family = "ipv6" if family == socket.AF_INET6 else ("ipv4" if family == socket.AF_INET else None)
                banner = ""
                if port in GREETING_PORTS:
                    try:
                        data = await asyncio.wait_for(reader.read(512), timeout=min(0.8, context.timeout))
                        banner = data.decode("utf-8", errors="replace").strip()[:512]
                    except Exception:
                        banner = ""
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                candidate = SERVICE_HINTS.get(port, "unknown")
                confirmed_service, identity_basis = _banner_identity(port, banner)
                service_state = "confirmed" if confirmed_service else ("candidate" if candidate != "unknown" else "unknown")
                open_services.append({
                    "host": host,
                    "resolved_ip": resolved_ip,
                    "address_family": address_family,
                    "port": port,
                    "service_candidate": candidate,
                    "service_hint": candidate,
                    "service_name": confirmed_service or "unknown",
                    "service_state": service_state,
                    "identity_basis": identity_basis or "conventional-port-candidate",
                    "connect_latency_ms": round(latency, 2),
                    "banner": banner or None,
                })
                return True, latency

        index = start_index
        batches = int(checkpoint.get("batches", 0))
        while index < len(tasks):
            dynamic_size = min(self.batch_size, max(controller.current * 2, 8))
            batch = tasks[index:index + dynamic_size]
            sem = asyncio.Semaphore(controller.current)
            await asyncio.gather(*(probe(host, port, sem) for host, port in batch))
            index += len(batch)
            batches += 1
            context.checkpoint_save({
                "next_index": index,
                "total_tasks": len(tasks),
                "attempts": attempts,
                "successes": successes,
                "latency_total": latency_total,
                "batches": batches,
                "open_services": open_services,
                "adaptive": controller.snapshot(),
            })

        # De-duplicate checkpoint and current observations before materializing inventory.
        deduped: dict[tuple[str, int, str | None], dict] = {}
        for item in open_services:
            key = (str(item.get("host") or ""), int(item.get("port") or 0), item.get("resolved_ip"))
            previous = deduped.get(key)
            if previous is None or (not previous.get("banner") and item.get("banner")):
                deduped[key] = item
        open_services = list(deduped.values())

        by_host: dict[str, list[dict]] = defaultdict(list)
        for item in open_services:
            by_host[str(item.get("host") or "")].append(item)

        anomaly_hosts: dict[str, dict] = {}
        for host, observations in by_host.items():
            profile = _acceptance_profile(observations, attempted_by_host.get(host, len(ports)))
            if profile["suspected_intermediary_or_tarpit"]:
                anomaly_hosts[host] = profile
                accepted_ports = sorted({int(item["port"]) for item in observations})
                peer_ips = sorted({str(item.get("resolved_ip")) for item in observations if item.get("resolved_ip")})
                surface = Asset(
                    kind="transport-surface",
                    value=host,
                    source=self.name,
                    attributes={
                        **profile,
                        "transport": "tcp",
                        "peer_ips": peer_ips,
                        "port_ranges": _port_ranges(accepted_ports),
                        "sample_ports": accepted_ports[:32],
                        "service_promotion_suppressed": True,
                        "reason": "broad TCP acceptance pattern requires application-protocol confirmation",
                    },
                )
                assets.append(surface)
                evidence.append(Evidence(
                    asset_id=surface.id,
                    engine=self.name,
                    category="tcp-acceptance-anomaly",
                    summary=f"Anomalous broad TCP acceptance pattern observed for {host}; unverified endpoints were collapsed instead of inventoried as services",
                    raw={
                        "host": host,
                        **profile,
                        "peer_ips": peer_ips,
                        "accepted_port_ranges": _port_ranges(accepted_ports),
                        "accepted_ports": accepted_ports,
                        "individual_service_promotion_suppressed": True,
                        "interpretation": "possible intermediary, proxy, firewall acceptor, tarpit, security appliance, or other non-application listener behavior",
                    },
                ))

        confirmed_count = 0
        endpoint_count = 0
        for item in open_services:
            host = str(item.get("host") or "")
            port = int(item.get("port") or 0)
            confirmed = str(item.get("service_state") or "").lower() == "confirmed" and str(item.get("service_name") or "unknown") != "unknown"
            anomaly = host in anomaly_hosts
            asset: Asset | None = None
            if confirmed:
                asset = Asset(kind="network-service", value=f"{host}:{port}/tcp", source=self.name, attributes={
                    **item,
                    "transport": "tcp",
                    "port_state": "connect-accepted",
                    "transport_state": "connect-accepted",
                    "inventory_class": "protocol-confirmed-service",
                })
                assets.append(asset)
                confirmed_count += 1
            elif not anomaly:
                asset = Asset(kind="transport-endpoint", value=f"{host}:{port}/tcp", source=self.name, attributes={
                    **item,
                    "transport": "tcp",
                    "port_state": "connect-accepted",
                    "transport_state": "connect-accepted",
                    "inventory_class": "unverified-transport-endpoint",
                    "service_promotion_suppressed": True,
                })
                assets.append(asset)
                endpoint_count += 1

            evidence.append(Evidence(
                asset_id=asset.id if asset else None,
                engine=self.name,
                category="port",
                summary=f"TCP/{port} accepted a connection on {host}",
                raw={
                    **item,
                    "state": "open",  # compatibility for historical evidence consumers
                    "port_state": "connect-accepted",
                    "transport_state": "connect-accepted",
                    "acceptance_anomaly_suspected": anomaly,
                    "inventory_kind": asset.kind if asset else "evidence-only",
                    "service_promotion_suppressed": (not confirmed),
                },
            ))

        duration = max(time.monotonic() - started_all, 1e-9)
        telemetry = {
            "attempted_connections": attempts,
            "accepted_connections": successes,
            "confirmed_services": confirmed_count,
            "unverified_transport_endpoints": endpoint_count,
            "collapsed_anomalous_hosts": len(anomaly_hosts),
            "batches": batches,
            "resumed_from_index": start_index,
            "checkpoint_recovered_services": len(recovered),
            "duration_seconds": round(duration, 4),
            "attempts_per_second": round(attempts / duration, 2),
            "mean_accept_latency_ms": round(latency_total / successes, 2) if successes else 0.0,
            "adaptive": controller.snapshot(),
            "hard_concurrency_ceiling": context.scope.policy.max_concurrency,
            "request_rate_ceiling": context.scope.policy.max_requests_per_second,
        }
        evidence.append(Evidence(
            engine=self.name,
            category="scan-telemetry",
            summary=f"ShadowScan completed {attempts} bounded TCP connection attempts",
            raw=telemetry,
        ))
        return EngineOutput(assets=assets, evidence=evidence, findings=[])
