from __future__ import annotations

import asyncio
import ipaddress
import os
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import urlparse

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Evidence


@dataclass(frozen=True)
class ToolCapability:
    name: str
    purpose: str


class SpecialistToolBridgeEngine(Engine):
    """Scope-gated specialist-tool adapters with normalized evidence ingestion.

    Tool discovery is always passive. Execution occurs only when the engagement explicitly
    enables specialist tools and names the adapter. The first executable adapter is Nmap,
    using connect/service discovery only (no NSE scripts, no OS exploitation, no evasion).
    Raw tool output is parsed into ShadowStrike assets/evidence and never trusted as a finding.
    """

    name = "ShadowToolBridge"
    TOOLS = (
        ToolCapability("nmap", "network/service fingerprinting"),
        ToolCapability("nuclei", "template-based vulnerability checks"),
        ToolCapability("amass", "DNS/asset discovery"),
        ToolCapability("httpx", "HTTP/TLS probing"),
        ToolCapability("ffuf", "bounded web content discovery"),
        ToolCapability("feroxbuster", "bounded web content discovery"),
        ToolCapability("katana", "deep web crawling and endpoint extraction"),
        ToolCapability("spiderfoot", "OSINT relationship enrichment"),
    )

    @staticmethod
    def _target_host(target: str) -> str:
        parsed = urlparse(target if "://" in target else f"//{target}")
        return (parsed.hostname or target).strip("[]").lower().rstrip(".")

    @staticmethod
    def _parse_nmap_xml(xml_text: str) -> tuple[list[Asset], list[Evidence]]:
        assets: list[Asset] = []
        evidence: list[Evidence] = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            return [], [Evidence(engine="ShadowToolBridge", category="specialist-tool-parse-error", summary="Nmap XML could not be normalized", raw={"tool": "nmap", "error": str(exc)})]
        for host_node in root.findall("host"):
            status = host_node.find("status")
            if status is not None and status.get("state") != "up":
                continue
            address_nodes = [a for a in host_node.findall("address") if a.get("addr")]
            addresses = [str(a.get("addr")) for a in address_nodes]
            host = next((a for a in addresses if ":" not in a and "." in a), addresses[0] if addresses else None)
            if not host:
                continue
            mac_node = next((a for a in address_nodes if a.get("addrtype") == "mac"), None)
            mac = mac_node.get("addr") if mac_node is not None else None
            vendor = mac_node.get("vendor") if mac_node is not None else None
            hostnames = [h.get("name") for h in host_node.findall("hostnames/hostname") if h.get("name")]
            os_matches: list[dict[str, object]] = []
            for match in host_node.findall("os/osmatch"):
                try:
                    accuracy = int(match.get("accuracy") or 0)
                except ValueError:
                    accuracy = 0
                classes: list[dict[str, object]] = []
                for cls in match.findall("osclass"):
                    classes.append({
                        "type": cls.get("type"), "vendor": cls.get("vendor"),
                        "osfamily": cls.get("osfamily"), "osgen": cls.get("osgen"),
                        "accuracy": int(cls.get("accuracy") or 0),
                        "cpe": [c.text for c in cls.findall("cpe") if c.text],
                    })
                os_matches.append({"name": match.get("name"), "accuracy": accuracy, "classes": classes})
            os_matches.sort(key=lambda x: int(x.get("accuracy") or 0), reverse=True)
            best_os = os_matches[0] if os_matches else None
            device_types = sorted({
                str(cls.get("type")) for match in os_matches[:4] for cls in (match.get("classes") or [])
                if isinstance(cls, dict) and cls.get("type")
            })
            host_scripts = [
                {"id": node.get("id"), "output": node.get("output")}
                for node in host_node.findall("hostscript/script") if node.get("id") or node.get("output")
            ]
            dev_attrs = {
                "host": host, "addresses": addresses, "hostnames": hostnames, "mac": mac,
                "vendor": vendor, "tool": "nmap", "identity_confidence": "observed",
                "os_fingerprint": best_os, "os_matches": os_matches[:5], "device_types": device_types,
                "host_scripts": host_scripts,
            }
            dev = Asset(kind="network-device", value=host, source="ShadowToolBridge", attributes=dev_attrs)
            assets.append(dev)
            evidence.append(Evidence(asset_id=dev.id, engine="ShadowToolBridge", category="specialist-host-observation", summary=f"Nmap confirmed host reachability for {host}", raw=dev_attrs))
            for script in host_scripts:
                evidence.append(Evidence(asset_id=dev.id, engine="ShadowToolBridge", category="nmap-host-script", summary=f"Nmap safe/default host script {script.get('id')} returned data for {host}", raw={"host": host, **script}))
            if best_os and best_os.get("name"):
                os_asset = Asset(
                    kind="operating-system", value=f"{host}:{best_os.get('name')}", source="ShadowToolBridge",
                    attributes={
                        "host": host, "name": best_os.get("name"),
                        "accuracy": best_os.get("accuracy"), "classes": best_os.get("classes") or [],
                        "identity_basis": "nmap-tcp-ip-stack-fingerprint",
                    },
                )
                assets.append(os_asset)
                evidence.append(Evidence(asset_id=os_asset.id, engine="ShadowToolBridge", category="os-fingerprint", summary=f"Nmap OS fingerprint for {host}: {best_os.get('name')} ({best_os.get('accuracy')}% match)", raw=os_asset.attributes))
            for port_node in host_node.findall("ports/port"):
                state = port_node.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port_node.find("service")
                port = int(port_node.get("portid") or 0)
                transport = port_node.get("protocol") or "tcp"
                raw_conf = service.get("conf") if service is not None else None
                try:
                    tool_confidence = int(raw_conf) if raw_conf is not None else 0
                except (TypeError, ValueError):
                    tool_confidence = 0
                observed_name = service.get("name") if service is not None else None
                normalized_name = str(observed_name or "").strip().lower()
                non_identity = normalized_name in {"", "unknown", "tcpwrapped"}
                service_state = (
                    "confirmed" if (not non_identity and tool_confidence >= 8)
                    else ("probable" if (not non_identity and tool_confidence >= 5) else "candidate")
                )
                port_scripts = [
                    {"id": node.get("id"), "output": node.get("output")}
                    for node in port_node.findall("script") if node.get("id") or node.get("output")
                ]
                attrs = {
                    "host": host, "port": port, "transport": transport, "state": "confirmed-open", "port_state": "confirmed-open",
                    "service_candidate": observed_name,
                    "service_name": observed_name if service_state == "confirmed" else "unknown",
                    "nmap_tcpwrapped": normalized_name == "tcpwrapped",
                    "service_state": service_state,
                    "identity_basis": ("nmap-wrapper-observation" if normalized_name == "tcpwrapped" else ("nmap-version-detection" if observed_name else "nmap-open-port")),
                    "product": service.get("product") if service is not None and service_state == "confirmed" else None,
                    "version": service.get("version") if service is not None and service_state == "confirmed" else None,
                    "extrainfo": service.get("extrainfo") if service is not None else None,
                    "cpe": [c.text for c in service.findall("cpe") if c.text] if service is not None and service_state == "confirmed" else [],
                    "tool": "nmap", "tool_confidence": tool_confidence, "scripts": port_scripts,
                }
                svc = Asset(
                    kind="network-service" if service_state == "confirmed" else "transport-endpoint",
                    value=f"{host}:{port}/{transport}",
                    source="ShadowToolBridge",
                    attributes={
                        **attrs,
                        "inventory_class": "protocol-confirmed-service" if service_state == "confirmed" else "unverified-transport-endpoint",
                        "service_promotion_suppressed": service_state != "confirmed",
                    },
                )
                assets.append(svc)
                evidence.append(Evidence(asset_id=svc.id, engine="ShadowToolBridge", category="specialist-service-observation", summary=f"Nmap endpoint observation: {host}:{port}/{transport} identity {service_state}", raw=attrs))
                for script in port_scripts:
                    evidence.append(Evidence(asset_id=svc.id, engine="ShadowToolBridge", category="nmap-port-script", summary=f"Nmap safe/default script {script.get('id')} returned data for {host}:{port}/{transport}", raw={"host": host, "port": port, "transport": transport, **script}))
        return assets, evidence

    async def _execute_nmap(self, cmd: list[str], *, context: EngineContext, allowed: list[str], profile: str) -> tuple[list[Asset], list[Evidence]]:
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=max(180.0, context.timeout * 40))
        except (OSError, asyncio.TimeoutError) as exc:
            return [], [Evidence(engine=self.name, category="specialist-tool-execution", summary=f"Nmap {profile} execution failed", raw={"tool": "nmap", "executed": True, "profile": profile, "error": f"{type(exc).__name__}: {exc}", "targets": allowed})]
        assets, evidence = self._parse_nmap_xml(stdout.decode("utf-8", "replace"))
        evidence.append(Evidence(engine=self.name, category="specialist-tool-execution", summary=f"Nmap {profile} completed for {len(allowed)} authorised target(s)", raw={"tool": "nmap", "executed": True, "returncode": proc.returncode, "targets": allowed, "normalized_assets": len(assets), "stderr_excerpt": stderr.decode("utf-8", "replace")[:3000], "command_profile": profile}))
        return assets, evidence

    async def _run_nmap(self, targets: list[str], context: EngineContext, path: str) -> EngineOutput:
        allowed: list[str] = []
        for target in targets:
            host = self._target_host(target)
            if context.scope.allows(host) and host not in allowed:
                allowed.append(host)
        for asset in context.assets or []:
            host = str((asset.attributes or {}).get("host") or "").strip()
            if host and context.scope.allows(host) and host not in allowed:
                allowed.append(host)
        allowed = allowed[:64]
        if not allowed:
            return EngineOutput(assets=[], evidence=[Evidence(engine=self.name, category="specialist-tool-execution", summary="Nmap adapter had no authorised targets to execute", raw={"tool": "nmap", "executed": False, "reason": "no-authorized-targets"})], findings=[])

        privileged = bool(hasattr(os, "geteuid") and os.geteuid() == 0)
        deep_enabled = bool(getattr(context.scope.policy, "allow_deep_nmap", True))
        anomalous = any((e.category in {"tcp-acceptance-anomaly", "transport-surface", "broad-tcp-acceptance"}) for e in (context.evidence or []))

        tcp = [path, "-Pn", "-sT", "-sV", "--reason", "-T3", "--max-retries", "2", "--host-timeout", "20m"]
        if context.profile == "deep" and deep_enabled and not anomalous:
            tcp.extend(["-p-", "--version-all"]); tcp_profile = "tcp-exhaustive-65535+version-all"
        elif context.profile in {"full", "deep"} and deep_enabled:
            tcp.extend(["--top-ports", "5000", "--version-all"]); tcp_profile = "tcp-top5000+version-all" + ("+anomaly-guard" if anomalous else "")
        else:
            tcp.extend(["--top-ports", "1000", "--version-intensity", "7"]); tcp_profile = "tcp-top1000+version"
        if privileged and context.profile in {"full", "deep"}:
            tcp.extend(["-O", "--osscan-guess", "--max-os-tries", "2", "--traceroute"])
        if deep_enabled and context.profile in {"full", "deep"}:
            tcp.extend(["--script", "default and safe", "--script-timeout", "45s"])
        tcp.extend(["-oX", "-", "--", *allowed])
        assets, evidence = await self._execute_nmap(tcp, context=context, allowed=allowed, profile=tcp_profile)

        # A second bounded UDP pass adds materially different protocol evidence. It is only
        # attempted with raw-packet privileges and explicit UDP permission.
        if privileged and deep_enabled and bool(getattr(context.scope.policy, "allow_udp_discovery", True)) and context.profile in {"full", "deep"}:
            udp_ports = "200" if context.profile == "full" else "500"
            udp = [path, "-Pn", "-sU", "-sV", "--top-ports", udp_ports, "--version-intensity", "7", "--reason", "-T3", "--max-retries", "1", "--host-timeout", "20m", "--script", "default and safe", "--script-timeout", "45s", "-oX", "-", "--", *allowed]
            ua, ue = await self._execute_nmap(udp, context=context, allowed=allowed, profile=f"udp-top{udp_ports}+version+safe-nse")
            assets.extend(ua); evidence.extend(ue)
        else:
            evidence.append(Evidence(engine=self.name, category="nmap-udp-coverage", summary="Deep Nmap UDP phase was not executed", raw={"privileged": privileged, "deep_enabled": deep_enabled, "udp_authorized": bool(getattr(context.scope.policy, "allow_udp_discovery", True)), "profile": context.profile, "reason": "requires privileged full/deep assessment with UDP enabled"}))

        evidence.append(Evidence(engine=self.name, category="nmap-deep-summary", summary="Deep Nmap orchestration completed", raw={"targets": allowed, "privileged": privileged, "anomalous_surface_guard": anomalous, "tcp_profile": tcp_profile, "os_fingerprinting_requested": bool(privileged and context.profile in {"full", "deep"}), "safe_default_nse": bool(deep_enabled and context.profile in {"full", "deep"}), "udp_phase_eligible": bool(privileged and deep_enabled and getattr(context.scope.policy, "allow_udp_discovery", True) and context.profile in {"full", "deep"})}))
        return EngineOutput(assets=assets, evidence=evidence, findings=[])

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        evidence: list[Evidence] = []
        available: dict[str, str] = {}
        for tool in self.TOOLS:
            path = shutil.which(tool.name)
            if path:
                available[tool.name] = path
            evidence.append(Evidence(engine=self.name, category="specialist-tool-capability", summary=f"{tool.name}: {'available' if path else 'not installed'}", raw={"tool": tool.name, "purpose": tool.purpose, "available": bool(path), "path": path, "scope_gated": True, "execution": "not-invoked"}))

        enabled = bool(getattr(context.scope.policy, "allow_specialist_tools", False))
        requested = {str(x).lower() for x in (getattr(context.scope.policy, "specialist_tools", []) or [])}
        if enabled and "nmap" in requested and "nmap" in available:
            output = await self._run_nmap(targets, context, available["nmap"])
            output.evidence = evidence + output.evidence
            return output

        evidence.append(Evidence(engine=self.name, category="specialist-tool-bridge-summary", summary=f"{len(available)} specialist tool adapter prerequisite(s) available; execution {'enabled' if enabled else 'disabled'}", raw={"available_tools": sorted(available), "execution_enabled": enabled, "requested_tools": sorted(requested), "implemented_execution_adapters": ["nmap"], "normalization_required": True}))
        return EngineOutput(assets=[], evidence=evidence, findings=[])
