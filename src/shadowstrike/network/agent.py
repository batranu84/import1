from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import platform
import secrets
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from shadowstrike.network.device import ShadowDevice
from shadowstrike.network.lan import ShadowLAN
from shadowstrike.network.snmp import ShadowSNMP
from shadowstrike.network.fingerprint import specialist_tool_status


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def local_firmware_inventory() -> dict[str, Any]:
    data: dict[str, Any] = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "node": platform.node(),
    }
    system = platform.system().lower()
    commands: list[tuple[str, list[str]]] = []
    if system == "darwin":
        commands = [("hardware", ["system_profiler", "SPHardwareDataType", "-detailLevel", "mini"])]
    elif system == "linux":
        commands = [
            ("bios_vendor", ["cat", "/sys/class/dmi/id/bios_vendor"]),
            ("bios_version", ["cat", "/sys/class/dmi/id/bios_version"]),
            ("bios_date", ["cat", "/sys/class/dmi/id/bios_date"]),
            ("product_name", ["cat", "/sys/class/dmi/id/product_name"]),
            ("board_name", ["cat", "/sys/class/dmi/id/board_name"]),
        ]
    for key, command in commands:
        try:
            value = subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL, timeout=4).strip()
        except (OSError, subprocess.SubprocessError):
            continue
        if value:
            data[key] = value[:12000]
    return data


@dataclass
class ShadowAgent:
    agent_id: str
    site: str = "default"
    status: str = "offline"
    last_seen: str | None = None
    evidence_queue: list = field(default_factory=list)
    assigned_assessment: str | None = None
    token_hash: str | None = None

    @classmethod
    def register(cls, site: str = "default") -> "ShadowAgent":
        return cls(agent_id=str(uuid4()), site=site, status="registered")

    @staticmethod
    def issue_token() -> tuple[str, str]:
        token = secrets.token_urlsafe(32)
        return token, hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def verify_token(token: str, digest: str | None) -> bool:
        if not token or not digest:
            return False
        actual = hashlib.sha256(token.encode()).hexdigest()
        return secrets.compare_digest(actual, digest)

    @staticmethod
    def capabilities() -> dict[str, Any]:
        tools = {row["name"]: row for row in specialist_tool_status()}
        return {
            "interface_inventory": True,
            "route_inventory": True,
            "automatic_network_detection": True,
            "icmp_discovery": True,
            "arp_neighbor_inventory": True,
            "multicast_mdns_ssdp_discovery": True,
            "tcp_port_discovery": True,
            "adaptive_port_planning": True,
            "service_validation": True,
            "snmp_v2c_read": True,
            "firmware_inventory_local_host": True,
            "nmap_service_fingerprint": bool(tools.get("nmap", {}).get("available")),
            "nmap_os_fingerprint": bool(tools.get("nmap", {}).get("available") and tools.get("nmap", {}).get("privileged")),
            "arp_scan_layer2": bool(tools.get("arp-scan", {}).get("available")),
            "tool_status": tools,
        }

    @staticmethod
    def detected_networks() -> list[dict[str, object]]:
        return [item.as_dict() for item in ShadowLAN.detected_networks()]

    def heartbeat(self) -> dict[str, Any]:
        self.status = "online"
        self.last_seen = utcnow()
        return {
            "agent_id": self.agent_id,
            "status": self.status,
            "last_seen": self.last_seen,
            "capabilities": self.capabilities(),
            "detected_networks": self.detected_networks(),
        }

    def assign(self, assessment_id: str) -> None:
        self.assigned_assessment = assessment_id

    def enqueue(self, item: Any) -> None:
        self.evidence_queue.append(item)

    def drain(self) -> list[Any]:
        items = list(self.evidence_queue)
        self.evidence_queue.clear()
        return items

    async def collect(
        self,
        cidr: str,
        snmp_community: str | None = None,
        ports: list[int] | None = None,
        port_profile: str = "adaptive",
    ) -> dict[str, Any]:
        lan = ShadowLAN(cidr)
        devices = await lan.discover(ports=ports, port_profile=port_profile)
        if snmp_community:
            network = ipaddress.ip_network(cidr, strict=False)
            known = {d.ip: d for d in devices}
            semaphore = asyncio.Semaphore(32)

            async def snmp_probe(ip: str) -> tuple[str, dict[str, Any] | None]:
                async with semaphore:
                    snmp = ShadowSNMP(host=ip, community=snmp_community, timeout=0.35)
                    descr = await asyncio.to_thread(snmp.get, "1.3.6.1.2.1.1.1.0")
                    if descr in (None, ""):
                        return ip, None
                    snmp.timeout = 0.8
                    inventory = await asyncio.to_thread(snmp.inventory)
                    if not inventory.get("sys_descr"):
                        inventory["sys_descr"] = descr
                    return ip, inventory

            results = await asyncio.gather(*(snmp_probe(str(ip)) for ip in network.hosts()))
            for ip, inventory in results:
                if not inventory:
                    continue
                device = known.get(ip)
                if device is None:
                    device = ShadowDevice(
                        ip=ip, metadata={"discovery": "snmp-positive-response"}, evidence_types=["snmp-response"]
                    )
                    devices.append(device)
                    known[ip] = device
                device.snmp = inventory
                device.vendor = inventory.get("vendor") or device.vendor
                device.firmware = inventory.get("firmware") or device.firmware
                lldp_links = []
                for neighbor in inventory.get("lldp_neighbors", []) or []:
                    target_id = str(neighbor.get("chassis_id") or neighbor.get("system_name") or "").strip()
                    if not target_id:
                        continue
                    lldp_links.append({
                        "source": device.ip,
                        "target": f"lldp:{target_id}",
                        "target_label": neighbor.get("system_name") or target_id,
                        "target_description": neighbor.get("system_description"),
                        "relation": "lldp-neighbor",
                        "local_port": neighbor.get("local_port_num"),
                        "remote_port": neighbor.get("port_id") or neighbor.get("port_description"),
                        "evidence": "snmp-lldp-mib",
                        "confidence": "confirmed",
                    })
                if lldp_links:
                    device.metadata["topology_links"] = lldp_links
                    device.metadata["lldp_role"] = "managed-network-device"
                    if "snmp-lldp" not in device.evidence_types:
                        device.evidence_types.append("snmp-lldp")
                if "snmp-response" not in device.evidence_types:
                    device.evidence_types.append("snmp-response")
                device.normalize()
            devices.sort(key=lambda d: ipaddress.ip_address(d.ip))
        local_ips = {x.address for x in ShadowLAN.local_interfaces()}
        firmware = local_firmware_inventory()
        for device in devices:
            if device.ip in local_ips:
                device.bios = firmware
                device.metadata["sensor_host"] = True
                if "local-agent-inventory" not in device.evidence_types:
                    device.evidence_types.append("local-agent-inventory")
                device.normalize()
        return {
            "agent_id": self.agent_id,
            "site": self.site,
            "assessment_id": self.assigned_assessment,
            "cidr": cidr,
            "gateway": lan.gateway,
            "interfaces": [vars(x) for x in ShadowLAN.local_interfaces()],
            "detected_networks": self.detected_networks(),
            "capabilities": self.capabilities(),
            "devices": [d.as_dict() for d in devices],
            "port_profile": port_profile,
            "collected_at": utcnow(),
        }

    async def submit(self, controller: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = controller.rstrip("/") + f"/sensors/{self.agent_id}/ingest"
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(url, headers={"X-ShadowStrike-Sensor-Token": token}, json=payload)
            response.raise_for_status()
            return response.json()

    async def send_heartbeat(self, controller: str, token: str, status: str = "online") -> dict[str, Any]:
        url = controller.rstrip("/") + f"/sensors/{self.agent_id}/heartbeat"
        body = {
            "status": status,
            "capabilities": self.capabilities(),
            "detected_networks": self.detected_networks(),
            "health": {
                "interfaces": len(ShadowLAN.local_interfaces()),
                "detected_networks": len(self.detected_networks()),
                "queued_evidence": len(self.evidence_queue),
                "fingerprint_tools": specialist_tool_status(),
            },
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, headers={"X-ShadowStrike-Sensor-Token": token}, json=body)
            response.raise_for_status()
            return response.json()


class SensorRegistry:
    def __init__(self, path: Path | str = "shadowstrike-sensors.json") -> None:
        self.path = Path(path)

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except Exception:
            return {}

    def _save(self, data: dict[str, dict[str, Any]]) -> None:
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    def create(self, site: str, assessment_id: str) -> tuple[dict[str, Any], str]:
        agent = ShadowAgent.register(site)
        token, digest = ShadowAgent.issue_token()
        record = {
            "agent_id": agent.agent_id,
            "site": site,
            "assessment_id": assessment_id,
            "status": "registered",
            "last_seen": None,
            "token_hash": digest,
            "created_at": utcnow(),
            "capabilities": {},
            "detected_networks": [],
            "health": {},
        }
        data = self._load()
        data[agent.agent_id] = record
        self._save(data)
        return {k: v for k, v in record.items() if k != "token_hash"}, token

    def get(self, agent_id: str) -> dict[str, Any] | None:
        return self._load().get(agent_id)

    def list(self, assessment_id: str | None = None) -> list[dict[str, Any]]:
        records = list(self._load().values())
        if assessment_id:
            records = [x for x in records if x.get("assessment_id") == assessment_id]
        now = datetime.now(timezone.utc)
        output: list[dict[str, Any]] = []
        for source in records:
            row = {k: v for k, v in source.items() if k != "token_hash"}
            last_seen = row.get("last_seen")
            if not last_seen:
                row["runtime_state"] = "awaiting-launch"
            else:
                try:
                    seen = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
                    age = max(0.0, (now - seen).total_seconds())
                    row["heartbeat_age_seconds"] = round(age, 1)
                    row["runtime_state"] = "online" if age <= 180 else "stale"
                except ValueError:
                    row["runtime_state"] = str(row.get("status") or "unknown")
            output.append(row)
        return output

    def heartbeat(
        self,
        agent_id: str,
        *,
        status: str = "online",
        capabilities: dict[str, Any] | None = None,
        detected_networks: list[dict[str, Any]] | None = None,
        health: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        data = self._load()
        record = data.get(agent_id)
        if not record:
            return None
        record["status"] = status or "online"
        record["last_seen"] = utcnow()
        if capabilities is not None:
            record["capabilities"] = capabilities
        if detected_networks is not None:
            # Keep only well-formed unique CIDRs reported by the authenticated sensor.
            clean: dict[str, dict[str, Any]] = {}
            for item in detected_networks:
                cidr = str(item.get("cidr", "")).strip()
                if cidr:
                    clean[cidr] = dict(item)
            record["detected_networks"] = list(clean.values())
        if health is not None:
            record["health"] = health
        self._save(data)
        return {k: v for k, v in record.items() if k != "token_hash"}
