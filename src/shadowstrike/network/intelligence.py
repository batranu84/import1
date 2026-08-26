from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DeviceProfile:
    address: str
    vendor: str | None = None
    device_type: str = "unknown"
    services: list[str] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class NetworkNode:
    node_id: str
    label: str
    kind: str
    metadata: dict = field(default_factory=dict)


@dataclass
class NetworkTopology:
    nodes: list[NetworkNode] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)

    def add_link(self, source: str, target: str, relation: str = "connected") -> None:
        self.edges.append({"source": source, "target": target, "relation": relation})


class NetworkRisk:
    # Risk weighting is based on protocol-confirmed identities, never conventional port numbers.
    MANAGEMENT_IDENTITIES = {
        "ssh", "telnet", "snmp", "https", "smb", "rdp", "winrm", "winrm-http",
        "winrm-https", "wsman", "proxmox", "vnc", "docker", "docker-http", "docker-api",
    }
    CLEAR_TEXT_IDENTITIES = {"ftp", "telnet", "pop3", "imap", "http"}

    @classmethod
    def score(cls, device: DeviceProfile) -> float:
        identities = {str(service).strip().lower() for service in device.services if str(service).strip()}
        score = len(identities) * 0.6 + float(device.risk_score)
        score += 0.8 * len(identities & cls.MANAGEMENT_IDENTITIES)
        score += 1.5 * len(identities & cls.CLEAR_TEXT_IDENTITIES)
        if device.device_type in {"switch", "firewall", "gateway/router"}:
            score += 0.7
        return round(min(10.0, score), 2)
