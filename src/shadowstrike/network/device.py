from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SERVICE_HINTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 123: "ntp", 135: "msrpc", 139: "netbios", 143: "imap",
    389: "ldap", 443: "tls", 445: "smb", 515: "lpd", 548: "afp", 554: "rtsp",
    631: "ipp", 636: "ldaps", 873: "rsync", 1433: "mssql", 1883: "mqtt",
    2049: "nfs", 2375: "docker", 2376: "docker-tls", 3000: "web-alt",
    3306: "mysql", 3389: "rdp", 5000: "web-alt", 5001: "web-alt-tls",
    5432: "postgresql", 5900: "vnc", 5985: "winrm", 5986: "winrm-tls",
    6379: "redis", 8000: "web-alt", 8006: "proxmox", 8080: "http-alt",
    8443: "https-alt", 8883: "mqtt-tls", 9000: "web-alt", 9100: "jetdirect",
    9200: "elasticsearch", 9443: "https-alt", 11211: "memcached", 27017: "mongodb",
}

# Small built-in OUI hints only. Unknown OUIs stay unknown; they are never guessed.
OUI_HINTS: dict[str, str] = {
    "00005E": "IANA/VRRP", "000C29": "VMware", "001B21": "Intel", "001C42": "Parallels",
    "001E52": "Apple", "0024E8": "Dell", "002590": "Super Micro", "005056": "VMware",
    "0C9D92": "ASUSTek", "18E829": "Ubiquiti", "24A43C": "Ubiquiti", "3C52A1": "Cisco",
    "44D9E7": "Ubiquiti", "5EBA2C": "Private/Randomized", "6805CA": "Intel",
    "6C3BE5": "Hewlett Packard", "74ACB9": "Ubiquiti", "80EA96": "Apple",
    "8CEC4B": "Dell", "9C05D6": "Ubiquiti", "A4BA76": "Huawei", "B4FBE4": "Ubiquiti",
    "D850E6": "ASUSTek", "DC9FDB": "Ubiquiti", "F09FC2": "Ubiquiti",
}


def vendor_from_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    normalized = "".join(ch for ch in mac.upper() if ch in "0123456789ABCDEF")
    if len(normalized) < 6:
        return None
    try:
        first = int(normalized[:2], 16)
    except ValueError:
        return None
    if first & 0x02:
        return "Locally administered/randomized"
    prefix = normalized[:6]
    if prefix in OUI_HINTS:
        return OUI_HINTS[prefix]
    # mac-vendor-lookup ships an offline IEEE OUI list. Failure remains unknown rather
    # than generating a vendor guess.
    try:
        from mac_vendor_lookup import MacLookup  # type: ignore

        return str(MacLookup().lookup(mac)).strip() or None
    except Exception:
        return None


def service_name(port: int) -> str:
    return SERVICE_HINTS.get(int(port), f"tcp/{int(port)}")


@dataclass
class ShadowDevice:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    device_type: str = "unknown"
    open_ports: list[int] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    os_hint: str | None = None
    firmware: str | None = None
    bios: dict[str, Any] | None = None
    is_gateway: bool = False
    snmp: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    observation_state: str = "observed"
    identity_confidence: str = "observed"
    evidence_types: list[str] = field(default_factory=list)
    candidate_types: list[str] = field(default_factory=list)

    def normalize(self) -> "ShadowDevice":
        self.open_ports = sorted({int(p) for p in self.open_ports})
        self.evidence_types = sorted({str(x) for x in self.evidence_types if x})
        if not self.vendor:
            self.vendor = vendor_from_mac(self.mac)

        service_by_port = {int(s.get("port")): dict(s) for s in self.services if s.get("port") is not None}
        for port in self.open_ports:
            item = service_by_port.setdefault(port, {})
            item.setdefault("port", port)
            item.setdefault("transport", "tcp")
            item.setdefault("service_candidate", service_name(port))
            item.setdefault("name", "unknown")
            item.setdefault("port_state", "confirmed-open")
            item.setdefault("service_state", "unconfirmed")
            item.setdefault("identity_basis", "conventional-port-candidate")
        self.services = [service_by_port[p] for p in sorted(service_by_port)]
        direct_service_text = " ".join(
            str(s.get("application_evidence") or s.get("banner") or "") for s in self.services
        ).strip()
        if direct_service_text:
            existing = str(self.metadata.get("banner_text", "")).strip()
            self.metadata["banner_text"] = (existing + " " + direct_service_text).strip()[:4096]

        self.device_type, self.identity_confidence, candidates = _classify_device_details(self)
        self.candidate_types = sorted(set(self.candidate_types) | set(candidates))
        self.os_hint = self.os_hint or infer_os(self)
        if self.is_gateway or self.snmp or len(self.evidence_types) >= 2:
            self.observation_state = "confirmed"
        elif self.open_ports or self.mac:
            self.observation_state = "observed"
        return self

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def infer_os(device: ShadowDevice) -> str | None:
    """Return an OS hint only when direct descriptive evidence exists.

    Open ports by themselves are deliberately not used to assert an OS family.
    """
    text = " ".join([
        device.hostname or "",
        str((device.snmp or {}).get("sys_descr", "")),
        str(device.metadata.get("banner_text", "")),
    ]).lower()
    if "windows" in text or "microsoft windows" in text:
        return "Windows"
    if any(x in text for x in ("linux", "ubuntu", "debian", "centos", "red hat", "kernel")):
        return "Linux"
    if "darwin" in text or "mac os" in text or "macos" in text:
        return "Apple/macOS"
    if "freebsd" in text or "truenas" in text:
        return "FreeBSD/TrueNAS"
    if "cisco" in text or "ios xe" in text or "ios-xe" in text:
        return "Cisco network OS"
    if "junos" in text or "juniper" in text:
        return "Juniper Junos"
    return None


def _classify_device_details(device: ShadowDevice) -> tuple[str, str, list[str]]:
    """Conservative device classification.

    Confirmed classes require direct role evidence (gateway status, SNMP description/object,
    protocol metadata). Port combinations are recorded only as candidate types.
    """
    ports = set(device.open_ports)
    snmp_text = " ".join([
        str((device.snmp or {}).get("sys_descr", "")),
        str((device.snmp or {}).get("sys_object_id", "")),
        str((device.snmp or {}).get("sys_name", "")),
        str((device.snmp or {}).get("model", "")),
    ]).lower()
    service_identity_text = " ".join(
        " ".join(str(s.get(k) or "") for k in ("name", "product", "devicetype", "ostype"))
        for s in device.services
        if str(s.get("service_state") or "").lower() == "confirmed"
    )
    direct_text = " ".join([
        snmp_text,
        str(device.metadata.get("mdns_role", "")),
        str(device.metadata.get("ssdp_role", "")),
        str(device.metadata.get("upnp_role", "")),
        str(device.metadata.get("lldp_role", "")),
        str(device.metadata.get("nmap_role", "")),
        service_identity_text,
    ]).lower()
    candidates: list[str] = []

    if device.is_gateway:
        return "gateway/router", "confirmed", candidates
    if any(x in direct_text for x in ("broadband router", "router", "gateway")):
        return "gateway/router", "confirmed", candidates
    if any(x in direct_text for x in ("switch", "catalyst", "procurve", "switchos", "edgeswitch")):
        return "switch", "confirmed", candidates
    if any(x in direct_text for x in ("access point", "wireless ap", "unifi ap", "aironet", " wap ")):
        return "wireless-ap", "confirmed", candidates
    if any(x in direct_text for x in ("firewall", "fortigate", "palo alto", "sonicwall", "opnsense", "pfsense")):
        return "firewall", "confirmed", candidates
    if any(x in direct_text for x in ("printer", "jetdirect", "laserjet", "officejet", "imageclass", "print server")):
        return "printer", "confirmed", candidates
    if any(x in direct_text for x in ("network video recorder", "nvr", "digital video recorder", "dvr")):
        return "nvr", "confirmed", candidates
    if any(x in direct_text for x in ("camera", "webcam", "hikvision", "dahua", "axis communications", "hanwha")):
        return "camera", "confirmed", candidates
    if any(x in direct_text for x in ("synology", "qnap", "truenas", "network attached storage", "storage-misc")):
        return "nas", "confirmed", candidates
    if any(x in direct_text for x in ("proxmox", "vmware esxi", "esxi", "hyper-v", "xenserver", "xcp-ng")):
        return "virtualization-host", "confirmed", candidates
    if any(x in direct_text for x in ("docker engine", "docker daemon", "containerd", "kubernetes node", "kubelet")):
        return "container-host", "confirmed", candidates

    # Candidate-only heuristics. These never become confirmed device types without stronger evidence.
    if 9100 in ports or 631 in ports or 515 in ports:
        candidates.append("printer")
    if 554 in ports:
        candidates.append("camera/streaming-device")
    if 554 in ports and ports & {80, 443, 8000, 8080, 8443}:
        candidates.append("camera-or-nvr")
    if 8006 in ports:
        candidates.append("virtualization-host")
    if 2049 in ports and 445 in ports:
        candidates.append("nas")
    if ports & {2375, 2376, 3306, 5432, 6379, 9200, 27017}:
        candidates.append("server")
    if ports & {3389, 5985, 5986}:
        candidates.append("windows-host")
    if device.snmp:
        candidates.append("managed-network-device")

    if device.snmp:
        return "network/appliance", "observed", candidates
    if device.open_ports or device.mac:
        return "host", "observed", candidates
    return "unknown", "informational", candidates


def classify_device(device: ShadowDevice) -> str:
    """Compatibility wrapper returning only the conservative device type."""
    return _classify_device_details(device)[0]
