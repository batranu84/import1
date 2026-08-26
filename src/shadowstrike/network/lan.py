from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import socket
import ssl
import subprocess
from dataclasses import dataclass, field
from typing import Iterable

from shadowstrike.network.device import ShadowDevice, service_name
from shadowstrike.network.fingerprint import ArpScanAdapter, MacVendorResolver, NmapFingerprintAdapter
from shadowstrike.network.multicast import discover_link_local, enrich_upnp_description

RFC1918_NETWORKS = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))

def _is_rfc1918_network(net: ipaddress._BaseNetwork) -> bool:
    return net.version == 4 and any(net.subnet_of(parent) for parent in RFC1918_NETWORKS)

def _usable_interface_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4 and not (address.is_unspecified or address.is_loopback or address.is_multicast) and str(address) != "255.255.255.255"

def _valid_local_network_candidate(net: ipaddress._BaseNetwork, *, route: bool = False) -> bool:
    if net.version != 4 or net.prefixlen == 0 or net.is_loopback or net.is_link_local or net.is_multicast:
        return False
    if str(net.network_address) in {"0.0.0.0", "255.255.255.255"}:
        return False
    if not _is_rfc1918_network(net):
        return False
    # macOS routing tables contain per-neighbour cloning/host routes. They are hosts, not LANs.
    if route and net.prefixlen >= 31:
        return False
    return True


DEFAULT_DISCOVERY_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 515, 548, 554,
    631, 636, 873, 1433, 1883, 2049, 2375, 2376, 3000, 3306, 3389, 5000, 5001,
    5432, 5900, 5985, 5986, 6379, 8000, 8006, 8080, 8443, 8883, 9000, 9100,
    9200, 9443, 11211, 27017,
]
STANDARD_PORTS = sorted(set(range(1, 1025)) | set(DEFAULT_DISCOVERY_PORTS))
# Initial host discovery is intentionally much smaller than service discovery. On a directly
# connected LAN, even a closed TCP port forces ARP resolution; the refreshed neighbour table
# then provides positive L2 host evidence. Routed networks use a broader cross-platform probe
# set because ARP is not visible across the router.
FAST_LOCAL_DISCOVERY_PORTS = [80, 443]
FAST_ROUTED_DISCOVERY_PORTS = [22, 53, 80, 135, 139, 443, 445, 554, 631, 3389, 5900, 5985, 8000, 8080, 8443, 9100]
FALLBACK_ADAPTIVE_PORTS = sorted(set(DEFAULT_DISCOVERY_PORTS) | {
    7, 9, 13, 19, 37, 42, 49, 67, 68, 69, 70, 79, 81, 88, 111, 113, 119,
    123, 161, 162, 179, 199, 264, 427, 464, 465, 514, 593, 623, 749, 902, 989,
    990, 992, 993, 995, 1025, 1080, 1194, 1723, 1812, 1813, 1900, 2000, 2082,
    2083, 2222, 3260, 3268, 3269, 3478, 3690, 4369, 4500, 4786, 5060, 5061,
    5222, 5223, 5353, 5555, 5671, 5672, 6443, 7000, 7001, 7070, 7443, 7777,
    8008, 8009, 8081, 8088, 8181, 8300, 8500, 8880, 8888, 9001, 9042, 9090,
    9092, 9418, 10000, 15672, 25565, 50000, 50070, 50075
})
TLS_PORTS = {443, 636, 2376, 5986, 8443, 8883, 9443}
HTTP_PORTS = {80, 3000, 5000, 8000, 8080}
HTTPS_PORTS = {443, 5001, 8443, 9443}


@dataclass
class NetworkInterface:
    name: str
    address: str
    prefix: int | None = None
    network: str | None = None


@dataclass
class DetectedNetwork:
    cidr: str
    interface: str | None = None
    gateway: str | None = None
    source: str = "route"
    directly_connected: bool = False
    private: bool = True
    approval_recommended: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "cidr": self.cidr,
            "interface": self.interface,
            "gateway": self.gateway,
            "source": self.source,
            "directly_connected": self.directly_connected,
            "private": self.private,
            "approval_recommended": self.approval_recommended,
        }


@dataclass
class ShadowLAN:
    subnet: str
    devices: list[ShadowDevice] = field(default_factory=list)
    gateway: str | None = None

    def add_device(self, device: ShadowDevice) -> ShadowDevice:
        existing = next((d for d in self.devices if d.ip == device.ip), None)
        if existing:
            existing.open_ports = sorted(set(existing.open_ports) | set(device.open_ports))
            existing.mac = existing.mac or device.mac
            existing.vendor = existing.vendor or device.vendor
            existing.hostname = existing.hostname or device.hostname
            existing.is_gateway = existing.is_gateway or device.is_gateway
            existing.services = device.services or existing.services
            existing.evidence_types = sorted(set(existing.evidence_types) | set(device.evidence_types))
            existing.metadata.update(device.metadata)
            existing.normalize()
            return existing
        device.normalize()
        self.devices.append(device)
        return device

    def inventory(self) -> list[ShadowDevice]:
        return sorted(self.devices, key=lambda d: ipaddress.ip_address(d.ip))

    @staticmethod
    def local_interfaces() -> list[NetworkInterface]:
        found: dict[str, NetworkInterface] = {}
        system = platform.system().lower()
        commands: list[list[str]] = []
        if system == "darwin":
            commands = [["ifconfig"]]
        elif system == "linux":
            commands = [["ip", "-o", "-4", "addr", "show"], ["ifconfig"]]
        for command in commands:
            try:
                text = subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL, timeout=3)
            except (OSError, subprocess.SubprocessError):
                continue
            if command[0] == "ip":
                for line in text.splitlines():
                    m = re.search(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
                    if not m:
                        continue
                    name, address, prefix_s = m.groups()
                    if not _usable_interface_address(address):
                        continue
                    prefix = int(prefix_s)
                    network = str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
                    found[address] = NetworkInterface(name=name, address=address, prefix=prefix, network=network)
            else:
                current = "unknown"
                for line in text.splitlines():
                    if line and not line[0].isspace() and ":" in line:
                        current = line.split(":", 1)[0]
                    m = re.search(r"\binet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)(?:\s+netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+))?", line)
                    if not m:
                        continue
                    address, mask = m.groups()
                    if not _usable_interface_address(address):
                        continue
                    prefix = None
                    if mask:
                        try:
                            prefix = bin(int(mask, 16)).count("1") if mask.startswith("0x") else ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                        except Exception:
                            prefix = None
                    network = str(ipaddress.ip_network(f"{address}/{prefix}", strict=False)) if prefix is not None else None
                    found[address] = NetworkInterface(name=current, address=address, prefix=prefix, network=network)
            if found:
                break
        if not found:
            try:
                for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                    address = info[4][0]
                    if _usable_interface_address(address):
                        found[address] = NetworkInterface(name="host", address=address)
            except OSError:
                pass
        return list(found.values())

    @staticmethod
    def default_gateway() -> str | None:
        system = platform.system().lower()
        commands = [["route", "-n", "get", "default"]] if system == "darwin" else [["ip", "route", "show", "default"]]
        for command in commands:
            try:
                text = subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL, timeout=2)
            except (OSError, subprocess.SubprocessError):
                continue
            for pattern in [r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)"]:
                m = re.search(pattern, text)
                if m:
                    return m.group(1)
        return None

    @classmethod
    def detected_networks(cls) -> list[DetectedNetwork]:
        """Return private directly-connected and routed IPv4 networks visible to this host."""
        found: dict[str, DetectedNetwork] = {}
        interfaces = cls.local_interfaces()
        for interface in interfaces:
            if not interface.network:
                continue
            net = ipaddress.ip_network(interface.network, strict=False)
            if not _valid_local_network_candidate(net):
                continue
            found[str(net)] = DetectedNetwork(
                cidr=str(net), interface=interface.name, source="interface", directly_connected=True,
                private=True, approval_recommended=net.prefixlen <= 30,
            )

        system = platform.system().lower()
        commands = [["netstat", "-rn", "-f", "inet"]] if system == "darwin" else [["ip", "-4", "route", "show"]]
        for command in commands:
            try:
                text = subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL, timeout=3)
            except (OSError, subprocess.SubprocessError):
                continue
            if system == "darwin":
                for line in text.splitlines():
                    parts = line.split()
                    if len(parts) < 4 or parts[0] in {"default", "Destination", "Routing"}:
                        continue
                    dest, gateway = parts[0], parts[1]
                    interface = parts[-1] if re.match(r"^(?:en|eth|utun|bridge|vlan|awdl|llw)\w*", parts[-1]) else None
                    try:
                        if "/" in dest:
                            net = ipaddress.ip_network(dest, strict=False)
                        elif re.fullmatch(r"\d+\.\d+\.\d+(?:\.\d+)?", dest):
                            # macOS often renders classful/direct routes without a prefix.
                            octets = dest.split(".")
                            padded = ".".join(octets + ["0"] * (4 - len(octets)))
                            prefix = min(32, len(octets) * 8)
                            net = ipaddress.ip_network(f"{padded}/{prefix}", strict=False)
                        else:
                            continue
                    except ValueError:
                        continue
                    if not _valid_local_network_candidate(net, route=True):
                        continue
                    gw = gateway if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", gateway) else None
                    key = str(net)
                    found.setdefault(key, DetectedNetwork(key, interface=interface, gateway=gw, source="route", directly_connected=gw is None, private=True, approval_recommended=True))
            else:
                for line in text.splitlines():
                    parts = line.split()
                    if not parts or parts[0] == "default":
                        continue
                    try:
                        net = ipaddress.ip_network(parts[0], strict=False)
                    except ValueError:
                        continue
                    if not _valid_local_network_candidate(net, route=True):
                        continue
                    gateway = parts[parts.index("via") + 1] if "via" in parts and parts.index("via") + 1 < len(parts) else None
                    interface = parts[parts.index("dev") + 1] if "dev" in parts and parts.index("dev") + 1 < len(parts) else None
                    key = str(net)
                    found.setdefault(key, DetectedNetwork(key, interface=interface, gateway=gateway, source="route", directly_connected=gateway is None, private=True, approval_recommended=True))
            break
        return sorted(found.values(), key=lambda x: (not x.directly_connected, ipaddress.ip_network(x.cidr).prefixlen, x.cidr))

    @staticmethod
    def arp_neighbors() -> dict[str, str]:
        neighbors: dict[str, str] = {}
        for command in [["arp", "-an"], ["ip", "neigh", "show"]]:
            try:
                text = subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL, timeout=2)
            except (OSError, subprocess.SubprocessError):
                continue
            for line in text.splitlines():
                ip_match = re.search(r"(?:\(|^)(\d+\.\d+\.\d+\.\d+)(?:\)|\s)", line)
                mac_match = re.search(r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b", line)
                if ip_match and mac_match:
                    ip = ip_match.group(1)
                    mac = mac_match.group(1).lower()
                    if not _usable_interface_address(ip):
                        continue
                    if mac in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
                        continue
                    try:
                        if int(mac.split(":", 1)[0], 16) & 1:
                            continue
                    except Exception:
                        continue
                    neighbors[ip] = mac
            if neighbors:
                break
        return neighbors

    @staticmethod
    async def _ping(ip: str, timeout: float, semaphore: asyncio.Semaphore) -> bool:
        system = platform.system().lower()
        if system == "windows":
            command = ["ping", "-n", "1", "-w", str(max(100, int(timeout * 1000))), ip]
        elif system == "darwin":
            command = ["ping", "-n", "-c", "1", "-W", str(max(100, int(timeout * 1000))), ip]
        else:
            command = ["ping", "-n", "-c", "1", "-W", "1", ip]
        async with semaphore:
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                await asyncio.wait_for(proc.wait(), timeout=max(1.0, timeout + 0.8))
                return proc.returncode == 0
            except (OSError, asyncio.TimeoutError):
                if proc is not None:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                return False

    @staticmethod
    async def _probe(ip: str, ports: Iterable[int], timeout: float, semaphore: asyncio.Semaphore) -> tuple[list[int], dict[int, float]]:
        open_ports: list[int] = []
        latency: dict[int, float] = {}
        loop = asyncio.get_running_loop()

        async def one(port: int) -> None:
            start = loop.time()
            async with semaphore:
                try:
                    _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, int(port)), timeout=timeout)
                except (OSError, asyncio.TimeoutError):
                    return
                try:
                    open_ports.append(int(port))
                    latency[int(port)] = round((loop.time() - start) * 1000, 2)
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

        await asyncio.gather(*(one(int(p)) for p in ports))
        return sorted(set(open_ports)), latency

    @classmethod
    async def _probe_chunked(cls, ip: str, ports: Iterable[int], timeout: float, semaphore: asyncio.Semaphore, chunk_size: int = 512) -> tuple[list[int], dict[int, float]]:
        port_list = [int(p) for p in ports]
        all_open: list[int] = []
        all_latency: dict[int, float] = {}
        for start in range(0, len(port_list), chunk_size):
            opened, latency = await cls._probe(ip, port_list[start:start + chunk_size], timeout, semaphore)
            all_open.extend(opened)
            all_latency.update(latency)
        return sorted(set(all_open)), all_latency

    @staticmethod
    async def _verify_service(ip: str, port: int, timeout: float = 0.7) -> dict[str, object]:
        candidate = service_name(port)
        result: dict[str, object] = {
            "port": int(port), "transport": "tcp", "name": "unknown",
            "service_candidate": candidate, "port_state": "confirmed-open",
            "service_state": "unconfirmed", "identity_basis": "conventional-port-candidate",
        }

        def _http_parts(blob: bytes) -> tuple[str, str]:
            text = blob.decode("latin1", "replace")[:8000]
            head, _, body = text.partition("\r\n\r\n")
            return head, body

        def _server_header(head: str) -> str | None:
            for line in head.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()[:300]
            return None

        try:
            if port in HTTPS_PORTS or port in TLS_PORTS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ctx, server_hostname=ip),
                    timeout=timeout,
                )
                result["name"] = "tls"
                result["service_state"] = "confirmed"
                result["identity_basis"] = "tls-handshake"
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    result["tls_version"] = ssl_obj.version()

                wants_http = port in HTTPS_PORTS or port in {2376, 5986}
                if wants_http:
                    if port == 2376:
                        request = f"GET /_ping HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                    elif port == 5986:
                        request = f"OPTIONS /wsman HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                    else:
                        request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                    writer.write(request.encode())
                    await writer.drain()
                    try:
                        blob = await asyncio.wait_for(reader.read(8192), timeout=timeout)
                    except asyncio.TimeoutError:
                        blob = b""
                    if blob.startswith(b"HTTP/"):
                        head, body = _http_parts(blob)
                        result["name"] = "https"
                        result["service_state"] = "confirmed"
                        result["identity_basis"] = "http-response-over-tls"
                        result["application_evidence"] = (head + ("\r\n\r\n" + body if body else ""))[:4000]
                        server = _server_header(head)
                        if server:
                            result["server"] = server
                        if port == 2376:
                            low_head = head.lower()
                            if body.strip().lower().startswith("ok") or "api-version:" in low_head or "docker-experimental:" in low_head:
                                result["name"] = "docker-tls"
                                result["service_state"] = "confirmed"
                                result["identity_basis"] = "docker-ping-response-over-tls"
                        elif port == 5986:
                            low_head = head.lower()
                            if "microsoft-httpapi" in low_head and "www-authenticate:" in low_head:
                                result["service_candidate"] = "winrm-https"
                                result["winrm_candidate_basis"] = "wsman-path+microsoft-httpapi-auth-challenge"

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return result

            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            if port in HTTP_PORTS or port in {2375, 5985, 9200}:
                if port == 2375:
                    request = f"GET /_ping HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                elif port == 5985:
                    request = f"OPTIONS /wsman HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                else:
                    request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()
                try:
                    blob = await asyncio.wait_for(reader.read(8192), timeout=timeout)
                except asyncio.TimeoutError:
                    blob = b""
                if blob.startswith(b"HTTP/"):
                    head, body = _http_parts(blob)
                    result["name"] = "http"
                    result["service_state"] = "confirmed"
                    result["identity_basis"] = "http-response"
                    result["application_evidence"] = (head + ("\r\n\r\n" + body if body else ""))[:4000]
                    server = _server_header(head)
                    if server:
                        result["server"] = server
                    if port == 2375:
                        low_head = head.lower()
                        if body.strip().lower().startswith("ok") or "api-version:" in low_head or "docker-experimental:" in low_head:
                            result["name"] = "docker-http"
                            result["service_state"] = "confirmed"
                            result["identity_basis"] = "docker-ping-response"
                    elif port == 5985:
                        low_head = head.lower()
                        if "microsoft-httpapi" in low_head and "www-authenticate:" in low_head:
                            result["service_candidate"] = "winrm-http"
                            result["winrm_candidate_basis"] = "wsman-path+microsoft-httpapi-auth-challenge"
                    elif port == 9200:
                        # HTTP on 9200 alone does not prove Elasticsearch. Preserve the port-based
                        # candidate and require product-specific response evidence later.
                        result["service_candidate"] = "elasticsearch"
            elif port == 445:
                # SMB2 NEGOTIATE with common dialects. A valid SMB2 response confirms the
                # protocol without authenticating or accessing shares.
                import os, struct
                smb_header = (b"\xfeSMB" + struct.pack("<H", 64) + b"\x00\x00" + b"\x00"*4 + struct.pack("<H", 0) + struct.pack("<H", 1) + b"\x00"*4 + b"\x00"*4 + struct.pack("<Q", 1) + b"\x00"*4 + b"\x00"*4 + b"\x00"*8 + b"\x00"*16)
                body = struct.pack("<HHHHI16sIHH", 36, 3, 1, 0, 0, os.urandom(16), 0, 0, 0) + struct.pack("<HHH", 0x0202, 0x0210, 0x0300)
                packet = b"\x00" + len(smb_header + body).to_bytes(3, "big") + smb_header + body
                writer.write(packet); await writer.drain()
                try:
                    blob = await asyncio.wait_for(reader.read(512), timeout=timeout)
                except asyncio.TimeoutError:
                    blob = b""
                if len(blob) >= 73 and blob[4:8] == b"\xfeSMB":
                    result["name"] = "smb"; result["service_state"] = "confirmed"
                    result["identity_basis"] = "smb2-negotiate-response"
                    dialect = int.from_bytes(blob[72:74], "little") if len(blob) >= 74 else None
                    if dialect:
                        result["smb_dialect"] = hex(dialect)
                    result["application_evidence"] = blob[:160].hex()
            elif port == 389:
                # Anonymous RootDSE search. This asks only for server identity/capability
                # metadata and does not bind as a user or enumerate directory objects.
                attrs = [b"defaultNamingContext", b"namingContexts", b"dnsHostName", b"supportedCapabilities"]
                attr_seq = b"".join(b"\x04" + bytes([len(a)]) + a for a in attrs)
                search = b"\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x01\x01\x01\x00" + b"\x87\x0bobjectClass" + b"\x30" + bytes([len(attr_seq)]) + attr_seq
                message = b"\x02\x01\x01" + b"\x63" + bytes([len(search)]) + search
                request = b"\x30" + bytes([len(message)]) + message
                writer.write(request); await writer.drain()
                try:
                    blob = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                except asyncio.TimeoutError:
                    blob = b""
                if blob.startswith(b"\x30") and (b"defaultNamingContext" in blob or b"namingContexts" in blob or b"dnsHostName" in blob):
                    result["name"] = "ldap"; result["service_state"] = "confirmed"
                    result["identity_basis"] = "ldap-rootdse-response"
                    result["application_evidence"] = blob[:2000].hex()
            elif port == 3389:
                # TPKT/X.224 RDP negotiation request; confirms RDP only.
                writer.write(bytes.fromhex("030000130ee000000000000100080003000000")); await writer.drain()
                try:
                    blob = await asyncio.wait_for(reader.read(256), timeout=timeout)
                except asyncio.TimeoutError:
                    blob = b""
                if len(blob) >= 11 and blob[:2] == b"\x03\x00":
                    result["name"] = "rdp"; result["service_state"] = "confirmed"
                    result["identity_basis"] = "rdp-x224-negotiation-response"
                    result["application_evidence"] = blob[:128].hex()
            elif port in {21, 22, 23, 25, 110, 143}:
                try:
                    blob = await asyncio.wait_for(reader.read(512), timeout=timeout)
                except asyncio.TimeoutError:
                    blob = b""
                text = blob.decode("latin1", "replace").strip()[:300]
                if port == 22 and text.startswith("SSH-"):
                    result["name"] = "ssh"; result["service_state"] = "confirmed"
                    result["identity_basis"] = "ssh-identification-string"
                elif port == 21 and text.startswith("220"):
                    result["name"] = "ftp"; result["service_state"] = "confirmed"
                    result["identity_basis"] = "ftp-greeting"
                elif port == 23 and b"\xff" in blob:
                    result["name"] = "telnet"; result["service_state"] = "confirmed"
                    result["identity_basis"] = "telnet-iac-negotiation"
                elif port == 25 and text.startswith("220"):
                    result["name"] = "smtp"; result["service_state"] = "confirmed"
                    result["identity_basis"] = "smtp-greeting"
                elif port == 110 and text.startswith("+OK"):
                    result["name"] = "pop3"; result["service_state"] = "confirmed"
                    result["identity_basis"] = "pop3-greeting"
                elif port == 143 and text.startswith("*"):
                    result["name"] = "imap"; result["service_state"] = "confirmed"
                    result["identity_basis"] = "imap-greeting"
                if text:
                    result["application_evidence"] = text
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except (OSError, asyncio.TimeoutError, ssl.SSLError):
            # The TCP connect that discovered the port remains authoritative. Failure of a
            # second application probe means only that the service identity is unconfirmed.
            pass
        return result

    async def discover(
        self,
        ports: Iterable[int] | None = None,
        timeout: float = 0.35,
        concurrency: int = 128,
        max_hosts: int = 2048,
        port_profile: str = "standard",
        verify_services: bool = True,
    ) -> list[ShadowDevice]:
        network = ipaddress.ip_network(self.subnet, strict=False)
        if network.is_loopback or network.is_multicast or network.is_unspecified or str(network.network_address) == "255.255.255.255":
            raise ValueError(f"Network {network} is not a usable LAN discovery network")
        host_count = max(network.num_addresses - (2 if network.version == 4 and network.prefixlen < 31 else 0), 0)
        if host_count > max_hosts:
            raise ValueError(f"Network {network} contains {host_count} hosts; maximum per LAN discovery run is {max_hosts}")
        self.gateway = self.gateway or self.default_gateway()
        neighbors = self.arp_neighbors()
        arp_scan_inventory: dict[str, dict[str, str]] = {}
        # On a directly connected LAN, arp-scan is the most reliable fast discovery source
        # for devices that ignore ICMP and have no conventional TCP listener. It is optional
        # and failure simply falls back to native ARP/ICMP/TCP discovery.
        interface = next(
            (i.name for i in self.local_interfaces() if i.network and ipaddress.ip_network(i.network, strict=False) == network),
            None,
        )
        if network.version == 4:
            arp_scan_inventory = await ArpScanAdapter.discover(str(network), interface=interface)
            for ip, row in arp_scan_inventory.items():
                try:
                    in_network = ipaddress.ip_address(ip) in network
                except ValueError:
                    in_network = False
                if in_network and row.get("mac"):
                    neighbors.setdefault(ip, row.get("mac") or "")

        multicast_inventory: dict[str, dict[str, object]] = {}
        if network.version == 4 and interface:
            try:
                raw_multicast = await discover_link_local(timeout=min(1.25, max(0.6, timeout * 3)))
                multicast_inventory = {
                    ip: data for ip, data in raw_multicast.items()
                    if ipaddress.ip_address(ip) in network
                }
                # Resolve advertised UPnP identity only after the responding IP has passed
                # the authorised-CIDR filter. This can reveal manufacturer/model/device role
                # without guessing from a port number.
                async def enrich_multicast_host(ip: str, data: dict[str, object]) -> None:
                    upnp = await enrich_upnp_description(ip, data, timeout=min(1.5, max(0.7, timeout * 3)))
                    if upnp:
                        data["upnp_description"] = upnp
                        roles = list(data.get("roles") or [])
                        roles.extend(upnp.get("roles") or [])
                        data["roles"] = sorted({str(x) for x in roles if x})

                await asyncio.gather(*(enrich_multicast_host(ip, data) for ip, data in multicast_inventory.items()))
            except Exception:
                multicast_inventory = {}

        semaphore = asyncio.Semaphore(max(1, min(int(concurrency), 512)))
        if ports is not None:
            discovery_ports = list(ports)
        elif interface:
            discovery_ports = list(FAST_LOCAL_DISCOVERY_PORTS)
        else:
            discovery_ports = list(FAST_ROUTED_DISCOVERY_PORTS)
        hosts = [str(h) for h in network.hosts()]

        async def initial_inspect(ip: str) -> ShadowDevice | None:
            opened, latency = await self._probe(ip, discovery_ports, timeout, semaphore)
            mac = neighbors.get(ip)
            ping_alive = False
            if not opened and not mac and ip != self.gateway:
                ping_alive = await self._ping(ip, timeout, semaphore)
            multicast = multicast_inventory.get(ip)
            if not opened and not mac and not ping_alive and ip != self.gateway and not multicast:
                return None
            evidence_types: list[str] = []
            if opened:
                evidence_types.append("tcp-connect")
            if mac:
                evidence_types.append("arp-neighbor")
            if ping_alive:
                evidence_types.append("icmp-echo")
            if ip == self.gateway:
                evidence_types.append("default-gateway")
            if multicast:
                evidence_types.extend(f"multicast:{x}" for x in multicast.get("protocols", []))
            hostname = None
            try:
                resolved = await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, ip), timeout=0.5)
                hostname = resolved[0]
                evidence_types.append("reverse-dns")
            except Exception:
                pass
            upnp = multicast.get("upnp_description") if multicast else None
            upnp_fields = (upnp or {}).get("fields") if isinstance(upnp, dict) else {}
            if not hostname and multicast:
                advertised = multicast.get("advertised_services") or []
                hostname = next((str(x.get("server")) for x in advertised if isinstance(x, dict) and x.get("server")), None)
                if hostname:
                    evidence_types.append("mdns-hostname")
            vendor = (arp_scan_inventory.get(ip) or {}).get("vendor") or (upnp_fields or {}).get("manufacturer") or MacVendorResolver.lookup(mac)
            if ip in arp_scan_inventory and "arp-scan" not in evidence_types:
                evidence_types.append("arp-scan")
            if upnp:
                evidence_types.append("upnp-device-description")
            return ShadowDevice(
                ip=ip, mac=mac, vendor=vendor, hostname=hostname, open_ports=opened, is_gateway=(ip == self.gateway),
                evidence_types=evidence_types,
                metadata={
                    "connect_latency_ms": {str(k): v for k, v in latency.items()},
                    "discovery": "positive-evidence-only",
                    "arp_scan": arp_scan_inventory.get(ip),
                    "multicast": multicast,
                    "mdns_role": ",".join(multicast.get("roles", [])) if multicast else "",
                    "ssdp_role": ",".join(multicast.get("roles", [])) if multicast else "",
                    "upnp_role": ",".join((upnp or {}).get("roles", [])) if isinstance(upnp, dict) else "",
                    "upnp_identity": upnp,
                },
            ).normalize()

        initial = await asyncio.gather(*(initial_inspect(ip) for ip in hosts))
        live = [d for d in initial if d is not None]

        # A direct-LAN TCP attempt populates the OS neighbour table even when the application
        # port is closed. Refresh it after the lightweight sweep so quiet printers/APs/IoT
        # endpoints are not missed merely because they have no common open TCP port.
        post_sweep_neighbors = self.arp_neighbors() if interface else {}
        known_live = {d.ip for d in live}
        for ip, mac in post_sweep_neighbors.items():
            try:
                in_network = ipaddress.ip_address(ip) in network
            except ValueError:
                in_network = False
            if not in_network or ip in known_live:
                continue
            hostname = None
            try:
                resolved = await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, ip), timeout=0.35)
                hostname = resolved[0]
            except Exception:
                pass
            live.append(ShadowDevice(
                ip=ip, mac=mac, vendor=MacVendorResolver.lookup(mac), hostname=hostname,
                is_gateway=(ip == self.gateway),
                evidence_types=["arp-neighbor"] + (["reverse-dns"] if hostname else []),
                metadata={"discovery": "post-sweep-arp-neighbor"},
            ).normalize())
            known_live.add(ip)
        live.sort(key=lambda d: ipaddress.ip_address(d.ip))

        # Port discovery is adaptive by default. Historical profile ``full`` used to mean a
        # 1-65535 sweep on every live device, which scales poorly and delays the useful
        # fingerprint phases. It now maps to adaptive deep discovery. Exhaustive scanning is
        # still available explicitly as ``exhaustive``.
        requested_profile = port_profile
        effective_profile = "adaptive" if port_profile == "full" else port_profile
        if ports is None:
            if effective_profile == "exhaustive":
                followup_ports: Iterable[int] = range(1, 65536)
            elif effective_profile == "discovery":
                followup_ports = DEFAULT_DISCOVERY_PORTS
            elif effective_profile == "standard":
                followup_ports = STANDARD_PORTS
            else:
                # Adaptive uses Nmap's maintained port-frequency data when present, then
                # merges ShadowStrike's technology-specific ports. It is intentionally not
                # a blind 1-1024 sweep of every endpoint.
                nmap_top = NmapFingerprintAdapter.top_tcp_ports(256)
                followup_ports = sorted(set(nmap_top or FALLBACK_ADAPTIVE_PORTS) | set(DEFAULT_DISCOVERY_PORTS))

            # Scan live devices concurrently behind one global socket semaphore. The old
            # implementation completed an entire host before starting the next one, making a
            # 15-device LAN roughly 15x slower than necessary. DNS-SD advertised TCP ports are
            # added to the adaptive plan so high/random service ports can be verified without a
            # blind 1-65535 sweep.
            async def followup_device(device: ShadowDevice) -> None:
                multicast = device.metadata.get("multicast") or {}
                advertised = multicast.get("advertised_services") or [] if isinstance(multicast, dict) else []
                advertised_tcp = {
                    int(x.get("port")) for x in advertised
                    if isinstance(x, dict) and x.get("transport") == "tcp" and x.get("port")
                }
                if effective_profile == "exhaustive":
                    planned_ports: Iterable[int] = followup_ports
                else:
                    planned_ports = sorted(set(int(x) for x in followup_ports) | advertised_tcp)
                opened, latency = await self._probe_chunked(device.ip, planned_ports, timeout, semaphore)
                device.open_ports = opened
                device.metadata["connect_latency_ms"] = {str(k): v for k, v in latency.items()}
                device.metadata["port_profile"] = requested_profile
                device.metadata["effective_port_profile"] = effective_profile
                device.metadata["dns_sd_advertised_ports"] = sorted(advertised_tcp)
                if opened and "tcp-connect" not in device.evidence_types:
                    device.evidence_types.append("tcp-connect")

            await asyncio.gather(*(followup_device(device) for device in live))

        refreshed = self.arp_neighbors()
        for device in live:
            if not device.mac and device.ip in refreshed:
                device.mac = refreshed[device.ip]
                if "arp-neighbor" not in device.evidence_types:
                    device.evidence_types.append("arp-neighbor")
            multicast = device.metadata.get("multicast") or {}
            advertised = multicast.get("advertised_services") or [] if isinstance(multicast, dict) else []
            advertised_by_port = {
                int(x.get("port")): dict(x) for x in advertised
                if isinstance(x, dict) and x.get("transport") == "tcp" and x.get("port")
            }
            udp_advertised = [
                dict(x) for x in advertised
                if isinstance(x, dict) and x.get("transport") == "udp" and x.get("port")
            ]
            if verify_services and device.open_ports:
                verified = [dict(x) for x in await asyncio.gather(*(self._verify_service(device.ip, port) for port in device.open_ports))]
                for item in verified:
                    port = int(item.get("port") or 0)
                    mdns = advertised_by_port.get(port)
                    if not mdns:
                        continue
                    item["dns_sd"] = mdns
                    if item.get("service_state") != "confirmed":
                        # The application identity comes from a genuine DNS-SD advertisement and
                        # transport reachability has independently succeeded on the advertised
                        # endpoint. This is stronger than a conventional-port guess.
                        item["name"] = mdns.get("name") or "unknown"
                        item["service_candidate"] = mdns.get("name") or item.get("service_candidate")
                        item["service_state"] = "confirmed"
                        item["identity_basis"] = "mdns-dns-sd-advertisement+tcp-connect"
                device.services = verified + udp_advertised
                confirmed = [str(x.get("name")) for x in verified if x.get("service_state") == "confirmed"]
                device.evidence_types.extend(f"service:{name}" for name in confirmed)
            elif udp_advertised:
                device.services.extend(udp_advertised)
            device.normalize()

        # Deep identity enrichment is a single batched pass, not one external command per
        # device. Nmap service/version detection is useful unprivileged; raw TCP/IP OS
        # fingerprinting is used only when the process has the privileges Nmap requires.
        fingerprints, fingerprint_status = await NmapFingerprintAdapter.fingerprint(
            live, timeout=max(60.0, timeout * 100), deep=effective_profile != "discovery"
        )
        for device in live:
            fp = fingerprints.get(device.ip)
            if fp:
                NmapFingerprintAdapter.apply(device, fp)
            else:
                device.vendor = device.vendor or MacVendorResolver.lookup(device.mac)
                device.normalize()
            device.metadata["fingerprint_backend"] = fingerprint_status
            self.add_device(device)
        return self.inventory()
