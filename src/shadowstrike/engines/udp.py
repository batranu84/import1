from __future__ import annotations

import asyncio
import ipaddress
import os
import random
import socket
import struct
import platform
import re
import subprocess
from typing import Any

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Evidence
from shadowstrike.network.snmp import ShadowSNMP
from shadowstrike.network.lan import ShadowLAN


class UdpProtocolDiscoveryEngine(Engine):
    """Positive-response UDP/service discovery for authorised internal assets.

    UDP has no connection handshake, so this engine never labels a silent port as open.
    It records a service only when a protocol-valid reply is received.  Discovery is
    limited to explicit in-scope IPs already observed by earlier internal stages plus
    literal in-scope IP targets.
    """

    name = "ShadowUDP"

    @staticmethod
    def _dns_query(name: str = ".", qtype: int = 2) -> tuple[int, bytes]:
        request_id = random.randint(1, 65535)
        header = struct.pack("!HHHHHH", request_id, 0x0100, 1, 0, 0, 0)
        labels = b"" if name == "." else b"".join(bytes([len(x)]) + x.encode("ascii", "ignore") for x in name.rstrip(".").split("."))
        question = labels + b"\x00" + struct.pack("!HH", qtype, 1)
        return request_id, header + question

    @staticmethod
    def _mdns_query() -> bytes:
        name = "_services._dns-sd._udp.local"
        labels = b"".join(bytes([len(x)]) + x.encode("ascii") for x in name.split(".")) + b"\x00"
        return struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + labels + struct.pack("!HH", 12, 0x8001)

    @staticmethod
    def _nbns_query() -> tuple[int, bytes]:
        txid = random.randint(1, 65535)
        # RFC 1002 encoded wildcard NetBIOS name (* padded to 16 bytes) for NBSTAT.
        raw = b"*" + (b"\x00" * 15)
        encoded = bytes(0x41 + ((b >> 4) & 0x0F) for b in raw for _ in (0,))
        # Build pairs manually because each input byte becomes two ASCII nibbles.
        encoded = b"".join(bytes((0x41 + (b >> 4), 0x41 + (b & 0x0F))) for b in raw)
        qname = b"\x20" + encoded + b"\x00"
        return txid, struct.pack("!HHHHHH", txid, 0, 1, 0, 0, 0) + qname + struct.pack("!HH", 0x21, 1)

    @staticmethod
    async def _exchange(host: str, port: int, payload: bytes, timeout: float) -> bytes | None:
        loop = asyncio.get_running_loop()
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_sendto(sock, payload, (host, port))
            data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 65535), timeout=timeout)
            return data
        except (OSError, asyncio.TimeoutError, NotImplementedError):
            return None
        finally:
            sock.close()

    @classmethod
    async def _probe_dns(cls, host: str, timeout: float) -> dict[str, Any] | None:
        txid, payload = cls._dns_query()
        data = await cls._exchange(host, 53, payload, timeout)
        if not data or len(data) < 12:
            return None
        rid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        if rid != txid or not (flags & 0x8000):
            return None
        return {"service": "dns", "port": 53, "transaction_id": rid, "rcode": flags & 0x000F, "answers": an, "authority": ns, "additional": ar, "response_bytes": len(data)}

    @classmethod
    async def _probe_ntp(cls, host: str, timeout: float) -> dict[str, Any] | None:
        payload = bytes([0x23]) + (b"\x00" * 47)  # VN4, client mode.
        data = await cls._exchange(host, 123, payload, timeout)
        if not data or len(data) < 48:
            return None
        li_vn_mode = data[0]
        mode = li_vn_mode & 0x07
        version = (li_vn_mode >> 3) & 0x07
        if mode not in {4, 5}:
            return None
        return {"service": "ntp", "port": 123, "version": version, "mode": mode, "stratum": data[1], "response_bytes": len(data)}

    @staticmethod
    def _parse_ssdp_response(data: bytes) -> dict[str, Any] | None:
        if not data or not data.startswith(b"HTTP/1.1 200"):
            return None
        text = data.decode("latin1", "replace")[:8192]
        headers: dict[str, str] = {}
        for line in text.splitlines()[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()[:1000]
        return {"service": "ssdp/upnp", "port": 1900, "server": headers.get("server"), "location": headers.get("location"), "st": headers.get("st"), "usn": headers.get("usn"), "response_bytes": len(data)}

    @staticmethod
    def _parse_mdns_response(data: bytes) -> dict[str, Any] | None:
        if not data or len(data) < 12:
            return None
        _rid, flags, _qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        if not (flags & 0x8000):
            return None
        text = data.decode("latin1", "ignore")
        service_hints = sorted({m.group(0)[:160] for m in re.finditer(r"_[A-Za-z0-9-]+\._(?:tcp|udp)\.local", text, re.I)})[:32]
        return {"service": "mdns/dns-sd", "port": 5353, "answers": an, "authority": ns, "additional": ar, "service_hints": service_hints, "response_bytes": len(data)}

    @classmethod
    async def _multicast_discover(cls, payload: bytes, destination: tuple[str, int], timeout: float, parser) -> list[tuple[str, dict[str, Any]]]:
        """Send one link-local multicast discovery query and collect positive replies.

        Response addresses are still ScopeGuard-filtered by the caller. This is used to
        discover devices that were not already present in ARP/TCP inventory.
        """
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setblocking(False)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            sock.bind(("0.0.0.0", 0))
            await loop.sock_sendto(sock, payload, destination)
            deadline = loop.time() + timeout
            found: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    data, peer = await asyncio.wait_for(loop.sock_recvfrom(sock, 65535), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                except (OSError, NotImplementedError):
                    break
                parsed = parser(data)
                if not parsed:
                    continue
                host = str(peer[0])
                key = (host, str(parsed.get("service") or destination[1]))
                found[key] = (host, parsed)
            return list(found.values())
        except (OSError, NotImplementedError):
            return []
        finally:
            sock.close()

    @classmethod
    async def _probe_ssdp(cls, host: str, timeout: float) -> dict[str, Any] | None:
        payload = ("M-SEARCH * HTTP/1.1\r\n" f"HOST: {host}:1900\r\n" "MAN: \"ssdp:discover\"\r\n" "MX: 1\r\n" "ST: ssdp:all\r\n\r\n").encode("ascii")
        data = await cls._exchange(host, 1900, payload, timeout)
        return cls._parse_ssdp_response(data)

    @classmethod
    async def _probe_mdns(cls, host: str, timeout: float) -> dict[str, Any] | None:
        data = await cls._exchange(host, 5353, cls._mdns_query(), timeout)
        return cls._parse_mdns_response(data)

    @classmethod
    async def _probe_nbns(cls, host: str, timeout: float) -> dict[str, Any] | None:
        txid, payload = cls._nbns_query()
        data = await cls._exchange(host, 137, payload, timeout)
        if not data or len(data) < 12:
            return None
        rid, flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
        if rid != txid or not (flags & 0x8000) or an < 1:
            return None
        return {"service": "netbios-ns", "port": 137, "answers": an, "response_bytes": len(data), "response_fingerprint": data[:64].hex()}


    @staticmethod
    def _passive_dhcp_observations() -> list[dict[str, Any]]:
        observations: list[dict[str, Any]] = []
        if platform.system().lower() != "darwin":
            return observations
        for interface in ShadowLAN.local_interfaces():
            try:
                text = subprocess.check_output(["ipconfig", "getpacket", interface.name], text=True, stderr=subprocess.DEVNULL, timeout=2)
            except (OSError, subprocess.SubprocessError):
                continue
            values: dict[str, str] = {}
            for key in ("yiaddr", "server_identifier", "subnet_mask", "router", "domain_name", "domain_name_server", "lease_time"):
                m = re.search(rf"(?m)^\s*{re.escape(key)}\s*(?:\([^)]*\))?\s*:\s*(.+?)\s*$", text)
                if m:
                    values[key] = m.group(1).strip().strip("{}")[:1000]
            if values:
                observations.append({"interface": interface.name, "address": interface.address, "network": interface.network, **values})
        return observations

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        if not getattr(context.scope.policy, "allow_udp_discovery", True):
            return EngineOutput(assets=[], evidence=[Evidence(engine=self.name, category="udp-discovery-skipped", summary="UDP discovery is disabled by engagement scope", raw={"enabled": False})], findings=[])

        hosts: set[str] = set()
        for target in targets:
            host = context.scope._host(target)
            try:
                ipaddress.ip_address(host)
            except ValueError:
                continue
            if context.scope.allows(host):
                hosts.add(host)
        for asset in context.assets or []:
            host = str((asset.attributes or {}).get("host") or asset.value).split(":", 1)[0].strip("[]")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                continue
            if context.scope.allows(host):
                hosts.add(host)

        max_hosts = max(1, int(getattr(context.scope.policy, "max_udp_hosts", 256)))
        selected = sorted(hosts, key=lambda value: ipaddress.ip_address(value))[:max_hosts]
        assets: list[Asset] = []
        evidence: list[Evidence] = []

        # Promote passive neighbour evidence even when the neighbour does not answer probes.
        for ip, mac in ShadowLAN.arp_neighbors().items():
            if not context.scope.allows(ip):
                continue
            asset = Asset(kind="arp-neighbor", value=ip, source=self.name, attributes={"host": ip, "mac": mac, "state": "passive-cache-observation"})
            assets.append(asset)
            evidence.append(Evidence(asset_id=asset.id, engine=self.name, category="arp-neighbor", summary=f"Passive ARP/neighbor cache observation for {ip}", raw={"host": ip, "mac": mac, "active_probe": False}))

        for lease in self._passive_dhcp_observations():
            address = str(lease.get("address") or lease.get("yiaddr") or "")
            if address and context.scope.allows(address):
                evidence.append(Evidence(engine=self.name, category="dhcp-lease-observation", summary=f"Passive DHCP lease/configuration observation on {lease.get('interface')}", raw={**lease, "active_probe": False}))

        sem = asyncio.Semaphore(min(64, max(1, context.scope.policy.max_concurrency)))

        async def inspect(host: str) -> list[dict[str, Any]]:
            async with sem:
                timeout = min(max(context.timeout, 0.25), 1.5)
                checks = [self._probe_dns(host, timeout), self._probe_ntp(host, timeout), self._probe_nbns(host, timeout), self._probe_ssdp(host, timeout), self._probe_mdns(host, timeout)]
                results = await asyncio.gather(*checks)
                observations = [item for item in results if item]
                communities = list(getattr(context.scope.policy, "snmp_communities", []) or [])
                for community in communities[:4]:
                    snmp = ShadowSNMP(host=host, community=community, timeout=min(timeout, 0.8))
                    descr = await asyncio.to_thread(snmp.get, "1.3.6.1.2.1.1.1.0")
                    if descr not in (None, ""):
                        inventory = await asyncio.to_thread(snmp.inventory)
                        observations.append({"service": "snmp", "port": 161, "sys_descr": descr, "inventory": inventory, "community_source": "engagement-supplied"})
                        break
                return observations

        # Link-local multicast discovery can reveal in-scope devices that were not already
        # present in ARP/TCP inventory. Replies outside the engagement scope are discarded.
        multicast_timeout = min(max(context.timeout, 0.35), 1.25)
        ssdp_payload = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n").encode("ascii")
        multicast = await asyncio.gather(
            self._multicast_discover(ssdp_payload, ("239.255.255.250", 1900), multicast_timeout, self._parse_ssdp_response),
            self._multicast_discover(self._mdns_query(), ("224.0.0.251", 5353), multicast_timeout, self._parse_mdns_response),
        )
        multicast_confirmed = 0
        for group in multicast:
            for host, obs in group:
                if not context.scope.allows(host):
                    continue
                port = int(obs["port"])
                asset = Asset(kind="network-service", value=f"{host}:{port}/udp", source=self.name, attributes={"host": host, "port": port, "transport": "udp", "state": "positive-multicast-response", "discovery": "link-local-multicast", **obs})
                assets.append(asset)
                evidence.append(Evidence(asset_id=asset.id, engine=self.name, category="udp-multicast-service", summary=f"In-scope multicast discovery response from {host}:{port} ({obs['service']})", raw={"host": host, "transport": "udp", "positive_response": True, "discovery": "link-local-multicast", **obs}))
                multicast_confirmed += 1

        for host, observations in zip(selected, await asyncio.gather(*(inspect(host) for host in selected)) if selected else []):
            for obs in observations:
                port = int(obs["port"])
                value = f"{host}:{port}/udp"
                asset = Asset(kind="network-service", value=value, source=self.name, attributes={"host": host, "port": port, "transport": "udp", "state": "positive-response", **obs})
                assets.append(asset)
                evidence.append(Evidence(asset_id=asset.id, engine=self.name, category="udp-service", summary=f"Protocol-valid UDP response from {host}:{port} ({obs['service']})", raw={"host": host, "transport": "udp", "positive_response": True, **obs}))

        evidence.append(Evidence(engine=self.name, category="udp-discovery-summary", summary=f"UDP protocol discovery checked {len(selected)} authorised host(s) and confirmed {len(assets)} service response(s)", raw={"hosts_considered": len(hosts), "hosts_checked": len(selected), "services_confirmed": sum(1 for a in assets if a.kind == "network-service"), "passive_neighbor_assets": sum(1 for a in assets if a.kind == "arp-neighbor"), "multicast_services_confirmed": multicast_confirmed, "silent_udp_ports_are_not_reported_open": True, "protocols": ["dns", "ntp", "netbios-ns", "ssdp/upnp", "mdns/dns-sd", "snmp-if-engagement-supplied"]}))
        return EngineOutput(assets=assets, evidence=evidence, findings=[])
