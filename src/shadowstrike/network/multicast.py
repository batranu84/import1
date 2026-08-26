from __future__ import annotations

import asyncio
import re
import socket
import struct
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

import httpx


def _mdns_query() -> bytes:
    name = "_services._dns-sd._udp.local"
    labels = b"".join(bytes([len(x)]) + x.encode("ascii") for x in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + labels + struct.pack("!HH", 12, 0x8001)


def _parse_ssdp(data: bytes) -> dict[str, Any] | None:
    if not data.startswith(b"HTTP/1.1 200"):
        return None
    text = data.decode("latin1", "replace")[:8192]
    headers: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()[:1000]
    combined = " ".join(headers.get(k, "") for k in ("server", "st", "usn", "location")).lower()
    roles: list[str] = []
    if any(x in combined for x in ("printer", "ipp", "print")):
        roles.append("printer")
    if any(x in combined for x in ("camera", "onvif", "hikvision", "dahua", "axis")):
        roles.append("camera")
    if any(x in combined for x in ("internetgatewaydevice", "wanipconnection", "router")):
        roles.append("gateway/router")
    if any(x in combined for x in ("mediarenderer", "roku", "chromecast", "airplay", "dlna")):
        roles.append("media-device")
    return {"protocol": "ssdp/upnp", "headers": headers, "roles": roles}


def _parse_mdns(data: bytes) -> dict[str, Any] | None:
    if len(data) < 12:
        return None
    _rid, flags, _qd, _an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if not (flags & 0x8000):
        return None
    text = data.decode("latin1", "ignore")
    services = sorted({m.group(0).lower() for m in re.finditer(r"_[A-Za-z0-9-]+\._(?:tcp|udp)\.local", text, re.I)})
    roles: list[str] = []
    joined = " ".join(services)
    if any(x in joined for x in ("_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp")):
        roles.append("printer")
    if any(x in joined for x in ("_rtsp._tcp", "_onvif._tcp")):
        roles.append("camera/streaming-device")
    if any(x in joined for x in ("_airplay._tcp", "_raop._tcp", "_googlecast._tcp")):
        roles.append("media-device")
    if "_workstation._tcp" in joined:
        roles.append("workstation")
    if "_ssh._tcp" in joined:
        roles.append("ssh-host")
    return {"protocol": "mdns/dns-sd", "services": services[:64], "roles": roles}


def _service_role(service_type: str) -> tuple[str | None, list[str]]:
    low = service_type.lower().rstrip(".")
    mapping: tuple[tuple[tuple[str, ...], str, str], ...] = (
        (("_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp"), "ipp", "printer"),
        (("_ssh._tcp",), "ssh", "ssh-host"),
        (("_sftp-ssh._tcp",), "sftp", "ssh-host"),
        (("_http._tcp", "_http-alt._tcp"), "http", "web-service"),
        (("_https._tcp",), "https", "web-service"),
        (("_smb._tcp",), "smb", "file-server"),
        (("_afpovertcp._tcp",), "afp", "file-server"),
        (("_rtsp._tcp", "_onvif._tcp"), "rtsp", "camera/streaming-device"),
        (("_airplay._tcp", "_raop._tcp", "_googlecast._tcp"), "media", "media-device"),
        (("_workstation._tcp",), "workstation", "workstation"),
        (("_device-info._tcp",), "device-info", "host"),
    )
    for needles, service, role in mapping:
        if any(n in low for n in needles):
            return service, [role]
    # Preserve the advertised service name even for an unknown type. This is protocol
    # evidence, but not a claim that the endpoint is reachable until a transport check passes.
    m = re.match(r"_([a-z0-9-]+)\._(tcp|udp)", low)
    return (m.group(1) if m else None), []


def _decode_txt(properties: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(properties, dict):
        return out
    for key, value in properties.items():
        if isinstance(key, bytes):
            key = key.decode("utf-8", "replace")
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        out[str(key)[:200]] = str(value)[:1000]
    return out


def _discover_zeroconf_sync(timeout: float = 1.4, max_types: int = 64, max_instances: int = 192) -> list[tuple[str, dict[str, Any]]]:
    """Resolve DNS-SD service instances using python-zeroconf when available.

    This complements the lightweight multicast parser by resolving the exact advertised
    service port, hostname and TXT metadata. It does not manufacture hosts and does not
    treat an advertisement as proof that the TCP/UDP endpoint is reachable.
    """
    try:
        from zeroconf import IPVersion, ServiceBrowser, ServiceStateChange, Zeroconf, ZeroconfServiceTypes  # type: ignore
    except Exception:
        return []

    zc = None
    browser = None
    try:
        zc = Zeroconf(ip_version=IPVersion.V4Only)
        service_types = tuple(ZeroconfServiceTypes.find(zc=zc, timeout=max(0.35, timeout * 0.45)))[:max_types]
        if not service_types:
            return []
        instances: set[tuple[str, str]] = set()

        def on_state_change(_zc, service_type: str, name: str, state_change) -> None:
            if state_change is ServiceStateChange.Added and len(instances) < max_instances:
                instances.add((service_type, name))

        browser = ServiceBrowser(zc, list(service_types), handlers=[on_state_change])
        time.sleep(max(0.35, timeout * 0.55))
        try:
            browser.cancel()
        except Exception:
            pass

        out: list[tuple[str, dict[str, Any]]] = []
        for service_type, name in list(instances)[:max_instances]:
            try:
                info = zc.get_service_info(service_type, name, timeout=650)
            except Exception:
                info = None
            if info is None:
                continue
            addresses: list[str] = []
            try:
                addresses = list(info.parsed_scoped_addresses())
            except Exception:
                try:
                    addresses = list(info.parsed_addresses())
                except Exception:
                    addresses = []
            service_name, roles = _service_role(service_type)
            observation = {
                "protocol": "mdns/dns-sd-resolved",
                "service_type": service_type,
                "instance": name,
                "service_name": service_name,
                "port": int(getattr(info, "port", 0) or 0),
                "server": str(getattr(info, "server", "") or "").rstrip("."),
                "properties": _decode_txt(getattr(info, "properties", {})),
                "roles": roles,
                "reachability": "advertised-not-yet-verified",
            }
            for address in addresses:
                try:
                    parsed = socket.getaddrinfo(address.split("%", 1)[0], None, socket.AF_INET)
                    ipv4 = parsed[0][4][0] if parsed else address
                except Exception:
                    ipv4 = address.split("%", 1)[0]
                if ipv4 and ":" not in ipv4:
                    out.append((ipv4, observation))
        return out
    except Exception:
        return []
    finally:
        if browser is not None:
            try:
                browser.cancel()
            except Exception:
                pass
        if zc is not None:
            try:
                zc.close()
            except Exception:
                pass


def _local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


async def enrich_upnp_description(host: str, inventory: dict[str, Any], timeout: float = 1.2) -> dict[str, Any] | None:
    """Fetch an SSDP-advertised UPnP device description from the same source host.

    The caller has already ScopeGuard-filtered ``host``. To preserve that guarantee, only a
    LOCATION URL whose hostname is exactly the responding IP is fetched; redirects are off.
    """
    locations: list[str] = []
    for observation in inventory.get("observations") or []:
        if not isinstance(observation, dict) or observation.get("protocol") != "ssdp/upnp":
            continue
        headers = observation.get("headers") or {}
        if isinstance(headers, dict) and headers.get("location"):
            locations.append(str(headers.get("location")))
    for location in locations[:4]:
        try:
            parsed = urlparse(location)
            if parsed.scheme not in {"http", "https"} or (parsed.hostname or "").strip("[]") != host:
                continue
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=False) as client:
                response = await client.get(location, headers={"User-Agent": "ShadowStrike-UPnP-Inventory/1"})
                if response.status_code >= 400 or len(response.content) > 2_000_000:
                    continue
            root = ET.fromstring(response.content)
        except Exception:
            continue
        values: dict[str, str] = {}
        wanted = {
            "friendlyName", "manufacturer", "manufacturerURL", "modelDescription",
            "modelName", "modelNumber", "modelURL", "serialNumber", "UDN", "deviceType",
            "presentationURL",
        }
        for node in root.iter():
            name = _local_tag(str(node.tag))
            if name in wanted and node.text and node.text.strip():
                values.setdefault(name, node.text.strip()[:1000])
        device_type = values.get("deviceType", "").lower()
        text = " ".join(values.values()).lower()
        roles: list[str] = []
        if "internetgatewaydevice" in device_type or "router" in text or "gateway" in text:
            roles.append("gateway/router")
        if "printer" in text:
            roles.append("printer")
        if any(x in text for x in ("camera", "onvif", "network video")):
            roles.append("camera")
        if any(x in text for x in ("mediarenderer", "mediaserver", "airplay", "chromecast", "roku")):
            roles.append("media-device")
        return {"location": location, "fields": values, "roles": sorted(set(roles)), "identity_basis": "upnp-device-description"}
    return None


async def _collect(payload: bytes, destination: tuple[str, int], timeout: float, parser) -> list[tuple[str, dict[str, Any]]]:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setblocking(False)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.bind(("0.0.0.0", 0))
        await loop.sock_sendto(sock, payload, destination)
        deadline = loop.time() + timeout
        out: list[tuple[str, dict[str, Any]]] = []
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                data, peer = await asyncio.wait_for(loop.sock_recvfrom(sock, 65535), remaining)
            except (OSError, asyncio.TimeoutError):
                break
            parsed = parser(data)
            if parsed:
                out.append((str(peer[0]), parsed))
        return out
    except OSError:
        return []
    finally:
        sock.close()


async def discover_link_local(timeout: float = 1.15) -> dict[str, dict[str, Any]]:
    """Collect positive SSDP/mDNS responses and resolved DNS-SD services.

    Only source/resolved IPs from protocol-valid responses are returned. Scope filtering is
    performed by the caller against the authorised CIDR.
    """
    ssdp = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")
    native_ssdp, native_mdns, resolved = await asyncio.gather(
        _collect(ssdp, ("239.255.255.250", 1900), timeout, _parse_ssdp),
        _collect(_mdns_query(), ("224.0.0.251", 5353), timeout, _parse_mdns),
        asyncio.to_thread(_discover_zeroconf_sync, max(0.8, timeout * 1.4)),
    )
    merged: dict[str, dict[str, Any]] = defaultdict(lambda: {"protocols": [], "roles": [], "observations": [], "advertised_services": []})
    for group in (native_ssdp, native_mdns, resolved):
        for host, observation in group:
            row = merged[host]
            row["protocols"].append(observation.get("protocol"))
            row["roles"].extend(observation.get("roles") or [])
            row["observations"].append(observation)
            if observation.get("protocol") == "mdns/dns-sd-resolved" and observation.get("port"):
                row["advertised_services"].append({
                    "port": int(observation["port"]),
                    "transport": "tcp" if "._tcp" in str(observation.get("service_type", "")).lower() else "udp",
                    "name": observation.get("service_name") or "unknown",
                    "service_type": observation.get("service_type"),
                    "instance": observation.get("instance"),
                    "server": observation.get("server"),
                    "properties": observation.get("properties") or {},
                    "identity_basis": "mdns-dns-sd-advertisement",
                    "service_state": "advertised",
                })
    for row in merged.values():
        row["protocols"] = sorted({x for x in row["protocols"] if x})
        row["roles"] = sorted({x for x in row["roles"] if x})
        seen: set[tuple[int, str, str]] = set()
        dedup: list[dict[str, Any]] = []
        for service in row["advertised_services"]:
            key = (int(service.get("port") or 0), str(service.get("transport") or ""), str(service.get("name") or ""))
            if key not in seen:
                seen.add(key)
                dedup.append(service)
        row["advertised_services"] = dedup
    return dict(merged)
