from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from shadowstrike.network.device import ShadowDevice


@dataclass(frozen=True)
class ToolProbe:
    name: str
    path: str | None
    available: bool
    privileged: bool
    purpose: str


class MacVendorResolver:
    """Resolve MAC vendors from installed authoritative/local databases.

    Lookup order is intentionally offline: Nmap/arp-scan databases first, then the
    optional mac-vendor-lookup package. A locally administered MAC is never assigned a
    hardware manufacturer because the OUI bits are not globally meaningful.
    """

    NMAP_FILES = (
        "/opt/homebrew/share/nmap/nmap-mac-prefixes",
        "/usr/local/share/nmap/nmap-mac-prefixes",
        "/usr/share/nmap/nmap-mac-prefixes",
    )
    ARP_SCAN_FILES = (
        "/opt/homebrew/share/arp-scan/ieee-oui.txt",
        "/usr/local/share/arp-scan/ieee-oui.txt",
        "/usr/share/arp-scan/ieee-oui.txt",
        "/usr/share/arp-scan/mac-vendor.txt",
        "/etc/arp-scan/mac-vendor.txt",
        "/usr/local/etc/arp-scan/mac-vendor.txt",
    )
    _prefixes: dict[str, str] | None = None

    @classmethod
    def _normalise(cls, mac: str | None) -> str:
        return "".join(ch for ch in str(mac or "").upper() if ch in "0123456789ABCDEF")

    @classmethod
    def _load_local_files(cls) -> dict[str, str]:
        if cls._prefixes is not None:
            return cls._prefixes
        prefixes: dict[str, str] = {}
        for raw_path in cls.NMAP_FILES + cls.ARP_SCAN_FILES:
            path = Path(raw_path)
            if not path.is_file():
                continue
            try:
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    text = line.strip()
                    if not text or text.startswith("#"):
                        continue
                    # Nmap: 00000C Cisco Systems
                    m = re.match(r"^([0-9A-Fa-f]{6,9})\s+(.+?)\s*$", text)
                    if m:
                        prefixes.setdefault(m.group(1).upper(), m.group(2).strip())
                        continue
                    # arp-scan: 00:00:0c<TAB>Cisco or 00000C<TAB>Cisco
                    parts = re.split(r"\s+", text, maxsplit=1)
                    if len(parts) == 2:
                        key = cls._normalise(parts[0])
                        if 6 <= len(key) <= 9:
                            prefixes.setdefault(key, parts[1].strip())
            except OSError:
                continue
        cls._prefixes = prefixes
        return prefixes

    @classmethod
    def lookup(cls, mac: str | None) -> str | None:
        value = cls._normalise(mac)
        if len(value) < 6:
            return None
        try:
            first = int(value[:2], 16)
        except ValueError:
            return None
        if first & 0x02:
            return "Locally administered/randomized"

        prefixes = cls._load_local_files()
        for length in (9, 7, 6):
            if value[:length] in prefixes:
                return prefixes[value[:length]]

        # Optional dependency ships a local IEEE OUI list. Never force a network update.
        try:
            from mac_vendor_lookup import MacLookup  # type: ignore

            return str(MacLookup().lookup(mac)).strip() or None
        except Exception:
            return None


class ArpScanAdapter:
    """Optional layer-2 discovery adapter for directly connected authorised IPv4 LANs."""

    @staticmethod
    def status() -> ToolProbe:
        path = shutil.which("arp-scan")
        return ToolProbe(
            name="arp-scan",
            path=path,
            available=bool(path),
            privileged=(os.geteuid() == 0 if hasattr(os, "geteuid") else False),
            purpose="layer-2 host discovery and MAC/OUI fingerprinting",
        )

    @staticmethod
    def parse(text: str) -> dict[str, dict[str, str]]:
        found: dict[str, dict[str, str]] = {}
        for line in text.splitlines():
            m = re.match(
                r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?:\s+(.+?))?\s*$",
                line,
            )
            if not m:
                continue
            ip, mac, vendor = m.groups()
            found[ip] = {
                "mac": mac.lower(),
                "vendor": (vendor or "").strip() or MacVendorResolver.lookup(mac) or "",
            }
        return found

    @classmethod
    async def discover(cls, cidr: str, interface: str | None = None, timeout: float = 12.0) -> dict[str, dict[str, str]]:
        status = cls.status()
        if not status.available or not status.path:
            return {}
        cmd = [status.path, "--numeric", "--retry=2", "--timeout=250"]
        if interface:
            cmd += ["--interface", interface]
        cmd += [cidr]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except (OSError, asyncio.TimeoutError):
            return {}
        return cls.parse(stdout.decode("utf-8", "replace"))


@dataclass
class NmapFingerprint:
    host: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    os_matches: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    device_types: list[str] = field(default_factory=list)

    @property
    def best_os(self) -> dict[str, Any] | None:
        return self.os_matches[0] if self.os_matches else None


class NmapFingerprintAdapter:
    """Use Nmap's maintained service and TCP/IP fingerprint databases when available.

    OS detection is enabled only when the sensor/controller process has the privileges Nmap
    requires for raw-packet fingerprinting. Unprivileged runs still perform service/version
    fingerprinting and can yield OS/device hints from application responses.
    """

    NMAP_SERVICE_FILES = (
        "/opt/homebrew/share/nmap/nmap-services",
        "/usr/local/share/nmap/nmap-services",
        "/usr/share/nmap/nmap-services",
    )

    @classmethod
    def top_tcp_ports(cls, limit: int = 256) -> list[int]:
        """Return Nmap's highest-frequency TCP ports when its service DB is installed."""
        for raw_path in cls.NMAP_SERVICE_FILES:
            path = Path(raw_path)
            if not path.is_file():
                continue
            weighted: dict[int, float] = {}
            try:
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    text = line.strip()
                    if not text or text.startswith("#"):
                        continue
                    parts = text.split()
                    if len(parts) < 2 or "/tcp" not in parts[1]:
                        continue
                    try:
                        port = int(parts[1].split("/", 1)[0])
                        frequency = float(parts[2]) if len(parts) >= 3 else 0.0
                    except (TypeError, ValueError):
                        continue
                    weighted[port] = max(weighted.get(port, 0.0), frequency)
            except OSError:
                continue
            if weighted:
                return [port for port, _freq in sorted(weighted.items(), key=lambda item: (-item[1], item[0]))[:max(1, limit)]]
        return []

    @staticmethod
    def status() -> ToolProbe:
        path = shutil.which("nmap")
        privileged = os.geteuid() == 0 if hasattr(os, "geteuid") else False
        return ToolProbe(
            name="nmap",
            path=path,
            available=bool(path),
            privileged=privileged,
            purpose="service/version and remote TCP/IP OS/device fingerprinting",
        )

    @staticmethod
    def _int(value: str | None, default: int = 0) -> int:
        try:
            return int(value or default)
        except (TypeError, ValueError):
            return default

    @classmethod
    def parse_xml(cls, xml_text: str) -> dict[str, NmapFingerprint]:
        out: dict[str, NmapFingerprint] = {}
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return out
        for host_node in root.findall("host"):
            status = host_node.find("status")
            if status is not None and status.get("state") != "up":
                continue
            addresses = [(a.get("addr"), a.get("addrtype"), a.get("vendor")) for a in host_node.findall("address")]
            ip = next((addr for addr, kind, _ in addresses if addr and kind in {"ipv4", "ipv6"}), None)
            if not ip:
                continue
            mac_row = next(((addr, vendor) for addr, kind, vendor in addresses if kind == "mac" and addr), (None, None))
            hostname = next((h.get("name") for h in host_node.findall("hostnames/hostname") if h.get("name")), None)
            fp = NmapFingerprint(host=ip, mac=mac_row[0], vendor=mac_row[1], hostname=hostname)

            for osmatch in host_node.findall("os/osmatch"):
                accuracy = cls._int(osmatch.get("accuracy"))
                classes = []
                for osclass in osmatch.findall("osclass"):
                    row = {
                        "type": osclass.get("type"),
                        "vendor": osclass.get("vendor"),
                        "osfamily": osclass.get("osfamily"),
                        "osgen": osclass.get("osgen"),
                        "accuracy": cls._int(osclass.get("accuracy")),
                        "cpe": [c.text for c in osclass.findall("cpe") if c.text],
                    }
                    classes.append(row)
                    if row["type"]:
                        fp.device_types.append(str(row["type"]))
                fp.os_matches.append(
                    {
                        "name": osmatch.get("name"),
                        "accuracy": accuracy,
                        "classes": classes,
                    }
                )
            fp.os_matches.sort(key=lambda x: int(x.get("accuracy") or 0), reverse=True)

            for port_node in host_node.findall("ports/port"):
                state = port_node.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port_node.find("service")
                if service is None:
                    continue
                conf = cls._int(service.get("conf"))
                row = {
                    "port": cls._int(port_node.get("portid")),
                    "transport": port_node.get("protocol") or "tcp",
                    "name": service.get("name") or "unknown",
                    "product": service.get("product"),
                    "version": service.get("version"),
                    "extrainfo": service.get("extrainfo"),
                    "ostype": service.get("ostype"),
                    "devicetype": service.get("devicetype"),
                    "hostname": service.get("hostname"),
                    "tunnel": service.get("tunnel"),
                    "confidence": conf,
                    "cpe": [c.text for c in service.findall("cpe") if c.text],
                }
                fp.services.append(row)
                if row.get("devicetype"):
                    fp.device_types.append(str(row["devicetype"]))
            fp.device_types = sorted({x for x in fp.device_types if x})
            out[ip] = fp
        return out

    @classmethod
    async def fingerprint(
        cls,
        devices: Iterable[ShadowDevice],
        *,
        timeout: float = 60.0,
        deep: bool = True,
    ) -> tuple[dict[str, NmapFingerprint], dict[str, Any]]:
        status = cls.status()
        device_list = [d for d in devices]
        hosts = [d.ip for d in device_list]
        if not status.available or not status.path or not hosts:
            return {}, {
                "available": status.available,
                "path": status.path,
                "privileged": status.privileged,
                "os_detection": False,
                "reason": "nmap-not-installed" if not status.available else "no-hosts",
            }

        # Reuse ports already observed by ShadowLAN and add a compact service-fingerprint
        # baseline. This avoids rescanning 65k ports per endpoint just to identify the OS.
        preferred = {
            22, 53, 80, 135, 139, 389, 443, 445, 515, 548, 554, 631, 636, 1433,
            1883, 2049, 2375, 2376, 3306, 3389, 5000, 5432, 5900, 5985, 5986,
            6379, 8000, 8006, 8080, 8443, 8883, 9000, 9100, 9200, 9443, 11211, 27017,
        }
        observed = sorted({int(p) for d in device_list for p in d.open_ports})
        ports = sorted(preferred | set(observed[:256]))[:320]
        cmd = [
            status.path,
            "-Pn",
            "-sT",
            "-sV",
            "--version-intensity",
            "7" if deep else "4",
            "--reason",
            "--max-retries",
            "1",
            "--host-timeout",
            "45s",
            "-T4",
            "-oX",
            "-",
        ]
        if status.privileged and deep:
            cmd += ["-O", "--osscan-limit", "--osscan-guess", "--max-os-tries", "1"]
        if ports:
            cmd += ["-p", ",".join(str(x) for x in ports)]
        cmd += ["--", *hosts]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=max(timeout, 60.0))
        except (OSError, asyncio.TimeoutError) as exc:
            return {}, {
                "available": True,
                "path": status.path,
                "privileged": status.privileged,
                "os_detection": bool(status.privileged and deep),
                "error": f"{type(exc).__name__}: {exc}",
            }
        parsed = cls.parse_xml(stdout.decode("utf-8", "replace"))
        return parsed, {
            "available": True,
            "path": status.path,
            "privileged": status.privileged,
            "os_detection": bool(status.privileged and deep),
            "hosts_requested": len(hosts),
            "hosts_fingerprinted": len(parsed),
            "returncode": proc.returncode,
            "stderr_excerpt": stderr.decode("utf-8", "replace")[:1200],
            "ports_considered": len(ports),
        }

    @staticmethod
    def apply(device: ShadowDevice, fp: NmapFingerprint) -> ShadowDevice:
        if fp.mac and not device.mac:
            device.mac = fp.mac.lower()
        device.vendor = device.vendor or fp.vendor or MacVendorResolver.lookup(device.mac)
        device.hostname = device.hostname or fp.hostname

        if fp.os_matches:
            best = fp.os_matches[0]
            accuracy = int(best.get("accuracy") or 0)
            name = str(best.get("name") or "").strip()
            if name:
                device.os_hint = f"{name} ({accuracy}% Nmap match)" if accuracy else name
            device.metadata["os_fingerprint"] = {
                "source": "nmap-tcpip",
                "best_match": best,
                "matches": fp.os_matches[:5],
                "state": "confirmed-fingerprint" if accuracy >= 90 else "probable-fingerprint",
            }
            if "nmap-os-fingerprint" not in device.evidence_types:
                device.evidence_types.append("nmap-os-fingerprint")

        # Nmap service/version fingerprints can independently expose the OS family/device
        # class even when raw -O fingerprinting is unavailable to an unprivileged sensor.
        confirmed_ostypes = [
            str(s.get("ostype")).strip() for s in fp.services
            if int(s.get("confidence") or 0) >= 8 and s.get("ostype")
        ]
        if not device.os_hint and confirmed_ostypes:
            counts: dict[str, int] = {}
            for value in confirmed_ostypes:
                counts[value] = counts.get(value, 0) + 1
            best_service_os = sorted(counts, key=lambda value: (-counts[value], value.lower()))[0]
            device.os_hint = f"{best_service_os} (Nmap service fingerprint)"
            device.metadata["os_service_fingerprint"] = {
                "source": "nmap-service-version",
                "os_family": best_service_os,
                "supporting_services": counts[best_service_os],
                "state": "service-derived",
            }
            if "nmap-service-os-hint" not in device.evidence_types:
                device.evidence_types.append("nmap-service-os-hint")

        by_port = {int(s.get("port")): dict(s) for s in device.services if s.get("port") is not None}
        for service in fp.services:
            port = int(service.get("port") or 0)
            if not port:
                continue
            row = by_port.setdefault(port, {"port": port, "transport": service.get("transport") or "tcp"})
            conf = int(service.get("confidence") or 0)
            name = str(service.get("name") or "unknown")
            row["nmap"] = service
            if conf >= 8 and name not in {"", "unknown", "tcpwrapped"}:
                row.update(
                    {
                        "name": name,
                        "service_candidate": name,
                        "service_state": "confirmed",
                        "identity_basis": "nmap-version-detection",
                        "product": service.get("product"),
                        "version": service.get("version"),
                        "cpe": service.get("cpe") or [],
                        "ostype": service.get("ostype"),
                        "devicetype": service.get("devicetype"),
                    }
                )
                if f"service:{name}" not in device.evidence_types:
                    device.evidence_types.append(f"service:{name}")
            elif conf >= 5 and name not in {"", "unknown"}:
                row.setdefault("service_candidate", name)
                row["nmap_candidate_confidence"] = conf
        device.services = [by_port[p] for p in sorted(by_port)]

        if fp.device_types:
            device.metadata["nmap_device_types"] = fp.device_types
            # Nmap's device class is an independent fingerprint source. Preserve the raw
            # type and let ShadowDevice.normalize combine it with other direct evidence.
            device.metadata["nmap_role"] = fp.device_types[0]
        device.metadata["fingerprint_sources"] = sorted(
            set(device.metadata.get("fingerprint_sources", [])) | {"nmap"}
        )
        return device.normalize()


def specialist_tool_status() -> list[dict[str, Any]]:
    return [vars(NmapFingerprintAdapter.status()), vars(ArpScanAdapter.status())]
