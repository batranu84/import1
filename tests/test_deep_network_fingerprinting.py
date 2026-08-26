import asyncio

import pytest

from shadowstrike.network.device import ShadowDevice
from shadowstrike.network.fingerprint import NmapFingerprintAdapter
from shadowstrike.network.lan import NetworkInterface, ShadowLAN
from shadowstrike.network.multicast import _service_role
from shadowstrike.network.snmp import ShadowSNMP
from shadowstrike.services.tool_bridge import SpecialistToolBridgeEngine


def test_dns_sd_service_role_maps_advertised_identity() -> None:
    assert _service_role("_ipp._tcp.local.") == ("ipp", ["printer"])
    assert _service_role("_ssh._tcp.local.") == ("ssh", ["ssh-host"])
    assert _service_role("_customsvc._tcp.local.")[0] == "customsvc"


def test_nmap_service_fingerprint_can_supply_os_hint_without_raw_os() -> None:
    xml = """<?xml version='1.0'?><nmaprun><host><status state='up'/><address addr='10.0.0.5' addrtype='ipv4'/><ports>
    <port protocol='tcp' portid='22'><state state='open'/><service name='ssh' product='OpenSSH' version='9.7' ostype='Linux' conf='10'><cpe>cpe:/a:openbsd:openssh:9.7</cpe></service></port>
    </ports></host></nmaprun>"""
    fp = NmapFingerprintAdapter.parse_xml(xml)["10.0.0.5"]
    device = ShadowDevice(ip="10.0.0.5", open_ports=[22]).normalize()
    NmapFingerprintAdapter.apply(device, fp)
    assert device.os_hint == "Linux (Nmap service fingerprint)"
    assert "nmap-service-os-hint" in device.evidence_types
    assert device.services[0]["service_state"] == "confirmed"


def test_specialist_bridge_preserves_nmap_os_and_device_type() -> None:
    xml = """<?xml version='1.0'?><nmaprun><host><status state='up'/>
    <address addr='10.0.0.1' addrtype='ipv4'/><address addr='00:11:22:33:44:55' addrtype='mac' vendor='Cisco'/>
    <os><osmatch name='Cisco IOS 15.X' accuracy='97'><osclass type='router' vendor='Cisco' osfamily='IOS' osgen='15' accuracy='97'><cpe>cpe:/o:cisco:ios:15</cpe></osclass></osmatch></os>
    </host></nmaprun>"""
    assets, evidence = SpecialistToolBridgeEngine._parse_nmap_xml(xml)
    host = next(a for a in assets if a.kind == "network-device")
    os_asset = next(a for a in assets if a.kind == "operating-system")
    assert host.attributes["vendor"] == "Cisco"
    assert "router" in host.attributes["device_types"]
    assert os_asset.attributes["accuracy"] == 97
    assert any(e.category == "os-fingerprint" for e in evidence)


@pytest.mark.asyncio
async def test_lan_uses_mdns_advertised_high_port_without_exhaustive_scan(monkeypatch) -> None:
    lan = ShadowLAN("10.0.0.0/30")
    monkeypatch.setattr(ShadowLAN, "default_gateway", staticmethod(lambda: None))
    monkeypatch.setattr(ShadowLAN, "arp_neighbors", staticmethod(lambda: {}))
    monkeypatch.setattr(ShadowLAN, "local_interfaces", staticmethod(lambda: [NetworkInterface(name="en0", address="10.0.0.1", prefix=30, network="10.0.0.0/30")]))

    async def multicast(timeout=1.15):
        return {
            "10.0.0.2": {
                "protocols": ["mdns/dns-sd-resolved"],
                "roles": ["workstation"],
                "observations": [],
                "advertised_services": [
                    {"port": 50000, "transport": "tcp", "name": "ssh", "service_type": "_ssh._tcp.local.", "server": "host.local", "properties": {}, "service_state": "advertised"}
                ],
            }
        }

    async def no_upnp(host, data, timeout=1.2):
        return None

    async def initial_probe(ip, ports, timeout, semaphore):
        return [], {}

    planned = {}

    async def followup(ip, ports, timeout, semaphore, chunk_size=512):
        values = list(ports)
        planned[ip] = values
        return ([50000], {50000: 1.0}) if ip == "10.0.0.2" else ([], {})

    async def verify(ip, port, timeout=0.7):
        return {"port": port, "transport": "tcp", "name": "unknown", "service_candidate": f"tcp/{port}", "port_state": "confirmed-open", "service_state": "unconfirmed", "identity_basis": "conventional-port-candidate"}

    async def no_fingerprint(devices, timeout=60.0, deep=True):
        return {}, {"available": False, "reason": "test"}

    monkeypatch.setattr("shadowstrike.network.lan.discover_link_local", multicast)
    monkeypatch.setattr("shadowstrike.network.lan.enrich_upnp_description", no_upnp)
    monkeypatch.setattr(ShadowLAN, "_probe", staticmethod(initial_probe))
    monkeypatch.setattr(ShadowLAN, "_probe_chunked", classmethod(lambda cls, ip, ports, timeout, semaphore, chunk_size=512: followup(ip, ports, timeout, semaphore, chunk_size)))
    monkeypatch.setattr(ShadowLAN, "_verify_service", staticmethod(verify))
    monkeypatch.setattr("shadowstrike.network.lan.NmapFingerprintAdapter.fingerprint", no_fingerprint)

    devices = await lan.discover(port_profile="adaptive")
    device = next(d for d in devices if d.ip == "10.0.0.2")
    assert 50000 in planned["10.0.0.2"]
    service = next(s for s in device.services if s.get("port") == 50000)
    assert service["name"] == "ssh"
    assert service["service_state"] == "confirmed"
    assert service["identity_basis"] == "mdns-dns-sd-advertisement+tcp-connect"


@pytest.mark.asyncio
async def test_lan_followup_scans_hosts_concurrently(monkeypatch) -> None:
    lan = ShadowLAN("10.0.0.0/29")
    monkeypatch.setattr(ShadowLAN, "default_gateway", staticmethod(lambda: None))
    monkeypatch.setattr(ShadowLAN, "arp_neighbors", staticmethod(lambda: {f"10.0.0.{i}": f"00:11:22:33:44:{i:02x}" for i in range(1, 5)}))
    monkeypatch.setattr("shadowstrike.network.lan.discover_link_local", lambda timeout=1.15: asyncio.sleep(0, result={}))

    async def initial_probe(ip, ports, timeout, semaphore):
        return [], {}

    active = 0
    maximum = 0

    async def followup(ip, ports, timeout, semaphore, chunk_size=512):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        await asyncio.sleep(0.02)
        active -= 1
        return [], {}

    async def no_fingerprint(devices, timeout=60.0, deep=True):
        return {}, {"available": False, "reason": "test"}

    monkeypatch.setattr(ShadowLAN, "_probe", staticmethod(initial_probe))
    monkeypatch.setattr(ShadowLAN, "_probe_chunked", classmethod(lambda cls, ip, ports, timeout, semaphore, chunk_size=512: followup(ip, ports, timeout, semaphore, chunk_size)))
    monkeypatch.setattr("shadowstrike.network.lan.NmapFingerprintAdapter.fingerprint", no_fingerprint)
    await lan.discover(port_profile="adaptive", verify_services=False)
    assert maximum > 1


def test_snmp_lldp_neighbors_are_inventory_evidence(monkeypatch) -> None:
    snmp = ShadowSNMP(host="10.0.0.2", community="read-only")
    monkeypatch.setattr(snmp, "get", lambda oid: "Cisco Catalyst IOS XE" if oid.endswith("1.1.0") else None)

    def walk(base_oid, max_rows=256):
        rows = {
            "1.0.8802.1.1.2.1.4.1.1.5": [("1.0.8802.1.1.2.1.4.1.1.5.100.7.1", "00:aa:bb:cc:dd:ee")],
            "1.0.8802.1.1.2.1.4.1.1.7": [("1.0.8802.1.1.2.1.4.1.1.7.100.7.1", "Gi1/0/48")],
            "1.0.8802.1.1.2.1.4.1.1.8": [("1.0.8802.1.1.2.1.4.1.1.8.100.7.1", "uplink")],
            "1.0.8802.1.1.2.1.4.1.1.9": [("1.0.8802.1.1.2.1.4.1.1.9.100.7.1", "core-switch")],
            "1.0.8802.1.1.2.1.4.1.1.10": [("1.0.8802.1.1.2.1.4.1.1.10.100.7.1", "Cisco core")],
        }
        return rows.get(base_oid, [])

    monkeypatch.setattr(snmp, "walk", walk)
    inventory = snmp.inventory()
    assert inventory["lldp_neighbor_count"] == 1
    neighbor = inventory["lldp_neighbors"][0]
    assert neighbor["system_name"] == "core-switch"
    assert neighbor["port_id"] == "Gi1/0/48"
