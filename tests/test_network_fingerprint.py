from shadowstrike.network.device import ShadowDevice, vendor_from_mac
from shadowstrike.network.fingerprint import ArpScanAdapter, NmapFingerprintAdapter


def test_nmap_xml_populates_os_device_and_service_fingerprint() -> None:
    xml = '''<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Example Networks"/>
<hostnames><hostname name="printer01.local"/></hostnames>
<ports><port protocol="tcp" portid="9100"><state state="open"/>
<service name="jetdirect" product="HP JetDirect" version="1.2" devicetype="printer" ostype="embedded" conf="10"><cpe>cpe:/h:hp:jetdirect</cpe></service>
</port></ports>
<os><osmatch name="HP embedded print server" accuracy="97"><osclass type="printer" vendor="HP" osfamily="embedded" accuracy="97"><cpe>cpe:/h:hp:printer</cpe></osclass></osmatch></os>
</host></nmaprun>'''
    parsed = NmapFingerprintAdapter.parse_xml(xml)
    fp = parsed["192.168.1.10"]
    assert fp.best_os["accuracy"] == 97
    assert "printer" in fp.device_types
    assert fp.services[0]["product"] == "HP JetDirect"

    device = ShadowDevice(ip="192.168.1.10", open_ports=[9100])
    NmapFingerprintAdapter.apply(device, fp)
    assert "97% Nmap match" in device.os_hint
    assert device.vendor == "Example Networks"
    assert device.device_type == "printer"
    assert device.services[0]["service_state"] == "confirmed"
    assert device.services[0]["version"] == "1.2"


def test_nmap_low_confidence_service_is_not_promoted() -> None:
    xml = '''<nmaprun><host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="12345"><state state="open"/><service name="http" conf="4"/></port></ports>
</host></nmaprun>'''
    fp = NmapFingerprintAdapter.parse_xml(xml)["10.0.0.2"]
    device = ShadowDevice(ip="10.0.0.2", open_ports=[12345]).normalize()
    NmapFingerprintAdapter.apply(device, fp)
    service = next(s for s in device.services if s["port"] == 12345)
    assert service["service_state"] == "unconfirmed"
    assert service["name"] == "unknown"


def test_arp_scan_parser_retains_mac_and_vendor() -> None:
    rows = ArpScanAdapter.parse("192.168.0.2\t00:11:22:33:44:55\tExample Vendor\n")
    assert rows["192.168.0.2"]["mac"] == "00:11:22:33:44:55"
    assert rows["192.168.0.2"]["vendor"] == "Example Vendor"


def test_locally_administered_mac_is_not_claimed_as_hardware_vendor() -> None:
    assert vendor_from_mac("02:00:00:00:00:01") == "Locally administered/randomized"
