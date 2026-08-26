import pytest
from shadowstrike.services.tool_bridge import SpecialistToolBridgeEngine


def test_tcpwrapped_is_not_confirmed_service():
    xml = """<?xml version='1.0'?><nmaprun><host><status state='up'/><address addr='203.0.113.10' addrtype='ipv4'/><ports><port protocol='tcp' portid='999'><state state='open'/><service name='tcpwrapped' conf='8'/></port></ports></host></nmaprun>"""
    assets, evidence = SpecialistToolBridgeEngine._parse_nmap_xml(xml)
    endpoint = next(a for a in assets if a.value == '203.0.113.10:999/tcp')
    assert endpoint.kind == 'transport-endpoint'
    assert endpoint.attributes['service_state'] == 'candidate'
    assert endpoint.attributes['service_name'] == 'unknown'
    assert endpoint.attributes['nmap_tcpwrapped'] is True
