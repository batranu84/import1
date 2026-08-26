from shadowstrike.engines.tcp import COMMON_PORTS, EXTENDED_PORTS, TcpDiscoveryEngine


def test_extended_profile_has_more_coverage():
    engine = TcpDiscoveryEngine()
    assert engine.ports_for_profile("quick") == COMMON_PORTS
    assert len(engine.ports_for_profile("full")) > len(COMMON_PORTS)
    assert 6443 in EXTENDED_PORTS
