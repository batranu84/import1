from shadowstrike.network.agent import ShadowAgent
from shadowstrike.network.intelligence import DeviceProfile, NetworkTopology, NetworkRisk

def test_agent_registration():
    a = ShadowAgent.register('hq')
    assert a.status == 'registered'
    assert a.heartbeat()['status'] == 'online'

def test_network_risk():
    d = DeviceProfile('10.0.0.2', services=['https','ssh'])
    assert NetworkRisk.score(d) > 0

def test_topology():
    t=NetworkTopology()
    t.add_link('fw','sw')
    assert len(t.edges)==1


def test_network_risk_does_not_treat_numeric_port_as_protocol_identity():
    numeric = DeviceProfile("10.0.0.3", services=["445"])
    confirmed = DeviceProfile("10.0.0.3", services=["smb"])
    assert NetworkRisk.score(numeric) == 0.6
    assert NetworkRisk.score(confirmed) > NetworkRisk.score(numeric)
