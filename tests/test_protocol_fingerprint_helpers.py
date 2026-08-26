from shadowstrike.network.device import service_name


def test_service_name_has_identity_protocol_ports():
    # The port map is only a candidate label. Active service verification is still required.
    assert service_name(445)
    assert service_name(389)
    assert service_name(3389)
