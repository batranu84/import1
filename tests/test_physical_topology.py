from shadowstrike.topology.physical_topology import PhysicalTopologyBuilder


def test_physical_asset_topology_creation():
    topo = PhysicalTopologyBuilder()
    topo.attach_physical(
        "10.0.0.20",
        "CCTV",
        parent="10.0.0.1",
        evidence=["RTSP", "ONVIF"],
        risk="medium",
    )

    exported = topo.export()
    assert any(n["id"] == "10.0.0.20" for n in exported["nodes"])
    assert exported["edges"][0]["relation"] == "hosts"
    assert "RTSP" in exported["nodes"][0]["evidence"] or "RTSP" in exported["nodes"][1]["evidence"]
