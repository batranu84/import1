from shadowstrike.topology.integration import TopologyIntegration


def test_physical_asset_integration():
    topo = TopologyIntegration()
    result = topo.ingest_many([
        {
            "id": "cam-01",
            "category": "CCTV",
            "evidence": ["RTSP", "ONVIF"],
            "risk": "medium",
            "parent": "switch-01",
        }
    ])

    assert any(n["id"] == "cam-01" for n in result["nodes"])
    assert any(e["target"] == "cam-01" for e in result["edges"])
