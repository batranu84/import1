from shadowstrike.physical.discovery_pipeline import DiscoveryPhysicalPipeline


def test_camera_device_enters_physical_pipeline():
    pipeline = DiscoveryPhysicalPipeline()
    result = pipeline.process([
        {
            "ip": "192.168.1.50",
            "vendor": "Hikvision",
            "services": ["rtsp", "onvif"],
        }
    ])
    assert len(result) == 1
    assert result[0]["category"] == "IP Camera"
    assert "RTSP service detected" in result[0]["evidence"]
