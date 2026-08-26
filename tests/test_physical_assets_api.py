from shadowstrike.api.app import physical_assets


def test_physical_assets_endpoint_shape():
    result = __import__("asyncio").run(physical_assets())
    assert isinstance(result, dict)
    assert "total" in result
    assert "categories" in result
