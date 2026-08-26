from shadowstrike.physical.assessment_inventory import PhysicalInventory


def test_physical_inventory_deduplicates():
    inv = PhysicalInventory()
    assets = []
    result = inv.merge(assets, [{"category":"CCTV", "ip":"10.0.0.5"}, {"category":"CCTV", "ip":"10.0.0.5"}])
    assert len(result) == 1
