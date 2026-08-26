from .physical_topology import PhysicalTopologyBuilder


class TopologyIntegration:
    """Integrates physical assets into the existing topology export model."""

    def __init__(self, builder=None):
        self.builder = builder or PhysicalTopologyBuilder()

    def ingest_asset(self, asset, parent=None):
        asset_id = asset.get("id") or asset.get("ip") or asset.get("hostname")
        category = asset.get("category", "unknown")
        evidence = asset.get("evidence", [])
        risk = asset.get("risk")
        return self.builder.attach_physical(
            asset_id,
            category,
            parent=parent,
            evidence=evidence,
            risk=risk,
        )

    def ingest_many(self, assets):
        result = None
        for asset in assets:
            result = self.ingest_asset(asset, parent=asset.get("parent"))
        return result or self.builder.export()
