from __future__ import annotations

from collections import defaultdict


class PhysicalInventory:
    """Maintains physical asset inventory during assessment execution."""

    def merge(self, existing_assets: list, physical_assets: list[dict]) -> list:
        seen = {(getattr(a, "kind", None), getattr(a, "value", None)) for a in existing_assets}

        for item in physical_assets:
            key = (item.get("category"), item.get("ip"))
            if key in seen:
                continue
            existing_assets.append({
                "kind": item.get("category"),
                "value": item.get("ip"),
                "source": "physical_pipeline",
                "attributes": item,
            })
            seen.add(key)

        return existing_assets
