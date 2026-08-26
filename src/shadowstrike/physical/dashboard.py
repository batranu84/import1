from __future__ import annotations

from collections import Counter


def physical_asset_summary(assets: list[dict]) -> dict:
    """Create dashboard-ready physical asset statistics from discovered assets."""
    categories = Counter()
    risks = Counter()

    for asset in assets:
        category = str(asset.get('category', 'unknown')).lower()
        categories[category] += 1
        risk = str(asset.get('risk', 'unknown')).lower()
        risks[risk] += 1

    return {
        'physical_assets': sum(categories.values()),
        'total': sum(categories.values()),
        'categories': dict(categories),
        'risk_summary': dict(risks),
    }
