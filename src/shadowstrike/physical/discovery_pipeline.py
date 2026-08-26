from dataclasses import asdict, dataclass, field

from .asset_pipeline import PhysicalAssetEngine


@dataclass
class PhysicalAssetRecord:
    ip: str
    category: str
    confidence: str
    evidence: list[str] = field(default_factory=list)
    source: str = "discovery"
    metadata: dict = field(default_factory=dict)


class DiscoveryPhysicalPipeline:
    """Connect discovered network devices to physical asset intelligence."""

    def __init__(self):
        self.engine = PhysicalAssetEngine()

    def process(self, devices: list[dict]) -> list[dict]:
        assets = []
        for device in devices:
            assessment = self.engine.assess(device)
            if assessment.category != "Unknown":
                assets.append(asdict(PhysicalAssetRecord(
                    ip=str(device.get("ip", "")),
                    category=assessment.category,
                    confidence=assessment.confidence,
                    evidence=assessment.evidence,
                    metadata={"device": device},
                )))
        return assets
