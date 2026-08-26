from dataclasses import asdict, dataclass, field

from .cctv import CCTVClassifier
from .iot import IoTClassifier
from .ot import OTClassifier


@dataclass
class PhysicalAssessment:
    category: str
    confidence: str
    evidence: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class PhysicalAssetEngine:
    """Evidence-first physical asset classification layer."""

    def __init__(self):
        self.cctv = CCTVClassifier()
        self.iot = IoTClassifier()
        self.ot = OTClassifier()

    def assess(self, asset: dict) -> PhysicalAssessment:
        results = [
            self.cctv.classify(asset),
            self.iot.classify(asset),
            self.ot.classify(asset),
        ]
        ranked = [r for r in results if getattr(r, "classification", "Unknown") != "Unknown"]
        if not ranked:
            return PhysicalAssessment("Unknown", "Low")
        best = ranked[0]
        evidence = list(getattr(best, "evidence", []))
        return PhysicalAssessment(
            getattr(best, "classification", "Unknown"),
            getattr(best, "confidence", "Low"),
            evidence,
            {"source": "physical-engine"},
        )
