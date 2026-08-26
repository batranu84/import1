from dataclasses import dataclass

@dataclass
class IoTProfile:
    ip: str
    category: str
    evidence: list[str]

class IoTClassifier:
    def classify(self, asset: dict) -> IoTProfile:
        text = str(asset).lower()
        category = "Unknown"
        evidence = []
        for term, label in [("fire tv", "Streaming Device"), ("chromecast", "Streaming Device"), ("lg", "Smart Display"), ("samsung", "Smart Display"), ("printer", "Printer")]:
            if term in text:
                category = label
                evidence.append(term)
        return IoTProfile(asset.get("ip", ""), category, evidence)
