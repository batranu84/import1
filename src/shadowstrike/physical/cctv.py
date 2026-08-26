from dataclasses import dataclass, field

@dataclass
class CCTVProfile:
    ip: str
    classification: str = "Unknown"
    vendor: str | None = None
    evidence: list[str] = field(default_factory=list)
    confidence: str = "Low"

class CCTVClassifier:
    VENDORS = {"hikvision": "Hikvision", "dahua": "Dahua", "axis": "Axis", "hanwha": "Hanwha"}

    def classify(self, asset: dict) -> CCTVProfile:
        text = " ".join(str(asset.get(k, "")) for k in asset).lower()
        evidence = []
        vendor = None
        for key, name in self.VENDORS.items():
            if key in text:
                vendor = name
                evidence.append("vendor fingerprint match")
        services = {str(x).lower() for x in asset.get("services", [])}
        if "rtsp" in services:
            evidence.append("RTSP service detected")
        if "onvif" in services:
            evidence.append("ONVIF detected")
        is_camera = bool(vendor or {"rtsp", "onvif"} & services)
        return CCTVProfile(asset.get("ip", ""), "IP Camera" if is_camera else "Unknown", vendor, evidence, "High" if len(evidence) >= 2 else "Medium" if evidence else "Low")
