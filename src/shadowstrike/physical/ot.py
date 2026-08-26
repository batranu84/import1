from dataclasses import dataclass

@dataclass
class OTProfile:
    ip: str
    protocol: str
    evidence: list[str]

class OTClassifier:
    def classify(self, asset: dict) -> OTProfile:
        services = {str(x).lower() for x in asset.get("services", [])}
        if "bacnet" in services:
            return OTProfile(asset.get("ip", ""), "BACnet", ["BACnet service evidence"])
        if "modbus" in services:
            return OTProfile(asset.get("ip", ""), "Modbus", ["Modbus service evidence"])
        return OTProfile(asset.get("ip", ""), "Unknown", [])
