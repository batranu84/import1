from dataclasses import dataclass

@dataclass
class RiskResult:
    score: int
    level: str
    reasons: list[str]

class RiskEngine:
    def assess(self, asset: dict) -> RiskResult:
        score = 0
        reasons = []
        category = str(asset.get('category','')).lower()
        evidence = [str(x).lower() for x in asset.get('evidence', [])]

        if category == 'cctv':
            if any('rtsp' in x for x in evidence):
                score += 15; reasons.append('RTSP service identified')
            if any('management' in x or 'http' in x for x in evidence):
                score += 20; reasons.append('Management interface detected')
        elif category == 'iot':
            score += 10; reasons.append('IoT asset requires review')
        elif category == 'ot':
            score += 25; reasons.append('OT asset requires segmentation review')

        if any('unknown' in x for x in evidence):
            score += 10; reasons.append('Unknown device evidence')

        level = 'Low' if score < 20 else 'Medium' if score < 50 else 'High'
        return RiskResult(score, level, reasons)
