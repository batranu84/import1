from shadowstrike.risk.engine import RiskEngine

class PhysicalRiskAdapter:
    def __init__(self):
        self.engine = RiskEngine()

    def evaluate(self, assets):
        return [
            {'asset': a, 'risk': self.engine.assess(a).__dict__}
            for a in assets
        ]
