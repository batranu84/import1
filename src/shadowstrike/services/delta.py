from __future__ import annotations

from shadowstrike.models.domain import AssessmentResult


class DeltaService:
    """Compare two assessment snapshots without re-scanning targets."""

    @staticmethod
    def _assets(result: AssessmentResult) -> set[tuple[str, str]]:
        return {(a.kind, a.value) for a in result.assets}

    @staticmethod
    def _findings(result: AssessmentResult) -> set[tuple[str, str, str, str]]:
        return {(f.title, f.affected_asset, f.severity.value, f.confidence.value) for f in result.findings}

    @staticmethod
    def _evidence_categories(result: AssessmentResult) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in result.evidence:
            counts[item.category] = counts.get(item.category, 0) + 1
        return counts

    def compare(self, previous: AssessmentResult, current: AssessmentResult) -> dict[str, object]:
        old_assets, new_assets = self._assets(previous), self._assets(current)
        old_findings, new_findings = self._findings(previous), self._findings(current)
        old_categories, new_categories = self._evidence_categories(previous), self._evidence_categories(current)
        categories = sorted(set(old_categories) | set(new_categories))
        return {
            "previous_assessment_id": str(previous.id),
            "current_assessment_id": str(current.id),
            "assets": {
                "added": [list(x) for x in sorted(new_assets - old_assets)],
                "removed": [list(x) for x in sorted(old_assets - new_assets)],
                "unchanged": len(old_assets & new_assets),
            },
            "findings": {
                "added": [list(x) for x in sorted(new_findings - old_findings)],
                "removed": [list(x) for x in sorted(old_findings - new_findings)],
                "unchanged": len(old_findings & new_findings),
            },
            "evidence_category_delta": {
                category: new_categories.get(category, 0) - old_categories.get(category, 0)
                for category in categories
                if new_categories.get(category, 0) != old_categories.get(category, 0)
            },
            "verification": {
                "previous": previous.verification.get("counts", {}),
                "current": current.verification.get("counts", {}),
            },
        }
