from __future__ import annotations

from collections import Counter

from shadowstrike.models.domain import AssessmentResult, ModuleState


class CoverageService:
    def summarize(self, result: AssessmentResult) -> dict[str, object]:
        states = Counter(module.state.value for module in result.modules)
        asset_kinds = Counter(asset.kind for asset in result.assets)
        evidence_categories = Counter(item.category for item in result.evidence)
        total = len(result.modules)
        completed = states.get(ModuleState.COMPLETED.value, 0)
        terminal = completed + states.get(ModuleState.FAILED.value, 0) + states.get(ModuleState.SKIPPED.value, 0)
        evidence_bearing = sum(1 for module in result.modules if module.state == ModuleState.COMPLETED and module.completed_units > 0)
        zero_evidence = [module.name for module in result.modules if module.state == ModuleState.COMPLETED and module.completed_units == 0]
        gaps = []
        for item in result.evidence:
            if item.category == "discovery-coverage-gap":
                raw = item.raw or {}
                gaps.append({"summary": item.summary, **raw})
        return {
            "modules": {
                "total": total,
                "completed": completed,
                "failed": states.get(ModuleState.FAILED.value, 0),
                "skipped": states.get(ModuleState.SKIPPED.value, 0),
                "completion_percent": round((completed / total * 100), 1) if total else 0.0,
                "execution_percent": round((terminal / total * 100), 1) if total else 0.0,
                "evidence_bearing_modules": evidence_bearing,
                "evidence_bearing_percent": round((evidence_bearing / total * 100), 1) if total else 0.0,
                "zero_evidence_completed": zero_evidence,
            },
            "assets_by_kind": dict(sorted(asset_kinds.items())),
            "evidence_by_category": dict(sorted(evidence_categories.items())),
            "graph": {
                "nodes": len(result.graph.get("nodes", [])),
                "edges": len(result.graph.get("edges", [])),
            },
            "discovery_gaps": gaps,
        }
