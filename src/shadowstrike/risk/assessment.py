from __future__ import annotations

from collections import Counter
from typing import Any

from shadowstrike.models.domain import AssessmentResult, Finding, Severity
from shadowstrike.internal.exposure import InternalExposureService


_SEVERITY_POINTS = {
    Severity.INFO: 2,
    Severity.LOW: 8,
    Severity.MEDIUM: 18,
    Severity.HIGH: 32,
    Severity.CRITICAL: 48,
}

_VALIDATION_POINTS = {
    "exploit-confirmed": 18,
    "access-confirmed": 22,
    "proof-objective-achieved": 25,
}


class AssessmentRiskService:
    """Deterministic client-level risk synthesis.

    The service only aggregates existing assessment evidence and operator-recorded
    validation/retest state. It does not probe targets or infer compromise.
    """

    @staticmethod
    def _asset_criticality(result: AssessmentResult, affected_asset: str) -> tuple[str, int, list[str]]:
        score = 0
        reasons: list[str] = []
        needle = affected_asset.lower()
        for asset in result.assets:
            if asset.value.lower() != needle:
                continue
            attrs = asset.attributes or {}
            role = str(attrs.get("role") or attrs.get("device_type") or attrs.get("category") or "").lower()
            criticality = str(attrs.get("criticality") or "").lower()
            if criticality in {"critical", "high"}:
                score += 18 if criticality == "critical" else 12
                reasons.append(f"asset criticality={criticality}")
            if any(x in role for x in ("domain controller", "firewall", "router", "gateway", "hypervisor", "nas", "database")):
                score += 12
                reasons.append(f"sensitive role={role}")
        if score >= 18:
            return "critical", score, reasons
        if score >= 12:
            return "high", score, reasons
        return "standard", score, reasons

    @staticmethod
    def _finding_score(result: AssessmentResult, finding: Finding) -> dict[str, Any]:
        score = _SEVERITY_POINTS[finding.severity]
        reasons = [f"severity={finding.severity.value}"]

        if finding.priority_score is not None:
            score += round(finding.priority_score * 0.18)
            reasons.append(f"remediation priority={finding.priority_score}")

        validated = False
        highest_validation = None
        for session in finding.validation_sessions:
            verdict = (session.verdict or "").lower()
            if verdict in _VALIDATION_POINTS:
                points = _VALIDATION_POINTS[verdict]
                if not validated or points > _VALIDATION_POINTS.get(highest_validation or "", 0):
                    highest_validation = verdict
                validated = True
        if validated and highest_validation:
            score += _VALIDATION_POINTS[highest_validation]
            reasons.append(f"controlled validation={highest_validation}")

        if finding.attack_path:
            score += min(12, max(4, len(finding.attack_path) * 2))
            reasons.append("exposure path present")

        criticality, criticality_points, criticality_reasons = AssessmentRiskService._asset_criticality(
            result, finding.affected_asset
        )
        score += criticality_points
        reasons.extend(criticality_reasons)

        remediation_state = (finding.remediation_status or "open").lower()
        if remediation_state in {"open", "planned", "in-progress", "ready-for-retest"}:
            score += 8
            reasons.append(f"remediation state={remediation_state}")
        elif remediation_state in {"remediated", "fixed"}:
            score -= 12
            reasons.append("remediation recorded")
        elif remediation_state == "risk-accepted":
            score -= 4
            reasons.append("risk formally accepted")

        retest = (finding.retest_status or "not-retested").lower()
        if retest in {"fixed", "passed", "remediated"}:
            score -= 18
            reasons.append("retest passed")
        elif retest in {"partially-fixed", "partial"}:
            score -= 6
            reasons.append("retest partially fixed")
        elif retest in {"not-fixed", "failed"}:
            score += 10
            reasons.append("retest failed")

        score = max(0, min(100, score))
        level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
        return {
            "finding_id": str(finding.id),
            "title": finding.title,
            "affected_asset": finding.affected_asset,
            "score": score,
            "level": level,
            "asset_criticality": criticality,
            "validated": validated,
            "validation_verdict": highest_validation,
            "remediation_status": finding.remediation_status,
            "retest_status": finding.retest_status,
            "reasons": reasons,
        }

    @classmethod
    def summarize(cls, result: AssessmentResult) -> dict[str, Any]:
        finding_risks = [cls._finding_score(result, finding) for finding in result.findings]
        counts = Counter(item["level"] for item in finding_risks)

        exposure = InternalExposureService.summarize(result.assets, result.evidence, result.findings)
        path_count = int(exposure.get("summary", {}).get("path_count", 0) or 0)
        high_path_count = int(exposure.get("summary", {}).get("high_or_critical_path_count", 0) or 0)

        if finding_risks:
            weighted = sum(item["score"] for item in finding_risks) / len(finding_risks)
            peak = max(item["score"] for item in finding_risks)
            overall = round((weighted * 0.6) + (peak * 0.4))
        else:
            overall = 0
        overall = min(100, overall + min(10, high_path_count * 2))
        level = "critical" if overall >= 80 else "high" if overall >= 60 else "medium" if overall >= 35 else "low"

        validated = sum(1 for x in finding_risks if x["validated"])
        open_high = sum(
            1 for x in finding_risks
            if x["level"] in {"high", "critical"} and x["remediation_status"] not in {"remediated", "fixed", "risk-accepted"}
        )
        retest_failed = sum(1 for x in finding_risks if str(x["retest_status"]).lower() in {"not-fixed", "failed"})

        priorities = sorted(finding_risks, key=lambda x: (-x["score"], x["title"]))[:10]
        failed_modules = [m.name for m in result.modules if getattr(m.state, "value", str(m.state)) == "failed"]
        assessment_complete = result.status == "completed" and not failed_modules
        return {
            "overall_score": overall,
            "overall_level": level,
            "assessment_complete": assessment_complete,
            "risk_final": assessment_complete,
            "failed_modules": failed_modules,
            "finding_counts_by_risk": dict(counts),
            "validated_finding_count": validated,
            "open_high_or_critical_count": open_high,
            "failed_retest_count": retest_failed,
            "exposure_path_count": path_count,
            "high_or_critical_exposure_path_count": high_path_count,
            "top_priorities": priorities,
            "finding_risk": finding_risks,
            "semantics": {
                "risk_score": "prioritization signal derived from existing evidence; not a compromise probability",
                "validation": "only operator-recorded controlled validation sessions influence validation weighting",
                "retest": "recorded remediation/retest state can reduce or increase residual risk",
            },
        }
