from __future__ import annotations

import hashlib

from shadowstrike.models.domain import Evidence, Finding


class CorrelationEngine:
    """Deduplicates evidence/findings and prepares stable fingerprints for future graph correlation."""

    @staticmethod
    def fingerprint_evidence(item: Evidence) -> str:
        body = f"{item.engine}|{item.category}|{item.summary}|{sorted(item.raw.items())}".encode()
        return hashlib.sha256(body).hexdigest()

    def normalize_evidence(self, evidence: list[Evidence]) -> list[Evidence]:
        seen: set[str] = set()
        output: list[Evidence] = []
        for item in evidence:
            fp = item.fingerprint or self.fingerprint_evidence(item)
            item.fingerprint = fp
            if fp in seen:
                continue
            seen.add(fp)
            output.append(item)
        return output

    @staticmethod
    def dedupe_findings(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str]] = set()
        output: list[Finding] = []
        for finding in findings:
            key = (finding.title.lower(), finding.affected_asset.lower())
            if key in seen:
                continue
            seen.add(key)
            output.append(finding)
        return output
