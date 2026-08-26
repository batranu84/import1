from __future__ import annotations

from collections import Counter
from html import escape
from pathlib import Path
from typing import Union

from shadowstrike.models.domain import AssessmentResult


class RetestReport:
    """Render a focused before/after remediation verification report."""

    def render(self, result: AssessmentResult) -> str:
        findings = [f for f in result.findings if f.retest_history or f.retest_status != "not-retested"]
        counts = Counter(f.retest_status for f in findings)
        rows = []
        for finding in findings:
            rounds = []
            for index, record in enumerate(finding.retest_history, start=1):
                before = ", ".join(str(x) for x in record.before_evidence_ids) or "-"
                after = ", ".join(str(x) for x in record.after_evidence_ids) or "-"
                rounds.append(
                    "<div class='round'>"
                    f"<b>Round {index}: {escape(record.status)}</b>"
                    f"<br>Requested: {escape(record.requested_at.isoformat())}"
                    f"<br>Completed: {escape(record.completed_at.isoformat() if record.completed_at else '-')}"
                    f"<br>Operator: {escape(record.operator or '-')}"
                    f"<br>Before evidence: <code>{escape(before)}</code>"
                    f"<br>After evidence: <code>{escape(after)}</code>"
                    f"<br>Notes: {escape(record.notes or '-')}"
                    "</div>"
                )
            rows.append(
                "<article class='finding'>"
                f"<h3>{escape(finding.title)}</h3>"
                f"<p><b>Affected:</b> {escape(finding.affected_asset)}</p>"
                f"<p><b>Severity:</b> {escape(finding.severity.value)} &nbsp; "
                f"<b>Remediation:</b> {escape(finding.remediation_status)} &nbsp; "
                f"<b>Retest:</b> {escape(finding.retest_status)}</p>"
                f"<p><b>Recommended fix:</b> {escape(finding.remediation)}</p>"
                + "".join(rounds)
                + "</article>"
            )
        body = "".join(rows) or "<p>No findings have entered the retest workflow.</p>"
        return f"""<!doctype html>
<html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>ShadowStrike Retest Report - {escape(result.name)}</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#0b0f14;color:#e8edf3}}
main{{max-width:1000px;margin:auto;padding:32px}} .finding,.metric,.round{{background:#121922;border:1px solid #253245;border-radius:12px;padding:16px;margin:12px 0}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}} code{{color:#9fe870;word-break:break-all}} .brand{{color:#9fe870}}
</style></head><body><main>
<h1><span class='brand'>ShadowStrike</span> Remediation & Retest Report</h1>
<p><b>{escape(result.name)}</b> - assessment {escape(str(result.id))}</p>
<section class='grid'>
<div class='metric'><b>{len(findings)}</b><br>Findings in workflow</div>
<div class='metric'><b>{counts.get('fixed', 0)}</b><br>Fixed</div>
<div class='metric'><b>{counts.get('partially-fixed', 0)}</b><br>Partially fixed</div>
<div class='metric'><b>{counts.get('not-fixed', 0)}</b><br>Not fixed</div>
<div class='metric'><b>{counts.get('pending', 0)}</b><br>Pending retest</div>
</section>
<h2>Retest findings</h2>{body}
</main></body></html>"""

    def write(self, result: AssessmentResult, path: Union[str, Path]) -> Path:
        destination = Path(path)
        destination.write_text(self.render(result), encoding="utf-8")
        return destination
