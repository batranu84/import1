from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Union

from shadowstrike.models.domain import AssessmentResult
from shadowstrike.risk.assessment import AssessmentRiskService


class ExecutiveRiskReport:
    def render(self, result: AssessmentResult) -> str:
        risk = AssessmentRiskService.summarize(result)
        priorities = risk["top_priorities"]
        rows = "".join(
            "<tr>"
            f"<td>{escape(str(item['title']))}</td>"
            f"<td>{escape(str(item['affected_asset']))}</td>"
            f"<td>{item['score']}</td>"
            f"<td>{escape(str(item['level']))}</td>"
            f"<td>{escape(str(item['validation_verdict'] or 'not exploit-validated'))}</td>"
            f"<td>{escape(str(item['remediation_status']))}</td>"
            f"<td>{escape(str(item['retest_status']))}</td>"
            "</tr>"
            for item in priorities
        ) or "<tr><td colspan='7'>No reportable findings.</td></tr>"
        return f"""<!doctype html>
<html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>ShadowStrike Executive Risk Report - {escape(result.name)}</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;background:#0b0f14;color:#e8edf3;margin:0}}
main{{max-width:1080px;margin:auto;padding:36px}} .brand{{color:#9fe870}} .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}
.card,.metric{{background:#121922;border:1px solid #253245;border-radius:12px;padding:18px;margin:14px 0}}
table{{width:100%;border-collapse:collapse;background:#121922}} th,td{{padding:10px;border-bottom:1px solid #253245;text-align:left}}
small{{color:#9eabb8}} .risk{{font-size:2rem;font-weight:700}}
</style></head><body><main>
<h1><span class='brand'>ShadowStrike</span> Executive Risk Report</h1>
<p><b>{escape(result.name)}</b> · status {escape(result.status)}</p>
<small>Assessment ID: {result.id}</small>
<div class='card'><div class='risk'>{risk['overall_score']}/100 · {escape(risk['overall_level'].upper())}</div>
<p>This score prioritizes existing assessment evidence, controlled validation, exposure context, remediation state and retest outcomes. It is not a probability of compromise.</p></div>
<section class='grid'>
<div class='metric'><b>{len(result.findings)}</b><br>Findings</div>
<div class='metric'><b>{risk['validated_finding_count']}</b><br>Controlled-validated findings</div>
<div class='metric'><b>{risk['open_high_or_critical_count']}</b><br>Open high/critical risks</div>
<div class='metric'><b>{risk['failed_retest_count']}</b><br>Failed retests</div>
<div class='metric'><b>{risk['exposure_path_count']}</b><br>Exposure paths</div>
<div class='metric'><b>{risk['high_or_critical_exposure_path_count']}</b><br>High/critical paths</div>
</section>
<h2>Priority remediation view</h2>
<table><thead><tr><th>Finding</th><th>Asset</th><th>Risk</th><th>Band</th><th>Validation</th><th>Remediation</th><th>Retest</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Risk interpretation</h2><div class='card'><pre>{escape(str(risk['semantics']))}</pre></div>
</main></body></html>"""

    def write(self, result: AssessmentResult, path: Union[str, Path]) -> Path:
        destination = Path(path)
        destination.write_text(self.render(result), encoding="utf-8")
        return destination
