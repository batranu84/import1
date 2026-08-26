from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Union

from shadowstrike import __version__
from shadowstrike.models.domain import AssessmentResult
from shadowstrike.internal.posture import InternalPostureService
from shadowstrike.internal.infrastructure import InternalInfrastructureService
from shadowstrike.internal.identity import InternalIdentityService
from shadowstrike.internal.segmentation import InternalSegmentationService
from shadowstrike.internal.exposure import InternalExposureService
from shadowstrike.services.assessment_truth import inventory_summary, valid_network_devices
from shadowstrike.services.coverage import CoverageService
from shadowstrike.risk.assessment import AssessmentRiskService


def _json(value: object) -> str:
    return escape(json.dumps(value, indent=2, sort_keys=True, default=str))


def _mapping_table(value: dict[str, object], empty: str = "No evidence recorded.") -> str:
    rows = []
    for key, item in value.items():
        if isinstance(item, (dict, list)):
            rendered = f"<details><summary>View</summary><pre>{_json(item)}</pre></details>" if item else "—"
        else:
            rendered = escape(str(item)) if item not in (None, "") else "—"
        rows.append(f"<tr><th><code>{escape(str(key))}</code><br><small>{escape(str(key).replace('_', ' ').title())}</small></th><td>{rendered}</td></tr>")
    return "<table class='kvtable'>" + "".join(rows) + "</table>" if rows else f"<p>{escape(empty)}</p>"


class HtmlReport:
    def render(self, result: AssessmentResult, profile: str = "technical") -> str:
        if profile not in {"technical", "bug-bounty"}:
            raise ValueError("report profile must be technical or bug-bounty")
        coverage = CoverageService().summarize(result)
        executive_risk = AssessmentRiskService.summarize(result)
        inventory = inventory_summary(result)
        legacy = result.engine_version != __version__
        modules = "".join(
            f"<tr><td>{escape(m.name)}</td><td>{escape(m.state.value)}</td>"
            f"<td>{m.completed_units}</td><td>{escape(m.message or ('completed with no evidence' if m.state.value == 'completed' and m.completed_units == 0 else ''))}</td></tr>"
            for m in result.modules
        )
        verification_counts = result.verification.get("counts", {})
        contacts = [a for a in result.assets if a.kind == "email-contact"]
        network_devices = valid_network_devices(result.assets)
        network_services = [a for a in result.assets if a.kind == "network-service" and a.source == "ShadowLAN" and str(a.attributes.get("service_state") or "confirmed").lower() == "confirmed"]
        internal_posture = InternalPostureService.summarize(result.assets, result.evidence)
        internal_infrastructure = InternalInfrastructureService.summarize(result.assets, result.evidence)
        internal_identity = InternalIdentityService.summarize(result.assets, result.evidence)
        internal_trust = InternalSegmentationService.summarize(result.assets, result.evidence)
        internal_exposure = InternalExposureService.summarize(result.assets, result.evidence, result.findings)
        contact_rows = "".join(f"<tr><td>{escape(a.value)}</td><td>{escape(str(a.attributes.get('role', 'personal/public')))}</td><td>{escape(str(a.attributes.get('source_count', 1)))}</td><td>{escape(str(a.attributes.get('source_url', '')))}</td></tr>" for a in contacts) or "<tr><td colspan='4'>No in-scope public contacts discovered.</td></tr>"
        device_rows = "".join(
            f"<tr><td>{escape(a.value)}</td><td>{escape(str(a.attributes.get('hostname') or '—'))}</td><td>{escape(str(a.attributes.get('device_type', 'unknown')))}</td><td>{escape(str(a.attributes.get('vendor') or '—'))}</td><td>{escape(', '.join(map(str, a.attributes.get('open_ports', []))) or '—')}</td><td>{escape(str(a.attributes.get('firmware') or ('BIOS available' if a.attributes.get('bios') else '—')))}</td></tr>"
            for a in network_devices
        ) or "<tr><td colspan='6'>No internal network devices recorded.</td></tr>"
        telemetry = [e.raw for e in result.evidence if e.category == "scan-telemetry"]
        validation_session_count = sum(len(f.validation_sessions) for f in result.findings)
        validated_finding_count = sum(1 for f in result.findings if any(s.verdict in {"exploit-confirmed", "access-confirmed", "proof-objective-achieved"} for s in f.validation_sessions))
        cleanup_confirmed_count = sum(1 for f in result.findings for s in f.validation_sessions if s.cleanup_confirmed)
        findings = "".join(
            "<article class='finding'>"
            f"<h3>{escape(f.title)}</h3>"
            f"<p><b>Severity:</b> {escape(f.severity.value)} &nbsp; <b>Confidence:</b> {escape(f.confidence.value)}</p>"
            f"<p><b>Affected:</b> {escape(f.affected_asset)}</p>"
            f"<p><b>Validation:</b> {escape(f.validation_status)} &nbsp; <b>Evidence quality:</b> {escape(f.evidence_quality)} &nbsp; <b>Priority:</b> {escape(f.remediation_priority or '—')} ({escape(str(f.priority_score) if f.priority_score is not None else '—')})</p>"
            f"<p><b>CWE:</b> {escape(f.cwe or '—')} &nbsp; <b>CVE:</b> {escape(', '.join(f.cve_ids) if f.cve_ids else '—')} &nbsp; <b>CVSS:</b> {escape(str(f.cvss) if f.cvss is not None else '—')}</p>"
            f"<p>{escape(f.description)}</p><p><b>Technical impact:</b> {escape(f.technical_impact or 'Not assessed.')}</p><p><b>Business impact:</b> {escape(f.business_impact or 'Not assessed.')}</p><p><b>Exposure path:</b> {escape(' → '.join(f.attack_path) if f.attack_path else '—')}</p><p><b>Remediation:</b> {escape(f.remediation)}</p><p><b>Remediation state:</b> {escape(f.remediation_status)} &nbsp; <b>Retest:</b> {escape(f.retest_status)}</p>"
            "</article>" for f in result.findings
        ) or "<p>No evidence-backed findings were recorded.</p>"
        risk_rows = "".join(
            f"<tr><th>{escape(str(k).replace('_',' ').title())}</th><td>{escape(str(v))}</td></tr>"
            for k, v in {
                "overall score": executive_risk.get("overall_score"), "overall level": executive_risk.get("overall_level"),
                "validated findings": executive_risk.get("validated_finding_count"), "open high or critical": executive_risk.get("open_high_or_critical_count"),
                "failed retests": executive_risk.get("failed_retest_count"), "exposure paths": executive_risk.get("exposure_path_count"),
                "high or critical paths": executive_risk.get("high_or_critical_exposure_path_count"),
            }.items()
        )
        incomplete_banner = f"<div class='warn'><b>Assessment incomplete:</b> Failed modules: {escape(', '.join(executive_risk.get('failed_modules', [])) or 'unknown')}. Risk score is not final and the engagement must be re-run after correcting failed branches.</div>" if not executive_risk.get('risk_final') else ""
        legacy_banner = f"<div class='warn'><b>Legacy assessment semantics:</b> This assessment was created by {escape(result.engine_version)} and is being viewed in {escape(__version__)}. Re-run the engagement before relying on inventory/service counts.</div>" if legacy else ""
        report_name = "Bug Bounty Report" if profile == "bug-bounty" else "Security Assessment Technical Report"
        return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>ShadowStrike Report - {escape(result.name)}</title><style>
body{{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#0b0f14;color:#e8edf3}}main{{max-width:1120px;margin:auto;padding:32px}}h1,h2{{letter-spacing:.02em}}.card,.finding{{background:#121922;border:1px solid #253245;border-radius:12px;padding:18px;margin:14px 0}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}.metric{{background:#121922;border:1px solid #253245;border-radius:12px;padding:16px}}table{{width:100%;border-collapse:collapse;background:#121922}}th,td{{padding:10px;border-bottom:1px solid #253245;text-align:left;vertical-align:top}}.kvtable th{{width:260px;color:#9eabb8}}small{{color:#9eabb8}}.brand{{color:#9fe870}}code{{color:#9fe870}}pre{{white-space:pre-wrap;word-break:break-word}}details summary{{cursor:pointer;color:#9fe870}}.warn{{border:1px solid #725d24;background:#211c0e;color:#f0d880;border-radius:12px;padding:14px;margin:16px 0}}
</style></head><body><main><h1><span class='brand'>ShadowStrike</span> {report_name}</h1>
<p><b>{escape(result.name)}</b> · profile {escape(result.profile)} · status {escape(result.status)}</p><small>Assessment ID: <code>{result.id}</code> · assessment engine {escape(result.engine_version)} · viewer {escape(__version__)}</small>{legacy_banner}{incomplete_banner}
<section class='grid'>
<div class='metric'><b>{(str(executive_risk['overall_score']) + '/100') if executive_risk.get('risk_final') else 'NOT FINAL'}</b><br>Executive risk</div><div class='metric'><b>{escape(executive_risk['overall_level']) if executive_risk.get('risk_final') else 'INCOMPLETE'}</b><br>Risk level</div><div class='metric'><b>{inventory['primary_assets']}</b><br>Primary assets</div><div class='metric'><b>{inventory['confirmed_services']}</b><br>Confirmed services</div><div class='metric'><b>{inventory['transport_observations']}</b><br>Transport observations</div><div class='metric'><b>{len(result.evidence)}</b><br>Evidence objects</div><div class='metric'><b>{len(result.findings)}</b><br>Findings</div><div class='metric'><b>{len(contacts)}</b><br>Public contacts</div><div class='metric'><b>{len(network_devices)}</b><br>Internal devices</div><div class='metric'><b>{len(network_services)}</b><br>Internal confirmed services</div><div class='metric'><b>{validation_session_count}</b><br>Validation sessions</div><div class='metric'><b>{validated_finding_count}</b><br>Validated findings</div><div class='metric'><b>{cleanup_confirmed_count}</b><br>Cleanup confirmed</div><div class='metric'><b>{coverage['modules']['completion_percent']}%</b><br>Modules completed successfully</div><div class='metric'><b>{coverage['modules']['evidence_bearing_percent']}%</b><br>Evidence-bearing modules</div>
</section>
<h2>Executive risk intelligence</h2><table class='kvtable'>{risk_rows}</table>
<h2>Module execution and evidence coverage</h2><table><thead><tr><th>Module</th><th>State</th><th>Evidence</th><th>Message</th></tr></thead><tbody>{modules}</tbody></table>
<div class='card'><b>Evidence coverage:</b> {coverage['modules']['evidence_bearing_modules']} of {coverage['modules']['total']} modules produced evidence. Zero-evidence completed modules: {escape(', '.join(coverage['modules']['zero_evidence_completed']) or 'none')}.</div>
<h2>Findings</h2>{findings}
<h2>Public domain contacts</h2><table><thead><tr><th>Email</th><th>Role</th><th>Sources</th><th>Observed source</th></tr></thead><tbody>{contact_rows}</tbody></table>
<h2>Internal network inventory</h2><table><thead><tr><th>IP</th><th>Hostname</th><th>Type</th><th>Vendor</th><th>Observed TCP ports</th><th>Firmware / BIOS</th></tr></thead><tbody>{device_rows}</tbody></table>
<h2>Internal posture</h2><div class='card'>{_mapping_table(internal_posture)}</div><h2>Internal infrastructure intelligence</h2><div class='card'>{_mapping_table(internal_infrastructure)}</div><h2>Internal identity &amp; Active Directory intelligence</h2><div class='card'>{_mapping_table(internal_identity)}</div><h2>Internal segmentation &amp; trust intelligence</h2><div class='card'>{_mapping_table(internal_trust)}</div><h2>Internal exposure &amp; attack-path intelligence</h2><div class='card'>{_mapping_table(internal_exposure)}</div><h2>Verification</h2><div class='card'>{_mapping_table(verification_counts)}</div>
{("<h2>Performance telemetry</h2><div class='card'><pre>" + _json(telemetry) + "</pre></div><h2>Coverage diagnostics</h2><div class='card'>" + _mapping_table(coverage) + "</div>") if profile == "technical" else "<div class='card'><b>Submission note:</b> Include only validated, in-scope evidence and concise reproduction details.</div>"}
</main></body></html>"""

    def write(self, result: AssessmentResult, path: Union[str, Path], profile: str = "technical") -> Path:
        destination = Path(path)
        destination.write_text(self.render(result, profile=profile), encoding="utf-8")
        return destination
