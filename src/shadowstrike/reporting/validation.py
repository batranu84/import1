from __future__ import annotations

from html import escape

from shadowstrike.models.domain import AssessmentResult


class ValidationReport:
    def render(self, result: AssessmentResult) -> str:
        sections: list[str] = []
        for finding in result.findings:
            if not finding.validation_sessions:
                continue
            sessions = []
            for session in finding.validation_sessions:
                poc_rows = "".join(
                    "<tr>"
                    f"<td>{escape(p.artifact_type)}</td>"
                    f"<td>{escape(p.title)}</td>"
                    f"<td><pre>{escape(p.content)}</pre></td>"
                    "</tr>"
                    for p in session.poc_artifacts
                ) or "<tr><td colspan='3'>No client PoC artifact recorded.</td></tr>"
                sessions.append(
                    "<div class='session'>"
                    f"<h3>Session {escape(str(session.id))}</h3>"
                    f"<p><b>State:</b> {escape(session.state.value)} &nbsp; <b>Verdict:</b> {escape(session.verdict or '—')}</p>"
                    f"<p><b>Authorization:</b> {escape(session.authorization_reference)} &nbsp; <b>Operator:</b> {escape(session.operator or '—')}</p>"
                    f"<p><b>Technique:</b> {escape(session.technique)}</p>"
                    f"<p><b>Proof objective:</b> {escape(session.proof_objective.description)}</p>"
                    f"<p><b>Proof marker:</b> <code>{escape(session.proof_objective.marker)}</code></p>"
                    f"<p><b>Access level achieved:</b> {escape(session.access_level_achieved or '—')}</p>"
                    f"<p><b>Cleanup confirmed:</b> {'Yes' if session.cleanup_confirmed else 'No'}</p>"
                    f"<p><b>Attempt evidence:</b> {escape(', '.join(map(str, session.attempt_evidence_ids)) or '—')}</p>"
                    f"<p><b>Proof evidence:</b> {escape(', '.join(map(str, session.proof_evidence_ids)) or '—')}</p>"
                    f"<p><b>Cleanup evidence:</b> {escape(', '.join(map(str, session.cleanup_evidence_ids)) or '—')}</p>"
                    "<h4>Client-safe PoC artifacts</h4>"
                    "<table><thead><tr><th>Type</th><th>Title</th><th>Content</th></tr></thead>"
                    f"<tbody>{poc_rows}</tbody></table>"
                    "</div>"
                )
            sections.append(
                "<section class='finding'>"
                f"<h2>{escape(finding.title)}</h2>"
                f"<p><b>Affected:</b> {escape(finding.affected_asset)} &nbsp; <b>Severity:</b> {escape(finding.severity.value)}</p>"
                + "".join(sessions)
                + "</section>"
            )
        body = "".join(sections) or "<p>No controlled validation sessions have been recorded.</p>"
        return f"""<!doctype html><html><head><meta charset='utf-8'><title>ShadowStrike Controlled Validation Report</title>
<style>body{{font-family:system-ui,-apple-system,sans-serif;background:#0b0f14;color:#e8edf3;margin:0}}main{{max-width:1100px;margin:auto;padding:32px}}.finding,.session{{background:#121922;border:1px solid #253245;border-radius:12px;padding:18px;margin:14px 0}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;border-bottom:1px solid #253245;text-align:left;vertical-align:top}}pre{{white-space:pre-wrap;word-break:break-word}}code{{color:#9fe870}}</style>
</head><body><main><h1>ShadowStrike Controlled Validation &amp; Proof-of-Access Report</h1>
<p><b>{escape(result.name)}</b> · Assessment ID <code>{result.id}</code></p>
<p>This report records explicitly authorized validation sessions. It distinguishes observed evidence from operator-confirmed exploitation/access and requires cleanup evidence for successful sessions.</p>
{body}</main></body></html>"""
