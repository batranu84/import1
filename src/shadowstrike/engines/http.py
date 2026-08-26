from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import httpx

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Confidence, Evidence, Finding, Severity


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}


class HttpEngine(Engine):
    name = "ShadowHTTP"

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        assets: list[Asset] = []
        evidence: list[Evidence] = []
        findings: list[Finding] = []
        sem = asyncio.Semaphore(context.scope.policy.max_concurrency)

        async with httpx.AsyncClient(timeout=context.timeout, follow_redirects=False, verify=True, headers={"User-Agent": context.user_agent}) as client, \
                httpx.AsyncClient(timeout=context.timeout, follow_redirects=False, verify=False, headers={"User-Agent": context.user_agent}) as observation_client:
            async def inspect(target: str) -> None:
                context.scope.require(target)
                urls = [target] if "://" in target else [f"https://{target}", f"http://{target}"]
                for url in urls:
                    parsed = urlparse(url)
                    if parsed.hostname and not context.scope.allows(parsed.hostname):
                        continue
                    await context.limiter.wait()
                    verification_bypassed = False
                    async with sem:
                        try:
                            response = await client.get(url)
                        except Exception as primary_exc:
                            if parsed.scheme != "https":
                                continue
                            try:
                                response = await observation_client.get(url)
                                verification_bypassed = True
                            except Exception:
                                continue
                    a = Asset(kind="web-application", value=url, source=self.name, attributes={"status_code": response.status_code, "server": response.headers.get("server"), "tls_verification_bypassed_for_observation": verification_bypassed})
                    assets.append(a)
                    ev = Evidence(asset_id=a.id, engine=self.name, category="http", summary=f"HTTP {response.status_code} from {url}", raw={"headers": dict(response.headers), "status_code": response.status_code, "content_length": len(response.content), "tls_verification_bypassed_for_observation": verification_bypassed})
                    evidence.append(ev)
                    missing = [friendly for header, friendly in SECURITY_HEADERS.items() if header not in response.headers]
                    if missing:
                        findings.append(Finding(title="Missing recommended HTTP security headers", severity=Severity.LOW, confidence=Confidence.CONFIRMED, affected_asset=url, description="The response omitted one or more commonly recommended browser security headers: " + ", ".join(missing), remediation="Review application requirements and deploy appropriate browser security headers without breaking intended functionality.", evidence_ids=[ev.id], tags=["web", "hardening", "headers"], cwe="CWE-693"))
                    break

        await asyncio.gather(*(inspect(t) for t in targets))
        return EngineOutput(assets=assets, evidence=evidence, findings=findings)
