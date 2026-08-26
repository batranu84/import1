from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

import httpx

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Evidence
from shadowstrike.utils.endpoints import absolute_url, normalize_url

_ROUTE = re.compile(r"[\"']((?:/|https?://)[A-Za-z0-9_./?=&%:@~-]{2,})[\"']")
_SOURCE_MAP = re.compile(r"sourceMappingURL\s*=\s*([^\s*]+)")
_IMPORT = re.compile(r"(?:import\s+(?:[^;]+?\s+from\s+)?|require\()?[\"\']([^\"\']+\.(?:js|mjs|cjs))[\"\']")
_INTERESTING = re.compile(
    r"(?i)(graphql|swagger|openapi|api[-_/]v?\d*|websocket|wss://|internal|staging|dev[-_.])"
)


class JavaScriptEngine(Engine):
    name = "ShadowJS"

    def __init__(self, max_scripts_per_target: int = 24) -> None:
        self.max_scripts_per_target = max_scripts_per_target

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        if not context.scope.policy.allow_active_web:
            return EngineOutput(assets=[], evidence=[], findings=[])
        assets: list[Asset] = []
        evidence: list[Evidence] = []
        sem = asyncio.Semaphore(min(context.scope.policy.max_concurrency, 12))

        async with httpx.AsyncClient(
            timeout=context.timeout,
            follow_redirects=False,
            verify=True,
            headers={"User-Agent": context.user_agent},
        ) as client:
            async def inspect(target: str) -> None:
                context.scope.require(target)
                roots = [target] if "://" in target else [f"https://{target}", f"http://{target}"]
                for root in roots:
                    host = urlparse(root).hostname
                    if not host or not context.scope.allows(host):
                        continue
                    await context.limiter.wait()
                    async with sem:
                        try:
                            response = await client.get(root)
                        except httpx.HTTPError:
                            continue
                    if "text/html" not in response.headers.get("content-type", ""):
                        continue
                    scripts = re.findall(r"(?i)<script[^>]+src=[\"']([^\"']+)", response.text[:2_000_000])
                    for src in scripts[: self.max_scripts_per_target]:
                        script_url = absolute_url(root, src)
                        parsed = urlparse(script_url)
                        if not parsed.hostname or not context.scope.allows(parsed.hostname):
                            continue
                        await context.limiter.wait()
                        async with sem:
                            try:
                                js = await client.get(script_url)
                            except httpx.HTTPError:
                                continue
                        text = js.text[:3_000_000]
                        js_asset = Asset(
                            kind="javascript-resource",
                            value=normalize_url(script_url),
                            source=self.name,
                            attributes={"status_code": js.status_code, "bytes": len(js.content)},
                        )
                        assets.append(js_asset)
                        routes = sorted({m.group(1) for m in _ROUTE.finditer(text)})[:500]
                        normalized_routes: list[str] = []
                        for candidate in routes:
                            absolute = absolute_url(script_url, candidate)
                            hp = urlparse(absolute).hostname
                            if hp and context.scope.allows(hp):
                                normalized_routes.append(normalize_url(absolute))
                        maps = [m.group(1).strip() for m in _SOURCE_MAP.finditer(text)]
                        dependencies = []
                        for dep in sorted(set(m.group(1) for m in _IMPORT.finditer(text)))[:100]:
                            dep_url = absolute_url(script_url, dep)
                            hp = urlparse(dep_url).hostname
                            if hp and context.scope.allows(hp):
                                dependencies.append(normalize_url(dep_url))
                        interesting = sorted(set(m.group(0) for m in _INTERESTING.finditer(text)))[:50]
                        evidence.append(
                            Evidence(
                                asset_id=js_asset.id,
                                engine=self.name,
                                category="javascript-analysis",
                                summary=f"Analyzed JavaScript resource {script_url}",
                                raw={
                                    "script_url": script_url,
                                    "routes": normalized_routes,
                                    "source_maps": maps,
                                    "dependencies": dependencies,
                                    "interesting_markers": interesting,
                                },
                            )
                        )
                        for dep in dependencies:
                            dep_asset = Asset(kind="javascript-dependency", value=dep, source=self.name, attributes={"imported_by": script_url})
                            assets.append(dep_asset)
                        for route in normalized_routes:
                            route_asset = Asset(
                                kind="javascript-endpoint-reference",
                                value=route,
                                source=self.name,
                                attributes={"source_url": script_url},
                            )
                            assets.append(route_asset)
                    break

            await asyncio.gather(*(inspect(t) for t in targets))
        return EngineOutput(assets=assets, evidence=evidence, findings=[])
