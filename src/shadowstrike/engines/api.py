from __future__ import annotations

import asyncio
import json
import re
from typing import Optional
from urllib.parse import urlparse

import httpx

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Evidence
from shadowstrike.utils.endpoints import normalize_url

OPENAPI_PATHS = (
    "/openapi.json", "/swagger.json", "/api/openapi.json", "/api/swagger.json", "/v3/api-docs",
)
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/graphql/", "/gql")
_WS_MARKER = re.compile(r"(?i)\b(?:wss?://[^\s\"'<>]+|websocket)\b")


class ApiDiscoveryEngine(Engine):
    name = "ShadowAPI"

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        if not context.scope.policy.allow_active_web:
            return EngineOutput(assets=[], evidence=[], findings=[])
        assets: list[Asset] = []
        evidence: list[Evidence] = []
        sem = asyncio.Semaphore(min(context.scope.policy.max_concurrency, 10))
        async with httpx.AsyncClient(
            timeout=context.timeout,
            follow_redirects=False,
            verify=True,
            headers={"User-Agent": context.user_agent},
        ) as client:
            async def get(url: str) -> Optional[httpx.Response]:
                await context.limiter.wait()
                async with sem:
                    try:
                        return await client.get(url)
                    except httpx.HTTPError:
                        return None

            async def inspect(target: str) -> None:
                context.scope.require(target)
                bases = [target.rstrip("/")] if "://" in target else [f"https://{target}", f"http://{target}"]
                for base in bases:
                    parsed = urlparse(base)
                    if not parsed.hostname or not context.scope.allows(parsed.hostname):
                        continue
                    base_reachable = False
                    for path in OPENAPI_PATHS:
                        url = base.rstrip("/") + path
                        response = await get(url)
                        if response is None:
                            continue
                        base_reachable = True
                        if response.status_code != 200:
                            continue
                        try:
                            doc = response.json()
                        except (json.JSONDecodeError, ValueError):
                            continue
                        if not isinstance(doc, dict) or not ("openapi" in doc or "swagger" in doc):
                            continue
                        api_asset = Asset(
                            kind="api-schema",
                            value=normalize_url(url),
                            source=self.name,
                            attributes={
                                "format": "openapi",
                                "version": str(doc.get("openapi") or doc.get("swagger") or "unknown"),
                            },
                        )
                        assets.append(api_asset)
                        path_map = doc.get("paths") or {}
                        paths = sorted(path_map.keys())[:2000]
                        methods = 0
                        operation_summaries = []
                        allowed_methods = {"get", "post", "put", "patch", "delete", "options", "head"}
                        for api_path, path_item in list(path_map.items())[:2000]:
                            if not isinstance(path_item, dict):
                                continue
                            inherited = path_item.get("parameters") if isinstance(path_item.get("parameters"), list) else []
                            for method, operation in path_item.items():
                                if method.lower() not in allowed_methods or not isinstance(operation, dict):
                                    continue
                                methods += 1
                                params = []
                                for param in [*inherited, *(operation.get("parameters") or [])]:
                                    if isinstance(param, dict):
                                        params.append({"name": param.get("name"), "in": param.get("in"), "required": bool(param.get("required", False))})
                                op_value = f"{method.upper()} {api_path}"
                                assets.append(Asset(kind="api-operation", value=op_value, source=self.name, attributes={
                                    "schema_url": normalize_url(url), "method": method.upper(), "path": api_path,
                                    "operation_id": operation.get("operationId"), "parameters": params[:100],
                                }))
                                operation_summaries.append({"method": method.upper(), "path": api_path, "parameters": params[:25]})
                        evidence.append(Evidence(
                            asset_id=api_asset.id,
                            engine=self.name,
                            category="api-schema",
                            summary=f"OpenAPI schema discovered at {url}",
                            raw={"url": url, "path_count": len(paths), "operation_count": methods, "paths": paths,
                                 "operations": operation_summaries[:500]},
                        ))

                    for path in GRAPHQL_PATHS:
                        url = base.rstrip("/") + path
                        response = await get(url)
                        if response is None:
                            continue
                        base_reachable = True
                        content_type = response.headers.get("content-type", "")
                        marker = "graphql" in response.text[:100_000].lower() or "application/graphql" in content_type.lower()
                        if response.status_code in {200, 400, 405} and marker:
                            asset = Asset(
                                kind="graphql-endpoint",
                                value=normalize_url(url),
                                source=self.name,
                                attributes={"status_code": response.status_code, "content_type": content_type},
                            )
                            assets.append(asset)
                            evidence.append(Evidence(
                                asset_id=asset.id,
                                engine=self.name,
                                category="graphql-inventory",
                                summary=f"GraphQL endpoint indicator observed at {url}",
                                raw={"url": url, "status_code": response.status_code, "method": "GET", "introspection_attempted": False},
                            ))
                            break

                    if base_reachable:
                        root = await get(base)
                        if root is not None:
                            markers = sorted(set(m.group(0) for m in _WS_MARKER.finditer(root.text[:500_000])))[:25]
                            for marker in markers:
                                if marker.lower().startswith(("ws://", "wss://")):
                                    host = urlparse(marker).hostname
                                    if not host or not context.scope.allows(host):
                                        continue
                                    asset = Asset(kind="websocket-reference", value=marker, source=self.name)
                                    assets.append(asset)
                                    evidence.append(Evidence(
                                        asset_id=asset.id,
                                        engine=self.name,
                                        category="websocket-inventory",
                                        summary=f"WebSocket reference observed from {base}",
                                        raw={"source": base, "reference": marker, "connection_attempted": False},
                                    ))
                        break

            await asyncio.gather(*(inspect(t) for t in targets))
        return EngineOutput(assets=assets, evidence=evidence, findings=[])
