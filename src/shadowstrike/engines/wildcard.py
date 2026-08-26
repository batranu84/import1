from __future__ import annotations

import asyncio
import secrets

import dns.asyncresolver

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Evidence


class WildcardDnsEngine(Engine):
    """Detect wildcard DNS behavior for explicitly scoped domain targets."""

    name = "ShadowWildcard"

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = context.timeout
        assets: list[Asset] = []
        evidence: list[Evidence] = []

        async def inspect(target: str) -> None:
            context.scope.require(target)
            host = context.scope._host(target)
            if host.replace(".", "").isdigit():
                return
            probe = f"ss-{secrets.token_hex(8)}.{host}"
            if not context.scope.allows(probe):
                return
            await context.limiter.wait()
            try:
                answer = await resolver.resolve(probe, "A", raise_on_no_answer=False)
            except Exception:
                return
            values = sorted({str(x).rstrip(".") for x in answer})
            if not values:
                return
            asset = Asset(
                kind="dns-wildcard",
                value=host,
                source=self.name,
                attributes={"addresses": values},
            )
            assets.append(asset)
            evidence.append(
                Evidence(
                    asset_id=asset.id,
                    engine=self.name,
                    category="dns-wildcard",
                    summary=f"Wildcard DNS behavior observed for {host}",
                    raw={"probe": probe, "addresses": values},
                )
            )

        await asyncio.gather(*(inspect(t) for t in targets))
        return EngineOutput(assets=assets, evidence=evidence, findings=[])
