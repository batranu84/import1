from __future__ import annotations

import asyncio
import ipaddress
import socket

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Evidence


class ReconEngine(Engine):
    """Conservative native asset enrichment.

    The engine resolves scoped names and records IP relationships. It does not expand into
    unrelated reverse-DNS space or brute-force external namespaces.
    """

    name = "ShadowRecon"

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        assets: list[Asset] = []
        evidence: list[Evidence] = []
        seen: set[tuple[str, str]] = set()

        async def inspect(target: str) -> None:
            context.scope.require(target)
            host = context.scope._host(target)
            try:
                ipaddress.ip_address(host)
                return
            except ValueError:
                pass
            await context.limiter.wait()
            try:
                infos = await asyncio.get_running_loop().getaddrinfo(
                    host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
                )
            except OSError:
                return
            ips = sorted({info[4][0] for info in infos})
            for ip in ips:
                key = (host, ip)
                if key in seen:
                    continue
                seen.add(key)
                asset = Asset(
                    kind="ip-address",
                    value=ip,
                    source=self.name,
                    attributes={"resolved_from": host},
                )
                assets.append(asset)
                evidence.append(
                    Evidence(
                        asset_id=asset.id,
                        engine=self.name,
                        category="asset-resolution",
                        summary=f"{host} resolved to {ip}",
                        raw={"hostname": host, "ip": ip},
                    )
                )

        await asyncio.gather(*(inspect(t) for t in targets))
        return EngineOutput(assets=assets, evidence=evidence, findings=[])
