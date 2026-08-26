from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.resolver

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Evidence


class DnsEngine(Engine):
    name = "ShadowDNS"

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = context.timeout
        assets: list[Asset] = []
        evidence: list[Evidence] = []

        async def query(host: str, rtype: str) -> tuple[list[str], bool]:
            """Return values and whether the resolver produced an authoritative no-answer.

            False/no-answer is only used for posture findings when the resolver explicitly
            returns NXDOMAIN/NoAnswer. Timeouts and network failures remain unknown.
            """
            await context.limiter.wait()
            try:
                answer = await resolver.resolve(host, rtype, raise_on_no_answer=True)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return [], True
            except Exception:
                return [], False
            return [str(r).rstrip(".") for r in answer], False

        async def inspect(target: str) -> None:
            context.scope.require(target)
            host = context.scope._host(target)
            records: dict[str, list[str]] = {}
            absence: dict[str, bool] = {}
            for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA"):
                values, confirmed_absent = await query(host, rtype)
                records[rtype] = values
                absence[rtype] = confirmed_absent
                if not values:
                    continue
                a = Asset(kind="dns-name", value=host, source=self.name, attributes={"record_type": rtype})
                assets.append(a)
                evidence.append(Evidence(
                    asset_id=a.id,
                    engine=self.name,
                    category="dns",
                    summary=f"{rtype} records observed for {host}",
                    raw={"type": rtype, "values": values},
                ))

            mail_domain = bool(records.get("MX"))
            txt_values = records.get("TXT", [])
            spf_present = any("v=spf1" in value.lower() for value in txt_values)
            evidence.append(Evidence(
                engine=self.name,
                category="dns-posture",
                summary=f"SPF posture evaluated for {host}",
                raw={"check": "SPF", "host": host, "present": spf_present, "mail_domain": mail_domain},
            ))

            if records.get("CAA"):
                caa_present = True
                caa_known = True
            else:
                caa_present = False
                caa_known = absence.get("CAA", False)
            if caa_known:
                evidence.append(Evidence(
                    engine=self.name,
                    category="dns-posture",
                    summary=f"CAA posture evaluated for {host}",
                    raw={"check": "CAA", "host": host, "present": caa_present},
                ))

            dmarc_host = f"_dmarc.{host}"
            dmarc_values, dmarc_absent = await query(dmarc_host, "TXT")
            if dmarc_values:
                evidence.append(Evidence(
                    engine=self.name,
                    category="dns-posture",
                    summary=f"DMARC policy observed for {host}",
                    raw={"check": "DMARC", "host": host, "present": True, "mail_domain": mail_domain, "values": dmarc_values},
                ))
            elif dmarc_absent:
                evidence.append(Evidence(
                    engine=self.name,
                    category="dns-posture",
                    summary=f"DMARC policy not observed for {host}",
                    raw={"check": "DMARC", "host": host, "present": False, "mail_domain": mail_domain},
                ))

        await asyncio.gather(*(inspect(t) for t in targets))
        return EngineOutput(assets=assets, evidence=evidence, findings=[])
