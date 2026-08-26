from __future__ import annotations

import ipaddress
from collections import defaultdict
from urllib.parse import urlparse

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Evidence


class IntelligenceGraphEngine(Engine):
    """Maltego-style transform/relationship synthesis over observed assessment evidence.

    Transforms are evidence-preserving and ScopeGuard aware. The engine may create new graph
    entities from already observed data (for example parent domains, IP networks, CPE/product
    entities and certificate SANs) but never contacts a newly derived entity itself.
    """
    name = "ShadowGraphIntel"

    @staticmethod
    def _host(asset: Asset) -> str | None:
        attrs=asset.attributes or {}
        host=str(attrs.get('host') or attrs.get('hostname') or '').strip().lower().rstrip('.')
        if host: return host
        if asset.kind in {'dns-name','domain','ct-dns-name','intel-host'}: return asset.value.lower().rstrip('.')
        if asset.kind in {'web-endpoint','web-application','javascript-endpoint-reference','api-endpoint-reference'}:
            return (urlparse(asset.value).hostname or '').lower().rstrip('.') or None
        return None

    @staticmethod
    def _parent_domain(host: str) -> str | None:
        parts=host.split('.')
        return '.'.join(parts[1:]) if len(parts)>2 else None

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        assets=[]; evidence=[]; entities={}; rels=set(); transform_counts=defaultdict(int)
        def entity(kind,value,**attrs):
            key=(kind,value)
            if key not in entities:
                entities[key]=Asset(kind=kind,value=value,source=self.name,attributes=attrs); assets.append(entities[key])
            return entities[key]
        def rel(src,kind,dst,transform):
            rels.add((src,kind,dst,transform)); transform_counts[transform]+=1

        for a in context.assets or []:
            attrs=a.attributes or {}; host=self._host(a)
            if host and context.scope.allows(host):
                h=entity('intel-host',host,source_kind=a.kind)
                parent=self._parent_domain(host)
                if parent and context.scope.allows(parent): entity('intel-domain',parent); rel(host,'subdomain-of',parent,'dns-parent')
                if a.kind=='ip-address': rel(host,'resolves-to',a.value,'dns-ip')
                elif a.kind in {'network-service','transport-endpoint'}:
                    port=attrs.get('port'); transport=attrs.get('transport','tcp')
                    if port is not None:
                        svc=entity('intel-service',f'{host}:{port}/{transport}',port=port,transport=transport,service=attrs.get('service_name'),state=attrs.get('service_state'))
                        rel(host,'exposes',svc.value,'service')
                        product=attrs.get('product'); version=attrs.get('version')
                        if product:
                            pval=f"{product} {version or ''}".strip(); entity('intel-product',pval,version=version); rel(svc.value,'identified-as',pval,'product-version')
                        for cpe in attrs.get('cpe') or []: entity('intel-cpe',str(cpe)); rel(svc.value,'maps-to-cpe',str(cpe),'cpe')
                elif a.kind in {'web-endpoint','web-application','javascript-endpoint-reference','api-endpoint-reference'}:
                    u=entity('intel-url',a.value); rel(host,'serves',u.value,'web')
                elif a.kind=='operating-system':
                    osn=entity('intel-os',a.value); rel(host,'runs',osn.value,'os')
                elif a.kind in {'tls-certificate','certificate','certificate-chain-member'}:
                    c=entity('intel-certificate',a.value); rel(host,'presents',c.value,'certificate')
                elif a.kind=='network-device':
                    vendor=attrs.get('vendor')
                    if vendor: entity('intel-vendor',str(vendor)); rel(host,'vendor',str(vendor),'vendor')
            if a.kind in {'email-address','contact'} and '@' in a.value:
                dom=a.value.rsplit('@',1)[1].lower().rstrip('.')
                if context.scope.allows(dom):
                    c=entity('intel-contact',a.value.lower()); entity('intel-host',dom); rel(c.value,'belongs-to',dom,'contact-domain')
            if a.kind=='ip-address':
                try:
                    ip=ipaddress.ip_address(a.value)
                    prefix=24 if ip.version==4 else 64; net=str(ipaddress.ip_network(f'{ip}/{prefix}',strict=False))
                    entity('intel-network',net); rel(a.value,'member-of',net,'ip-network')
                except ValueError: pass

        for ev in context.evidence or []:
            raw=ev.raw or {}; host=str(raw.get('host') or '').lower().rstrip('.')
            for san in raw.get('san_dns_names') or []:
                san=str(san).lower().rstrip('.')
                clean=san[2:] if san.startswith('*.') else san
                if host and context.scope.allows(host) and context.scope.allows(clean):
                    entity('intel-host',host); entity('intel-host',clean); rel(host,'certificate-san',clean,'certificate-san')
            if ev.category=='certificate-transparency-summary':
                base=str(raw.get('base_domain') or '').lower().rstrip('.')
                for name in raw.get('names') or []:
                    name=str(name).lower().rstrip('.')
                    if base and context.scope.allows(name): entity('intel-host',name); entity('intel-domain',base); rel(name,'ct-observed-for',base,'certificate-transparency')
            if ev.category in {'dns-a','dns-aaaa','dns-answer'}:
                for ip in raw.get('answers') or raw.get('addresses') or []:
                    if host: entity('intel-host',host); entity('intel-ip',str(ip)); rel(host,'resolves-to',str(ip),'dns-ip')
            if ev.category in {'nmap-port-script','nmap-host-script'} and host:
                sid=str(raw.get('id') or 'nse'); n=entity('intel-observation',f'{host}:{sid}',script=sid); rel(host,'nmap-observation',n.value,'nmap-nse')

        degree=defaultdict(int)
        for src,r,dst,transform in sorted(rels):
            degree[src]+=1; degree[dst]+=1
            evidence.append(Evidence(engine=self.name,category='intelligence-relationship',summary=f'{src} --{r}--> {dst}',raw={'source':src,'relationship':r,'target':dst,'transform':transform}))
        evidence.append(Evidence(engine=self.name,category='intelligence-graph-summary',summary=f'Intelligence graph synthesized {len(entities)} entities and {len(rels)} relationships',raw={'entities':len(entities),'relationships':len(rels),'transform_counts':dict(sorted(transform_counts.items())),'top_connected':sorted(degree.items(),key=lambda x:x[1],reverse=True)[:50]}))
        return EngineOutput(assets=assets,evidence=evidence,findings=[])
