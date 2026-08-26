from __future__ import annotations

import asyncio
import json
import re
import ipaddress
import shutil
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.engines.tls import _candidate_endpoints
from shadowstrike.models.domain import Asset, Confidence, Evidence, Finding, Severity

_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


class CertificateIntelligenceEngine(Engine):
    """Certificate-chain, hostname, CT and lifecycle intelligence for scoped TLS assets."""
    name = "ShadowCerts"

    @staticmethod
    def _base_domain(host: str) -> str:
        parts=host.lower().rstrip('.').split('.')
        return '.'.join(parts[-2:]) if len(parts)>=2 else host

    async def _openssl_chain(self, host: str, port: int, context: EngineContext) -> tuple[list[Asset], list[Evidence]]:
        path=shutil.which('openssl')
        if not path: return [], [Evidence(engine=self.name,category='certificate-chain-coverage',summary='OpenSSL unavailable; full presented chain not collected',raw={'host':host,'port':port,'available':False})]
        cmd=[path,'s_client','-showcerts','-servername',host,'-connect',f'{host}:{port}']
        try:
            proc=await asyncio.create_subprocess_exec(*cmd,stdin=asyncio.subprocess.DEVNULL,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
            stdout,stderr=await asyncio.wait_for(proc.communicate(),timeout=max(10.0,context.timeout*3))
        except Exception as exc:
            return [], [Evidence(engine=self.name,category='certificate-chain-coverage',summary=f'Certificate chain collection failed for {host}:{port}',raw={'host':host,'port':port,'error':f'{type(exc).__name__}: {exc}'})]
        text=(stdout+stderr).decode('utf-8','replace'); blocks=_PEM_RE.findall(text)
        assets=[]; evidence=[]; chain=[]
        for idx,pem in enumerate(blocks[:10]):
            try: cert=x509.load_pem_x509_certificate(pem.encode())
            except Exception: continue
            fp=cert.fingerprint(hashes.SHA256()).hex()
            attrs={'host':host,'port':port,'chain_index':idx,'subject':cert.subject.rfc4514_string(),'issuer':cert.issuer.rfc4514_string(),'serial_number':format(cert.serial_number,'x'),'not_before':cert.not_valid_before_utc.isoformat(),'not_after':cert.not_valid_after_utc.isoformat(),'sha256':fp,'is_self_issued':cert.subject==cert.issuer}
            ca=Asset(kind='certificate-chain-member',value=f'{host}:{port}:{idx}:{fp}',source=self.name,attributes=attrs); assets.append(ca); chain.append(attrs)
            evidence.append(Evidence(asset_id=ca.id,engine=self.name,category='certificate-chain-member',summary=f'Presented certificate chain member {idx} for {host}:{port}',raw=attrs,fingerprint=fp))
        evidence.append(Evidence(engine=self.name,category='certificate-chain-summary',summary=f'Collected {len(chain)} presented certificate(s) for {host}:{port}',raw={'host':host,'port':port,'chain_length':len(chain),'verify_returncode':proc.returncode,'chain':chain}))
        return assets,evidence

    async def _ct_lookup(self, host: str, context: EngineContext) -> tuple[list[Asset], list[Evidence]]:
        base=self._base_domain(host)
        if not context.scope.allows(base) and not context.scope.allows(host): return [],[]
        url=f'https://crt.sh/?q=%25.{base}&output=json'
        try:
            async with httpx.AsyncClient(timeout=max(8.0,context.timeout*2),headers={'User-Agent':context.user_agent}) as client:
                resp=await client.get(url)
            if resp.status_code!=200:
                return [],[Evidence(engine=self.name,category='certificate-transparency-coverage',summary=f'CT lookup returned HTTP {resp.status_code} for {base}',raw={'base_domain':base,'status_code':resp.status_code})]
            rows=resp.json()
        except Exception as exc:
            return [],[Evidence(engine=self.name,category='certificate-transparency-coverage',summary=f'CT lookup unavailable for {base}',raw={'base_domain':base,'error':f'{type(exc).__name__}: {exc}'})]
        names=set(); issuers=set(); cert_ids=set()
        for row in rows[:5000] if isinstance(rows,list) else []:
            if not isinstance(row,dict): continue
            cert_ids.add(str(row.get('id') or ''))
            if row.get('issuer_name'): issuers.add(str(row['issuer_name']))
            for name in str(row.get('name_value') or '').splitlines():
                n=name.strip().lower().rstrip('.')
                if n.startswith('*.'): n=n[2:]
                if n and (context.scope.allows(n) or n==base): names.add(n)
        assets=[Asset(kind='ct-dns-name',value=n,source=self.name,attributes={'base_domain':base,'contacted':False,'scope_allowed':context.scope.allows(n)}) for n in sorted(names)]
        evidence=[Evidence(asset_id=a.id,engine=self.name,category='certificate-transparency-name',summary=f'Certificate Transparency referenced {a.value}',raw=a.attributes) for a in assets]
        evidence.append(Evidence(engine=self.name,category='certificate-transparency-summary',summary=f'CT intelligence found {len(names)} in-scope DNS name(s) for {base}',raw={'base_domain':base,'names':sorted(names)[:1000],'issuers':sorted(issuers)[:100],'certificate_record_count':len(cert_ids),'query_url':url}))
        return assets,evidence

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        assets=[]; evidence=[]; findings=[]
        ct_done=set()
        for host, port, _source in _candidate_endpoints(targets, context.assets or [])[:128]:
            if not context.scope.allows(host): continue
            matches=[e for e in (context.evidence or []) if e.category=='tls-certificate' and (e.raw or {}).get('host')==host and int((e.raw or {}).get('port') or 0)==port]
            for ev in matches:
                raw=ev.raw or {}; san=[str(x) for x in raw.get('san_dns_names') or []]
                cert=Asset(kind='certificate',value=f"{host}:{port}:{raw.get('sha256','unknown')}",source=self.name,attributes={**raw,'hostname':host,'port':port,'san_count':len(san),'wildcard_sans':[x for x in san if x.startswith('*.')]})
                assets.append(cert); evidence.append(Evidence(asset_id=cert.id,engine=self.name,category='certificate-posture',summary=f'Certificate posture analyzed for {host}:{port}',raw=cert.attributes))
                covered=False
                for name in san:
                    low=name.lower().rstrip('.')
                    if low==host.lower().rstrip('.'): covered=True
                    elif low.startswith('*.') and host.lower().endswith(low[1:]) and host.count('.')==low.count('.'): covered=True
                if san and not covered:
                    findings.append(Finding(title='TLS certificate hostname mismatch',severity=Severity.MEDIUM,confidence=Confidence.CONFIRMED,affected_asset=f'{host}:{port}',description=f'The presented certificate SAN set does not cover {host}.',remediation='Deploy a certificate whose SAN set explicitly covers the intended hostname and verify SNI/virtual-host routing.',evidence_ids=[ev.id],tags=['tls','certificate','hostname','evidence-backed'],cwe='CWE-297'))
                if len(san)>100:
                    evidence.append(Evidence(asset_id=cert.id,engine=self.name,category='certificate-large-san-set',summary=f'Certificate on {host}:{port} contains {len(san)} DNS SAN entries',raw={'host':host,'port':port,'san_count':len(san)}))
            ca,ce=await self._openssl_chain(host,port,context); assets.extend(ca); evidence.extend(ce)
            try:
                ipaddress.ip_address(host); is_ip=True
            except ValueError:
                is_ip=False
            base=self._base_domain(host)
            if not is_ip and base not in ct_done:
                ct_done.add(base); ta,te=await self._ct_lookup(host,context); assets.extend(ta); evidence.extend(te)
        if not assets:
            evidence.append(Evidence(engine=self.name,category='certificate-coverage',summary='No TLS certificate evidence was available for deep certificate analysis',raw={'status':'no-certificate-evidence'}))
        return EngineOutput(assets=assets,evidence=evidence,findings=findings)
