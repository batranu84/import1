from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Evidence
from shadowstrike.utils.endpoints import normalize_url

_JS_ROUTE = re.compile(r"[\"']((?:/|https?://|wss?://)[A-Za-z0-9_./?=&%:@#~+,-]{2,})[\"']")
_ABS_URL = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.I)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_API_HINT = re.compile(r"(?:/api(?:/|\b)|/v[1-9](?:/|\b)|graphql|swagger|openapi|\.json(?:\?|$)|/rest(?:/|\b))", re.I)
_TECH_HEADERS = {"server", "x-powered-by", "x-generator", "x-drupal-cache", "x-shopify-stage", "x-vercel-id", "x-amz-cf-id"}


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links=set(); self.scripts=set(); self.forms=[]; self.meta_refresh=[]; self.meta=[]
    def handle_starttag(self, tag, attrs):
        d={k.lower():v for k,v in attrs if k}
        if tag in {"a","link","iframe","frame","source","img","video","audio","embed","object"}:
            for key in ("href","src","data"):
                if d.get(key): self.links.add(d[key])
        if tag=="script" and d.get("src"): self.scripts.add(d["src"])
        if tag=="form": self.forms.append({"action":d.get("action") or "", "method":(d.get("method") or "get").lower(), "enctype":d.get("enctype")})
        if tag=="meta":
            self.meta.append(d)
            if (d.get("http-equiv") or "").lower()=="refresh" and d.get("content"):
                self.meta_refresh.append(d["content"])


class CrawlerEngine(Engine):
    name="ShadowCrawler"

    def __init__(self, max_pages_per_target: int = 80) -> None:
        self.max_pages_per_target=max_pages_per_target

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        if not context.scope.policy.allow_active_web:
            return EngineOutput(assets=[],evidence=[],findings=[])
        assets=[]; evidence=[]
        page_limit = int(getattr(context.scope.policy,"max_crawl_pages",300)) if getattr(context.scope.policy,"allow_deep_crawl",True) and context.profile in {"full","deep"} else self.max_pages_per_target
        depth_limit = int(getattr(context.scope.policy,"max_crawl_depth",6)) if context.profile in {"full","deep"} else 3
        sem=asyncio.Semaphore(min(context.scope.policy.max_concurrency,32))
        async with httpx.AsyncClient(timeout=max(context.timeout,7),follow_redirects=False,verify=True,headers={"User-Agent":context.user_agent}) as client:
            async def fetch(url):
                await context.limiter.wait()
                async with sem:
                    try: return await client.get(url)
                    except httpx.HTTPError as exc:
                        evidence.append(Evidence(engine=self.name, category="crawl-request-error", summary=f"Crawler request failed for {url}", raw={"url":url,"error":f"{type(exc).__name__}: {exc}"}))
                        return None
            async def crawl(target):
                context.scope.require(target)
                roots=[target] if '://' in target else [f'https://{target}',f'http://{target}']
                roots=[r for r in roots if urlparse(r).hostname and context.scope.allows(urlparse(r).hostname)]
                if not roots: return
                q=deque(); seen=set(); content_hashes=set(); pages=0; hosts=set(); forms=0; api_refs=0; js_refs=0; email_refs=0; external_refs=0; technologies=set(); sitemap_urls=0
                for root in roots:
                    q.extend([(root,0),(urljoin(root,'/robots.txt'),1),(urljoin(root,'/sitemap.xml'),1),(urljoin(root,'/sitemap_index.xml'),1)])
                while q and pages < page_limit:
                    url,depth=q.popleft(); norm=normalize_url(url)
                    if norm in seen or depth>depth_limit: continue
                    seen.add(norm); parsed=urlparse(norm)
                    if not parsed.hostname or not context.scope.allows(parsed.hostname): continue
                    hosts.add(parsed.hostname.lower())
                    resp=await fetch(norm)
                    if resp is None: continue
                    pages+=1; ctype=(resp.headers.get('content-type') or '').lower(); body=resp.text[:5_000_000]
                    digest=hashlib.sha256(resp.content[:3_000_000]).hexdigest(); duplicate=digest in content_hashes; content_hashes.add(digest)
                    tech={k.lower():v for k,v in resp.headers.items() if k.lower() in _TECH_HEADERS and v}
                    for k,v in tech.items(): technologies.add(f"{k}:{v}")
                    a=Asset(kind='web-endpoint',value=norm,source=self.name,attributes={"status_code":resp.status_code,"content_type":ctype,"depth":depth,"content_sha256":digest,"duplicate_content":duplicate,"server":resp.headers.get('server'),"location":resp.headers.get('location'),"technology_headers":tech})
                    assets.append(a); evidence.append(Evidence(asset_id=a.id,engine=self.name,category='endpoint',summary=f'Crawled {norm} ({resp.status_code})',raw=a.attributes|{"url":norm}))
                    loc=resp.headers.get('location')
                    if loc:
                        nxt=urljoin(norm,loc); hp=urlparse(nxt).hostname
                        if hp and context.scope.allows(hp): q.append((nxt,depth+1))
                        elif hp: external_refs+=1; evidence.append(Evidence(engine=self.name,category='out-of-scope-reference',summary=f'Observed out-of-scope redirect reference {hp}',raw={"source_url":norm,"url":nxt,"host":hp,"contacted":False}))
                    if parsed.path.endswith('/robots.txt') or 'text/plain' in ctype:
                        for line in body.splitlines():
                            key,sep,val=line.partition(':')
                            if not sep: continue
                            if key.strip().lower() in {'allow','disallow','sitemap'} and val.strip():
                                nxt=urljoin(norm,val.strip()); hp=urlparse(nxt).hostname
                                if hp and context.scope.allows(hp): q.append((nxt,depth+1))
                    if 'xml' in ctype or parsed.path.endswith('.xml'):
                        for m in re.finditer(r'<loc>\s*([^<]+)\s*</loc>',body,re.I):
                            nxt=m.group(1).strip(); hp=urlparse(nxt).hostname
                            if hp and context.scope.allows(hp): q.append((nxt,depth+1)); sitemap_urls+=1
                    if 'html' in ctype:
                        p=_Parser()
                        try: p.feed(body)
                        except Exception: pass
                        for ref in sorted(p.links|p.scripts):
                            nxt=urljoin(norm,ref); hp=urlparse(nxt).hostname
                            if hp and context.scope.allows(hp): q.append((nxt,depth+1))
                            elif hp: external_refs+=1
                        for f in p.forms:
                            action=urljoin(norm,f['action'] or norm); hp=urlparse(action).hostname
                            if hp and context.scope.allows(hp):
                                forms+=1; fa=Asset(kind='web-form',value=action,source=self.name,attributes={"source_url":norm,"method":f['method'],"enctype":f.get('enctype')})
                                assets.append(fa); evidence.append(Evidence(asset_id=fa.id,engine=self.name,category='web-form',summary=f"Form {f['method'].upper()} {action}",raw=fa.attributes))
                        for item in p.meta_refresh:
                            m=re.search(r'url\s*=\s*(.+)$',item,re.I)
                            if m:
                                nxt=urljoin(norm,m.group(1).strip(' \"\'')); hp=urlparse(nxt).hostname
                                if hp and context.scope.allows(hp): q.append((nxt,depth+1))
                    # Extract routes from HTML/JS/JSON/XML/text. JSON is also recursively inspected for URL-like strings.
                    if any(x in ctype for x in ('javascript','html','json','xml','text')) or parsed.path.endswith(('.js','.json','.map')):
                        refs={m.group(1) for m in _JS_ROUTE.finditer(body)} | set(_ABS_URL.findall(body))
                        if 'json' in ctype:
                            try:
                                obj=json.loads(body)
                                def walk(v):
                                    if isinstance(v,dict):
                                        for x in v.values(): yield from walk(x)
                                    elif isinstance(v,list):
                                        for x in v: yield from walk(x)
                                    elif isinstance(v,str) and (v.startswith('/') or v.startswith('http')): yield v
                                refs.update(walk(obj))
                            except Exception: pass
                        for ref in sorted(refs):
                            nxt=urljoin(norm,ref); hp=urlparse(nxt).hostname
                            if hp and context.scope.allows(hp):
                                kind='api-endpoint-reference' if _API_HINT.search(nxt) else 'javascript-endpoint-reference'
                                api_refs += kind.startswith('api'); js_refs += not kind.startswith('api')
                                ja=Asset(kind=kind,value=normalize_url(nxt),source=self.name,attributes={"source_url":norm})
                                assets.append(ja); evidence.append(Evidence(asset_id=ja.id,engine=self.name,category='api-route' if kind.startswith('api') else 'javascript-route',summary=f'Referenced endpoint {ja.value}',raw=ja.attributes)); q.append((nxt,depth+1))
                            elif hp:
                                external_refs+=1; evidence.append(Evidence(engine=self.name,category='out-of-scope-reference',summary=f'Observed out-of-scope web reference {hp}',raw={"source_url":norm,"url":nxt,"host":hp,"contacted":False}))
                    for email in sorted(set(_EMAIL.findall(body))):
                        dom=email.rsplit('@',1)[1].lower().rstrip('.')
                        if context.scope.allows(dom):
                            email_refs+=1; ea=Asset(kind='email-address',value=email.lower(),source=self.name,attributes={"source_url":norm})
                            assets.append(ea); evidence.append(Evidence(asset_id=ea.id,engine=self.name,category='public-contact',summary=f'Public email reference {email.lower()}',raw=ea.attributes))
                evidence.append(Evidence(engine=self.name,category='crawl-coverage',summary=f'Deep crawl visited {pages} page(s) across {len(hosts)} in-scope host(s)',raw={"roots":roots,"pages":pages,"page_limit":page_limit,"depth_limit":depth_limit,"hosts":sorted(hosts),"unique_content":len(content_hashes),"forms":forms,"api_refs":api_refs,"js_refs":js_refs,"email_refs":email_refs,"external_refs":external_refs,"sitemap_urls":sitemap_urls,"technologies":sorted(technologies)[:100],"queue_remaining":len(q),"limit_reached":pages>=page_limit}))
            await asyncio.gather(*(crawl(t) for t in targets))
        return EngineOutput(assets=assets,evidence=evidence,findings=[])
