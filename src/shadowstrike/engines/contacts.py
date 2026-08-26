from __future__ import annotations

import asyncio
import html
import ipaddress
import io
import re
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Evidence
from shadowstrike.utils.endpoints import absolute_url, normalize_url

_EMAIL_RE = re.compile(r"(?i)(?<![A-Z0-9._%+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63})(?![A-Z0-9._%+-])")
_OBFUSCATED_RE = re.compile(
    r"(?ix)(?<![A-Z0-9._%+-])([A-Z0-9._%+-]{1,64})\s*(?:\[|\(|\{)?\s*(?:at|@)\s*(?:\]|\)|\})?\s*"
    r"([A-Z0-9.-]{1,200}?)\s*(?:\[|\(|\{)?\s*(?:dot|\.)\s*(?:\]|\)|\})?\s*([A-Z]{2,63})(?![A-Z0-9._%+-])"
)
_CONTACT_RE = re.compile(r"(?im)^Contact:\s*(?:mailto:)?([^\s<>]+@[^\s<>]+)$")
_CFEMAIL_RE = re.compile(r'(?i)(?:data-cfemail|__cf_email__)[=\"\'\s:>]+([0-9a-f]{6,})')
_SITEMAP_LOC_RE = re.compile(r"(?is)<loc>\s*(https?://[^<\s]+)\s*</loc>")
_ROBOTS_SITEMAP_RE = re.compile(r"(?im)^\s*Sitemap:\s*(https?://\S+)\s*$")

_ROLE_PREFIXES = {
    "security": "security",
    "abuse": "abuse",
    "privacy": "privacy",
    "dpo": "privacy",
    "support": "support",
    "help": "support",
    "sales": "sales",
    "info": "general",
    "admin": "administrative",
    "administrator": "administrative",
    "webmaster": "technical",
    "hostmaster": "technical",
    "noc": "technical",
    "tech": "technical",
    "press": "press",
    "media": "press",
    "hr": "hr",
    "jobs": "hr",
    "careers": "hr",
}


class _ContactLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()
        self.mailtos: set[str] = set()
        self.cfemails: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        data = dict(attrs)
        href = data.get("href") or ""
        if href.lower().startswith("mailto:"):
            self.mailtos.add(href[7:].split("?", 1)[0])
        elif tag in {"a", "link", "script"} and href:
            self.links.add(href)
        if tag == "script" and data.get("src"):
            self.links.add(data["src"] or "")
        cf = data.get("data-cfemail")
        if cf:
            self.cfemails.add(cf)


def _decode_cfemail(value: str) -> Optional[str]:
    try:
        data = bytes.fromhex(value)
        if len(data) < 2:
            return None
        key = data[0]
        decoded = bytes(b ^ key for b in data[1:]).decode("utf-8", "ignore")
        return decoded if "@" in decoded else None
    except (ValueError, UnicodeError):
        return None


def _decode_script_escapes(text: str) -> str:
    return (
        text.replace("\\u0040", "@").replace("\\u002e", ".").replace("\\u002E", ".")
        .replace("\\x40", "@").replace("\\x2e", ".").replace("\\x2E", ".")
        .replace("&#64;", "@").replace("&#46;", ".")
    )


def _classify_role(address: str) -> str:
    local = address.split("@", 1)[0].lower()
    token = re.split(r"[._+-]", local, maxsplit=1)[0]
    return _ROLE_PREFIXES.get(token, "personal/public")


def _extract_pdf_text(content: bytes) -> str:
    try:
        from pypdf import PdfReader  # optional at runtime; launcher installs it in 0.9.2
    except Exception:
        return ""
    try:
        reader = PdfReader(io.BytesIO(content), strict=False)
        chunks: list[str] = []
        for page in reader.pages[:100]:
            try:
                chunks.append(page.extract_text() or "")
            except Exception:
                continue
        return "\n".join(chunks)[:4_000_000]
    except Exception:
        return ""


class ContactDiscoveryEngine(Engine):
    """Discover public, in-scope contact addresses without generating mailbox names.

    The engine follows in-scope HTML, JavaScript/text resources, sitemap indexes and public
    PDF documents. It also recognizes common human-readable address obfuscation. Results are
    deduplicated by address and preserve all observed source URLs.
    """

    name = "ShadowContacts"

    def __init__(self, max_pages_per_target: int = 1500, max_contacts_per_target: int = 25000) -> None:
        self.max_pages_per_target = max_pages_per_target
        self.max_contacts_per_target = max_contacts_per_target

    @staticmethod
    def _allowed_email_domain(email: str, context: EngineContext, target_host: str) -> bool:
        try:
            domain = email.rsplit("@", 1)[1].lower().strip(".")
        except Exception:
            return False
        candidates: set[str] = set()
        host_candidate = target_host.lower().strip(".")
        try:
            ipaddress.ip_address(host_candidate)
        except ValueError:
            if "." in host_candidate:
                candidates.add(host_candidate)
        for item in context.scope.policy.allowed_domains:
            base = item.lower().strip().lstrip("*.").strip(".")
            if base:
                candidates.add(base)
        return any(domain == base or domain.endswith("." + base) for base in candidates)

    @staticmethod
    def _seed_urls(target: str, context: EngineContext) -> list[str]:
        seeds: list[str] = []
        target_host = urlparse(target if "://" in target else f"https://{target}").hostname or target
        for asset in context.assets:
            if asset.kind not in {"web-endpoint", "web-application", "javascript-resource", "javascript-endpoint-reference"}:
                continue
            parsed = urlparse(asset.value)
            if parsed.scheme in {"http", "https"} and parsed.hostname and context.scope.allows(parsed.hostname):
                if parsed.hostname == target_host or parsed.hostname.endswith("." + target_host) or target_host.endswith("." + parsed.hostname):
                    seeds.append(asset.value)
        roots = [target] if "://" in target else [f"https://{target}", f"http://{target}"]
        seeds.extend(roots)
        paths = [
            "/.well-known/security.txt", "/security.txt", "/contact", "/contact-us",
            "/about", "/about-us", "/team", "/people", "/leadership", "/staff",
            "/support", "/help", "/privacy", "/privacy-policy", "/legal", "/terms",
            "/press", "/media", "/careers", "/jobs", "/robots.txt", "/sitemap.xml",
            "/sitemap_index.xml", "/wp-sitemap.xml",
        ]
        for root in roots:
            seeds.extend(absolute_url(root, path) for path in paths)
        out: list[str] = []
        seen: set[str] = set()
        for url in seeds:
            try:
                norm = normalize_url(url)
            except Exception:
                continue
            if norm not in seen:
                seen.add(norm)
                out.append(url)
        return out

    @staticmethod
    def _extract_candidates(text: str) -> set[str]:
        decoded = _decode_script_escapes(html.unescape(text))
        candidates = {m.group(1) for m in _EMAIL_RE.finditer(decoded)}
        for m in _OBFUSCATED_RE.finditer(decoded):
            candidates.add(f"{m.group(1)}@{m.group(2).strip('. ')}.{m.group(3)}")
        return candidates

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        if not context.scope.policy.allow_active_web:
            return EngineOutput(assets=[], evidence=[], findings=[])

        assets: list[Asset] = []
        evidence: list[Evidence] = []
        sem = asyncio.Semaphore(min(context.scope.policy.max_concurrency, 12))

        async with httpx.AsyncClient(
            timeout=max(context.timeout, 5.0),
            follow_redirects=True,
            verify=True,
            headers={"User-Agent": context.user_agent},
        ) as client:
            async def inspect_target(target: str) -> None:
                context.scope.require(target)
                parsed_target = urlparse(target if "://" in target else f"https://{target}")
                target_host = parsed_target.hostname or ""
                queue = self._seed_urls(target, context)
                queued: set[str] = set()
                for seed in queue:
                    try:
                        queued.add(normalize_url(seed))
                    except Exception:
                        pass
                visited: set[str] = set()
                address_sources: dict[str, set[str]] = {}
                address_methods: dict[str, set[str]] = {}

                while queue and len(visited) < self.max_pages_per_target and len(address_sources) < self.max_contacts_per_target:
                    url = queue.pop(0)
                    try:
                        norm = normalize_url(url)
                    except Exception:
                        continue
                    if norm in visited:
                        continue
                    visited.add(norm)
                    parsed = urlparse(url)
                    if not parsed.hostname or not context.scope.allows(parsed.hostname):
                        continue
                    await context.limiter.wait()
                    async with sem:
                        try:
                            response = await client.get(url)
                        except httpx.HTTPError:
                            continue
                    final_url = str(response.url)
                    final_parsed = urlparse(final_url)
                    if not final_parsed.hostname or not context.scope.allows(final_parsed.hostname):
                        continue
                    content_type = response.headers.get("content-type", "").lower()
                    body = response.content[:10_000_000]
                    is_pdf = "application/pdf" in content_type or final_parsed.path.lower().endswith(".pdf")
                    if is_pdf:
                        text = await asyncio.to_thread(_extract_pdf_text, body)
                    else:
                        is_text = any(x in content_type for x in ("text", "json", "xml", "javascript", "html"))
                        if not is_text and not final_parsed.path.endswith(("security.txt", "robots.txt", "sitemap.xml", ".js", ".json", ".xml", ".vcf")):
                            continue
                        text = response.text[:4_000_000]
                    if not text:
                        continue

                    source_norm = normalize_url(final_url)
                    candidates = self._extract_candidates(text)
                    if final_parsed.path.endswith("security.txt"):
                        candidates.update(m.group(1) for m in _CONTACT_RE.finditer(text))

                    parser = _ContactLinkParser()
                    looks_html = "html" in content_type or "<html" in text[:500].lower()
                    if looks_html:
                        try:
                            parser.feed(text)
                        except Exception:
                            pass
                        candidates.update(parser.mailtos)
                        for encoded in parser.cfemails | set(_CFEMAIL_RE.findall(text)):
                            decoded = _decode_cfemail(encoded)
                            if decoded:
                                candidates.add(decoded)
                        for href in sorted(parser.links):
                            absolute = urljoin(final_url, href)
                            ap = urlparse(absolute)
                            if not ap.hostname or not context.scope.allows(ap.hostname):
                                continue
                            try:
                                candidate_norm = normalize_url(absolute)
                            except Exception:
                                continue
                            if candidate_norm not in visited and candidate_norm not in queued and len(queued) < self.max_pages_per_target * 8:
                                queued.add(candidate_norm)
                                queue.append(absolute)

                    if final_parsed.path.endswith("robots.txt"):
                        for sitemap in _ROBOTS_SITEMAP_RE.findall(text):
                            sp = urlparse(sitemap)
                            if sp.hostname and context.scope.allows(sp.hostname):
                                try:
                                    sn = normalize_url(sitemap)
                                except Exception:
                                    continue
                                if sn not in visited and sn not in queued:
                                    queued.add(sn)
                                    queue.append(sitemap)
                    if "xml" in content_type or "sitemap" in final_parsed.path.lower():
                        for sitemap_url in _SITEMAP_LOC_RE.findall(text):
                            sp = urlparse(sitemap_url)
                            if not sp.hostname or not context.scope.allows(sp.hostname):
                                continue
                            try:
                                sn = normalize_url(sitemap_url)
                            except Exception:
                                continue
                            if sn not in visited and sn not in queued and len(queued) < self.max_pages_per_target * 8:
                                queued.add(sn)
                                queue.append(sitemap_url)

                    for address in candidates:
                        clean = address.strip().strip(".,;:()[]{}<>\"'").lower()
                        if not self._allowed_email_domain(clean, context, target_host):
                            continue
                        address_sources.setdefault(clean, set()).add(source_norm)
                        methods = address_methods.setdefault(clean, set())
                        methods.add("public-reference")
                        if clean in {x.lower() for x in parser.mailtos}:
                            methods.add("mailto")
                        if final_parsed.path.endswith("security.txt"):
                            methods.add("security.txt")
                        if is_pdf:
                            methods.add("public-pdf")

                for clean in sorted(address_sources):
                    sources = sorted(address_sources[clean])
                    email_domain = clean.rsplit("@", 1)[1]
                    role = _classify_role(clean)
                    asset = Asset(
                        kind="email-contact",
                        value=clean,
                        source=self.name,
                        attributes={
                            "domain": email_domain,
                            "source_url": sources[0] if sources else "",
                            "source_urls": sources,
                            "source_count": len(sources),
                            "discovery": sorted(address_methods.get(clean, {"public-reference"})),
                            "role": role,
                            "confidence": "confirmed-public-reference",
                            "verified_mailbox": False,
                        },
                    )
                    assets.append(asset)
                    evidence.append(
                        Evidence(
                            asset_id=asset.id,
                            engine=self.name,
                            category="contact-email",
                            summary=f"Publicly referenced in-scope email address {clean}",
                            raw={
                                "email": clean,
                                "domain": email_domain,
                                "role": role,
                                "source_urls": sources,
                                "source_count": len(sources),
                                "discovery": sorted(address_methods.get(clean, {"public-reference"})),
                                "verification": "publicly-referenced-only",
                                "pages_inspected": len(visited),
                            },
                        )
                    )

                evidence.append(Evidence(
                    engine=self.name,
                    category="contact-discovery-summary",
                    summary=f"Contact discovery inspected {len(visited)} public in-scope resource(s) and found {len(address_sources)} unique public email reference(s) for {target_host or target}",
                    raw={
                        "target": target,
                        "target_host": target_host,
                        "pages_inspected": len(visited),
                        "unique_contacts_found": len(address_sources),
                        "unique_source_urls": len({u for urls in address_sources.values() for u in urls}),
                        "page_limit": self.max_pages_per_target,
                        "contact_limit": self.max_contacts_per_target,
                        "page_limit_reached": len(visited) >= self.max_pages_per_target,
                        "contact_limit_reached": len(address_sources) >= self.max_contacts_per_target,
                        "generated_mailbox_names": False,
                        "mailbox_verification_performed": False,
                    },
                ))

            await asyncio.gather(*(inspect_target(target) for target in targets))

        return EngineOutput(assets=assets, evidence=evidence, findings=[])
