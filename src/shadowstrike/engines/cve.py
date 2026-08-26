from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import quote

import httpx

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Confidence, Evidence, Finding, Severity

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OpenSSH", re.compile(r"(?i)OpenSSH[_/ -]?([0-9][0-9A-Za-z.+p-]*)")),
    ("Exim", re.compile(r"(?i)Exim\s+([0-9][0-9A-Za-z.+-]*)")),
    ("Dovecot", re.compile(r"(?i)Dovecot(?:\s+ready)?[^0-9]{0,12}([0-9]+(?:\.[0-9A-Za-z+-]+){1,4})")),
    ("Pure-FTPd", re.compile(r"(?i)Pure-FTPd(?:\s+|/)([0-9][0-9A-Za-z.+-]*)")),
    ("nginx", re.compile(r"(?i)nginx/([0-9][0-9A-Za-z.+-]*)")),
    ("Apache HTTP Server", re.compile(r"(?i)Apache/([0-9][0-9A-Za-z.+-]*)")),
    ("LiteSpeed", re.compile(r"(?i)LiteSpeed(?:/|\s+)([0-9][0-9A-Za-z.+-]*)")),
    ("Microsoft IIS", re.compile(r"(?i)Microsoft-IIS/([0-9][0-9A-Za-z.+-]*)")),
    ("Apache Tomcat", re.compile(r"(?i)(?:Apache[- ]Tomcat|Tomcat)/?\s*([0-9][0-9A-Za-z.+-]*)")),
    ("Jetty", re.compile(r"(?i)Jetty(?:\(|/|\s+)([0-9][0-9A-Za-z.+-]*)")),
    ("Redis", re.compile(r"(?i)redis(?:_version:|/|\s+)([0-9]+(?:\.[0-9A-Za-z+-]+){1,4})")),
    ("PostgreSQL", re.compile(r"(?i)PostgreSQL(?:/|\s+)([0-9]+(?:\.[0-9A-Za-z+-]+){0,4})")),
    ("MySQL", re.compile(r"(?i)(?:MySQL|mysql)(?:/|\s+)([0-9]+(?:\.[0-9A-Za-z+-]+){1,4})")),
    ("MongoDB", re.compile(r"(?i)MongoDB(?:/|\s+| v)([0-9]+(?:\.[0-9A-Za-z+-]+){1,4})")),
    ("Elasticsearch", re.compile(r"(?i)Elasticsearch(?:/|\s+)([0-9]+(?:\.[0-9A-Za-z+-]+){1,4})")),
    ("Docker", re.compile(r"(?i)Docker(?:/|\s+)([0-9]+(?:\.[0-9A-Za-z+-]+){1,4})")),
]


@dataclass(frozen=True)
class SoftwareFingerprint:
    product: str
    version: str
    asset_id: Optional[str]
    asset_value: str
    evidence_ids: tuple[str, ...]


def parse_product_version(text: str) -> Optional[tuple[str, str]]:
    for product, pattern in _PATTERNS:
        match = pattern.search(text or "")
        if match:
            return product, match.group(1).strip(".,;)")
    return None


def _norm_cpe_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower().replace("\\", "")).strip("_")


def _product_aliases(product: str) -> set[str]:
    normalized = _norm_cpe_token(product)
    aliases = {normalized} if normalized else set()
    known = {
        # Common normalized names emitted by native banners and Nmap service/version XML.
        "apache_http_server": {"http_server"},
        "apache_httpd": {"http_server"},
        "apache_tomcat": {"tomcat"},
        "microsoft_iis": {"internet_information_services", "iis"},
        "microsoft_iis_httpd": {"internet_information_services", "iis"},
        "microsoft_internet_information_services": {"internet_information_services", "iis"},
        "microsoft_sql_server": {"sql_server"},
        "microsoft_sql_server_database_engine": {"sql_server"},
        "oracle_mysql": {"mysql"},
        "mysql": {"mysql"},
        "postgresql": {"postgresql"},
        "redis": {"redis"},
        "mongodb": {"mongodb"},
        "elasticsearch": {"elasticsearch"},
        "openssh": {"openssh"},
        "nginx": {"nginx"},
        "docker": {"docker"},
        "docker_engine": {"docker"},
        "vmware_esxi": {"esxi"},
        "proxmox_virtual_environment": {"proxmox_virtual_environment"},
    }
    aliases.update(known.get(normalized, set()))
    return aliases


def _walk_cpe_matches(nodes: Iterable[dict]) -> Iterable[str]:
    for node in nodes or []:
        for item in node.get("cpeMatch", []) or []:
            criteria = item.get("criteria")
            if criteria:
                yield str(criteria)
        children = node.get("nodes", []) or []
        if children:
            yield from _walk_cpe_matches(children)


def _exact_version_cpe(vulnerability: dict, product: str, version: str) -> bool:
    """Require exact CPE product + version, not a vendor-word substring match.

    The previous implementation accepted the first word of a product name anywhere in the
    CPE string. For example, ``Apache HTTP Server 2.4.x`` could accidentally match an
    unrelated Apache product carrying the same version. High-fidelity correlation requires
    the CPE product component itself to match a conservative product alias.
    """
    aliases = _product_aliases(product)
    expected_version = str(version).strip().lower()
    if not aliases or not expected_version:
        return False
    configurations = vulnerability.get("cve", {}).get("configurations", []) or []
    for config in configurations:
        for criteria in _walk_cpe_matches(config.get("nodes", []) or []):
            parts = str(criteria).split(":")
            if len(parts) < 6 or parts[0].lower() != "cpe" or parts[1] != "2.3":
                continue
            cpe_product = _norm_cpe_token(parts[4])
            cpe_version = str(parts[5]).lower()
            if cpe_version == expected_version and cpe_product in aliases:
                return True
    return False


def _cvss_score(cve: dict) -> Optional[float]:
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key, []) or []
        if not values:
            continue
        data = values[0].get("cvssData", {}) or {}
        value = data.get("baseScore")
        if value is not None:
            try:
                return float(value)
            except (TypeError, ValueError):
                pass
    return None


def _weaknesses(cve: dict) -> list[str]:
    found: list[str] = []
    for weakness in cve.get("weaknesses", []) or []:
        for desc in weakness.get("description", []) or []:
            value = str(desc.get("value", ""))
            if value.startswith("CWE-") and value not in found:
                found.append(value)
    return found


def _severity(score: Optional[float]) -> Severity:
    if score is None:
        return Severity.INFO
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


class CveIntelligenceEngine(Engine):
    """Correlate exact observed software versions with NVD CPE data.

    Results remain candidates: the engine does not execute exploits or assert that a CVE
    is reachable merely because a version appears in a banner.
    """

    name = "ShadowCVE"

    def __init__(self, max_fingerprints: int = 64, max_cves_per_product: int = 12) -> None:
        self.max_fingerprints = max_fingerprints
        self.max_cves_per_product = max_cves_per_product

    def _fingerprints(self, context: EngineContext) -> list[SoftwareFingerprint]:
        assets = context.assets or []
        evidence = context.evidence or []
        evidence_by_asset: dict[str, list[str]] = {}
        text_by_asset: dict[str, list[str]] = {}
        for item in evidence:
            if item.asset_id:
                key = str(item.asset_id)
                evidence_by_asset.setdefault(key, []).append(str(item.id))
                raw = item.raw or {}
                parts = [item.summary]
                for value in raw.values():
                    if isinstance(value, (str, int, float)):
                        parts.append(str(value))
                    elif isinstance(value, dict):
                        parts.extend(str(v) for v in value.values() if isinstance(v, (str, int, float)))
                text_by_asset.setdefault(key, []).append(" ".join(parts))

        unique: dict[tuple[str, str, str], SoftwareFingerprint] = {}
        for asset in assets:
            attrs = asset.attributes or {}
            # Specialist/version-aware engines frequently provide product and version as
            # separate normalized fields. Treat that pair as direct observed version
            # evidence instead of requiring a banner string to repeat both tokens.
            explicit_product = str(attrs.get("product") or "").strip()
            explicit_version = str(attrs.get("version") or "").strip()
            identity_confirmed = asset.kind != "network-service" or str(attrs.get("service_state") or "").lower() == "confirmed"
            if explicit_product and explicit_version and identity_confirmed and re.match(r"^[0-9]", explicit_version):
                fp = SoftwareFingerprint(
                    product=explicit_product, version=explicit_version, asset_id=str(asset.id),
                    asset_value=asset.value,
                    evidence_ids=tuple(evidence_by_asset.get(str(asset.id), [])),
                )
                unique[(explicit_product.lower(), explicit_version.lower(), asset.value.lower())] = fp
            candidates: list[str] = []
            for key in ("banner", "server", "application_evidence", "service_banner", "product", "version", "software", "tls_banner"):
                if attrs.get(key):
                    candidates.append(str(attrs[key]))
            candidates.extend(text_by_asset.get(str(asset.id), []))
            # Common service assets may store host separately; keep the finding tied to the concrete endpoint.
            for text in candidates:
                parsed = parse_product_version(text)
                if not parsed:
                    continue
                product, version = parsed
                fp = SoftwareFingerprint(
                    product=product, version=version, asset_id=str(asset.id),
                    asset_value=asset.value,
                    evidence_ids=tuple(evidence_by_asset.get(str(asset.id), [])),
                )
                unique[(product.lower(), version.lower(), asset.value.lower())] = fp
        return list(unique.values())[: self.max_fingerprints]

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        del targets
        evidence: list[Evidence] = []
        findings: list[Finding] = []
        fingerprints = self._fingerprints(context)
        if not fingerprints:
            return EngineOutput(assets=[], evidence=[], findings=[])

        async with httpx.AsyncClient(timeout=max(context.timeout, 8.0), follow_redirects=True) as client:
            for fp in fingerprints:
                try:
                    response = await client.get(
                        _NVD_URL,
                        params={"keywordSearch": f"{fp.product} {fp.version}", "resultsPerPage": 20},
                        headers={"User-Agent": context.user_agent},
                    )
                    response.raise_for_status()
                    payload = response.json()
                except Exception as exc:
                    evidence.append(Evidence(
                        engine=self.name,
                        category="cve-provider-status",
                        summary=f"Online CVE lookup unavailable for {fp.product} {fp.version}",
                        raw={"product": fp.product, "version": fp.version, "provider": "NVD", "error": f"{type(exc).__name__}: {exc}"},
                    ))
                    continue

                matched = 0
                for wrapper in payload.get("vulnerabilities", []) or []:
                    if matched >= self.max_cves_per_product:
                        break
                    cve = wrapper.get("cve", {}) or {}
                    if not _exact_version_cpe(wrapper, fp.product, fp.version):
                        continue
                    cve_id = str(cve.get("id", "")).strip()
                    if not cve_id.startswith("CVE-"):
                        continue
                    score = _cvss_score(cve)
                    cwes = _weaknesses(cve)
                    ev = Evidence(
                        engine=self.name,
                        category="cve-correlation",
                        summary=f"NVD candidate {cve_id} matched observed {fp.product} {fp.version}",
                        raw={
                            "provider": "NVD",
                            "cve_id": cve_id,
                            "product": fp.product,
                            "version": fp.version,
                            "cvss": score,
                            "cwe_ids": cwes,
                            "match_basis": "exact-version-cpe",
                            "status": "candidate-not-actively-validated",
                            "nvd_reference": f"https://nvd.nist.gov/vuln/detail/{quote(cve_id)}",
                        },
                    )
                    evidence.append(ev)
                    linked = [ev.id]
                    linked.extend(fp.evidence_ids)
                    findings.append(Finding(
                        title=f"Candidate {cve_id} associated with observed {fp.product} {fp.version}",
                        severity=_severity(score),
                        confidence=Confidence.PROBABLE,
                        affected_asset=fp.asset_value,
                        description=(
                            f"ShadowStrike observed {fp.product} {fp.version} and NVD returned {cve_id} with an exact-version CPE match. "
                            "This is version correlation only; exploitability and target-specific applicability have not been actively validated."
                        ),
                        remediation="Review the vendor/NVD advisory, confirm the exact installed build and configuration, then patch or apply vendor mitigations if the CVE is applicable.",
                        evidence_ids=linked,
                        tags=["cve", "version-correlation", "needs-validation"],
                        cwe=cwes[0] if cwes else None,
                        cvss=score,
                        cve_ids=[cve_id],
                    ))
                    matched += 1

        return EngineOutput(assets=[], evidence=evidence, findings=findings)
