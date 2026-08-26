from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import ssl
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from shadowstrike.engines.base import Engine, EngineContext, EngineOutput
from shadowstrike.models.domain import Asset, Confidence, Evidence, Finding, Severity


_TLS_PORTS = {443, 465, 636, 853, 993, 995, 2376, 5001, 5986, 8443, 8883, 9443}


def _candidate_endpoints(targets: list[str], assets: Iterable[Asset]) -> list[tuple[str, int, str]]:
    found: dict[tuple[str, int], str] = {}

    for target in targets:
        parsed = urlparse(target if "://" in target else f"//{target}")
        host = parsed.hostname
        if not host:
            continue
        if parsed.scheme == "https":
            found[(host.lower(), parsed.port or 443)] = target
        elif not parsed.scheme:
            # Bare scoped hostnames are normal assessment targets; try the standard HTTPS endpoint.
            found[(host.lower(), 443)] = target

    for asset in assets:
        attrs = asset.attributes or {}
        if asset.kind == "web-application":
            parsed = urlparse(asset.value)
            if parsed.scheme == "https" and parsed.hostname:
                found[(parsed.hostname.lower(), parsed.port or 443)] = asset.value
        elif asset.kind in {"network-service", "transport-endpoint"}:
            host = str(attrs.get("host", "")).strip().lower()
            try:
                port = int(attrs.get("port"))
            except (TypeError, ValueError):
                continue
            if not host and ":" in asset.value:
                host = asset.value.rsplit(":", 1)[0].strip("[]").lower()
            hint = str(attrs.get("service_hint") or attrs.get("service_name") or "").lower()
            if host and (port in _TLS_PORTS or "tls" in hint or hint in {"https", "ldaps", "imaps", "pop3s", "smtps"}):
                found[(host, port)] = asset.value

    return [(host, port, source) for (host, port), source in sorted(found.items())]


def _name(cert_name: x509.Name) -> str:
    parts = []
    for attribute in cert_name:
        parts.append(f"{attribute.oid._name or attribute.oid.dotted_string}={attribute.value}")
    return ", ".join(parts)


def _san_names(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return sorted(set(san.get_values_for_type(x509.DNSName)))


def _public_key_metadata(cert: x509.Certificate) -> dict[str, object]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return {"type": "RSA", "bits": key.key_size}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"type": "EC", "curve": key.curve.name, "bits": key.key_size}
    return {"type": type(key).__name__}


class TlsIntelligenceEngine(Engine):
    """Collect bounded TLS/certificate metadata for already-scoped external endpoints.

    The engine performs a normal TLS handshake only. It does not attempt downgrade,
    renegotiation abuse, cipher enumeration, authentication bypass, or exploitation.
    """

    name = "ShadowTLS"

    async def _inspect(self, host: str, port: int, context: EngineContext) -> tuple[list[Evidence], list[Finding]]:
        context.scope.require(host)
        await context.limiter.wait()

        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        server_hostname = host
        try:
            ipaddress.ip_address(host)
            # SNI with a literal IP is legal but usually unhelpful; retaining it is safe.
        except ValueError:
            pass

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_context, server_hostname=server_hostname),
                timeout=max(context.timeout, 3.0),
            )
            del reader
        except Exception as exc:
            return [Evidence(
                engine=self.name,
                category="tls-status",
                summary=f"TLS handshake unavailable for {host}:{port}",
                raw={"host": host, "port": port, "status": "unavailable", "error": f"{type(exc).__name__}: {exc}"},
            )], []

        findings: list[Finding] = []
        evidence: list[Evidence] = []
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                return [], []
            der = ssl_object.getpeercert(binary_form=True)
            cipher = ssl_object.cipher()
            protocol = ssl_object.version()
            if not der:
                return [], []

            cert = x509.load_der_x509_certificate(der)
            now = datetime.now(timezone.utc)
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            days_remaining = int((not_after - now).total_seconds() // 86400)
            san_names = _san_names(cert)
            fingerprint = hashlib.sha256(der).hexdigest()

            ev = Evidence(
                engine=self.name,
                category="tls-certificate",
                summary=f"TLS certificate observed on {host}:{port}",
                raw={
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "cipher": cipher[0] if cipher else None,
                    "cipher_bits": cipher[2] if cipher else None,
                    "subject": _name(cert.subject),
                    "issuer": _name(cert.issuer),
                    "serial_number": format(cert.serial_number, "x"),
                    "not_before": not_before.isoformat(),
                    "not_after": not_after.isoformat(),
                    "days_remaining": days_remaining,
                    "san_dns_names": san_names,
                    "sha256": fingerprint,
                    "public_key": _public_key_metadata(cert),
                },
                fingerprint=fingerprint,
            )
            evidence.append(ev)

            if not_after <= now:
                findings.append(Finding(
                    title="Expired TLS certificate observed",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=f"{host}:{port}",
                    description=f"The TLS certificate presented by {host}:{port} expired on {not_after.date().isoformat()}.",
                    remediation="Replace the expired certificate with a valid certificate and verify automated renewal/monitoring is operating correctly.",
                    evidence_ids=[ev.id],
                    tags=["external", "tls", "certificate", "availability", "evidence-backed"],
                ))
            elif days_remaining < 30:
                findings.append(Finding(
                    title="TLS certificate approaching expiry",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=f"{host}:{port}",
                    description=f"The TLS certificate presented by {host}:{port} has approximately {max(days_remaining, 0)} days remaining before expiry.",
                    remediation="Renew or rotate the certificate before expiry and verify automated renewal monitoring.",
                    evidence_ids=[ev.id],
                    tags=["external", "tls", "certificate", "maintenance", "evidence-backed"],
                ))

            key = cert.public_key()
            if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
                findings.append(Finding(
                    title="Weak RSA key size in TLS certificate",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=f"{host}:{port}",
                    description=f"The observed certificate uses a {key.key_size}-bit RSA public key, below the common 2048-bit baseline.",
                    remediation="Replace the certificate/key pair with a modern key size or approved elliptic-curve key according to organisational cryptographic policy.",
                    evidence_ids=[ev.id],
                    tags=["external", "tls", "cryptography", "certificate", "evidence-backed"],
                    cwe="CWE-326",
                ))

            if protocol in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}:
                findings.append(Finding(
                    title="Legacy TLS protocol negotiated",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=f"{host}:{port}",
                    description=f"A normal TLS handshake negotiated legacy protocol {protocol}.",
                    remediation="Disable legacy SSL/TLS protocol versions and require TLS 1.2 or newer where client compatibility permits.",
                    evidence_ids=[ev.id],
                    tags=["external", "tls", "protocol", "cryptography", "evidence-backed"],
                    cwe="CWE-327",
                ))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        return evidence, findings

    async def run(self, targets: list[str], context: EngineContext) -> EngineOutput:
        candidates = _candidate_endpoints(targets, context.assets or [])
        evidence: list[Evidence] = []
        findings: list[Finding] = []
        skipped: list[dict[str, object]] = []
        for host, port, source in candidates[:128]:
            if not context.scope.allows(host):
                skipped.append({"host": host, "port": port, "source": source, "reason": "candidate-host-not-independently-authorized"})
                continue
            ev, fn = await self._inspect(host, port, context)
            evidence.extend(ev)
            findings.extend(fn)
        if skipped:
            evidence.append(Evidence(engine=self.name, category="tls-candidate-skipped", summary=f"Skipped {len(skipped)} TLS candidate endpoint(s) that were not independently authorized", raw={"skipped": skipped[:64], "scope_guarded": True}))
        return EngineOutput(assets=[], evidence=evidence, findings=findings)
