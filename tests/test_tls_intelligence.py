from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from shadowstrike.engines.tls import _candidate_endpoints, _public_key_metadata, _san_names
from shadowstrike.models.domain import Asset


def test_tls_candidate_endpoints_deduplicate_https_and_services():
    assets = [
        Asset(kind="web-application", value="https://Example.com/", source="http"),
        Asset(kind="network-service", value="example.com:443", source="scan", attributes={"host": "example.com", "port": 443}),
        Asset(kind="network-service", value="example.com:22", source="scan", attributes={"host": "example.com", "port": 22}),
    ]
    candidates = _candidate_endpoints(["https://example.com"], assets)
    assert candidates == [("example.com", 443, "example.com:443")]


def test_tls_certificate_helpers_extract_san_and_key_metadata():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com"), x509.DNSName("www.example.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    assert _san_names(cert) == ["example.com", "www.example.com"]
    assert _public_key_metadata(cert) == {"type": "RSA", "bits": 2048}
