# 0.26.0 - Full Intelligence & Deep Assessment

- Added deep Nmap orchestration profiles.
- Added bounded privileged UDP Nmap service/version phase.
- Added Nmap host/port safe/default NSE output normalization.
- Preserved `tcpwrapped` as unidentified transport rather than service identity.
- Added `ShadowGraphIntel`, a Maltego-style typed entity/relationship transform engine.
- Added product/version, CPE, parent-domain, CT, certificate-SAN, vendor, OS, IP-network and NSE transforms.
- Added `ShadowCerts` certificate-chain collection using OpenSSL when present.
- Added Certificate Transparency intelligence using crt.sh with ScopeGuard-aware name recording.
- Expanded native crawler with robots/sitemap discovery, sitemap indexes, JSON route walking, broad text/JS URL extraction, form metadata, technology headers and out-of-scope reference evidence.
- Added new regression coverage for Nmap wrapper semantics, NSE evidence and graph transforms.
- Full test suite passes 184 tests.
