# ShadowStrike deep-discovery upstream sources

ShadowStrike normalizes evidence from mature upstream projects rather than reimplementing weaker fingerprint databases. Upstream results are evidence, not automatic vulnerability findings.

- **Nmap** — https://nmap.org/ — GPL-2.0-or-later. `nmap-service-probes`, `nmap-services`, `nmap-os-db` are used through the installed Nmap executable for service/version, port-frequency and TCP/IP OS/device fingerprinting.
- **arp-scan** — https://github.com/royhills/arp-scan — GPL-3.0. Used by privileged directly-connected sensors for ARP host/MAC discovery.
- **python-zeroconf 0.150.x** — https://github.com/python-zeroconf/python-zeroconf — LGPL-2.1-or-later. Used for mDNS/DNS-SD service-type and service-instance resolution.
- **mac-vendor-lookup 0.1.15** — https://pypi.org/project/mac-vendor-lookup/ — Apache-2.0. Ships a local IEEE OUI prefix list for offline MAC vendor lookup.
- **IEEE Registration Authority OUI data** — https://standards.ieee.org/products-programs/regauth/ — authoritative manufacturer prefix source used by the upstream OUI databases.
- **ShadowSNMP** — native read-only SNMPv2c implementation for system, IF-MIB and LLDP-MIB collection with engagement-supplied communities. No default-community guessing is performed.

`install-discovery-tools.command` installs Nmap and arp-scan from Homebrew or apt. Python dependencies are installed into ShadowStrike's local `.venv` by the launchers.
- **OWASP Amass** — mature attack-surface mapping/Open Asset Model reference used as an architectural reference for ShadowGraphIntel and future normalized adapters.
- **ProjectDiscovery Katana** — mature automation-focused crawler reference; its JS/known-file/headless design informs ShadowCrawler expansion and remains detectable by ShadowToolBridge for future normalized execution.
- **crt.sh / public Certificate Transparency logs** — public certificate-name intelligence source used by ShadowCerts. CT-derived names are recorded as candidates and are not contacted unless separately in scope.
- **OpenSSL** — used, when installed, to collect the server-presented certificate chain without vendoring cryptographic protocol code.
