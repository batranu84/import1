# ShadowStrike 0.26.0 - Full Intelligence, Deep Nmap, Certificate & Crawl Engine

0.26.0 expands ShadowStrike's evidence-first assessment core in four areas: deep Nmap orchestration, a Maltego-style relationship/transform graph, certificate-chain and Certificate Transparency intelligence, and deeper web crawling. All derived entities remain ScopeGuard-gated and specialist-tool output is normalized as evidence rather than automatically promoted to a vulnerability.

## Major capabilities

- Deep Nmap TCP service/version discovery with `--version-all` in full/deep profiles.
- Privileged Nmap OS fingerprinting, traceroute and OS guess correlation.
- Safe/default NSE collection with script output retained as evidence.
- Separate privileged UDP top-port service/version phase in full/deep profiles.
- `tcpwrapped` remains unidentified transport, never a confirmed protocol.
- Maltego-style entity/relationship synthesis for hosts, domains, IPs, networks, URLs, services, products, CPEs, certificates, contacts, vendors and observations.
- Transform provenance for DNS, CT, SAN, product/version, CPE, OS, vendor, service, contact-domain and IP-network relationships.
- Certificate chain collection through installed OpenSSL, including chain members, subject/issuer, serial, validity and SHA-256 fingerprints.
- Certificate Transparency enumeration through crt.sh for scoped domain targets; newly observed names are recorded but not contacted by the certificate engine.
- Stronger crawler seeding from robots.txt, sitemap.xml and sitemap indexes.
- HTML, JS, JSON, XML and text route extraction; form inventory; redirects; public email references; API/GraphQL/OpenAPI hints; technology-header inventory; out-of-scope reference recording without contact.
- Existing authorization, ScopeGuard, evidence fidelity and assessment-truth rules remain enforced.

## Important semantics

A TCP connection, Nmap wrapper marker, port convention, candidate hostname or CT name is not a confirmed application service or vulnerability. A result is promoted only when the relevant evidence supports that conclusion.

## Start

Extract the ZIP into a permanent folder, then run `start.command` on macOS or `start.sh` on Linux. Run `install-discovery-tools.command` once to install Nmap and arp-scan where supported.
