
## 0.22.0 deep-discovery layer

`ShadowDeepDiscovery` runs after TLS/service collection and before CVE/posture synthesis. It does not perform uncontrolled probing; it normalizes already collected certificate, network, OS and software evidence and makes collection gaps explicit. Internal assessments additionally inventory locally visible networks passively and then actively scan only CIDRs approved in engagement scope.

Internal deep pipeline: `ShadowScan -> ShadowLAN -> ShadowUDP -> ShadowTLS -> ShadowDeepDiscovery -> ShadowAdaptive -> ShadowToolBridge -> ShadowCVE -> ShadowInternal -> ShadowInfrastructure -> ShadowIdentity -> ShadowTrust -> ShadowPath`.

External deep pipeline: `ShadowRecon -> ShadowWildcard -> ShadowDNS -> ShadowScan -> ShadowHTTP -> ShadowCrawler -> ShadowContacts -> ShadowJS -> ShadowAPI -> ShadowTLS -> ShadowDeepDiscovery -> ShadowAdaptive -> ShadowToolBridge -> ShadowCVE -> ShadowExternal -> ShadowValidate`.

# ShadowStrike Architecture Roadmap

## Product goal

A professional, evidence-driven platform for authorized pentesting, defensive assessment, and bug-bounty scope analysis. ShadowStrike should favor accurate, correlated findings over raw scanner volume.

## Core principles

1. Scope is enforced centrally, below every engine.
2. Every assessment carries an authorization reference.
3. Engines return normalized Assets, Evidence, and Findings.
4. One failed module never kills the full assessment.
5. Findings have severity and confidence separately.
6. Evidence provenance is preserved for reproducibility.
7. External tools are optional validators, never hard dependencies.
8. Potentially disruptive load testing remains isolated from normal assessment profiles.
9. Credential interception, persistence, evasion, destructive actions, and automated compromise are outside the core platform.
10. Performance claims must come from ShadowLab benchmarks, not marketing estimates.

## Engine families

### Foundation
- ShadowScope — domains/CIDRs/exclusions, rate and concurrency budgets.
- ShadowQueue — persistent jobs, retries, checkpointing, cancellation.
- ShadowEvidence — normalized evidence, provenance, hashing, redaction.
- ShadowBrain — correlation, prioritization, next-safe-action planning.
- ShadowVerify — observation -> candidate -> correlated -> safely validated -> reportable.

### Discovery
- ShadowRecon — passive/active asset discovery and historical change tracking.
- ShadowDNS — A/AAAA/MX/NS/TXT/CNAME intelligence and wildcard handling.
- ShadowScan — bounded TCP service discovery with adaptive concurrency.
- ShadowUDP — positive-response UDP discovery, passive neighbor/DHCP enrichment, and supplied-credential SNMP reads.
- ShadowHTTP — HTTP reachability, redirects, headers, TLS metadata.
- ShadowJS — endpoint/config/source-map intelligence from public application assets.

### Web and API assessment
- ShadowCrawler — state-aware crawling and endpoint graph construction.
- ShadowFuzz — scoped content/vhost/parameter discovery with wildcard and soft-404 suppression.
- ShadowAPI — REST/OpenAPI/GraphQL/WebSocket mapping and safe configuration analysis.
- ShadowState — supplied-test-identity comparison for authorization boundary analysis.
- ShadowTemplate — normalized template checks with independent result validation.

### Enterprise / identity
- ShadowAD — authorized LDAP/SMB/Kerberos posture and relationship inventory.
- ShadowPKI — TLS/PKI and AD CS configuration posture.
- ShadowIAM — identity graph across supplied AD/cloud IAM data.
- ShadowGraph — asset, identity, service, and finding relationship graph.

### Cloud / code / supply chain
- ShadowCloud — exposed cloud asset and configuration intelligence.
- ShadowSecrets — public/supplied artifact secret detection with confidence scoring.
- ShadowCode — SAST-style analysis for supplied source repositories.
- ShadowSupply — dependency/SBOM correlation with deployed reachability evidence.
- ShadowContainer — Docker/Kubernetes posture from authorized targets/configuration.

### Operations
- ShadowDelta — compare attack surfaces and findings over time.
- ShadowReplay — minimum safe retest corpus for confirmed findings.
- ShadowCoverage — explicit tested/skipped/unreachable coverage accounting.
- ShadowReport — pentest, bug-bounty, technical, and executive output.
- ShadowLab — regression, precision/recall, throughput, memory, and crash benchmarks.
- ShadowLoad — separately authorized load/performance testing with hard ceilings and abort thresholds.

## External adapter strategy

Adapters may optionally consume output from mature tools such as Nmap, Nuclei, Amass, ffuf, Feroxbuster, Impacket, NetExec, BloodHound, Certipy, ZAP, Semgrep, and similar authorized-testing utilities. Adapter results must be normalized into ShadowStrike evidence and remain subject to scope, deduplication, confidence, and validation rules.

## Profiles

### Bug Bounty
Prioritize scope-safe passive discovery, HTTP, JS, endpoints, APIs, cloud exposure, takeover indicators, public secrets, change detection, evidence validation, and concise submission-ready reporting.

### Internal Pentest
Prioritize hosts, services, identity/AD posture, PKI, configuration weaknesses, internal web/API coverage, graph correlation, and remediation evidence.

### Web Application
Prioritize crawling, endpoint extraction, API mapping, supplied test-account state comparison, security headers, TLS posture, input-surface coverage, and retesting.

### Full Assessment
Combines all non-disruptive modules explicitly permitted by the engagement scope.

### Load Lab
Separate profile requiring allow_load_testing=true plus independent concurrency/RPS ceilings and emergency abort conditions.

## Immediate build sequence

1. Persist assessments/results to SQLite/PostgreSQL.
2. Add ShadowQueue and resumable job state.
3. Expand ShadowScan to configurable port profiles and service metadata.
4. Add ShadowRecon and robust wildcard-aware DNS discovery.
5. Build ShadowCrawler/ShadowJS and endpoint normalization.
6. Add ShadowAPI and OpenAPI import.
7. Add evidence graph + finding lineage.
8. Add HTML/JSON professional reports.
9. Add optional adapter SDK.
10. Establish ShadowLab test fixtures and performance baselines.


## 0.7.1 intelligence layer

`ShadowContacts` is a scoped public-reference collector. `ShadowCVE` is a post-discovery intelligence engine using previously observed software fingerprints. CVE correlation is intentionally non-exploitative: observed product/version -> NVD query -> exact-version CPE filter -> candidate finding -> manual/safe validation state.

## 0.9.2 discovery-reliability architecture

- **ShadowLAN**: rootless, bounded discovery on explicitly allowed CIDRs using TCP-connect reachability, ICMP reachability where available, reverse DNS, and local neighbor-table/MAC correlation.
- **ShadowDevice**: deterministic classification for gateways/routers, switches, APs, firewalls, printers, cameras, NAS, virtualization hosts, servers and workstations from observed services, position and management evidence.
- **ShadowSNMP**: read-only SNMP v2c system inventory using an operator-supplied community string. No community guessing or write operations.
- **ShadowAgent**: token-authenticated remote sensor that retrieves controller-assigned CIDR scope before collection, then submits normalized inventory. It has no arbitrary remote command channel.
- **ShadowTopology**: observed gateway/device relationships integrated into the evidence graph.
- **WebApp/API**: Devices, Topology, Sensors and Network Risk views plus scoped scan, sensor registration, heartbeat, assignment and ingestion endpoints.
- **Firmware/BIOS**: collected from the sensor/controller host itself and from managed-device descriptions when exposed by authorized management protocols; not inferred for arbitrary remote hosts.

## ShadowValidate (0.12.0)

The external pipeline terminates in a passive validation/correlation stage:

`Discovery -> Protocol Evidence -> Inventory/Posture -> ShadowValidate -> Findings/Verification/Report`

`ShadowValidate` does not probe targets. It cross-correlates previously captured TCP, banner, HTTP, TLS, API, and CVE evidence. CVE candidates may be promoted from probable to high confidence when independent service identity evidence supports applicability, but they are never marked exploit-validated solely by this correlation.


## Findings Intelligence (0.13.0)

Finalisation now applies a deterministic consultancy enrichment stage after native and correlated findings are deduplicated:

`Evidence -> Finding -> Validation state -> Evidence quality -> Impact -> Priority -> Retest state -> Report`

The enrichment stage does not probe targets and does not infer exploitation. CVE applicability remains explicitly distinct from exploit validation. Exposure paths describe observable reachability relationships (for example Internet -> host -> service -> finding), not proven compromise chains.

## Remediation & Retest (0.14.0)

The consultancy lifecycle now continues beyond initial reporting:

`Finding -> Remediation Plan -> Implementation -> Ready for Retest -> Before/After Evidence -> Operator Verification -> Fixed / Partially Fixed / Not Fixed / Risk Accepted`

Retest is modeled as an explicit evidence-backed workflow. Each round stores before-evidence references, after-evidence references, operator attribution, timestamps, and notes. After-evidence must already exist in the assessment evidence store. ShadowStrike does not infer remediation success from absence of scanner output and does not run target-side validation merely because a finding is marked ready for retest.

## 0.16.0 Internal Infrastructure Intelligence

`ShadowInfrastructure` is a passive synthesis stage that runs after `ShadowInternal`. It does not probe hosts. It correlates normalized ShadowLAN assets, SNMP inventory already collected by an authorized scan, sensor-provided topology relationships, service observations, and physical/CCTV inventory.

The stage keeps three separate concepts: confirmed infrastructure identity, candidate platform hints, and observed management surfaces. Port combinations alone never promote a candidate into a confirmed switch, NAS, hypervisor, container host, camera, or NVR. SNMP IF-MIB interface rows are retained as evidence-backed operational metadata and topology edges are labelled by their evidence source and confidence.


## ShadowIdentity (0.17.0)

`ShadowIdentity` is a passive identity/Active Directory synthesis stage executed after `ShadowInfrastructure` for internal and hybrid assessments. It consumes existing authorized assets/evidence and does not initiate authentication attempts. Confirmed roles require direct metadata; service-port combinations remain candidate indicators.

## 0.18.0 - ShadowTrust

`ShadowTrust` is a passive internal segmentation and trust-boundary synthesis stage. It consumes only existing authorized observations: explicit zone/VLAN/subnet metadata, topology links, service reachability metadata, and prior asset identity. It produces zone inventory, trust-boundary relationships, management/trust-service views, cross-zone exposure paths, and policy-backed findings. Cross-zone visibility without an explicit policy basis remains inventory and is not promoted to a vulnerability.


## 0.19.0 - ShadowPath

`ShadowPath` is a passive internal exposure-correlation stage that runs after `ShadowTrust`. It consumes accumulated assets, evidence, and findings from `EngineContext` and produces an `internal-exposure-path-summary` evidence object. It performs no new target I/O. Cross-zone paths are based on explicit reachability metadata; finding-correlated paths preserve the validation status and evidence quality of the underlying finding.


## 0.20.0 - Controlled Validation & Proof-of-Access

Controlled validation is a post-finding workflow rather than an automatic assessment engine. The engagement scope must explicitly enable it and carry a separate validation authorization reference. `ControlledValidationService` generates the proof marker, enforces the safe PoC metadata contract, validates evidence IDs against the assessment snapshot, and persists validation sessions on the finding. Actual target-side execution remains an explicit operator action under the Rules of Engagement.

Lifecycle: `validation-authorized -> poc-prepared -> execution-attempted -> exploit-confirmed/access-confirmed/proof-objective-achieved -> cleanup-confirmed`. A failed attempt closes as `validation-failed`.


## 0.21.0 - Executive Risk & Assessment Intelligence
`AssessmentRiskService` is a passive synthesis layer. It consumes existing assets, findings, controlled-validation records, internal exposure-path summaries, remediation state and retest outcomes. It produces deterministic finding-level residual-risk scores plus an overall client-level priority view. It performs no probing and does not infer compromise probability. The dedicated `ExecutiveRiskReport` renders this data for management audiences.

## 0.24 specialist execution boundary

Specialist command execution is an engagement capability, not a global default. The first executable adapter is Nmap and is limited to connect/version discovery without NSE. Every target is passed through ScopeGuard, execution is explicitly opt-in, and parsed results become evidence that still requires ShadowStrike correlation/validation. UDP discovery similarly reports only protocol-valid replies; timeout/silence is never promoted to an open-port claim.

## 0.24.1 evidence-fidelity invariant

All downstream engines must preserve this state progression: `transport observed -> service candidate -> protocol confirmed -> product/version confirmed -> vulnerability candidate -> applicability supported -> controlled validation`. Conventional port mappings may guide the next safe protocol check but are never independent evidence. Conflicting identity evidence suppresses promotion. External and internal reporting must expose candidate/confirmed state explicitly.


## 0.24.2 transport/service inventory invariant

ShadowStrike separates network observations into three inventory classes:

1. `transport-endpoint` - a TCP connection was accepted but the application protocol is not confirmed.
2. `network-service` - application/protocol identity is confirmed by direct evidence.
3. `transport-surface` - an anomalously broad acceptance pattern was detected and individual unverified endpoint promotion was suppressed.

A TCP connection acceptance can never by itself increase the confirmed service count. Broad acceptance patterns are treated as possible intermediary/proxy/tarpit/security-appliance behavior until protocol-specific validation establishes otherwise. Top-level asset counts exclude transport/service sub-resources.


## 0.24.3 assessment-truth invariant
Local network discovery must distinguish directly-connected RFC1918 networks from host/neighbour routes. Broadcast, multicast, loopback and limited-broadcast addresses can never become network devices. Assessment completion, evidence coverage, primary asset inventory, transport reachability and protocol-confirmed services are separate metrics. Persisted assessments carry the engine version that created their evidence semantics.

## 0.25.0 deep network fingerprinting invariant

Internal discovery is phased rather than exhaustive-by-default:

1. directly-connected network and route truth,
2. L2/ARP, multicast and lightweight liveness discovery,
3. adaptive frequency-based TCP discovery for positive hosts,
4. protocol-specific validation and DNS-SD advertised-port verification,
5. Nmap service/version and device/OS fingerprint correlation,
6. SNMP/LLDP infrastructure enrichment when authorized read credentials exist,
7. explicit exhaustive scanning only when the operator selects that profile.

Port reachability, service identity, OS/device fingerprint confidence and vulnerability applicability remain separate evidence states. Distributed sensors initiate outbound authenticated sessions and receive only the CIDRs approved by the controller. Raw Nmap OS fingerprinting and arp-scan are delegated to an explicitly privileged sensor worker rather than requiring the controller to run as root.
