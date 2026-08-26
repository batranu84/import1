# 0.22.0 Deep Discovery

Local interface/route visibility is passive and always recorded. Active discovery remains scope-gated. `full` internal discovery performs complete TCP port coverage on positively identified live hosts; service verification captures direct application evidence for device/OS/software correlation. Unknown identity remains unknown/candidate rather than being guessed.

# ShadowStrike 0.9.2 Discovery Reliability

ShadowLAN now performs bounded TCP-connect discovery and neighbor-table correlation on CIDRs explicitly listed in the engagement scope. It can classify observed devices, build a simple gateway-centric topology and add network services into the existing evidence/findings pipeline.

ShadowSNMP performs read-only SNMP v2c system inventory only when an operator supplies an authorized community string. It does not guess community strings. SNMP evidence can identify managed switches, routers, firewalls and appliances when their sysDescr/sysName data is available.

ShadowAgent supports a remote-sensor workflow for private networks not routed to the controller. Register a sensor in the WebApp, run `shadowstrike sensor` inside the authorized remote network, and submit the bounded inventory over an approved routed/VPN path. Sensors do not expose arbitrary remote command execution.

BIOS/firmware inventory is collected from the sensor host itself using platform-provided hardware data and from managed appliances where SNMP exposes firmware descriptions. ShadowStrike does not claim to read BIOS from arbitrary remote endpoints without an authorized management channel.

## 0.16.0 infrastructure intelligence

ShadowInfrastructure correlates the internal asset graph after ShadowInternal. It inventories confirmed network infrastructure, platform roles, management surfaces, read-only SNMP IF-MIB interface metadata, CCTV/NVR assets, and evidence-labelled topology relationships. Port-only heuristics remain candidates. Direct role evidence from SNMP, mDNS/SSDP/LLDP metadata, or other normalized sensor observations is required for confirmed device-role promotion.

SNMP interface inventory now records interface name/description/alias, type, administrative and operational state, and speed metadata when the authorized read community returns those IF-MIB columns. ShadowStrike does not guess community strings.

## ShadowTrust segmentation intelligence

The 0.18.0 internal pipeline adds passive trust-boundary correlation. Explicit network-zone, VLAN, subnet, reachability, and sensor-topology metadata can be correlated into zone maps and cross-zone exposure paths. ShadowStrike does not infer a segmentation failure solely from service visibility; a finding requires direct policy metadata or sensor evidence that marks the observed path as a violation.


### 0.19.0 exposure-path correlation

The internal pipeline now includes `ShadowPath`, which combines explicit zone reachability, trust-boundary metadata, device roles, and already-recorded findings into evidence-supported exposure paths. Path scoring prioritizes review but is not an exploitability score. No authentication, credential use, lateral movement, or exploitation is performed by the stage.

## 0.24.1 service identity semantics

A successful TCP connect establishes only transport reachability to the resolved peer at that time. Port conventions are recorded as `service_candidate`; `service_name` is populated only after protocol/product evidence confirms identity. Device classification, management/data-service findings, network risk, trust paths and CVE fingerprints consume confirmed identity where protocol-specific semantics matter. Candidate-only observations remain searchable inventory and can trigger deeper validation, but they cannot silently become service/vulnerability findings.

## 0.24.2 service inventory semantics

A successful TCP connect is retained as transport evidence. It becomes a `network-service` only after a direct application/protocol check confirms identity. Otherwise it is a `transport-endpoint`; when ShadowStrike observes an anomalously broad acceptance pattern, individual unverified endpoints are collapsed into a single `transport-surface` diagnostic so proxies, tarpits, firewalls, or generic TCP acceptors cannot inflate service or asset counts.


## 0.24.3 local-network truth model
On macOS, `netstat -rn` may expose per-neighbour cloning routes as `/32` entries. ShadowStrike excludes these from auto-approval candidates and prioritizes directly-connected RFC1918 interface networks. Broadcast/multicast/unspecified addresses are not devices. Open TCP ports remain transport observations until application protocol evidence confirms a service.

## 0.25.0 network fingerprinting sources

- **Nmap `-sV`**: protocol/product/version/CPE/device/OS-family evidence from the maintained `nmap-service-probes` database.
- **Nmap `-O`**: TCP/IP stack OS/device fingerprinting only when the authorized worker has the raw-packet privileges Nmap requires.
- **arp-scan**: direct-LAN ARP discovery and MAC collection from a privileged sensor.
- **MAC/OUI**: installed Nmap/arp-scan vendor databases and the offline `mac-vendor-lookup` IEEE OUI list.
- **DNS-SD/mDNS**: service instances, exact advertised ports, service hostnames and TXT metadata via `python-zeroconf`; advertised endpoints are transport-verified before becoming confirmed reachable services.
- **SSDP/UPnP**: positive multicast responses plus same-host device-description XML for manufacturer/model/device-role evidence.
- **SNMP/LLDP**: system/IF-MIB plus LLDP remote-neighbour evidence only with engagement-supplied read credentials.

The adaptive profile uses Nmap's `nmap-services` frequency data when available instead of scanning every low port on every host. A full 1-65535 TCP sweep is retained under the explicit `exhaustive` profile.
