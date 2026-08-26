from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from shadowstrike.models.domain import Confidence, Evidence, Finding, Severity


CORRELATED_TAG = "shadowstrike-correlated"


class FindingsEngine:
    """Turn direct observations into conservative, evidence-backed findings.

    The rules intentionally describe exposure/posture rather than asserting exploitability.
    A reachable service can be a valid architecture choice, so findings include remediation
    as a review/hardening action unless evidence proves a stronger condition.
    """

    SERVICE_RULES: dict[int, tuple[str, Severity, str, str, list[str]]] = {
        21: (
            "FTP service reachable",
            Severity.MEDIUM,
            "A clear-text FTP service accepted a TCP connection. FTP can expose credentials and data if TLS is not enforced.",
            "Prefer SFTP or FTPS. If FTP is required, disable anonymous access, enforce encrypted authentication/data channels, and restrict source networks.",
            ["service", "ftp", "cleartext"],
        ),
        23: (
            "Telnet service reachable",
            Severity.HIGH,
            "A Telnet service accepted a TCP connection. Telnet normally transmits session data without transport encryption.",
            "Disable Telnet and use SSH or another encrypted management protocol restricted to trusted administration networks.",
            ["service", "telnet", "cleartext", "remote-access"],
        ),
        110: (
            "Clear-text POP3 service reachable",
            Severity.MEDIUM,
            "POP3 is reachable on its conventional clear-text port. Authentication may be exposed unless STARTTLS is strictly required.",
            "Prefer POP3S or enforce STARTTLS before authentication. Disable clear-text authentication and retire POP3 if it is not required.",
            ["service", "mail", "pop3", "cleartext"],
        ),
        143: (
            "Clear-text IMAP service reachable",
            Severity.MEDIUM,
            "IMAP is reachable on its conventional clear-text port. Authentication may be exposed unless STARTTLS is strictly required.",
            "Prefer IMAPS or enforce STARTTLS before authentication. Disable clear-text authentication and restrict access where possible.",
            ["service", "mail", "imap", "cleartext"],
        ),
        161: (
            "SNMP service exposed",
            Severity.MEDIUM,
            "SNMP is reachable. Legacy/community-string configurations can disclose infrastructure information or permit management actions.",
            "Use SNMPv3 with authentication and encryption, disable default community strings, and restrict access to management networks.",
            ["service", "snmp", "management"],
        ),
        389: (
            "LDAP service exposed",
            Severity.LOW,
            "LDAP is reachable on TCP/389. Directory services should be intentionally exposed and protected against clear-text credential use.",
            "Confirm LDAP exposure is required, require signing/TLS where appropriate, disable simple binds without TLS, and restrict source networks.",
            ["service", "ldap", "identity"],
        ),
        445: (
            "SMB service exposed",
            Severity.MEDIUM,
            "SMB is reachable. Exposed file-sharing and Windows management surfaces increase the attack surface and require strong authentication and signing policy.",
            "Restrict SMB to intended networks, enforce supported SMB versions and signing policy, disable guest access, and keep the host patched.",
            ["service", "smb", "windows"],
        ),
        1433: (
            "Microsoft SQL Server service exposed",
            Severity.MEDIUM,
            "A database listener is reachable on TCP/1433.",
            "Restrict database access to approved application/administration networks, require encrypted connections and strong authentication, and remove public exposure where unnecessary.",
            ["service", "database", "mssql"],
        ),
        2049: (
            "NFS service exposed",
            Severity.MEDIUM,
            "NFS is reachable on TCP/2049. Misconfigured exports can expose files or permit unintended writes.",
            "Restrict NFS to trusted networks, review export permissions/root-squash settings, and remove unused exports.",
            ["service", "nfs", "file-sharing"],
        ),
        2375: (
            "Docker API clear-text endpoint reachable",
            Severity.HIGH,
            "The conventional unencrypted Docker API port accepted a TCP connection. Unprotected Docker APIs can provide powerful host/container control.",
            "Do not expose the Docker API without authentication. Prefer a local Unix socket or mutually authenticated TLS on an explicitly restricted management network.",
            ["service", "docker", "management", "cleartext"],
        ),
        3306: (
            "MySQL service exposed",
            Severity.MEDIUM,
            "A MySQL listener is reachable on TCP/3306.",
            "Restrict database access to approved application/administration networks, require encrypted connections where supported, and enforce strong authentication.",
            ["service", "database", "mysql"],
        ),
        3389: (
            "Remote Desktop service exposed",
            Severity.MEDIUM,
            "RDP is reachable on TCP/3389 and represents a remote administration surface.",
            "Restrict RDP behind VPN/zero-trust access controls, require NLA and MFA where possible, monitor authentication attempts, and keep the host patched.",
            ["service", "rdp", "remote-access"],
        ),
        5432: (
            "PostgreSQL service exposed",
            Severity.MEDIUM,
            "A PostgreSQL listener is reachable on TCP/5432.",
            "Restrict database access to approved application/administration networks, require encrypted connections and strong authentication.",
            ["service", "database", "postgresql"],
        ),
        5900: (
            "VNC remote-access service exposed",
            Severity.HIGH,
            "VNC is reachable on TCP/5900. VNC is a high-value remote administration surface and some deployments provide weak transport protection.",
            "Place VNC behind an authenticated encrypted tunnel/VPN, restrict source networks, require strong authentication, and disable it when unnecessary.",
            ["service", "vnc", "remote-access"],
        ),
        5985: (
            "WinRM HTTP service exposed",
            Severity.MEDIUM,
            "WinRM is reachable over its HTTP transport on TCP/5985.",
            "Restrict WinRM to administration networks, prefer encrypted transport where appropriate, use strong authentication, and review remoting policy.",
            ["service", "winrm", "windows", "remote-access"],
        ),
        6379: (
            "Redis service exposed",
            Severity.HIGH,
            "Redis is reachable on TCP/6379. Redis should not normally be broadly accessible and weakly protected deployments can expose sensitive data or administrative functionality.",
            "Bind Redis to trusted interfaces, enforce authentication/ACLs and TLS where applicable, and restrict access with network controls.",
            ["service", "database", "redis"],
        ),
        9200: (
            "Elasticsearch HTTP service exposed",
            Severity.MEDIUM,
            "The conventional Elasticsearch HTTP port is reachable.",
            "Require authentication/TLS, restrict access to intended clients, and verify cluster APIs are not exposed to untrusted networks.",
            ["service", "database", "elasticsearch"],
        ),
        11211: (
            "Memcached service exposed",
            Severity.HIGH,
            "Memcached is reachable on TCP/11211. It is generally intended for trusted application networks rather than broad exposure.",
            "Restrict Memcached to trusted interfaces/networks, disable it if unused, and ensure it cannot be reached from untrusted networks.",
            ["service", "cache", "memcached"],
        ),
        27017: (
            "MongoDB service exposed",
            Severity.MEDIUM,
            "MongoDB is reachable on TCP/27017.",
            "Restrict database access to approved application/administration networks and require authentication and encrypted transport.",
            ["service", "database", "mongodb"],
        ),
    }

    # Port numbers are not service identities. A rule can fire only when the direct evidence
    # names a protocol/product that is compatible with the rule for that port.
    SERVICE_IDENTITIES: dict[int, set[str]] = {
        21: {"ftp"},
        23: {"telnet"},
        110: {"pop3"},
        143: {"imap"},
        161: {"snmp"},
        389: {"ldap"},
        445: {"smb", "microsoft-ds"},
        1433: {"mssql", "ms-sql-s", "microsoft-sql-server"},
        2049: {"nfs"},
        2375: {"docker", "docker-http", "docker-api"},
        3306: {"mysql"},
        3389: {"rdp", "ms-wbt-server"},
        5432: {"postgresql", "postgres"},
        5900: {"vnc"},
        5985: {"winrm", "winrm-http", "wsman"},
        6379: {"redis"},
        9200: {"elasticsearch"},
        11211: {"memcached"},
        27017: {"mongodb", "mongo"},
    }

    def analyze(self, evidence: Iterable[Evidence]) -> list[Finding]:
        items = list(evidence)
        findings: list[Finding] = []
        open_by_host: dict[str, list[Evidence]] = defaultdict(list)
        anomaly_by_host: dict[str, Evidence] = {
            str(item.raw.get("host") or "").strip(): item
            for item in items
            if item.category == "tcp-acceptance-anomaly" and str(item.raw.get("host") or "").strip()
        }

        for item in items:
            if item.category != "port" or item.raw.get("state") not in {"open", "connect-accepted"}:
                continue
            host = str(item.raw.get("host", "")).strip()
            try:
                port = int(item.raw.get("port"))
            except (TypeError, ValueError):
                continue
            if host:
                open_by_host[host].append(item)
            rule = self.SERVICE_RULES.get(port)
            # A conventional port number is not sufficient to assert an application protocol.
            # Promote service-specific exposure only after a positive protocol/product validation
            # whose identity is compatible with this rule.
            service_name = str(item.raw.get("service_name") or item.raw.get("name") or "").strip().lower()
            allowed_names = self.SERVICE_IDENTITIES.get(port, set())
            if (
                not rule
                or item.raw.get("service_state") != "confirmed"
                or not service_name
                or service_name not in allowed_names
            ):
                continue
            title, severity, description, remediation, tags = rule
            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=f"{host}:{port}" if host else f"TCP/{port}",
                    description=description,
                    remediation=remediation,
                    evidence_ids=[item.id],
                    tags=[CORRELATED_TAG, "exposure", *tags],
                )
            )

        for host, host_items in open_by_host.items():
            unique_ports = sorted({int(e.raw.get("port")) for e in host_items if e.raw.get("port") is not None})
            anomaly = anomaly_by_host.get(host)
            if anomaly is not None:
                raw = anomaly.raw or {}
                findings.append(
                    Finding(
                        title="Anomalous broad TCP acceptance pattern",
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        affected_asset=host,
                        description=(
                            f"{raw.get('accepted_ports', len(unique_ports))} TCP connection attempts were accepted across "
                            f"{raw.get('attempted_ports', 'the tested')} ports, but application-protocol identity was not established. "
                            "The pattern is consistent with an intermediary, proxy, firewall acceptor, tarpit, security appliance, "
                            "or other behavior that can make many ports appear reachable. Individual unverified ports are therefore "
                            "not promoted to services."
                        ),
                        remediation="Validate representative endpoints with protocol-specific checks and review the serving/edge network path before treating individual accepted ports as application services.",
                        evidence_ids=[anomaly.id],
                        tags=[CORRELATED_TAG, "diagnostic", "transport-reachability", "possible-intermediary", "false-positive-control"],
                    )
                )
            elif len(unique_ports) >= 8:
                sample = ", ".join(map(str, unique_ports[:24])) + (" ..." if len(unique_ports) > 24 else "")
                findings.append(
                    Finding(
                        title="Broad TCP port reachability observed",
                        severity=Severity.INFO,
                        confidence=Confidence.CONFIRMED,
                        affected_asset=host,
                        description=f"{len(unique_ports)} TCP ports accepted connections. Representative ports: {sample}. This confirms transport behavior only; it does not confirm the application protocol behind each port.",
                        remediation="Review the reachable TCP surface, confirm the business purpose and protocol identity of representative listeners, then remove or restrict endpoints that are not required.",
                        evidence_ids=[e.id for e in host_items[:64]],
                        tags=[CORRELATED_TAG, "exposure", "attack-surface", "transport-reachability", "needs-protocol-validation"],
                    )
                )

            clear_mail = [
                e for e in host_items
                if int(e.raw.get("port", -1)) in {110, 143}
                and e.raw.get("service_state") == "confirmed"
                and str(e.raw.get("service_name") or "").lower() in {"pop3", "imap"}
            ]
            secure_mail = [
                e for e in host_items
                if int(e.raw.get("port", -1)) in {993, 995}
                and e.raw.get("service_state") == "confirmed"
                and str(e.raw.get("service_name") or "").lower() in {"imaps", "pop3s", "imap-tls", "pop3-tls"}
            ]
            if clear_mail and secure_mail:
                findings.append(
                    Finding(
                        title="Clear-text and encrypted mailbox protocols exposed together",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        affected_asset=host,
                        description="Clear-text mailbox retrieval ports and encrypted alternatives are both reachable. Clients may still be able to use the weaker transport unless server policy strictly enforces STARTTLS before authentication.",
                        remediation="Prefer encrypted-only mailbox services (IMAPS/POP3S) or strictly require STARTTLS before authentication, and disable clear-text authentication.",
                        evidence_ids=[e.id for e in clear_mail + secure_mail],
                        tags=[CORRELATED_TAG, "mail", "cleartext", "transport-security"],
                    )
                )

        # DNS posture evidence is emitted only when the DNS engine can distinguish an
        # authoritative no-answer from a generic resolver/network error.
        for item in items:
            if item.category != "dns-posture":
                continue
            check = str(item.raw.get("check", ""))
            present = item.raw.get("present")
            host = str(item.raw.get("host", item.raw.get("domain", "domain")))
            if present is not False:
                continue
            if check == "CAA":
                findings.append(Finding(
                    title="CAA record not observed",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=host,
                    description="No Certificate Authority Authorization (CAA) record was observed for the assessed domain.",
                    remediation="Consider publishing CAA records to restrict which certificate authorities are permitted to issue certificates for the domain.",
                    evidence_ids=[item.id],
                    tags=[CORRELATED_TAG, "dns", "pki", "hardening"],
                ))
            elif check == "SPF" and item.raw.get("mail_domain"):
                findings.append(Finding(
                    title="SPF policy not observed",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=host,
                    description="The domain has mail infrastructure but no SPF policy was observed in its TXT records.",
                    remediation="Publish an SPF policy that authorizes the legitimate sending infrastructure and end with an appropriate policy qualifier after validation.",
                    evidence_ids=[item.id],
                    tags=[CORRELATED_TAG, "dns", "email-security", "spf"],
                ))
            elif check == "DMARC" and item.raw.get("mail_domain"):
                findings.append(Finding(
                    title="DMARC policy not observed",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=host,
                    description="The domain has mail infrastructure but no DMARC policy was observed at _dmarc.",
                    remediation="Publish and monitor a DMARC policy, align legitimate SPF/DKIM identifiers, then move toward an enforcement policy when reporting shows it is safe.",
                    evidence_ids=[item.id],
                    tags=[CORRELATED_TAG, "dns", "email-security", "dmarc"],
                ))

        # CWE mapping is applied only where the observed condition directly supports a weakness class.
        for finding in findings:
            tags = set(finding.tags)
            if "cleartext" in tags and finding.cwe is None:
                finding.cwe = "CWE-319"
        return findings
