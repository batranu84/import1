from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any


SYS_OIDS = {
    "sys_descr": "1.3.6.1.2.1.1.1.0",
    "sys_object_id": "1.3.6.1.2.1.1.2.0",
    "sys_uptime": "1.3.6.1.2.1.1.3.0",
    "sys_contact": "1.3.6.1.2.1.1.4.0",
    "sys_name": "1.3.6.1.2.1.1.5.0",
    "sys_location": "1.3.6.1.2.1.1.6.0",
}


def _ber_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(payload)) + payload


def _integer(value: int) -> bytes:
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big", signed=False)
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    return _tlv(0x02, raw)


def _oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.strip(".").split(".")]
    if len(parts) < 2:
        raise ValueError("OID must contain at least two components")
    encoded = bytearray([40 * parts[0] + parts[1]])
    for value in parts[2:]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        encoded.extend(reversed(chunk))
    return _tlv(0x06, bytes(encoded))


def _snmp_request_packet(community: str, oid: str, request_id: int = 1, pdu_tag: int = 0xA0) -> bytes:
    varbind = _tlv(0x30, _oid(oid) + _tlv(0x05, b""))
    varbinds = _tlv(0x30, varbind)
    pdu = _tlv(pdu_tag, _integer(request_id) + _integer(0) + _integer(0) + varbinds)
    message = _integer(1) + _tlv(0x04, community.encode("utf-8")) + pdu
    return _tlv(0x30, message)


def _snmp_get_packet(community: str, oid: str, request_id: int = 1) -> bytes:
    return _snmp_request_packet(community, oid, request_id=request_id, pdu_tag=0xA0)


def _snmp_getnext_packet(community: str, oid: str, request_id: int = 1) -> bytes:
    return _snmp_request_packet(community, oid, request_id=request_id, pdu_tag=0xA1)


def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or offset + count > len(data):
        raise ValueError("invalid BER length")
    return int.from_bytes(data[offset:offset + count], "big"), offset + count


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("truncated BER")
    tag = data[offset]
    length, start = _read_length(data, offset + 1)
    end = start + length
    if end > len(data):
        raise ValueError("truncated BER value")
    return tag, data[start:end], end


def _decode_oid(payload: bytes) -> str:
    if not payload:
        return ""
    first = payload[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in payload[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            parts.append(value)
            value = 0
    return ".".join(str(x) for x in parts)


def _decode_value(tag: int, payload: bytes) -> Any:
    if tag in {0x02, 0x41, 0x42, 0x43, 0x46}:
        return int.from_bytes(payload or b"\x00", "big", signed=(tag == 0x02))
    if tag == 0x04:
        # SNMP OCTET STRING is used for both human-readable text and binary identifiers
        # such as LLDP chassis MAC addresses. Preserve binary values as colon-hex instead
        # of corrupting them with Unicode replacement characters.
        try:
            text = payload.decode("utf-8")
            printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
            if text and printable / max(1, len(text)) >= 0.9:
                return text.strip("\x00")
        except UnicodeDecodeError:
            pass
        return ":".join(f"{byte:02x}" for byte in payload)
    if tag == 0x06:
        return _decode_oid(payload)
    if tag == 0x40 and len(payload) == 4:
        return ".".join(str(x) for x in payload)
    if tag in {0x80, 0x81, 0x82}:
        return None
    return payload.hex()


def _parse_get_response(data: bytes) -> tuple[str, Any] | None:
    try:
        tag, outer, _ = _read_tlv(data, 0)
        if tag != 0x30:
            return None
        off = 0
        _, _, off = _read_tlv(outer, off)  # version
        _, _, off = _read_tlv(outer, off)  # community
        pdu_tag, pdu, off = _read_tlv(outer, off)
        if pdu_tag != 0xA2:
            return None
        poff = 0
        _, _, poff = _read_tlv(pdu, poff)  # request id
        _, error_status, poff = _read_tlv(pdu, poff)
        _, _, poff = _read_tlv(pdu, poff)  # error index
        if int.from_bytes(error_status or b"\x00", "big") != 0:
            return None
        _, varbinds, poff = _read_tlv(pdu, poff)
        _, varbind, _ = _read_tlv(varbinds, 0)
        voff = 0
        _, oid_payload, voff = _read_tlv(varbind, voff)
        value_tag, value_payload, _ = _read_tlv(varbind, voff)
        return _decode_oid(oid_payload), _decode_value(value_tag, value_payload)
    except (ValueError, IndexError):
        return None


@dataclass
class ShadowSNMP:
    host: str | None = None
    community: str | None = None
    port: int = 161
    timeout: float = 0.8
    enabled: bool = True
    vendor: str | None = None
    model: str | None = None
    firmware: str | None = None
    interfaces: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def _request(self, packet: bytes) -> tuple[str, Any] | None:
        if not self.enabled or not self.host or not self.community:
            return None
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(packet, (self.host, self.port))
            data, _ = sock.recvfrom(65535)
        except OSError:
            return None
        finally:
            sock.close()
        return _parse_get_response(data)

    def get(self, oid: str) -> Any:
        if not self.community:
            return None
        parsed = self._request(_snmp_get_packet(self.community, oid))
        return parsed[1] if parsed else None

    def getnext(self, oid: str) -> tuple[str, Any] | None:
        if not self.community:
            return None
        return self._request(_snmp_getnext_packet(self.community, oid))

    def walk(self, base_oid: str, max_rows: int = 256) -> list[tuple[str, Any]]:
        rows: list[tuple[str, Any]] = []
        current = base_oid.rstrip(".")
        seen: set[str] = set()
        for _ in range(max(0, max_rows)):
            item = self.getnext(current)
            if not item:
                break
            oid, value = item
            if not (oid == base_oid or oid.startswith(base_oid.rstrip(".") + ".")):
                break
            if oid in seen:
                break
            seen.add(oid)
            rows.append((oid, value))
            current = oid
        return rows

    def inventory(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        for name, oid in SYS_OIDS.items():
            value = self.get(oid)
            if value not in (None, ""):
                data[name] = value

        # Interface rows are read only after a positive SNMP response and never guessed.
        # IF-MIB columns are joined by interface index so the report can distinguish
        # administrative state, operational state, interface type, aliases and speed.
        def indexed(base_oid: str, max_rows: int = 512) -> dict[str, Any]:
            return {oid.rsplit(".", 1)[-1]: value for oid, value in self.walk(base_oid, max_rows=max_rows)}

        if_descr = indexed("1.3.6.1.2.1.2.2.1.2")
        if_type = indexed("1.3.6.1.2.1.2.2.1.3")
        if_speed = indexed("1.3.6.1.2.1.2.2.1.5")
        if_admin = indexed("1.3.6.1.2.1.2.2.1.7")
        if_oper = indexed("1.3.6.1.2.1.2.2.1.8")
        if_name = indexed("1.3.6.1.2.1.31.1.1.1.1")
        if_alias = indexed("1.3.6.1.2.1.31.1.1.1.18")
        if_high_speed = indexed("1.3.6.1.2.1.31.1.1.1.15")

        indexes = sorted(
            set(if_descr) | set(if_name) | set(if_oper) | set(if_admin),
            key=lambda value: (0, int(value)) if value.isdigit() else (1, value),
        )
        interfaces: list[dict[str, Any]] = []
        for idx in indexes:
            speed_bps = if_speed.get(idx)
            high_speed_mbps = if_high_speed.get(idx)
            interfaces.append({
                "index": int(idx) if idx.isdigit() else idx,
                "name": if_name.get(idx),
                "description": if_descr.get(idx),
                "alias": if_alias.get(idx),
                "if_type": if_type.get(idx),
                "admin_status": if_admin.get(idx),
                "oper_status": if_oper.get(idx),
                "speed_bps": speed_bps,
                "high_speed_mbps": high_speed_mbps,
            })
        self.interfaces = interfaces

        # LLDP-MIB remote systems table. This is direct switch/AP/router adjacency evidence
        # when the managed device exposes it through the engagement-supplied read community.
        def indexed_suffix(base_oid: str, max_rows: int = 1024) -> dict[str, Any]:
            prefix = base_oid.rstrip(".") + "."
            out: dict[str, Any] = {}
            for oid, value in self.walk(base_oid, max_rows=max_rows):
                suffix = oid[len(prefix):] if oid.startswith(prefix) else oid.rsplit(".", 1)[-1]
                out[suffix] = value
            return out

        lldp_chassis = indexed_suffix("1.0.8802.1.1.2.1.4.1.1.5")
        lldp_port_id = indexed_suffix("1.0.8802.1.1.2.1.4.1.1.7")
        lldp_port_desc = indexed_suffix("1.0.8802.1.1.2.1.4.1.1.8")
        lldp_sys_name = indexed_suffix("1.0.8802.1.1.2.1.4.1.1.9")
        lldp_sys_desc = indexed_suffix("1.0.8802.1.1.2.1.4.1.1.10")
        lldp_indexes = sorted(set(lldp_chassis) | set(lldp_port_id) | set(lldp_sys_name))
        lldp_neighbors: list[dict[str, Any]] = []
        for idx in lldp_indexes[:512]:
            parts = idx.split(".")
            local_port = parts[-2] if len(parts) >= 2 else None
            rem_index = parts[-1] if parts else None
            row = {
                "index": idx,
                "local_port_num": int(local_port) if local_port and local_port.isdigit() else local_port,
                "remote_index": int(rem_index) if rem_index and rem_index.isdigit() else rem_index,
                "chassis_id": lldp_chassis.get(idx),
                "port_id": lldp_port_id.get(idx),
                "port_description": lldp_port_desc.get(idx),
                "system_name": lldp_sys_name.get(idx),
                "system_description": lldp_sys_desc.get(idx),
            }
            if any(row.get(k) not in (None, "") for k in ("chassis_id", "port_id", "system_name")):
                lldp_neighbors.append(row)

        descr = str(data.get("sys_descr", ""))
        vendor, model, firmware = self._fingerprint(descr)
        self.vendor = self.vendor or vendor
        self.model = self.model or model
        self.firmware = self.firmware or firmware
        self.raw = data
        return {
            **data,
            "vendor": self.vendor,
            "model": self.model,
            "firmware": self.firmware,
            "interfaces": self.interfaces,
            "interface_count": len(self.interfaces),
            "lldp_neighbors": lldp_neighbors,
            "lldp_neighbor_count": len(lldp_neighbors),
            "collection_state": "confirmed" if data else "unavailable",
        }

    @staticmethod
    def _fingerprint(descr: str) -> tuple[str | None, str | None, str | None]:
        low = descr.lower()
        vendor = None
        for marker, name in [
            ("cisco", "Cisco"), ("junos", "Juniper"), ("juniper", "Juniper"),
            ("aruba", "Aruba/HPE"), ("procurve", "HPE"), ("ubiquiti", "Ubiquiti"),
            ("edgeos", "Ubiquiti"), ("mikrotik", "MikroTik"), ("routeros", "MikroTik"),
            ("fortigate", "Fortinet"), ("pfsense", "Netgate/pfSense"), ("synology", "Synology"),
            ("qnap", "QNAP"), ("truenas", "TrueNAS"),
        ]:
            if marker in low:
                vendor = name
                break
        model = descr.strip()[:180] or None
        firmware = None
        for token in ("version ", "ver ", "firmware ", "software "):
            idx = low.find(token)
            if idx >= 0:
                firmware = descr[idx:idx + 80].strip()
                break
        return vendor, model, firmware
