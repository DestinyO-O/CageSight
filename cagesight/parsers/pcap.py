"""Minimal, dependency-free pcap parser for DNS / TLS-SNI / HTTP-Host telemetry.

We deliberately do not reuse scapy: the sandbox that runs this tool should not
need network packages installed, and the parsing surface we need is small.

Supported link types: Ethernet (1), raw IP (101), Linux SLL (113), SLL2 (276).
Supported protocols: IPv4/IPv6, UDP/53 (DNS), TCP with TLS ClientHello SNI or
plain HTTP Host header.
"""

from __future__ import annotations

import ipaddress
import struct
from typing import List, Optional, Tuple

from cagesight.model import Event

QTYPE = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\x3c\x4d": (">", True),   # nanosecond precision
    b"\x4d\x3c\xb2\xa1": ("<", True),
}

SERVER_PORTS = {21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1080, 3000, 4444, 5000, 6379, 8000, 8080, 8443, 9001, 9090, 1337}


def _u16(data: bytes, offset: int, endian: str = ">") -> int:
    return struct.unpack_from(endian + "H", data, offset)[0]


def _u32(data: bytes, offset: int, endian: str = ">") -> int:
    return struct.unpack_from(endian + "I", data, offset)[0]


def _strip_link_layer(data: bytes, linktype: int) -> Optional[Tuple[bytes, int]]:
    """Return (ip_packet_bytes, ethertype)."""
    if linktype in (0, 108):  # BSD loopback / LOOP: 4-byte address family
        if len(data) < 4:
            return None
        family = struct.unpack("<I", data[:4])[0]
        if family not in (2, 10, 23, 24, 26, 28, 30):
            family = struct.unpack(">I", data[:4])[0]
        if family in (2, 24, 28, 30):
            return data[4:], 0x0800
        if family in (10, 23, 26):
            return data[4:], 0x86DD
        return None
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None
        offset = 12
        ethertype = _u16(data, offset)
        # 支持 802.1Q / QinQ（0x8100、0x88A8）
        while ethertype in (0x8100, 0x88A8):
            offset += 4
            if len(data) < offset + 2:
                return None
            ethertype = _u16(data, offset)
        return data[offset + 2 :], ethertype
    if linktype == 101:  # raw IP
        if not data:
            return None
        version = data[0] >> 4
        return data, 0x0800 if version == 4 else 0x86DD
    if linktype == 113:  # Linux SLL
        if len(data) < 16:
            return None
        return data[16:], _u16(data, 14)
    if linktype == 276:  # Linux SLL2
        if len(data) < 20:
            return None
        return data[20:], _u16(data, 0)
    return None


def _parse_ipv4(packet: bytes) -> Optional[Tuple[int, str, str, bytes]]:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl:
        return None
    protocol = packet[9]
    src = str(ipaddress.IPv4Address(packet[12:16]))
    dst = str(ipaddress.IPv4Address(packet[16:20]))
    total_length = _u16(packet, 2)
    payload = packet[ihl:total_length] if total_length >= ihl else packet[ihl:]
    return protocol, src, dst, payload


def _parse_ipv6(packet: bytes) -> Optional[Tuple[int, str, str, bytes]]:
    if len(packet) < 40 or packet[0] >> 4 != 6:
        return None
    next_header = packet[6]
    src = str(ipaddress.IPv6Address(packet[8:24]))
    dst = str(ipaddress.IPv6Address(packet[24:40]))
    payload_length = _u16(packet, 4)
    payload = packet[40 : 40 + payload_length] if payload_length else packet[40:]
    return next_header, src, dst, payload


def _parse_dns(payload: bytes) -> Optional[Tuple[str, str]]:
    if len(payload) < 12:
        return None
    flags = _u16(payload, 2)
    if flags & 0x8000:  # QR=1: response, not a query. Ignored on purpose.
        return None
    qdcount = _u16(payload, 4)
    if qdcount < 1:
        return None
    offset = 12
    labels: List[str] = []
    while offset < len(payload):
        length = payload[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:  # compression pointer, not expected in a question
            return None
        if offset + length > len(payload):
            return None
        labels.append(payload[offset : offset + length].decode("ascii", "ignore"))
        offset += length
    if offset + 2 > len(payload):
        return None
    qtype = _u16(payload, offset)
    return ".".join(labels), QTYPE.get(qtype, "TYPE%d" % qtype)


def _parse_tls_sni(payload: bytes) -> Optional[str]:
    if len(payload) < 43 or payload[0] != 0x16 or payload[1] != 0x03:
        return None
    if payload[5] != 0x01:  # ClientHello
        return None
    offset = 9  # record(5) + handshake header(4)
    if offset + 34 > len(payload):
        return None
    offset += 34  # version(2) + random(32)
    session_len = payload[offset]
    offset += 1 + session_len
    if offset + 2 > len(payload):
        return None
    cipher_len = _u16(payload, offset)
    offset += 2 + cipher_len
    if offset + 1 > len(payload):
        return None
    compression_len = payload[offset]
    offset += 1 + compression_len
    if offset + 2 > len(payload):
        return None
    extensions_len = _u16(payload, offset)
    offset += 2
    end = min(len(payload), offset + extensions_len)
    while offset + 4 <= end:
        ext_type = _u16(payload, offset)
        ext_len = _u16(payload, offset + 2)
        offset += 4
        if ext_type == 0x0000:  # server_name
            if offset + 5 > len(payload):
                return None
            list_len = _u16(payload, offset)
            name_type = payload[offset + 2]
            name_len = _u16(payload, offset + 3)
            if name_type == 0 and offset + 5 + name_len <= len(payload):
                return payload[offset + 5 : offset + 5 + name_len].decode("ascii", "ignore")
            return None
        offset += ext_len
    return None


def _parse_http_host(payload: bytes) -> Optional[str]:
    if not payload or payload[0] not in b"GPHODUT":
        return None
    head = payload[:2048]
    if b"\r\n\r\n" not in head and b"\n\n" not in head:
        return None
    lowered = head.lower()
    index = lowered.find(b"\r\nhost:")
    if index < 0:
        index = lowered.find(b"\nhost:")
    if index < 0:
        return None
    start = lowered.find(b":", index) + 1
    end = lowered.find(b"\r\n", start)
    if end < 0:
        end = lowered.find(b"\n", start)
    host = head[start:end].strip().decode("ascii", "ignore")
    return host.split(":")[0]


MAX_RECORD = 16 << 20  # 16 MiB：单帧上限，防止畸形长度字段触发超大分配


def parse_pcap(path: str) -> List[Event]:
    """Stream the capture file record by record; never load it whole."""
    events: List[Event] = []
    with open(path, "rb") as handle:
        magic = handle.read(4)
        if not magic:
            return []
        if magic == b"\x0a\x0d\x0d\x0a":
            raise ValueError("pcapng 暂不支持，请先转换为 pcap（editcap -F pcap in.pcapng out.pcap）")
        magic_info = PCAP_MAGICS.get(magic)
        if not magic_info:
            raise ValueError("不是有效的 pcap 文件")
        endian, nanosecond = magic_info
        rest = handle.read(20)
        if len(rest) < 20:
            return []
        linktype = _u32(rest, 16, endian)

        while True:
            record = handle.read(16)
            if len(record) < 16:
                break
            ts_sec = _u32(record, 0, endian)
            ts_frac = _u32(record, 4, endian)
            incl_len = _u32(record, 8, endian)
            if incl_len <= 0:
                break
            if incl_len > MAX_RECORD:
                raise ValueError("pcap 记录长度异常（%d 字节）" % incl_len)
            frame = handle.read(incl_len)
            if len(frame) < incl_len:
                break
            ts = ts_sec + ts_frac / (1_000_000_000.0 if nanosecond else 1_000_000.0)
            try:
                event = _parse_frame(frame, linktype, ts)
            except Exception:
                event = None
            if event:
                events.append(event)
    events.sort(key=lambda e: e.ts)
    return events


def _parse_frame(frame: bytes, linktype: int, ts: float) -> Optional[Event]:
    stripped = _strip_link_layer(frame, linktype)
    if not stripped:
        return None
    packet, ethertype = stripped
    if ethertype == 0x86DD:
        parsed = _parse_ipv6(packet)
    elif ethertype in (0x0800, 0):
        parsed = _parse_ipv4(packet)
    else:
        return None
    if not parsed:
        return None
    protocol, src, dst, payload = parsed

    if protocol == 17:  # UDP
        if len(payload) < 8:
            return None
        sport = _u16(payload, 0)
        dport = _u16(payload, 2)
        data = payload[8:]
        if dport == 53 or sport == 53:
            parsed_dns = _parse_dns(data)
            if not parsed_dns:
                return None
            qname, qtype = parsed_dns
            return Event(
                ts=ts,
                source="pcap",
                kind="dns",
                domain=qname,
                qtype=qtype,
                dst_ip=dst,
                dst_port=dport,
                extra={"src_ip": src, "dns_server": dst},
            )
        if dport in SERVER_PORTS:
            return Event(
                ts=ts,
                source="pcap",
                kind="net",
                dst_ip=dst,
                dst_port=dport,
                nbytes=len(data),
                extra={"src_ip": src, "proto": "udp"},
            )
        return None

    if protocol == 6:  # TCP
        if len(payload) < 20:
            return None
        dport = _u16(payload, 2)
        if dport == 53:
            # DNS-over-TCP 暂不支持；不要把它误报成一次普通外联。
            return None
        data_offset = (payload[12] >> 4) * 4
        if data_offset < 20 or len(payload) < data_offset:
            return None
        data = payload[data_offset:]
        # 只把“客户端 -> 服务端口”的包视为出站。veth 上抓包是双向的，
        # 若把服务器回包也当成外联，会产生大量误报。
        if dport not in SERVER_PORTS:
            return None
        sni = _parse_tls_sni(data) if data else None
        host = sni or (_parse_http_host(data) if data else None)
        if not data and not host:
            return None
        return Event(
            ts=ts,
            source="pcap",
            kind="net",
            domain=host or "",
            dst_ip=dst,
            dst_port=dport,
            nbytes=len(data),
            extra={"src_ip": src, "proto": "tcp", "sni": sni or "", "direction": "out"},
        )
    return None
