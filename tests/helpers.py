"""Shared test helpers."""

from __future__ import annotations

import struct
from typing import Any, Dict, List

from cagesight.config import load_config, load_rules
from cagesight.engine import Engine, Result
from cagesight.model import Event

BASE_TS = 1794182400.0


def event(**kwargs: Any) -> Event:
    payload: Dict[str, Any] = {
        "ts": BASE_TS,
        "source": "test",
        "pid": 4242,
        "ppid": 1,
        "comm": "python3",
        "kind": "generic",
    }
    payload.update(kwargs)
    return Event.from_dict(payload)


def run(events: List[Event]) -> Result:
    engine = Engine(config=load_config(), rules=load_rules())
    return engine.run(events)


def rule_ids(result: Result) -> set:
    return {finding.rule_id for finding in result.findings}


# -- pcap builders -------------------------------------------------------
def mac(value: str) -> bytes:
    return bytes.fromhex(value.replace(":", ""))


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return mac("02:42:ac:11:00:02") + mac("02:42:ac:11:00:01") + struct.pack(">H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        0,
        0x4000,
        64,
        proto,
        0,
        bytes(map(int, src.split("."))),
        bytes(map(int, dst.split("."))),
    )
    return header + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x18, 65535, 0, 0) + payload


def dns_query(txid: int, qname: str, qtype: int = 1, response: bool = False) -> bytes:
    flags = 0x8180 if response else 0x0100
    answers = 1 if response else 0
    header = struct.pack(">HHHHHH", txid, flags, 1, answers, 0, 0)
    question = b""
    for label in qname.split("."):
        question += bytes([len(label)]) + label.encode()
    question += b"\x00" + struct.pack(">HH", qtype, 1)
    return header + question


def tls_client_hello(sni: str) -> bytes:
    name = sni.encode()
    server_name = b"\x00" + struct.pack(">H", len(name)) + name
    sni_data = struct.pack(">H", len(server_name)) + server_name
    extension = struct.pack(">HH", 0x0000, len(sni_data)) + sni_data
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + struct.pack(">H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
        + struct.pack(">H", len(extension))
        + extension
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def build_pcap(frames: List[bytes], linktype: int = 1) -> bytes:
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for index, frame in enumerate(frames):
        out += struct.pack("<IIII", int(BASE_TS) + index, 0, len(frame), len(frame)) + frame
    return out
