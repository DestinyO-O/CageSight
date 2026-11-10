"""Input parsers: auditd, strace, pcap and normalized JSONL."""

from __future__ import annotations

import os
from typing import List

from cagesight.model import Event

from cagesight.parsers import auditd, jsonl, pcap, strace


def detect_input_type(path: str) -> str:
    """Best-effort sniffing of the input format."""
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "rb") as handle:
        head = handle.read(4096)
    if head[:4] in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
        return "pcap"
    text = head.decode("utf-8", "ignore")
    if "type=SYSCALL" in text or "msg=audit(" in text:
        return "auditd"
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "jsonl"
    if " = " in text and "(" in text:
        return "strace"
    return "jsonl"


def load_events(path: str, input_type: str = "auto") -> List[Event]:
    if input_type == "auto":
        input_type = detect_input_type(path)
    if input_type == "pcap":
        return pcap.parse_pcap(path)
    if input_type == "auditd":
        return auditd.parse_file(path)
    if input_type == "strace":
        return strace.parse_file(path)
    return jsonl.parse_file(path)


__all__ = ["detect_input_type", "load_events", "auditd", "jsonl", "pcap", "strace"]
