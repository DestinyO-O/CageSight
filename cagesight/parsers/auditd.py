"""Parser for Linux auditd logs (SYSCALL / EXECVE / PATH / SOCKADDR records).

Usage on the host::

    auditctl -a always,exit -F arch=b64 -S execve,connect,openat,ptrace,setns,unshare,mount
    ausearch --raw | cagesight scan - --input-type auditd

The parser groups records by audit message id and emits one normalized event
per syscall.
"""

from __future__ import annotations

import ipaddress
import re
from collections import OrderedDict
from typing import Dict, Iterable, List, Optional, Tuple

from cagesight.model import Event

FIELD_RE = re.compile(r"(\w+)=(\"([^\"]*)\"|'([^']*)'|(\S+))")
MSG_RE = re.compile(r"audit\(([0-9.]+):(\d+)\)")

X86_64 = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    41: "socket",
    42: "connect",
    43: "accept",
    49: "bind",
    50: "listen",
    59: "execve",
    85: "creat",
    90: "chmod",
    92: "chown",
    101: "ptrace",
    105: "setuid",
    106: "setgid",
    165: "mount",
    166: "umount2",
    175: "init_module",
    257: "openat",
    272: "unshare",
    308: "setns",
    313: "finit_module",
    321: "bpf",
    322: "execveat",
    437: "openat2",
}

AARCH64 = {
    40: "mount",
    39: "umount2",
    52: "chmod",
    54: "chown",
    56: "openat",
    97: "unshare",
    105: "init_module",
    117: "ptrace",
    198: "socket",
    200: "bind",
    201: "listen",
    202: "accept",
    203: "connect",
    221: "execve",
    268: "setns",
    273: "finit_module",
    280: "bpf",
    281: "execveat",
}

INTERESTING = {
    "execve",
    "execveat",
    "open",
    "openat",
    "openat2",
    "creat",
    "connect",
    "socket",
    "ptrace",
    "setns",
    "unshare",
    "mount",
    "umount2",
    "init_module",
    "finit_module",
    "bpf",
    "chmod",
    "chown",
    "mknod",
}


def _clean(value: str) -> str:
    return value.strip().strip('"').strip("'")


def _is_hex_arg(value: str) -> bool:
    return len(value) >= 4 and len(value) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in value)


def _decode_arg(value: str) -> str:
    if not _is_hex_arg(value):
        return value
    try:
        raw = bytes.fromhex(value)
        decoded = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return value
    if decoded and all(ch.isprintable() or ch in "\t\r\n" for ch in decoded):
        return decoded
    return value


def _parse_fields(line: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for match in FIELD_RE.finditer(line):
        key = match.group(1)
        value = match.group(3)
        if value is None:
            value = match.group(4)
        if value is None:
            value = match.group(5)
        fields[key] = value
    return fields


def _decode_sockaddr(saddr: str) -> Tuple[str, int, str]:
    """Return (ip, port, family) from an auditd SOCKADDR value.

    Supports both raw hex (``ausearch --raw``) and interpreted output
    (``ausearch -i``, e.g. ``saddr=1.2.3.4:443``).
    """
    saddr = saddr.strip().lower()
    if "." in saddr or ":" in saddr:
        host, _, port_text = saddr.rpartition(":")
        if host and "." in host and port_text.isdigit():
            return host, int(port_text), "inet"
        try:
            ipaddress.ip_address(saddr)
            return saddr, 0, "inet"
        except ValueError:
            pass
    if len(saddr) < 8:
        return "", 0, ""
    try:
        # sockaddr family is a little-endian u16 stored as network bytes
        family = int(saddr[2:4] + saddr[0:2], 16)
    except ValueError:
        return "", 0, ""
    if family == 2 and len(saddr) >= 16:  # AF_INET
        port = int(saddr[4:8], 16)
        ip = ".".join(str(int(saddr[i : i + 2], 16)) for i in (8, 10, 12, 14))
        return ip, port, "inet"
    if family == 10 and len(saddr) >= 48:  # AF_INET6
        port = int(saddr[4:8], 16)
        try:
            ip = str(ipaddress.IPv6Address(bytes.fromhex(saddr[16:48])))
        except ValueError:
            ip = ""
        return ip, port, "inet6"
    if family == 1:  # AF_UNIX
        try:
            path = bytes.fromhex(saddr[4:]).decode("utf-8", "ignore").strip("\x00")
        except ValueError:
            path = ""
        return path, 0, "unix"
    return "", 0, ""


def _syscall_name(fields: Dict[str, str]) -> str:
    raw = fields.get("syscall", "")
    try:
        number = int(raw)
    except (TypeError, ValueError):
        return raw.lower()
    arch = (fields.get("arch") or "").lower()
    table = AARCH64 if arch == "c00000b7" else X86_64
    return table.get(number, "syscall_%d" % number)


def _collect_argv(records: List[Dict[str, str]]) -> Tuple[str, ...]:
    for record in records:
        if "argc" in record:
            try:
                argc = int(record["argc"])
            except ValueError:
                argc = 0
            argv = []
            for index in range(argc):
                value = record.get("a%d" % index)
                if value is None:
                    break
                argv.append(_decode_arg(value))
            if argv:
                return tuple(argv)
    return ()


def _collect_path(records: List[Dict[str, str]]) -> str:
    candidates = []
    for record in records:
        if "name" in record and record.get("nametype", "NORMAL") in ("NORMAL", "CREATE"):
            candidates.append(_clean(record["name"]))
    return candidates[-1] if candidates else ""


def _build_event(msg_id: str, group: Dict[str, object]) -> Optional[Event]:
    syscall_records: List[Dict[str, str]] = group.get("SYSCALL", [])  # type: ignore[assignment]
    if not syscall_records:
        return None
    syscall = syscall_records[0]
    name = _syscall_name(syscall)
    if name not in INTERESTING:
        return None

    ts = float(group.get("ts", 0.0))
    pid = int(syscall.get("pid", 0) or 0)
    ppid = int(syscall.get("ppid", 0) or 0)
    comm = _clean(syscall.get("comm", ""))
    uid = int(syscall.get("uid", -1) or -1)
    exe = _clean(syscall.get("exe", ""))

    event = Event(
        ts=ts,
        source="auditd",
        pid=pid,
        ppid=ppid,
        comm=comm,
        uid=uid,
        syscall=name,
        ret=_clean(syscall.get("exit", "")),
        extra={"audit_id": msg_id, "exe": exe},
    )

    if name in ("execve", "execveat"):
        event.kind = "exec"
        event.argv = _collect_argv(group.get("EXECVE", []))  # type: ignore[arg-type]
        event.path = exe or (event.argv[0] if event.argv else _collect_path(group.get("PATH", [])))
    elif name in ("open", "openat", "openat2", "creat"):
        event.kind = "file"
        event.path = _collect_path(group.get("PATH", [])) or _decode_arg(syscall.get("a1", ""))
    elif name == "connect":
        event.kind = "net"
        sockaddrs = group.get("SOCKADDR", [])
        if sockaddrs:
            ip, port, family = _decode_sockaddr(sockaddrs[0].get("saddr", ""))
            event.dst_ip = ip
            event.dst_port = port
            event.extra["family"] = family
    elif name == "socket":
        event.kind = "net"
        try:
            event.extra["sock_type"] = int(syscall.get("a1", "0"), 16)
        except ValueError:
            event.extra["sock_type"] = 0
    else:
        event.kind = "syscall"
        if name == "ptrace":
            try:
                event.extra["request"] = int(syscall.get("a1", "0"), 16)
            except ValueError:
                pass
        if name in ("init_module", "finit_module"):
            event.path = _clean(syscall.get("a1", ""))
    return event


def parse_lines(lines: Iterable[str]) -> List[Event]:
    groups: "OrderedDict[str, Dict[str, object]]" = OrderedDict()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        msg = MSG_RE.search(line)
        if not msg:
            continue
        timestamp, msg_id = msg.group(1), msg.group(2)
        type_match = re.search(r"type=(\w+)", line)
        if not type_match:
            continue
        record_type = type_match.group(1)
        fields = _parse_fields(line)
        group = groups.setdefault(msg_id, {"ts": float(timestamp)})
        group.setdefault(record_type, []).append(fields)  # type: ignore[union-attr]

    events: List[Event] = []
    for msg_id, group in groups.items():
        try:
            event = _build_event(msg_id, group)
        except Exception:
            continue
        if event is not None:
            events.append(event)
    events.sort(key=lambda e: e.ts)
    return events


def parse_file(path: str) -> List[Event]:
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        return parse_lines(handle)
