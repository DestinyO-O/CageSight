"""Parser for ``strace -f -tt -s 256`` output.

This is the easiest way to collect telemetry for a single agent process when
auditd is not available::

    strace -f -tt -s 256 -o agent.strace python agent.py
    cagesight scan agent.strace
"""

from __future__ import annotations

import re
from typing import Iterable, List, Tuple

from cagesight.model import Event

PID_RE = re.compile(r"^\[pid\s+(\d+)\]\s*")
TS_RE = re.compile(r"^(\d{9,}(?:\.\d+)?)\s+")
CALL_RE = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_]*)\(")
QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
HEXQUOTE_RE = re.compile(r'\\x([0-9a-fA-F]{2})')

INTERESTING = {
    "execve",
    "execveat",
    "open",
    "openat",
    "openat2",
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
}

SKIP = {"read", "close", "fstat", "lseek", "mmap", "mprotect", "rt_sigaction", "nanosleep"}


def _unescape(value: str) -> str:
    value = value.replace('\\"', '"').replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\\")
    return HEXQUOTE_RE.sub(lambda m: chr(int(m.group(1), 16)), value)


def _split_call(line: str) -> Tuple[str, str, str]:
    """Return (syscall, args, return_value)."""
    if " = " in line:
        body, ret = line.rsplit(" = ", 1)
    else:
        body, ret = line, ""
    body = body.strip()
    match = CALL_RE.match(body)
    if not match:
        return "", "", ret
    name = match.group(1)
    start = body.find("(")
    end = body.rfind(")")
    args = body[start + 1 : end] if start >= 0 and end > start else ""
    return name, args, ret.strip()


def _parse_sockaddr(args: str) -> Tuple[str, int, str]:
    family = ""
    if "AF_UNIX" in args:
        family = "unix"
    elif "AF_INET6" in args:
        family = "inet6"
    elif "AF_INET" in args:
        family = "inet"
    port = 0
    port_match = re.search(r"(?:sin6?_port|htons)\((\d+)\)", args)
    if port_match:
        port = int(port_match.group(1))
    ip = ""
    ip_match = re.search(r'inet_addr\("([^"]+)"\)', args)
    if ip_match:
        ip = ip_match.group(1)
    else:
        ip6_match = re.search(r'inet_pton\(AF_INET6,\s*"([^"]+)"', args)
        if ip6_match:
            ip = ip6_match.group(1)
    unix_match = re.search(r'sun_path="([^"]+)"', args)
    if unix_match:
        ip = _unescape(unix_match.group(1))
    return ip, port, family


def _parse_line(line: str, fallback_ts: float) -> Tuple[Event, float]:
    pid = 0
    pid_match = PID_RE.match(line)
    if pid_match:
        pid = int(pid_match.group(1))
        line = line[pid_match.end() :]

    ts = fallback_ts
    ts_match = TS_RE.match(line)
    if ts_match:
        ts = float(ts_match.group(1))
        line = line[ts_match.end() :]

    name, args, ret = _split_call(line)
    if not name:
        return Event(ts=ts), ts

    event = Event(ts=ts, source="strace", pid=pid, syscall=name, ret=ret)

    if name in ("execve", "execveat"):
        event.kind = "exec"
        argv: List[str] = []
        bracket = re.search(r"\[(.*)\]", args, re.S)
        if bracket:
            argv = [_unescape(m.group(1)) for m in QUOTED_RE.finditer(bracket.group(1))]
        else:
            quoted = QUOTED_RE.findall(args)
            argv = [_unescape(q) for q in quoted[:1]]
        event.argv = tuple(argv)
        event.path = argv[0] if argv else ""
    elif name in ("open", "openat", "openat2"):
        event.kind = "file"
        quoted = [_unescape(q) for q in QUOTED_RE.findall(args)]
        if quoted:
            event.path = quoted[-1]
    elif name == "connect":
        event.kind = "net"
        ip, port, family = _parse_sockaddr(args)
        event.dst_ip = ip
        event.dst_port = port
        if family == "unix":
            event.path = ip
        event.extra["family"] = family
    elif name == "socket":
        event.kind = "net"
        if "SOCK_RAW" in args:
            event.extra["sock_type"] = 3
        elif "SOCK_DGRAM" in args:
            event.extra["sock_type"] = 2
        else:
            event.extra["sock_type"] = 1
        event.extra["args"] = args
    elif name == "ptrace":
        event.kind = "syscall"
        request = args.split(",")[0].strip() if args else ""
        event.extra["request_name"] = request
        if request in ("PTRACE_ATTACH", "PTRACE_SEIZE"):
            event.extra["request"] = 16 if request == "PTRACE_ATTACH" else 0x4206
    else:
        event.kind = "syscall"
        event.extra["args"] = args

    return event, ts


def parse_lines(lines: Iterable[str]) -> List[Event]:
    events: List[Event] = []
    last_ts = 0.0
    last_comm = ""
    for line in lines:
        line = line.strip()
        if not line or line.startswith("---") or "unfinished" in line:
            continue
        match = CALL_RE.match(PID_RE.sub("", TS_RE.sub("", line)))
        if not match:
            continue
        name = match.group(1)
        if name in SKIP or (name not in INTERESTING and not name.startswith("open")):
            continue
        try:
            event, ts = _parse_line(line, last_ts)
        except Exception:
            continue
        if ts > 0:
            last_ts = ts
        if event.ts == 0:
            event.ts = last_ts
        if event.ts == 0:
            event.ts = 0.001 * len(events)
        if event.kind == "exec" and not event.argv and not event.path:
            # 截断行（没有 " = " 或参数不完整）不应产生空的 exec 事件
            continue
        if not event.comm:
            event.comm = last_comm
        if event.kind == "exec" and event.argv:
            last_comm = event.argv[0].rsplit("/", 1)[-1]
            event.comm = last_comm
        events.append(event)
    events.sort(key=lambda e: e.ts)
    return events


def parse_file(path: str) -> List[Event]:
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        return parse_lines(handle)
