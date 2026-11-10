"""Normalized event and finding models.

Every parser converts its native format into :class:`Event`. Detectors only
ever look at ``Event`` objects, which keeps the rule layer independent from
the telemetry source (auditd / strace / pcap / agent runtime logs).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Tuple

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_SCORE = {"info": 5, "low": 20, "medium": 45, "high": 70, "critical": 90}


def severity_at_least(value: str, floor: str) -> bool:
    return SEVERITY_ORDER.get(value, 0) >= SEVERITY_ORDER.get(floor, 0)


@dataclass
class Event:
    """A single telemetry event, normalized across sources.

    ``kind`` is one of: exec, file, net, dns, syscall, tool, generic.
    Unused fields stay at their defaults; detectors only read what they need.
    """

    ts: float = 0.0
    source: str = "jsonl"
    kind: str = "generic"
    pid: int = 0
    ppid: int = 0
    comm: str = ""
    argv: Tuple[str, ...] = ()
    path: str = ""
    domain: str = ""
    qtype: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    nbytes: int = 0
    uid: int = -1
    syscall: str = ""
    ret: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    # -- convenience -----------------------------------------------------
    @property
    def cmdline(self) -> str:
        return " ".join(self.argv) if self.argv else ""

    def text(self) -> str:
        """Everything string-ish, lowercased, for keyword rules."""
        parts = [self.comm, self.cmdline, self.path, self.domain]
        parts.extend(str(v) for v in self.extra.values())
        return " ".join(p for p in parts if p).lower()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["argv"] = list(self.argv or ())
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        if not isinstance(data, dict):
            raise ValueError("event must be a JSON object")

        def pick(*names, default=None):
            for n in names:
                if n in data and data[n] not in (None, ""):
                    return data[n]
            return default

        argv = pick("argv", "args", "cmd", default=())
        if isinstance(argv, str):
            argv = tuple(argv.split())
        elif isinstance(argv, (list, tuple)):
            argv = tuple(str(x) for x in argv)
        else:
            argv = ()

        ts = pick("ts", "time", "timestamp", default=None)
        if isinstance(ts, str):
            ts = parse_timestamp(ts)
        try:
            ts = float(ts) if ts is not None else time.time()
        except (TypeError, ValueError):
            ts = time.time()

        def as_int(value, default=0):
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        return cls(
            ts=ts,
            source=str(pick("source", "parser", default="jsonl")),
            kind=str(pick("kind", "type", default="generic")),
            pid=as_int(pick("pid", default=0)),
            ppid=as_int(pick("ppid", default=0)),
            comm=str(pick("comm", "process", default="")),
            argv=argv,
            path=str(pick("path", "file", default="")),
            domain=str(pick("domain", "host", "qname", default="")),
            qtype=str(pick("qtype", "query_type", default="")),
            dst_ip=str(pick("dst_ip", "ip", "dst", default="")),
            dst_port=as_int(pick("dst_port", "port", default=0)),
            nbytes=as_int(pick("nbytes", "bytes", "size", default=0)),
            uid=as_int(pick("uid", default=-1), -1),
            syscall=str(pick("syscall", default="")),
            ret=str(pick("ret", "return", default="")),
            extra=data.get("extra") if isinstance(data.get("extra"), dict) else {},
        )


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    score: int
    description: str = ""
    evidence: str = ""
    ts: float = 0.0
    pid: int = 0
    comm: str = ""
    mitre: str = ""
    tags: Tuple[str, ...] = ()
    count: int = 1

    @property
    def time_str(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts)) if self.ts else "-"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["tags"] = list(self.tags)
        data["time"] = self.time_str
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


def parse_timestamp(value: str) -> float:
    """Parse the timestamp formats we meet in the wild."""
    value = value.strip().replace("Z", "+00:00")
    # epoch seconds (possibly with fraction)
    try:
        return float(value)
    except ValueError:
        pass
    try:
        from datetime import datetime

        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            import datetime as _dt

            return _dt.datetime.strptime(value, fmt).timestamp()
        except ValueError:
            continue
    return time.time()


def coerce_events(raw: List[Dict[str, Any]]) -> List[Event]:
    events = []
    for item in raw:
        try:
            events.append(Event.from_dict(item))
        except Exception:
            continue
    events.sort(key=lambda e: e.ts)
    return events
