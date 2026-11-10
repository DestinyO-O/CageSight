"""Outbound connection detection: allowlist, metadata service, raw sockets, volume and ports."""

from __future__ import annotations

import re
from collections import deque
from typing import Dict, List, Tuple

from cagesight.config import Context, is_public_ip
from cagesight.detectors.base import BaseDetector
from cagesight.model import Event, Finding

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# 云厂商元数据服务：Agent 沙箱访问它们几乎等同于窃取实例凭据/角色 Token。
METADATA_IPS = {"169.254.169.254", "169.254.170.2", "169.254.0.23", "100.100.100.200", "fd00:ec2::254"}
METADATA_DOMAINS = {"metadata.google.internal", "metadata.goog", "metadata.tencentyun.com"}


def _is_metadata(ip: str, domain: str) -> bool:
    if ip and ip.lower() in METADATA_IPS:
        return True
    if domain and domain.lower().rstrip(".") in METADATA_DOMAINS:
        return True
    return False


def _host_port(host: str, port: int) -> str:
    """IPv6 地址必须加方括号，否则 dst=2001:db8::1:443 无法区分地址和端口。"""
    if ":" in host and not host.startswith("["):
        return "[%s]:%d" % (host, port)
    return "%s:%d" % (host, port)


class EgressDetector(BaseDetector):
    name = "egress"

    def __init__(self) -> None:
        super().__init__()
        # key -> [deque of (ts, bytes), running total]
        self._volume: Dict[Tuple[str, int], list] = {}

    def feed(self, event: Event, ctx: Context) -> List[Finding]:
        if event.kind != "net":
            return []

        findings: List[Finding] = []
        thresholds = ctx.thresholds.get("net", {})
        window_sec = float(thresholds.get("window_sec", 120))
        upload_bytes = int(thresholds.get("upload_bytes", 5 * 1024 * 1024))
        common_ports = set(int(p) for p in thresholds.get("common_ports", [53, 80, 443]))

        # -- CS-NET-003: raw socket --------------------------------------
        if event.extra.get("sock_type") == 3:
            if not self.dedupe(("CS-NET-003", event.pid), event.ts, 300):
                finding = ctx.finding(
                    "CS-NET-003",
                    event,
                    "pid=%d comm=%s socket(SOCK_RAW) args=%s"
                    % (event.pid, event.comm or "-", event.extra.get("args", "")),
                )
                if finding:
                    findings.append(finding)

        destination = (event.dst_ip or "").strip()
        domain = (event.domain or "").strip()
        if event.path and not destination:
            # AF_UNIX connect: sandbox escape rules handle runtime sockets.
            return findings

        # -- CS-CRED-006: cloud metadata service -------------------------
        if _is_metadata(destination, domain):
            key = destination.lower() or domain.lower().rstrip(".")
            if not self.dedupe(("CS-CRED-006", key), event.ts, 300):
                target = destination or domain
                finding = ctx.finding(
                    "CS-CRED-006",
                    event,
                    "dst=%s metadata_service comm=%s"
                    % (_host_port(target, event.dst_port), event.comm or "-"),
                )
                if finding:
                    findings.append(finding)
            return findings

        if not destination and not domain:
            return findings
        if destination and not (IPV4_RE.match(destination) or ":" in destination):
            return findings

        allowed = ctx.ip_allowed(destination) if destination else False
        if domain and ctx.domain_allowed(domain):
            allowed = True

        # -- CS-NET-004: upload volume -----------------------------------
        if not allowed:
            key = (destination or domain, event.dst_port)
            entry = self._volume.setdefault(key, [deque(), 0])
            queue, total = entry
            size = max(0, event.nbytes)
            queue.append((event.ts, size))
            total += size
            cutoff = event.ts - window_sec
            while queue and queue[0][0] < cutoff:
                _, expired = queue.popleft()
                total -= expired
            entry[1] = total
            if total >= upload_bytes and not self.dedupe(("CS-NET-004", key[0], key[1]), event.ts, window_sec):
                finding = ctx.finding(
                    "CS-NET-004",
                    event,
                    "dst=%s uploaded=%d bytes in %.0fs" % (_host_port(key[0], event.dst_port), total, window_sec),
                )
                if finding:
                    findings.append(finding)

        if allowed:
            return findings

        port = event.dst_port
        target = _host_port(domain or destination, port)

        # One primary finding per connection, highest signal first.
        if not domain and destination and is_public_ip(destination):
            rule_id = "CS-NET-002"
            evidence = "dst=%s public_ip_without_domain comm=%s" % (target, event.comm or "-")
        elif port not in common_ports:
            rule_id = "CS-NET-005"
            evidence = "dst=%s unusual_port" % target
        else:
            rule_id = "CS-NET-001"
            evidence = "dst=%s not_in_allowlist" % target

        if self.dedupe((rule_id, target), event.ts, 120):
            return findings

        finding = ctx.finding(rule_id, event, evidence)
        if finding:
            findings.append(finding)
        return findings
