"""DNS tunneling detection: entropy, label length, rate and record type."""

from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from typing import Deque, Dict, List, Tuple

from cagesight.config import Context
from cagesight.detectors.base import BaseDetector
from cagesight.model import Event, Finding

MULTI_LABEL_SUFFIXES = {
    "com.cn",
    "net.cn",
    "org.cn",
    "gov.cn",
    "edu.cn",
    "ac.cn",
    "com.hk",
    "com.tw",
    "com.mo",
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "co.jp",
    "ne.jp",
    "or.jp",
    "co.kr",
    "or.kr",
    "com.au",
    "net.au",
    "org.au",
    "com.br",
    "net.br",
    "org.br",
    "co.in",
    "net.in",
    "com.mx",
    "com.ar",
    "com.tr",
    "com.sg",
    "com.my",
    "co.id",
    "co.th",
    "com.ph",
    "com.vn",
    "com.sa",
    "com.ae",
    "co.za",
    "com.eg",
    "com.ua",
    "com.pl",
    "co.nz",
    "com.co",
    "com.pe",
    "com.ve",
}


def base_domain(qname: str) -> str:
    labels = [label for label in qname.lower().strip(".").split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


class DnsTunnelDetector(BaseDetector):
    name = "dns_tunnel"

    def __init__(self) -> None:
        super().__init__()
        self._windows: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        # 每个基础域的域名计数，用于 O(1) 维护窗口内唯一域名数，
        # 避免每个事件都遍历整个窗口（否则高并发 DNS 会退化为 O(n^2)）。
        self._counts: Dict[str, Counter] = defaultdict(Counter)

    def feed(self, event: Event, ctx: Context) -> List[Finding]:
        if event.kind != "dns" or not event.domain:
            return []

        thresholds = ctx.thresholds.get("dns", {})
        base = base_domain(event.domain)
        if not base or ctx.domain_allowed(base):
            return []

        sub = event.domain[: -(len(base) + 1)] if event.domain.endswith("." + base) else event.domain
        sub_compact = sub.replace(".", "")
        labels = [label for label in sub.split(".") if label]
        longest = max(labels, key=len) if labels else ""

        label_len = int(thresholds.get("label_len", 30))
        entropy_floor = float(thresholds.get("entropy", 3.4))
        window_sec = float(thresholds.get("window_sec", 60))
        min_queries = int(thresholds.get("min_queries", 20))
        unique_ratio = float(thresholds.get("unique_ratio", 0.9))
        suspicious_qtypes = {str(q).upper() for q in thresholds.get("suspicious_qtypes", ["TXT", "NULL"])}

        findings: List[Finding] = []
        entropy = shannon_entropy(longest) if longest else 0.0

        # -- CS-DNS-001: encoded-looking label ---------------------------
        if longest and len(longest) >= label_len and entropy >= entropy_floor:
            if not self.dedupe(("CS-DNS-001", base), event.ts, window_sec):
                finding = ctx.finding(
                    "CS-DNS-001",
                    event,
                    "qname=%s base=%s label_len=%d entropy=%.2f"
                    % (event.domain, base, len(longest), entropy),
                )
                if finding:
                    findings.append(finding)

        # -- CS-DNS-003: TXT / NULL abuse --------------------------------
        if event.qtype.upper() in suspicious_qtypes and (len(longest) >= 20 or entropy >= 3.0):
            if not self.dedupe(("CS-DNS-003", base), event.ts, window_sec):
                finding = ctx.finding(
                    "CS-DNS-003",
                    event,
                    "qtype=%s qname=%s base=%s" % (event.qtype, event.domain, base),
                )
                if finding:
                    findings.append(finding)

        # -- sliding window: rate + uniqueness ---------------------------
        window = self._windows[base]
        counts = self._counts[base]
        window.append((event.ts, event.domain))
        counts[event.domain] += 1
        cutoff = event.ts - window_sec
        while window and window[0][0] < cutoff:
            _, expired = window.popleft()
            counts[expired] -= 1
            if counts[expired] <= 0:
                del counts[expired]

        count = len(window)
        unique = len(counts)
        ratio = unique / count if count else 0.0

        # 高熵/长标签是隧道流量的必要条件；仅凭“查询多、子域唯一”
        # 会把 CDN 预签名、多级公共后缀等正常流量误判。
        rate_label_len = int(thresholds.get("rate_min_label_len", 12))
        rate_entropy = float(thresholds.get("rate_min_entropy", 2.8))
        looks_encoded = len(longest) >= rate_label_len and entropy >= rate_entropy

        if count >= min_queries and ratio >= unique_ratio and looks_encoded:
            if not self.dedupe(("CS-DNS-002", base), event.ts, window_sec):
                finding = ctx.finding(
                    "CS-DNS-002",
                    event,
                    "base=%s queries=%d window=%.0fs unique_ratio=%.2f"
                    % (base, count, window_sec, ratio),
                )
                if finding:
                    findings.append(finding)

        if count >= min_queries and ratio >= unique_ratio and looks_encoded and len(sub_compact) >= 8:
            if not self.dedupe(("CS-DNS-004", base), event.ts, window_sec):
                finding = ctx.finding(
                    "CS-DNS-004",
                    event,
                    "base=%s unique=%d/%d sub_len=%d" % (base, unique, count, len(sub_compact)),
                )
                if finding:
                    findings.append(finding)

        return findings
