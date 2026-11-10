"""Detection engine: runs detectors, correlates findings into chains, scores."""

from __future__ import annotations

import os
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from cagesight.config import Context, load_config, load_rules
from cagesight.detectors import build_detectors
from cagesight.model import Event, Finding, SEVERITY_ORDER, severity_at_least


@dataclass
class Result:
    findings: List[Finding] = field(default_factory=list)
    events: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0
    sources: Dict[str, int] = field(default_factory=dict)
    detector_errors: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.finished_at - self.started_at)

    def counts(self) -> Dict[str, int]:
        counter = Counter(f.severity for f in self.findings)
        return {sev: counter.get(sev, 0) for sev in ("critical", "high", "medium", "low", "info")}

    def highest(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity

    def by_rule(self) -> Dict[str, int]:
        return dict(Counter(f.rule_id for f in self.findings))

    def filtered(self, minimum: str) -> List[Finding]:
        return [f for f in self.findings if severity_at_least(f.severity, minimum)]


class Engine:
    def __init__(self, config: Optional[dict] = None, rules: Optional[dict] = None):
        self.config = config if config is not None else load_config()
        self.rules = rules if rules is not None else load_rules()
        self.ctx = Context(self.config, self.rules)

    def run(self, events: Iterable[Event]) -> Result:
        started = time.time()
        event_list = list(events)
        detectors = build_detectors()
        findings: List[Finding] = []
        sources: Dict[str, int] = defaultdict(int)
        detector_errors = 0

        for event in event_list:
            sources[event.source or "unknown"] += 1
            for detector in detectors:
                try:
                    findings.extend(detector.feed(event, self.ctx))
                except Exception:
                    if os.environ.get("CAGESIGHT_DEBUG"):
                        raise
                    detector_errors += 1
                    continue

        findings.extend(self._correlate(findings))

        deduped: List[Finding] = []
        seen: set = set()
        for finding in findings:
            key = (finding.rule_id, finding.pid, finding.evidence[:120])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)

        deduped.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.ts))
        return Result(
            findings=deduped,
            events=len(event_list),
            started_at=started,
            finished_at=time.time(),
            sources=dict(sources),
            detector_errors=detector_errors,
        )

    # -- correlation -----------------------------------------------------
    def _correlate(self, findings: List[Finding]) -> List[Finding]:
        settings = self.config.get("correlation", {})
        window = float(settings.get("window_sec", 600))
        escape_window = float(settings.get("escape_window_sec", 300))

        chains = self._correlate_by_pid(findings, window, escape_window)
        if not chains:
            # Cross-source fallback: pcap events carry no pid, so a real chain
            # may span auditd (pid) and pcap (0). Only used when nothing matched.
            chains = self._correlate_by_pid(findings, window, escape_window, ignore_pid=True)
        return chains

    def _correlate_by_pid(
        self,
        findings: List[Finding],
        window: float,
        escape_window: float,
        ignore_pid: bool = False,
    ) -> List[Finding]:
        groups: Dict[int, List[Finding]] = defaultdict(list)
        for finding in findings:
            groups[0 if ignore_pid else finding.pid].append(finding)

        chains: List[Finding] = []
        for pid, group in groups.items():
            group.sort(key=lambda f: f.ts)
            chains.extend(self._chain_collection(group, pid, window))
            chains.extend(self._chain_escape(group, pid, escape_window))
        return chains

    def _chain_collection(self, group: List[Finding], pid: int, window: float) -> List[Finding]:
        tags = self._first_hits(group, {"credential", "staging", "egress"})
        if len(tags) < 3:
            return []
        first = min(tags.values(), key=lambda f: f.ts)
        last = max(tags.values(), key=lambda f: f.ts)
        if last.ts - first.ts > window:
            return []
        evidence = self._evidence(tags, ("credential", "staging", "egress"))
        event = Event(ts=last.ts, pid=pid, comm=last.comm, kind="chain", source="correlation")
        finding = self.ctx.finding(
            "CS-CHAIN-001",
            event,
            "%s window=%.0fs pid=%s" % (evidence, window, pid or "-"),
            severity="critical",
        )
        if finding:
            finding.score = 100
        return [finding] if finding else []

    def _chain_escape(self, group: List[Finding], pid: int, window: float) -> List[Finding]:
        tags = self._first_hits(group, {"escape", "exec"})
        if len(tags) < 2:
            return []
        first = min(tags.values(), key=lambda f: f.ts)
        last = max(tags.values(), key=lambda f: f.ts)
        if last.ts - first.ts > window:
            return []
        evidence = self._evidence(tags, ("escape", "exec"))
        event = Event(ts=last.ts, pid=pid, comm=last.comm, kind="chain", source="correlation")
        finding = self.ctx.finding(
            "CS-CHAIN-002",
            event,
            "%s window=%.0fs pid=%s" % (evidence, window, pid or "-"),
            severity="critical",
        )
        if finding:
            finding.score = 100
        return [finding] if finding else []

    @staticmethod
    def _evidence(tags: Dict[str, Finding], order: Tuple[str, ...]) -> str:
        pairs = sorted(
            ((tag, tags[tag]) for tag in order if tag in tags),
            key=lambda item: item[1].ts,
        )
        return " -> ".join(
            "%s@%s" % (finding.rule_id, time.strftime("%H:%M:%S", time.localtime(finding.ts)))
            for _, finding in pairs
        )

    @staticmethod
    def _first_hits(group: List[Finding], wanted: set) -> Dict[str, Finding]:
        hits: Dict[str, Finding] = {}
        for finding in group:
            for tag in wanted:
                if tag in finding.tags and tag not in hits:
                    hits[tag] = finding
        return hits
