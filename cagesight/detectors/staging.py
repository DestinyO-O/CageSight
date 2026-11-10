"""Staging detection: archive creation in temp dirs and bulk sensitive reads."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, List, Set

from cagesight.config import Context, which_sensitive_group
from cagesight.detectors.base import BaseDetector
from cagesight.model import Event, Finding

ARCHIVE_RE = re.compile(r"\b(tar|zip|7z|rar|gzip|bzip2|xz)\b")
TMP_TARGET_RE = re.compile(r"(/tmp/|/dev/shm/|/var/tmp/|\\temp\\)")


class StagingDetector(BaseDetector):
    name = "staging"

    def __init__(self) -> None:
        super().__init__()
        self._buckets: Dict[int, Set[str]] = defaultdict(set)

    def feed(self, event: Event, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []

        if event.kind == "exec":
            command = event.cmdline
            if ARCHIVE_RE.search(command) and TMP_TARGET_RE.search(command):
                if not self.dedupe(("CS-STG-001", command[:150]), event.ts, 300):
                    finding = ctx.finding("CS-STG-001", event, "cmd=%s" % command[:180])
                    if finding:
                        findings.append(finding)

        if event.kind == "file" and event.path:
            group = which_sensitive_group(event.path, ctx.sensitive_paths)
            if group:
                settings = ctx.thresholds.get("staging", {})
                window = float(settings.get("window_sec", 300))
                current = int(event.ts // window)
                # 只保留当前与上一个窗口，避免长日志下桶无限增长。
                if len(self._buckets) > 4:
                    for key in [k for k in self._buckets if k < current - 1]:
                        del self._buckets[key]
                bucket = self._buckets[current]
                bucket.add(event.path)
                minimum = int(settings.get("min_files", 3))
                if len(bucket) >= minimum and not self.dedupe(("CS-STG-002",), event.ts, window):
                    sample = ", ".join(sorted(bucket)[:3])
                    finding = ctx.finding(
                        "CS-STG-002",
                        event,
                        "files=%d in window, sample=[%s]" % (len(bucket), sample),
                    )
                    if finding:
                        findings.append(finding)

        return findings
