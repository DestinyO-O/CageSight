"""Command execution chain detection: download-and-exec, obfuscation, temp dirs."""

from __future__ import annotations

import re
from typing import List

from cagesight.config import Context
from cagesight.detectors.base import BaseDetector
from cagesight.model import Event, Finding

DOWNLOAD_EXEC = re.compile(
    r"(curl|wget)[^|]{0,400}\|\s*(sudo\s+)?(ba|z|k)?sh\b", re.IGNORECASE
)
B64_EXEC = re.compile(
    r"base64\s+(?:-d|--decode)[^|]{0,300}\|\s*(sudo\s+)?(ba|z|k)?sh\b", re.IGNORECASE
)
TMP_INTERP = re.compile(
    r"(?:^|[\s/])(?:ba|z|k)?sh\s+(?:-c\s+)?[\"']?(?:/tmp/|/dev/shm/|/var/tmp/)", re.IGNORECASE
)
TMP_SCRIPT = re.compile(
    r"\b(python[0-9.]*|perl|ruby|node|php)\s+(?:-c\s+)?[\"']?(?:/tmp/|/dev/shm/|/var/tmp/)",
    re.IGNORECASE,
)
REVERSE_SHELL = re.compile(
    r"(^|[\s/])(nc|ncat|netcat|socat)\b[^\n]*(-e\s|exec:|tcp:|udp:)|/dev/tcp/", re.IGNORECASE
)


class ExecChainDetector(BaseDetector):
    name = "exec_chain"

    def feed(self, event: Event, ctx: Context) -> List[Finding]:
        if event.kind != "exec":
            return []
        command = event.cmdline
        if not command:
            return []

        checks = (
            ("CS-EXEC-001", DOWNLOAD_EXEC),
            ("CS-EXEC-002", B64_EXEC),
            ("CS-EXEC-003", TMP_INTERP),
            ("CS-EXEC-003", TMP_SCRIPT),
            ("CS-EXEC-004", REVERSE_SHELL),
        )

        findings: List[Finding] = []
        for rule_id, pattern in checks:
            if not pattern.search(command):
                continue
            if self.dedupe((rule_id, command[:160]), event.ts, 300):
                continue
            finding = ctx.finding(rule_id, event, "cmd=%s" % command[:200])
            if finding:
                findings.append(finding)
        return findings
