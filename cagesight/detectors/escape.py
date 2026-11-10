"""Sandbox escape primitives: ptrace, namespaces, mounts, modules, runtime sockets."""

from __future__ import annotations

import re
from typing import List

from cagesight.config import Context
from cagesight.detectors.base import BaseDetector
from cagesight.model import Event, Finding

RUNTIME_SOCKET_RE = re.compile(
    r"(docker\.sock|containerd\.sock|crio\.sock|podman\.sock|/run/containerd/|/var/run/docker)"
)
PROC_WRITE_RE = re.compile(r"^/proc/(sys/.+|self/mem|\d+/mem)$")
PTRACE_REQUESTS = {16, 0x4206}  # PTRACE_ATTACH, PTRACE_SEIZE


class EscapeDetector(BaseDetector):
    name = "escape"

    def feed(self, event: Event, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []

        if event.kind == "syscall":
            findings.extend(self._check_syscall(event, ctx))
        elif event.kind == "file":
            findings.extend(self._check_file(event, ctx))
        elif event.kind == "net" and event.path:
            findings.extend(self._check_unix(event, ctx))

        return findings

    # -- syscalls --------------------------------------------------------
    def _check_syscall(self, event: Event, ctx: Context) -> List[Finding]:
        syscall = event.syscall.lower()
        request = event.extra.get("request")
        request_name = str(event.extra.get("request_name", ""))

        if syscall == "ptrace":
            if request in PTRACE_REQUESTS or request_name in ("PTRACE_ATTACH", "PTRACE_SEIZE"):
                if self.dedupe(("CS-ESC-001", event.pid), event.ts, 300):
                    return []
                finding = ctx.finding(
                    "CS-ESC-001",
                    event,
                    "pid=%d comm=%s ptrace(%s)" % (event.pid, event.comm or "-", request_name or request),
                )
                return [finding] if finding else []
            return []

        table = {
            "setns": ("CS-ESC-002", "setns()"),
            "unshare": ("CS-ESC-002", "unshare()"),
            "mount": ("CS-ESC-003", "mount()"),
            "umount2": ("CS-ESC-003", "umount2()"),
            "init_module": ("CS-ESC-004", "init_module()"),
            "finit_module": ("CS-ESC-004", "finit_module()"),
        }
        entry = table.get(syscall)
        if not entry:
            return []
        rule_id, label = entry
        if self.dedupe((rule_id, event.pid), event.ts, 300):
            return []
        finding = ctx.finding(rule_id, event, "pid=%d comm=%s %s" % (event.pid, event.comm or "-", label))
        return [finding] if finding else []

    # -- file paths ------------------------------------------------------
    def _check_file(self, event: Event, ctx: Context) -> List[Finding]:
        path = event.path or ""
        lowered = path.lower()
        findings: List[Finding] = []

        if RUNTIME_SOCKET_RE.search(lowered):
            if not self.dedupe(("CS-ESC-006", path), event.ts, 300):
                finding = ctx.finding("CS-ESC-006", event, "path=%s comm=%s" % (path, event.comm or "-"))
                if finding:
                    findings.append(finding)

        if PROC_WRITE_RE.match(lowered):
            if not self.dedupe(("CS-ESC-005", path), event.ts, 300):
                finding = ctx.finding("CS-ESC-005", event, "path=%s comm=%s" % (path, event.comm or "-"))
                if finding:
                    findings.append(finding)

        return findings

    def _check_unix(self, event: Event, ctx: Context) -> List[Finding]:
        if not RUNTIME_SOCKET_RE.search((event.path or "").lower()):
            return []
        if self.dedupe(("CS-ESC-006", event.path), event.ts, 300):
            return []
        finding = ctx.finding(
            "CS-ESC-006",
            event,
            "connect(unix, %s) pid=%d" % (event.path, event.pid),
        )
        return [finding] if finding else []
