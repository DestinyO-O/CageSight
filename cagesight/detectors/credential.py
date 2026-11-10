"""Credential access detection: SSH keys, cloud creds, env vars, cluster creds."""

from __future__ import annotations

import re
from typing import List

from cagesight.config import Context, which_sensitive_group
from cagesight.detectors.base import BaseDetector
from cagesight.model import Event, Finding

GROUP_RULE = {
    "ssh": "CS-CRED-001",
    "cloud": "CS-CRED-002",
    "app": "CS-CRED-002",
    "envfiles": "CS-CRED-002",
    "container": "CS-CRED-004",
}

RUNTIME_SOCKETS = ("docker.sock", "containerd.sock", "crio.sock", "podman.sock")

ENV_COMMANDS = re.compile(r"(^|/)(env|printenv)$")
ENV_ARGS = re.compile(r"printenv|/proc/(self|\d+)/environ|/etc/environment")


class CredentialDetector(BaseDetector):
    name = "credential"

    def __init__(self) -> None:
        super().__init__()
        self._batch = {}

    def feed(self, event: Event, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []

        if event.kind == "file" and event.path:
            findings.extend(self._check_path(event, ctx))
        elif event.kind == "exec":
            findings.extend(self._check_exec(event, ctx))

        return findings

    def _check_path(self, event: Event, ctx: Context) -> List[Finding]:
        path = event.path
        lowered = path.lower()
        group = which_sensitive_group(path, ctx.sensitive_paths)
        if not group:
            return []

        # Runtime sockets are reported by the escape detector (CS-ESC-006).
        if group == "container" and any(sock in lowered for sock in RUNTIME_SOCKETS):
            return []

        if group == "system":
            rule_id = "CS-CRED-003" if "environ" in lowered else "CS-CRED-005"
        elif group == "app" and ".docker/config.json" in lowered:
            rule_id = "CS-CRED-004"
        else:
            rule_id = GROUP_RULE.get(group)
        if not rule_id:
            return []
        if self.dedupe((rule_id, path), event.ts, 300):
            return []

        finding = ctx.finding(rule_id, event, "path=%s group=%s comm=%s" % (path, group, event.comm or "-"))
        return [finding] if finding else []

    def _check_exec(self, event: Event, ctx: Context) -> List[Finding]:
        if not event.argv:
            return []
        base = event.argv[0].lower().rsplit("/", 1)[-1]
        command = event.cmdline.lower()
        if not (ENV_COMMANDS.search("/" + base) or ENV_ARGS.search(command)):
            return []
        if self.dedupe(("CS-CRED-003", command[:120]), event.ts, 300):
            return []
        finding = ctx.finding("CS-CRED-003", event, "cmd=%s" % (command[:180] or base))
        return [finding] if finding else []
