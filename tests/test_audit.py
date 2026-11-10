"""Sandbox configuration audit tests."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cagesight.audit import audit_file  # noqa: E402


def write_temp(content: str, suffix: str = ".yml") -> str:
    handle = tempfile.NamedTemporaryFile("w", delete=False, suffix=suffix, encoding="utf-8")
    handle.write(content)
    handle.close()
    return handle.name


class AuditTest(unittest.TestCase):
    def tearDown(self) -> None:
        for path in getattr(self, "_paths", []):
            try:
                os.unlink(path)
            except OSError:
                pass

    def _write(self, content: str, suffix: str = ".yml") -> str:
        path = write_temp(content, suffix)
        self._paths = getattr(self, "_paths", []) + [path]
        return path

    def test_insecure_compose(self):
        content = """
services:
  agent:
    image: python:3.12
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""
        result = audit_file(self._write(content))
        ids = {issue.rule_id for issue in result.issues}
        self.assertIn("SBX-001", ids)
        self.assertIn("SBX-003", ids)
        self.assertIn("SBX-008", ids)
        self.assertEqual(result.highest(), "critical")

    def test_docker_inspect(self):
        payload = [
            {
                "Name": "/agent",
                "HostConfig": {
                    "Privileged": True,
                    "PidMode": "host",
                    "Binds": ["/var/run/docker.sock:/var/run/docker.sock"],
                    "CapAdd": ["SYS_ADMIN"],
                    "ReadonlyRootfs": False,
                },
                "Config": {"User": ""},
            }
        ]
        result = audit_file(self._write(json.dumps(payload), ".json"))
        ids = {issue.rule_id for issue in result.issues}
        for expected in ("SBX-001", "SBX-002", "SBX-005", "SBX-008", "SBX-011"):
            self.assertIn(expected, ids)

    def test_kubernetes_pod(self):
        payload = {
            "spec": {
                "hostPID": True,
                "containers": [
                    {"name": "agent", "securityContext": {"privileged": True, "runAsUser": 0}}
                ],
            }
        }
        result = audit_file(self._write(json.dumps(payload), ".json"))
        ids = {issue.rule_id for issue in result.issues}
        self.assertIn("SBX-002", ids)
        self.assertIn("SBX-001", ids)
        self.assertIn("SBX-011", ids)

    def test_seccomp_allow_all(self):
        payload = {"defaultAction": "SCMP_ACT_ALLOW", "syscalls": []}
        result = audit_file(self._write(json.dumps(payload), ".json"))
        self.assertIn("SBX-006", {issue.rule_id for issue in result.issues})

    def test_utf8_bom_json_is_parsed_structurally(self):
        payload = [{"Name": "/a", "HostConfig": {"Privileged": True}, "Config": {"User": "1000"}}]
        handle = tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8-sig")
        handle.write(json.dumps(payload))
        handle.close()
        self._paths = getattr(self, "_paths", []) + [handle.name]
        result = audit_file(handle.name)
        ids = {issue.rule_id for issue in result.issues}
        self.assertIn("SBX-001", ids)
        self.assertNotIn("SBX-000", ids)

    def test_unknown_json_falls_back_to_text(self):
        # 结构未知的 JSON 不能被静默当成“没有问题”。
        payload = {"outer": {"privileged": True, "network_mode": "host"}}
        result = audit_file(self._write(json.dumps(payload), ".json"))
        ids = {issue.rule_id for issue in result.issues}
        self.assertIn("SBX-001", ids)
        self.assertIn("SBX-003", ids)

    def test_random_json_reports_unrecognized(self):
        result = audit_file(self._write(json.dumps({"hello": "world"}), ".json"))
        ids = {issue.rule_id for issue in result.issues}
        self.assertIn("SBX-000", ids)

    def test_docker_run_host_mount(self):
        content = "docker run --rm -v /:/host -v /proc:/host/proc agent:latest"
        result = audit_file(self._write(content, ".txt"))
        self.assertIn("SBX-009", {issue.rule_id for issue in result.issues})

    def test_normal_data_mount_is_allowed(self):
        content = "docker run --rm -v /data:/data:ro --read-only agent:latest"
        result = audit_file(self._write(content, ".txt"))
        self.assertNotIn("SBX-009", {issue.rule_id for issue in result.issues})

    def test_hardened_config_has_no_critical(self):
        payload = {
            "Name": "/agent",
            "HostConfig": {
                "Privileged": False,
                "PidMode": "",
                "NetworkMode": "bridge",
                "CapAdd": [],
                "SecurityOpt": ["no-new-privileges", "seccomp=default"],
                "ReadonlyRootfs": True,
                "Memory": 536870912,
                "Binds": ["/data:/data:ro"],
            },
            "Config": {"User": "1000"},
        }
        result = audit_file(self._write(json.dumps(payload), ".json"))
        self.assertNotIn("critical", {issue.severity for issue in result.issues})


if __name__ == "__main__":
    unittest.main()
