"""Response action tests: kill guard and firewall command generation."""

from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cagesight import response  # noqa: E402
from cagesight.engine import Engine  # noqa: E402
from cagesight.model import Event  # noqa: E402


class KillGuardTest(unittest.TestCase):
    def test_protected_pids_are_skipped(self):
        killed = []

        def fake_kill(pid, sig):
            killed.append(pid)

        with mock.patch.object(response.os, "name", "posix"), mock.patch.object(response.os, "kill", side_effect=fake_kill):
            messages = response.kill_processes({0, 1, 4242}, enforce=True)

        self.assertEqual(killed, [4242])
        self.assertTrue(any("skip" in message and "0,1" in message for message in messages))

    def test_negative_pid_is_protected(self):
        # POSIX 上 kill(-1) 会杀掉当前用户能杀的所有进程
        killed = []
        with mock.patch.object(response.os, "name", "posix"), mock.patch.object(
            response.os, "kill", side_effect=lambda pid, sig: killed.append(pid)
        ):
            messages = response.kill_processes({-1, 4242}, enforce=True)
        self.assertEqual(killed, [4242])
        self.assertTrue(any("-1" in message for message in messages))

    def test_dry_run_only_lists_safe_pids(self):
        messages = response.kill_processes({1, 4242}, enforce=False)
        joined = "\n".join(messages)
        self.assertIn("dry-run", joined)
        self.assertIn("4242", joined)
        self.assertTrue(any("skip" in message for message in messages))

    def test_block_commands_use_split_safe_arguments(self):
        commands = response.block_commands({"45.77.12.9"})
        self.assertTrue(commands)
        self.assertIn("45.77.12.9", commands[0])
        # 命令最终以 split() 参数执行，不经过 shell。
        self.assertNotIn(";", commands[0])
        self.assertNotIn("|", commands[0])

    def test_ipv6_targets_are_collected_and_blocked(self):
        result = Engine().run(
            [
                Event.from_dict(
                    {
                        "ts": 1794182400,
                        "kind": "net",
                        "pid": 4242,
                        "comm": "a",
                        "dst_ip": "2001:db8::66",
                        "dst_port": 4444,
                    }
                )
            ]
        )
        targets = response.collect_targets(result)
        self.assertEqual(targets["ips"], {"2001:db8::66"})

        commands = response.block_commands(targets["ips"])
        self.assertIn("ip6 daddr", commands[0])
        self.assertIn("2001:db8::66", commands[0])

        legacy = response.block_commands(targets["ips"], backend="iptables")
        self.assertTrue(legacy[0].startswith("ip6tables"))


if __name__ == "__main__":
    unittest.main()
