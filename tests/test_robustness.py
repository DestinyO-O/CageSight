"""Robustness tests: malformed inputs must never crash the parsers or engine."""

from __future__ import annotations

import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cagesight.engine import Engine  # noqa: E402
from cagesight.audit import audit_file  # noqa: E402
from cagesight.model import Event  # noqa: E402
from cagesight.parsers import auditd, jsonl, pcap, strace  # noqa: E402

ALPHABET = "abc{}[]()=\"',:/.-_ 0123456789\\|;<>$%&*+"


class FuzzTest(unittest.TestCase):
    def test_random_text_inputs_do_not_crash(self):
        rng = random.Random(20261109)
        for _ in range(200):
            lines = [
                "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 120)))
                for _ in range(rng.randint(0, 20))
            ]
            for parser in (auditd.parse_lines, strace.parse_lines, jsonl.parse_lines):
                parser(lines)

    def test_random_pcap_bytes_do_not_crash(self):
        rng = random.Random(42)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "fuzz.pcap")
            for _ in range(60):
                blob = bytes(rng.randrange(256) for _ in range(rng.randint(0, 400)))
                with open(path, "wb") as handle:
                    handle.write(blob)
                try:
                    pcap.parse_pcap(path)
                except ValueError:
                    pass  # 明确的格式错误是可接受的

    def test_random_events_do_not_crash_engine(self):
        rng = random.Random(7)
        events = []
        for _ in range(100):
            events.append(
                Event.from_dict(
                    {
                        "ts": rng.randint(0, 1794182400),
                        "kind": rng.choice(["exec", "file", "net", "dns", "syscall", "tool"]),
                        "pid": rng.randint(0, 5000),
                        "comm": "".join(rng.choice("abc") for _ in range(3)),
                        "path": "".join(rng.choice("/abc.ssh") for _ in range(rng.randint(0, 30))),
                        "domain": "".join(rng.choice("ab.-") for _ in range(rng.randint(0, 40))),
                        "dst_port": rng.randint(0, 70000),
                        "nbytes": rng.randint(0, 10**7),
                    }
                )
            )
        Engine().run(events)

    def test_deeply_nested_json_does_not_crash(self):
        deep = "[" * 100000 + "]" * 100000
        self.assertEqual(jsonl.parse_lines([deep]), [])
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "deep.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(deep)
            result = audit_file(path)
            self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
