"""CLI and report rendering tests."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cagesight.cli import main  # noqa: E402
from cagesight.engine import Engine, Result  # noqa: E402
from cagesight.model import Finding  # noqa: E402
from cagesight.report import render_json, render_markdown, render_sarif, render_table  # noqa: E402
from tests.helpers import BASE_TS, event  # noqa: E402


def run_cli(args) -> tuple:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = main(args)
    return code, buffer.getvalue()


class CliTest(unittest.TestCase):
    def test_scan_json_and_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "events.jsonl")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "ts": BASE_TS,
                            "kind": "file",
                            "pid": 4242,
                            "path": "/home/agent/.aws/credentials",
                        }
                    )
                    + "\n"
                )
            code, output = run_cli(["scan", path, "--format", "json"])
            payload = json.loads(output)
            self.assertEqual(code, 2)
            self.assertEqual(payload["findings"][0]["rule_id"], "CS-CRED-002")

    def test_rules_command(self):
        code, output = run_cli(["rules"])
        self.assertEqual(code, 0)
        self.assertIn("CS-CHAIN-001", output)

    def test_demo_runs(self):
        code, output = run_cli(["demo"])
        self.assertEqual(code, 0)
        self.assertIn("CS-CHAIN-001", output)

    def test_markdown_output_file(self):
        with tempfile.TemporaryDirectory() as directory:
            source = os.path.join(directory, "events.jsonl")
            target = os.path.join(directory, "report.md")
            with open(source, "w", encoding="utf-8") as handle:
                handle.write(json.dumps({"ts": BASE_TS, "kind": "file", "path": "/home/agent/.ssh/id_rsa"}) + "\n")
            code, _ = run_cli(["scan", source, "--format", "md", "--out", target])
            self.assertEqual(code, 2)
            with open(target, encoding="utf-8") as handle:
                content = handle.read()
            self.assertIn("# CageSight", content)
            self.assertIn("CS-CRED-001", content)

    def test_min_severity_controls_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            source = os.path.join(directory, "events.jsonl")
            with open(source, "w", encoding="utf-8") as handle:
                # 只有 high（SSH 私钥），没有 critical
                handle.write(json.dumps({"ts": BASE_TS, "kind": "file", "path": "/home/agent/.ssh/id_rsa"}) + "\n")
            code, output = run_cli(["scan", source, "--min-severity", "critical", "--format", "json"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)["findings"], [])


class ReportTest(unittest.TestCase):
    def setUp(self) -> None:
        events = [
            event(ts=BASE_TS, kind="file", path="/home/agent/.aws/credentials"),
            event(ts=BASE_TS + 1, kind="exec", argv=["sh", "-c", "tar czf /tmp/loot.tgz /home/agent/.aws"]),
            event(ts=BASE_TS + 2, kind="net", dst_ip="45.77.12.9", dst_port=4444),
        ]
        self.result = Engine().run(events)

    def test_table(self):
        text = render_table(self.result, color=False)
        self.assertIn("CS-CHAIN-001", text)
        self.assertIn("完整攻击链", text)

    def test_single_critical_is_not_called_a_chain(self):
        finding = Finding(
            rule_id="CS-CRED-006",
            title="访问云元数据服务",
            severity="critical",
            score=90,
            evidence="dst=169.254.169.254:80",
            ts=BASE_TS,
        )
        text = render_table(Result(findings=[finding], events=1), color=False)
        self.assertIn("严重风险", text)
        self.assertNotIn("完整攻击链", text)

    def test_sarif(self):
        payload = json.loads(render_sarif(self.result))
        self.assertEqual(payload["version"], "2.1.0")
        self.assertTrue(payload["runs"][0]["results"])

    def test_json_and_markdown(self):
        payload = json.loads(render_json(self.result))
        self.assertEqual(payload["highest"], "critical")
        text = render_markdown(self.result)
        self.assertIn("数据外带链路", text)

    def test_control_chars_are_stripped(self):
        # 日志内容可被攻击者控制，不能让 ANSI 转义码 / RTL 字符进入终端。
        finding = Finding(
            rule_id="CS-TEST-001",
            title="test",
            severity="high",
            score=70,
            evidence="evil\x1b[31mPWNED\x1b[0m\u202e",
            comm="agent\x07\u200b",
            ts=BASE_TS,
        )
        result = Result(findings=[finding], events=1)
        text = render_table(result, color=False)
        markdown = render_markdown(result)
        for bad in ("\x1b", "\x07", "\u202e", "\u200b"):
            self.assertNotIn(bad, text)
            self.assertNotIn(bad, markdown)


if __name__ == "__main__":
    unittest.main()
