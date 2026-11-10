"""CageSight command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from typing import List, Optional

from cagesight import __version__
from cagesight.audit import audit_file
from cagesight.config import load_config, load_rules
from cagesight.demo import write_demo
from cagesight.engine import Engine, Result
from cagesight.model import SEVERITY_ORDER, Event
from cagesight.parsers import auditd, jsonl, pcap, strace
from cagesight.report import (
    render_audit_markdown,
    render_audit_table,
    render_json,
    render_markdown,
    render_sarif,
    render_table,
)
from cagesight.response import apply_block, collect_targets, kill_processes, notify_webhook


def _enable_ansi() -> None:
    if os.name != "nt":
        return
    try:  # pragma: no cover - windows console detail
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def _read_stdin(input_type: str) -> List[Event]:
    data = sys.stdin.buffer.read()
    if input_type in ("auto", "pcap") and data[:4] in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"):
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        try:
            handle.write(data)
            handle.close()
            return pcap.parse_pcap(handle.name)
        finally:
            os.unlink(handle.name)
    text = data.decode("utf-8", "ignore")
    lines = text.splitlines()
    if input_type == "auditd" or (input_type == "auto" and "audit(" in text):
        return auditd.parse_lines(lines)
    if input_type == "strace" or (input_type == "auto" and " = " in text and "(" in text):
        return strace.parse_lines(lines)
    return jsonl.parse_lines(lines)


def _load_events(path: str, input_type: str) -> List[Event]:
    if path == "-":
        return _read_stdin(input_type)
    if input_type == "auto":
        from cagesight.parsers import detect_input_type

        input_type = detect_input_type(path)
    if input_type == "pcap":
        return pcap.parse_pcap(path)
    if input_type == "auditd":
        return auditd.parse_file(path)
    if input_type == "strace":
        return strace.parse_file(path)
    return jsonl.parse_file(path)


def _exit_code(result: Result, minimum: str, fail_on: str) -> int:
    """Exit 2 only for findings that are actually shown (>= min-severity)."""
    findings = result.filtered(minimum)
    if not findings:
        return 0
    highest = max(SEVERITY_ORDER.get(finding.severity, 0) for finding in findings)
    return 2 if highest >= SEVERITY_ORDER.get(fail_on, 3) else 0


def _run_scan(args: argparse.Namespace, input_type: Optional[str] = None) -> int:
    config = load_config(args.config)
    rules = load_rules(args.rules)
    events = _load_events(args.input, input_type or getattr(args, "input_type", "auto"))
    engine = Engine(config=config, rules=rules)
    result = engine.run(events)

    if result.detector_errors:
        print(
            "警告: %d 个事件在检测器中处理失败（设置 CAGESIGHT_DEBUG=1 查看堆栈）"
            % result.detector_errors,
            file=sys.stderr,
        )

    color = not args.no_color and sys.stdout.isatty()
    if args.format == "json":
        output = render_json(result, args.min_severity)
    elif args.format == "sarif":
        output = render_sarif(result, args.min_severity)
    elif args.format in ("md", "markdown"):
        output = render_markdown(result, args.min_severity)
    else:
        output = render_table(result, args.min_severity, color=color)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(output + "\n")
        print("报告已写入 %s" % args.out)
    else:
        print(output)

    targets = collect_targets(result)
    if args.block:
        for line in apply_block(targets["ips"], args.enforce):
            print(line)
    if args.kill:
        for line in kill_processes(targets["pids"], args.enforce):
            print(line)
    if args.webhook:
        message = notify_webhook(args.webhook, result, minimum=args.min_severity)
        if message:
            print(message)

    return _exit_code(result, args.min_severity, args.fail_on)


def _cmd_scan(args: argparse.Namespace) -> int:
    return _run_scan(args)


def _cmd_pcap(args: argparse.Namespace) -> int:
    return _run_scan(args, input_type="pcap")


def _cmd_audit(args: argparse.Namespace) -> int:
    result = audit_file(args.target)
    color = not args.no_color and sys.stdout.isatty()
    if args.format == "json":
        output = json.dumps(
            {
                "tool": "cagesight",
                "version": __version__,
                "target": result.target,
                "highest": result.highest(),
                "summary": result.counts(),
                "issues": [issue.__dict__ for issue in result.issues],
            },
            ensure_ascii=False,
            indent=2,
        )
    elif args.format in ("md", "markdown"):
        output = render_audit_markdown(result)
    else:
        output = render_audit_table(result, color=color)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(output + "\n")
        print("报告已写入 %s" % args.out)
    else:
        print(output)
    return 2 if SEVERITY_ORDER.get(result.highest(), 0) >= SEVERITY_ORDER.get(args.fail_on, 3) else 0


def _cmd_rules(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    items = rules.get("rules", [])
    if args.format == "json":
        print(json.dumps(rules, ensure_ascii=False, indent=2))
        return 0
    print("ID             SEV       MITRE        TITLE")
    print("-" * 88)
    for rule in items:
        print(
            "%-14s %-9s %-12s %s"
            % (rule.get("id"), rule.get("severity"), rule.get("mitre", "-"), rule.get("title"))
        )
    print("\n共 %d 条规则" % len(items))
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    directory = tempfile.mkdtemp(prefix="cagesight-demo-")
    paths = write_demo(directory)
    print("演示数据已生成：%s" % directory)
    print("\n[1/2] 事件日志检测（%s）" % paths["events"])
    config = load_config(None)
    rules = load_rules(None)
    events = jsonl.parse_file(paths["events"])
    result = Engine(config=config, rules=rules).run(events)
    print(render_table(result, "low", color=False))
    print("\n[2/2] pcap 流量检测（%s）" % paths["pcap"])
    pcap_result = Engine(config=config, rules=rules).run(pcap.parse_pcap(paths["pcap"]))
    print(render_table(pcap_result, "low", color=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cagesight",
        description="CageSight - Agent 沙箱外传/逃逸检测工具",
    )
    parser.add_argument("--version", action="version", version="cagesight " + __version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_scan_options(target: argparse.ArgumentParser, include_input_type: bool = True) -> None:
        target.add_argument("input", help="事件文件，- 表示标准输入")
        if include_input_type:
            target.add_argument(
                "--input-type",
                default="auto",
                choices=["auto", "auditd", "strace", "jsonl", "pcap"],
                help="输入格式（默认自动识别）",
            )
        target.add_argument("--format", default="table", choices=["table", "json", "sarif", "md"], help="输出格式")
        target.add_argument("--out", help="报告输出文件")
        target.add_argument("--min-severity", default="low", choices=["low", "medium", "high", "critical"])
        target.add_argument("--config", help="JSON 配置文件")
        target.add_argument("--rules", help="自定义规则文件")
        target.add_argument("--no-color", action="store_true", help="关闭颜色")
        target.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical"],
                            help="达到该等级时返回退出码 2")
        target.add_argument("--block", action="store_true", help="生成/执行出站封禁命令")
        target.add_argument("--kill", action="store_true", help="终止命中规则的进程")
        target.add_argument("--enforce", action="store_true", help="真正执行 --block/--kill（默认 dry-run）")
        target.add_argument("--webhook", help="告警 webhook 地址")

    scan = subparsers.add_parser("scan", help="分析事件日志")
    add_scan_options(scan)
    scan.set_defaults(func=_cmd_scan)

    pcap_parser = subparsers.add_parser("pcap", help="分析 pcap 流量")
    add_scan_options(pcap_parser, include_input_type=False)
    pcap_parser.set_defaults(func=_cmd_pcap)

    audit = subparsers.add_parser("audit-config", help="沙箱配置静态体检")
    audit.add_argument("target", help="docker inspect / k8s pod / compose / seccomp 文件")
    audit.add_argument("--format", default="table", choices=["table", "json", "md"])
    audit.add_argument("--out")
    audit.add_argument("--no-color", action="store_true")
    audit.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical"])
    audit.set_defaults(func=_cmd_audit)

    rules = subparsers.add_parser("rules", help="列出检测规则")
    rules.add_argument("--rules", help="自定义规则文件")
    rules.add_argument("--format", default="table", choices=["table", "json"])
    rules.set_defaults(func=_cmd_rules)

    demo = subparsers.add_parser("demo", help="运行内置演示")
    demo.set_defaults(func=_cmd_demo)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _enable_ansi()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print("文件不存在: %s" % exc, file=sys.stderr)
        return 1
    except OSError as exc:
        print("无法读取文件: %s" % exc, file=sys.stderr)
        return 1
    except ValueError as exc:
        print("输入错误: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
