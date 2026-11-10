"""Report renderers: console table, JSON, SARIF and Markdown."""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from typing import Dict, List

from cagesight import __version__
from cagesight.audit import AuditResult
from cagesight.engine import Result
from cagesight.model import SEVERITY_ORDER

SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}

ANSI = {
    "critical": "\033[1;97;41m",
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[1;36m",
    "info": "\033[0;37m",
    "reset": "\033[0m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "green": "\033[1;32m",
    "red": "\033[1;31m",
}


def _paint(text: str, severity: str, enabled: bool) -> str:
    if not enabled:
        return text
    return ANSI.get(severity, "") + text + ANSI["reset"]


def _truncate(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    return text[: max(0, width - 3)] + "..."


CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
# 双向控制符 / 零宽字符：可被用来在终端里伪造文本顺序（Trojan Source 类攻击）
DIRECTIONAL_CHARS = re.compile("[\u200b-\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029]")


def _safe(value) -> str:
    """Strip control and bidi characters so attacker-controlled logs cannot
    inject ANSI escapes, carriage returns or visually reorder terminal text."""
    text = CONTROL_CHARS.sub(".", str(value).replace("\r", " ").replace("\n", " "))
    return DIRECTIONAL_CHARS.sub("", text)


def _summarize(findings: List) -> tuple:
    counter = Counter(finding.severity for finding in findings)
    counts = {severity: counter.get(severity, 0) for severity in ("critical", "high", "medium", "low", "info")}
    highest = "info"
    if findings:
        highest = max(findings, key=lambda finding: SEVERITY_ORDER.get(finding.severity, 0)).severity
    return counts, highest


def render_table(result: Result, minimum: str = "low", color: bool = True) -> str:
    findings = result.filtered(minimum)
    counts, highest = _summarize(findings)
    lines: List[str] = []
    header = "CageSight %s | events=%d shown=%d/%d duration=%.2fs | critical=%d high=%d medium=%d low=%d" % (
        __version__,
        result.events,
        len(findings),
        len(result.findings),
        result.duration,
        counts.get("critical", 0),
        counts.get("high", 0),
        counts.get("medium", 0),
        counts.get("low", 0),
    )
    lines.append(header)
    if result.sources:
        source_text = ", ".join("%s=%d" % (_safe(k), v) for k, v in sorted(result.sources.items()))
        lines.append("sources: " + source_text)
    lines.append("")

    if not findings:
        lines.append("未发现达到阈值的可疑行为。")
        return "\n".join(lines)

    columns = ("TIME", "SEV", "RULE", "PID/COMM", "EVIDENCE")
    widths = (8, 14, 13, 18, 0)
    lines.append("  ".join(title.ljust(width) if width else title for title, width in zip(columns, widths)))
    lines.append("-" * 96)
    for finding in findings:
        pid_comm = _safe("%s/%s" % (finding.pid or "-", finding.comm or "-"))
        evidence = _safe(finding.evidence)
        row = [
            finding.time_str[11:] if finding.ts else "-",
            "%s(%d)" % (SEVERITY_LABEL.get(finding.severity, "?"), finding.score),
            finding.rule_id,
            pid_comm,
            evidence,
        ]
        formatted = [
            _truncate(row[0], widths[0]).ljust(widths[0]),
            _truncate(row[1], widths[1]).ljust(widths[1]),
            _truncate(row[2], widths[2]).ljust(widths[2]),
            _truncate(row[3], widths[3]).ljust(widths[3]),
            _truncate(row[4], 60),
        ]
        formatted[1] = _paint(formatted[1], finding.severity, color)
        lines.append("  ".join(formatted))

    lines.append("")
    has_chain = any(finding.rule_id.startswith("CS-CHAIN") for finding in findings)
    if has_chain:
        verdict = "存在完整攻击链，建议立即处置"
    elif highest == "critical":
        verdict = "存在严重风险，建议立即处置"
    elif highest == "high":
        verdict = "存在高危行为，建议人工核实"
    else:
        verdict = "未发现高危行为"
    lines.append("结论: " + _paint(verdict, highest, color))
    return "\n".join(lines)


def render_json(result: Result, minimum: str = "low") -> str:
    findings = result.filtered(minimum)
    counts, highest = _summarize(findings)
    payload = {
        "tool": "cagesight",
        "version": __version__,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "events": result.events,
        "sources": result.sources,
        "summary": counts,
        "highest": highest,
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _sarif_level(severity: str) -> str:
    if severity in ("critical", "high"):
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def render_sarif(result: Result, minimum: str = "low") -> str:
    findings = result.filtered(minimum)
    rules: Dict[str, dict] = {}
    for finding in findings:
        if finding.rule_id in rules:
            continue
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description or finding.title},
            "properties": {"security-severity": str(finding.score / 10.0), "tags": ["security", "ai-agent"]},
        }
    rule_index = {rule_id: index for index, rule_id in enumerate(rules)}

    results = []
    for finding in findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": rule_index[finding.rule_id],
                "level": _sarif_level(finding.severity),
                "message": {"text": "%s | %s" % (finding.title, finding.evidence)},
                "properties": {
                    "score": finding.score,
                    "severity": finding.severity,
                    "mitre": finding.mitre,
                    "pid": finding.pid,
                    "comm": finding.comm,
                },
                "locations": [
                    {
                        "logicalLocations": [
                            {"fullyQualifiedName": finding.comm or "agent", "kind": "process"}
                        ],
                        "physicalLocation": {
                            "artifactLocation": {"uri": "cagesight://sandbox/event/%d" % finding.pid}
                        },
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CageSight",
                        "version": __version__,
                        "informationUri": "https://github.com/cagesight/cagesight",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)


def render_markdown(result: Result, minimum: str = "low", title: str = "CageSight Agent 沙箱外传/逃逸检测报告") -> str:
    findings = result.filtered(minimum)
    counts, highest = _summarize(findings)
    lines: List[str] = []
    lines.append("# %s" % title)
    lines.append("")
    lines.append("生成时间：%s　工具版本：%s" % (time.strftime("%Y-%m-%d %H:%M:%S"), __version__))
    lines.append("")
    lines.append("## 一、概览")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("| --- | --- |")
    lines.append("| 输入事件 | %d |" % result.events)
    lines.append("| 命中规则 | %d |" % len(findings))
    lines.append("| 严重 | %d |" % counts.get("critical", 0))
    lines.append("| 高危 | %d |" % counts.get("high", 0))
    lines.append("| 中危 | %d |" % counts.get("medium", 0))
    lines.append("| 低危 | %d |" % counts.get("low", 0))
    lines.append("| 最高等级 | %s |" % highest)
    lines.append("")
    if result.sources:
        lines.append("数据源：" + "、".join("%s(%d)" % (_safe(k), v) for k, v in sorted(result.sources.items())))
        lines.append("")

    if not findings:
        lines.append("未发现达到阈值的可疑行为。")
        return "\n".join(lines)

    lines.append("## 二、检测明细")
    lines.append("")
    for finding in findings:
        lines.append("### %s %s（%s，%d 分）" % (finding.rule_id, _safe(finding.title), finding.severity, finding.score))
        lines.append("")
        lines.append("- 时间：%s" % finding.time_str)
        lines.append("- 进程：%s (pid=%s)" % (_safe(finding.comm or "-"), finding.pid or "-"))
        if finding.mitre:
            lines.append("- ATT&CK：%s" % finding.mitre)
        lines.append("- 证据：`%s`" % _safe(finding.evidence).replace("`", "'"))
        if finding.description:
            lines.append("- 说明：%s" % _safe(finding.description))
        lines.append("")

    lines.append("## 三、处置建议")
    lines.append("")
    if highest in ("critical", "high"):
        lines.append("1. 立即隔离该 Agent 实例，保留磁盘与内存镜像。")
        lines.append("2. 核查沙箱配置：是否挂载 docker.sock、是否 privileged、是否共享宿主命名空间。")
        lines.append("3. 轮换沙箱内可见的云凭据、SSH Key 与 API Token。")
        lines.append("4. 在边界防火墙封禁报告中出现的非白名单目标。")
        lines.append("5. 回溯同镜像、同配置的其他实例是否存在相同行为。")
    else:
        lines.append("1. 保持观察，确认告警是否来自正常业务行为。")
        lines.append("2. 若确认为误报，将目标加入 allowlist 并记录原因。")
    lines.append("")
    return "\n".join(lines)


AUDIT_ORDER = ("critical", "high", "medium", "low")


def render_audit_table(result: AuditResult, color: bool = True) -> str:
    counts = result.counts()
    lines = [
        "CageSight %s | 沙箱配置体检 | target=%s issues=%d | critical=%d high=%d medium=%d low=%d"
        % (
            __version__,
            result.target,
            len(result.issues),
            counts.get("critical", 0),
            counts.get("high", 0),
            counts.get("medium", 0),
            counts.get("low", 0),
        ),
        "",
    ]
    if not result.issues:
        lines.append("未发现明显的沙箱配置风险。")
        return "\n".join(lines)

    lines.append("%-10s %-9s %-18s %-42s %s" % ("RULE", "SEV", "TITLE", "EVIDENCE", "ADVICE"))
    lines.append("-" * 120)
    for issue in result.issues:
        severity = _paint(issue.severity.upper().ljust(9), issue.severity, color)
        lines.append(
            "%-10s %s %-18s %-42s %s"
            % (
                issue.rule_id,
                severity,
                _truncate(_safe(issue.title), 18).ljust(18),
                _truncate(_safe(issue.evidence), 42).ljust(42),
                _truncate(_safe(issue.advice), 40),
            )
        )
    lines.append("")
    lines.append("结论: " + _paint(_audit_verdict(result), result.highest(), color))
    return "\n".join(lines)


def _audit_verdict(result: AuditResult) -> str:
    highest = result.highest()
    if highest == "critical":
        return "沙箱配置存在可直接逃逸/接管的缺陷，必须整改后再运行 Agent"
    if highest == "high":
        return "沙箱隔离强度不足，建议按高风险条目整改"
    if highest == "medium":
        return "存在中等风险项，建议加固"
    return "配置基本合理"


def render_audit_markdown(result: AuditResult) -> str:
    counts = result.counts()
    lines = [
        "# CageSight 沙箱配置体检报告",
        "",
        "- 目标：`%s`" % result.target,
        "- 结论：%s" % _audit_verdict(result),
        "- 统计：critical=%d high=%d medium=%d low=%d"
        % (
            counts.get("critical", 0),
            counts.get("high", 0),
            counts.get("medium", 0),
            counts.get("low", 0),
        ),
        "",
        "| 等级 | 规则 | 问题 | 证据 | 建议 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for issue in result.issues:
        lines.append(
            "| %s | %s | %s | `%s` | %s |"
            % (
                issue.severity,
                issue.rule_id,
                _safe(issue.title),
                _safe(issue.evidence).replace("|", "\\|"),
                _safe(issue.advice),
            )
        )
    if not result.issues:
        lines.append("| - | - | 未发现明显风险 | - | - |")
    lines.append("")
    return "\n".join(lines)
