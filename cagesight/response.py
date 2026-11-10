"""Response actions: webhook notification, firewall blocking, process kill.

Enforcement is opt-in (``--enforce``); without it every action is printed as a
dry-run plan, which is what you want in an audit-first deployment.
"""

from __future__ import annotations

import ipaddress
import json
import os
import signal
import subprocess
import time
import urllib.request
from typing import Dict, List, Optional, Set

from cagesight.engine import Result
from cagesight.model import SEVERITY_ORDER

BLOCKABLE_PREFIXES = ("CS-NET", "CS-CHAIN", "CS-CRED-006")


def collect_targets(result: Result) -> Dict[str, Set]:
    ips: Set[str] = set()
    pids: Set[int] = set()
    for finding in result.findings:
        if finding.pid > 0:
            pids.add(finding.pid)
        if not finding.rule_id.startswith(BLOCKABLE_PREFIXES):
            continue
        for token in finding.evidence.split():
            address = _extract_ip(token)
            if address:
                ips.add(address)
    return {"ips": ips, "pids": pids}


def _extract_ip(token: str) -> Optional[str]:
    """Pull an IPv4/IPv6 address out of an evidence token.

    Handles ``dst=1.2.3.4:443`` and ``dst=[2001:db8::1]:443``.
    """
    value = token.split("=", 1)[-1]
    if value.startswith("["):
        end = value.find("]")
        candidate = value[1:end] if end > 1 else ""
    elif value.count(":") == 1:
        candidate = value.rsplit(":", 1)[0]
    else:
        candidate = value
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def block_commands(ips: Set[str], backend: str = "nft") -> List[str]:
    commands = []
    for ip in sorted(ips):
        try:
            version = ipaddress.ip_address(ip).version
        except ValueError:
            continue
        if backend == "iptables":
            tool = "ip6tables" if version == 6 else "iptables"
            commands.append("%s -I OUTPUT -d %s -j DROP" % (tool, ip))
        else:
            family = "ip6" if version == 6 else "ip"
            commands.append("nft add rule inet cagesight output %s daddr %s drop" % (family, ip))
    return commands


def apply_block(ips: Set[str], enforce: bool, backend: str = "nft") -> List[str]:
    commands = block_commands(ips, backend)
    if not commands:
        return []
    if not enforce:
        return ["[dry-run] " + command for command in commands]
    if os.name != "posix":
        return ["[skip] 当前平台不支持自动封禁，请手动执行： " + "; ".join(commands)]
    results = []
    for command in commands:
        try:
            subprocess.run(command.split(), check=True, capture_output=True, timeout=5)
            results.append("[ok] " + command)
        except Exception as exc:  # pragma: no cover - depends on host
            results.append("[fail] %s (%s)" % (command, exc))
    return results


def kill_processes(pids: Set[int], enforce: bool) -> List[str]:
    if not pids:
        return []
    safe: List[int] = []
    protected: List[int] = []
    for pid in sorted(pids):
        # pid <= 1 包含 0、1 和负数；在 POSIX 上 kill(-1) 会杀掉当前用户
        # 能杀的全部进程，必须显式拒绝。
        if pid <= 1 or pid == os.getpid():
            protected.append(pid)
        else:
            safe.append(pid)

    results: List[str] = []
    if protected:
        results.append(
            "[skip] 拒绝终止保护进程 pids=" + ",".join(str(p) for p in protected)
            + "（pid 0/1 或当前进程）"
        )
    if not safe:
        return results
    if not enforce:
        results.append("[dry-run] kill -9 pids=" + ",".join(str(p) for p in safe))
        return results
    if os.name != "posix":
        results.append("[skip] 当前平台不支持 kill，请手动处置 pids=" + ",".join(str(p) for p in safe))
        return results
    kill_signal = getattr(signal, "SIGKILL", signal.SIGTERM)
    for pid in safe:
        try:
            os.kill(pid, kill_signal)
            results.append("[ok] killed pid=%d" % pid)
        except Exception as exc:  # pragma: no cover
            results.append("[fail] pid=%d (%s)" % (pid, exc))
    return results


def notify_webhook(
    url: str,
    result: Result,
    timeout: float = 5.0,
    minimum: Optional[str] = None,
) -> Optional[str]:
    if not url:
        return None
    findings = result.filtered(minimum) if minimum else result.findings
    counts: Dict[str, int] = {severity: 0 for severity in ("critical", "high", "medium", "low")}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    highest = "info"
    if findings:
        highest = max(findings, key=lambda finding: SEVERITY_ORDER.get(finding.severity, 0)).severity
    payload = {
        "tool": "cagesight",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "highest": highest,
        "summary": counts,
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "pid": f.pid,
                "evidence": f.evidence,
            }
            for f in findings[:50]
        ],
    }
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return "webhook -> HTTP %s" % response.status
    except Exception as exc:
        return "webhook 失败: %s" % exc
