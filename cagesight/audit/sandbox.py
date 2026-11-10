"""Static sandbox configuration audit."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

from cagesight.model import SEVERITY_ORDER

MAX_CONFIG_BYTES = 32 << 20  # 配置/清单文件不应超过 32 MiB

SOCKET_HINTS = ("docker.sock", "containerd.sock", "crio.sock", "podman.sock")
DANGEROUS_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "DAC_READ_SEARCH"}
HOST_MOUNT_RE = re.compile(
    r"(?:-v|--volume)\s+[\"']?(?:/|/proc|/sys|/dev)(?:[\"'/:])"
    r"|^\s*-\s*[\"']?(?:/|/proc|/sys|/dev)[\"']?:",
    re.MULTILINE,
)


@dataclass
class Issue:
    rule_id: str
    title: str
    severity: str
    evidence: str
    advice: str


@dataclass
class AuditResult:
    target: str
    issues: List[Issue] = field(default_factory=list)

    def counts(self) -> Dict[str, int]:
        counts = {key: 0 for key in ("critical", "high", "medium", "low")}
        for issue in self.issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1
        return counts

    def highest(self) -> str:
        if not self.issues:
            return "info"
        return max(self.issues, key=lambda i: SEVERITY_ORDER.get(i.severity, 0)).severity


def _add(result: AuditResult, rule_id: str, title: str, severity: str, evidence: str, advice: str) -> None:
    result.issues.append(Issue(rule_id, title, severity, evidence, advice))


def audit_file(path: str) -> AuditResult:
    result = AuditResult(target=path)
    size = os.path.getsize(path)
    if size > MAX_CONFIG_BYTES:
        raise ValueError("配置文件过大（%d 字节），拒绝加载" % size)
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        text = handle.read()
    if text.startswith("\ufeff"):
        text = text[1:]

    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except (json.JSONDecodeError, RecursionError):
            data = None
        if data is not None:
            if _audit_json(result, data):
                _finish(result)
                return result
            # 结构未识别：只做“阳性关键字”扫描，避免基于“缺少某配置”的判断产生误报。
            _audit_text(result, text, absence_checks=False)
            if not result.issues:
                _add(result, "SBX-000", "未识别的配置格式", "low",
                     "文件既不是 docker inspect / k8s / seccomp，也未匹配到已知关键字",
                     "确认文件类型，或使用 docker inspect / kubectl get pod -o json 导出")
            _finish(result)
            return result

    _audit_text(result, text)
    _finish(result)
    return result


def _finish(result: AuditResult) -> None:
    result.issues.sort(key=lambda i: -SEVERITY_ORDER.get(i.severity, 0))


def _audit_json(result: AuditResult, data: Any) -> bool:
    """Return True if the JSON matched a known configuration shape."""
    if isinstance(data, list) and data and isinstance(data[0], dict) and "HostConfig" in data[0]:
        for container in data:
            _audit_docker_inspect(result, container)
        return True
    if isinstance(data, dict) and "HostConfig" in data:
        _audit_docker_inspect(result, data)
        return True
    if isinstance(data, dict) and "spec" in data:
        _audit_k8s(result, data)
        return True
    if isinstance(data, dict) and "defaultAction" in data:
        _audit_seccomp(result, data)
        return True
    # Unknown JSON structure: let the caller fall back to the text heuristics
    # instead of silently reporting "no issues".
    return False


def _audit_docker_inspect(result: AuditResult, container: Dict[str, Any]) -> None:
    host = container.get("HostConfig") or {}
    config = container.get("Config") or {}
    name = container.get("Name", "container")

    if host.get("Privileged"):
        _add(result, "SBX-001", "容器以 privileged 模式运行", "critical",
             "%s: HostConfig.Privileged=true" % name,
             "移除 --privileged，仅授予必要 capability")
    if host.get("PidMode") == "host":
        _add(result, "SBX-002", "容器共享宿主 PID 命名空间", "high",
             "%s: HostConfig.PidMode=host" % name, "禁止 --pid=host")
    if host.get("NetworkMode") == "host":
        _add(result, "SBX-003", "容器共享宿主网络命名空间", "high",
             "%s: HostConfig.NetworkMode=host" % name, "改用 bridge 网络并配置出站白名单")
    if host.get("IpcMode") == "host":
        _add(result, "SBX-004", "容器共享宿主 IPC 命名空间", "medium",
             "%s: HostConfig.IpcMode=host" % name, "禁止 --ipc=host")

    caps = set(host.get("CapAdd") or [])
    risky = caps & DANGEROUS_CAPS
    if risky:
        _add(result, "SBX-005", "容器被授予高危 capability", "high",
             "%s: CapAdd=%s" % (name, ",".join(sorted(risky))),
             "移除 SYS_ADMIN/SYS_PTRACE/SYS_MODULE 等 capability")

    security_opt = " ".join(host.get("SecurityOpt") or [])
    if "seccomp=unconfined" in security_opt:
        _add(result, "SBX-006", "seccomp 被关闭", "high",
             "%s: SecurityOpt=%s" % (name, security_opt), "启用默认 seccomp profile")
    if "no-new-privileges" not in security_opt:
        _add(result, "SBX-007", "未启用 no-new-privileges", "low",
             "%s: SecurityOpt 缺少 no-new-privileges" % name, "添加 --security-opt no-new-privileges")

    mounts = []
    for bind in host.get("Binds") or []:
        mounts.append(str(bind))
    for mount in host.get("Mounts") or []:
        mounts.append(str(mount.get("Source", "")))
    mount_text = " ".join(mounts)
    if any(sock in mount_text for sock in SOCKET_HINTS):
        _add(result, "SBX-008", "挂载了容器运行时 Socket", "critical",
             "%s: mounts=%s" % (name, mount_text[:160]),
             "移除 docker.sock 挂载，改用受限代理")
    for dangerous in ("/proc", "/sys", "/dev", "/:/", "Source=/,"):
        if dangerous in mount_text:
            _add(result, "SBX-009", "挂载了宿主敏感目录", "high",
                 "%s: mounts=%s" % (name, mount_text[:160]), "仅挂载必要的只读数据目录")
            break

    if not host.get("ReadonlyRootfs"):
        _add(result, "SBX-010", "根文件系统可写", "low",
             "%s: ReadonlyRootfs=false" % name, "启用 --read-only 并以 tmpfs 提供可写目录")

    user = str(config.get("User") or "").strip()
    if user in ("", "0", "root", "0:0"):
        _add(result, "SBX-011", "容器以 root 运行", "medium",
             "%s: Config.User=%r" % (name, user or ""), "使用非 root 用户运行 Agent")

    memory = host.get("Memory") or 0
    if not memory:
        _add(result, "SBX-012", "未限制内存", "low",
             "%s: Memory=%s" % (name, memory), "设置 --memory/--cpus 限额，降低资源滥用影响")


def _audit_k8s(result: AuditResult, pod: Dict[str, Any]) -> None:
    spec = (pod.get("spec") or {})
    if spec.get("hostPID"):
        _add(result, "SBX-002", "Pod 共享宿主 PID 命名空间", "high", "spec.hostPID=true", "关闭 hostPID")
    if spec.get("hostNetwork"):
        _add(result, "SBX-003", "Pod 共享宿主网络命名空间", "high", "spec.hostNetwork=true", "关闭 hostNetwork")
    if spec.get("hostIPC"):
        _add(result, "SBX-004", "Pod 共享宿主 IPC 命名空间", "medium", "spec.hostIPC=true", "关闭 hostIPC")

    for volume in spec.get("volumes") or []:
        host_path = (volume or {}).get("hostPath") or {}
        path = str(host_path.get("path", ""))
        if not path:
            continue
        if "docker.sock" in path or "containerd.sock" in path:
            _add(result, "SBX-008", "Pod 挂载了容器运行时 Socket", "critical",
                 "hostPath=%s" % path, "移除该 hostPath")
        elif path in ("/", "/proc", "/sys", "/dev", "/var/run"):
            _add(result, "SBX-009", "Pod 挂载了宿主敏感目录", "high",
                 "hostPath=%s" % path, "改用只读 ConfigMap/EmptyDir")

    for container in spec.get("containers") or []:
        security = (container or {}).get("securityContext") or {}
        name = (container or {}).get("name", "container")
        if security.get("privileged"):
            _add(result, "SBX-001", "Pod 以 privileged 模式运行", "critical",
                 "%s.securityContext.privileged=true" % name, "关闭 privileged")
        if security.get("allowPrivilegeEscalation"):
            _add(result, "SBX-007", "允许权限提升", "medium",
                 "%s.allowPrivilegeEscalation=true" % name, "设置 allowPrivilegeEscalation=false")
        run_as = security.get("runAsUser")
        if run_as == 0:
            _add(result, "SBX-011", "Pod 以 root 运行", "medium",
                 "%s.runAsUser=0" % name, "改用非 root UID")
        caps = ((security.get("capabilities") or {}).get("add") or [])
        risky = set(c.upper() for c in caps) & DANGEROUS_CAPS
        if risky:
            _add(result, "SBX-005", "Pod 被授予高危 capability", "high",
                 "%s.capabilities.add=%s" % (name, ",".join(sorted(risky))), "移除高危 capability")


def _audit_seccomp(result: AuditResult, profile: Dict[str, Any]) -> None:
    action = str(profile.get("defaultAction", "")).upper()
    if action == "SCMP_ACT_ALLOW":
        _add(result, "SBX-006", "seccomp 默认动作是放行", "high",
             "defaultAction=SCMP_ACT_ALLOW", "改为 SCMP_ACT_ERRNO 并按需放行")


def _audit_text(result: AuditResult, text: str, absence_checks: bool = True) -> None:
    lowered = text.lower()

    if re.search(r"--privileged\b|\"?privileged\"?\s*:\s*true|security\.privileged\s*:\s*\"?true", lowered):
        _add(result, "SBX-001", "沙箱以 privileged 模式运行", "critical",
             _line_of(text, r"privileged"), "移除 privileged，按需授予 capability")
    if re.search(r"--pid[= ]host|\"?pid\"?\s*:\s*[\"']?host", lowered):
        _add(result, "SBX-002", "沙箱共享宿主 PID 命名空间", "high", _line_of(text, r"pid"), "使用独立 PID 命名空间")
    if re.search(r"--net(work)?[= ]host|\"?network_mode\"?\s*:\s*[\"']?host", lowered):
        _add(result, "SBX-003", "沙箱共享宿主网络命名空间", "high", _line_of(text, r"network"), "使用 bridge 网络并配置白名单")
    if any(sock in lowered for sock in SOCKET_HINTS):
        _add(result, "SBX-008", "挂载了容器运行时 Socket", "critical", _line_of(text, r"docker\.sock|containerd\.sock"), "移除 socket 挂载")
    if HOST_MOUNT_RE.search(lowered):
        _add(result, "SBX-009", "挂载了宿主敏感目录", "high", _line_of(text, r"/proc|/sys|/dev|/:/"), "仅挂载必要的只读数据目录")
    if re.search(r"cap[_-]add[^\n]*(sys_admin|sys_ptrace|sys_module)", lowered):
        _add(result, "SBX-005", "授予了高危 capability", "high", _line_of(text, r"cap[_-]add"), "移除高危 capability")
    if re.search(r"seccomp\s*[=:]\s*[\"']?unconfined", lowered):
        _add(result, "SBX-006", "seccomp 被关闭", "high", _line_of(text, r"seccomp"), "启用 seccomp")
    if re.search(r"--user[= ](\"|\')?(root|0)(\"|\')?\b|\"?user\"?\s*:\s*[\"']?(root|0)\b", lowered):
        _add(result, "SBX-011", "以 root 用户运行", "medium", _line_of(text, r"user"), "使用非 root 用户")
    if "no-new-privileges" not in lowered and "docker run" in lowered:
        _add(result, "SBX-007", "未启用 no-new-privileges", "low", "docker run 参数", "添加 no-new-privileges")
    if absence_checks and "read_only" not in lowered and "read-only" not in lowered:
        _add(result, "SBX-010", "根文件系统可写", "low", "未发现只读根文件系统配置", "启用 read-only rootfs")


def _line_of(text: str, pattern: str) -> str:
    for line in text.splitlines():
        if re.search(pattern, line, re.IGNORECASE):
            return line.strip()[:160]
    return ""
