# 检测规则说明

规则分为两类：**运行时规则（CS-*）** 与 **配置体检规则（SBX-*）**。可用 `cagesight rules` 查看运行时规则，用 `--rules custom.json` 覆盖等级或关闭规则。

## 运行时规则（CS）

| ID | 等级 | ATT&CK | 触发条件 | 调优建议 |
| --- | --- | --- | --- | --- |
| CS-DNS-001 | high | T1071.004 | 子域标签长度 ≥ 30 且香农熵 ≥ 3.4 | 业务使用长随机子域（CDN、S3 预签名）时加入 allowlist |
| CS-DNS-002 | high | T1048.003 | 同一基础域 60s 内查询 ≥ 20 次且唯一子域占比 ≥ 0.9，并且标签长度 ≥ 12、熵 ≥ 2.8 | 按业务 DNS 基线调整 `min_queries` / `rate_min_*` |
| CS-DNS-003 | high | T1048.003 | TXT/NULL 查询且标签长度 ≥ 20 或熵 ≥ 3.0 | 内部确实使用 TXT 服务时，将其基础域加入 allowlist |
| CS-DNS-004 | medium | T1071.004 | 窗口内唯一子域比例 ≥ 0.9 且查询量达标，同时标签呈编码特征 | 与 002 联动，可单独关闭 |
| CS-NET-001 | high | T1048 | 连接非白名单目标（域名或 IP） | 维护 `allowlist.domains` / `cidrs` |
| CS-NET-002 | medium | T1071 | 无域名直连公网 IP | 依赖 IP 白名单的业务需补充 `cidrs` |
| CS-NET-003 | medium | T1095 | 创建 SOCK_RAW | 沙箱内一般不应出现，出现即复核 |
| CS-NET-004 | high | T1048 | 窗口内上传 ≥ 5 MiB 到非白名单目标 | 按业务上传量调整 `upload_bytes` |
| CS-NET-005 | medium | T1571 | 连接 80/443/53 之外的端口且非白名单 | 内部服务端口多时建议改为显式白名单 |
| CS-CRED-001 | high | T1552.004 | 读取 `.ssh/id_*`、`.ssh/config` | 无 |
| CS-CRED-002 | critical | T1552.001 | 读取 `.aws/credentials`、`.config/gcloud/`、`.azure/`、`.netrc`、`.env` 等 | 无 |
| CS-CRED-003 | high | T1552.001 | 执行 `env` / `printenv`，或读取 `/proc/*/environ` | Agent 正常业务不应读取全局环境变量 |
| CS-CRED-004 | critical | T1552 | 读取 kubeconfig、K8s ServiceAccount Token、`/run/secrets/` 等集群/容器凭据 | 运行时 Socket 由 CS-ESC-006 单独报告 |
| CS-CRED-005 | high | T1552.001 | 读取 `/etc/shadow`、`/etc/sudoers` 等系统敏感文件 | 无 |
| CS-CRED-006 | critical | T1552.005 | 访问 169.254.169.254、169.254.0.23、100.100.100.200、fd00:ec2::254、metadata.google.internal 等元数据端点 | 元数据端点整体视为高危，不参与白名单 |
| CS-ESC-001 | high | T1055 | `ptrace(PTRACE_ATTACH/SEIZE)` | 调试场景需临时关闭 |
| CS-ESC-002 | critical | T1611 | `setns` / `unshare` | 沙箱内出现即高危 |
| CS-ESC-003 | high | T1611 | `mount` / `umount2` | 容器内挂载属异常 |
| CS-ESC-004 | critical | T1547.006 | `init_module` / `finit_module` | 容器内不应出现 |
| CS-ESC-005 | high | T1611 | 写 `/proc/sys/*` 或 `/proc/*/mem` | 无 |
| CS-ESC-006 | critical | T1611 | 访问/连接 docker.sock、containerd.sock、crio.sock、podman.sock | 无 |
| CS-STG-001 | high | T1560 | 打包命令输出落在 `/tmp`、`/dev/shm`、`/var/tmp` | 业务构建产物可白名单目录 |
| CS-STG-002 | medium | T1005 | 300s 内读取 ≥ 3 个敏感路径 | 与 CS-CRED-* 联动判断 |
| CS-EXEC-001 | critical | T1059 | `curl/wget ... | sh` | 无 |
| CS-EXEC-002 | high | T1140 | `base64 -d ... | sh` | 无 |
| CS-EXEC-003 | high | T1059 | 解释器执行 `/tmp`、`/dev/shm`、`/var/tmp` 下的脚本 | 无 |
| CS-EXEC-004 | high | T1059 | `nc/ncat/socat -e`、`/dev/tcp` | 无 |
| CS-CHAIN-001 | critical | T1048 | 同进程窗口内出现「凭据 → 暂存 → 外发」 | 窗口由 `correlation.window_sec` 控制 |
| CS-CHAIN-002 | critical | T1611 | 同进程窗口内出现「逃逸原语 → 执行」 | 窗口由 `correlation.escape_window_sec` 控制 |

## 配置体检规则（SBX）

| ID | 等级 | 检查项 |
| --- | --- | --- |
| SBX-001 | critical | `privileged: true` / `--privileged` |
| SBX-002 | high | 共享宿主 PID 命名空间（`pid: host`、`hostPID`） |
| SBX-003 | high | 共享宿主网络命名空间（`network_mode: host`、`hostNetwork`） |
| SBX-004 | medium | 共享宿主 IPC 命名空间 |
| SBX-005 | high | 高危 capability（`SYS_ADMIN`、`SYS_PTRACE`、`SYS_MODULE`、`SYS_RAWIO`、`DAC_READ_SEARCH`） |
| SBX-006 | high | seccomp 被关闭或默认放行 |
| SBX-007 | low / medium | 未启用 `no-new-privileges` / 允许权限提升 |
| SBX-008 | critical | 挂载 docker.sock、containerd.sock 等运行时 Socket |
| SBX-009 | high | 挂载 `/`、`/proc`、`/sys`、`/dev` 等宿主敏感目录 |
| SBX-010 | low | 根文件系统可写（未启用 read-only rootfs） |
| SBX-011 | medium | 以 root（UID 0）运行 |
| SBX-012 | low | 未限制内存（Docker inspect 场景） |
| SBX-000 | low | 未识别的配置格式（仅做关键字扫描，避免静默通过） |

## 自定义规则

```json
{
  "rules": [
    { "id": "CS-DNS-002", "enabled": false },
    { "id": "CS-NET-001", "severity": "medium" }
  ]
}
```

```bash
cagesight scan agent.audit --rules my-rules.json
```

规则文件中只需写要覆盖的字段，未出现的规则沿用内置定义。
