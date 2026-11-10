# 提交信息表（奇安信攻防社区 · AI 安全工具）

> 用途：直接对照社区的「发布 AI 工具」表单填写。带 `<...>` 的字段需要你替换。

## 一、基本信息

| 字段 | 填写内容 |
| --- | --- |
| 工具名称 | CageSight |
| 工具分类 | **推理环境安全**（首选，栏目内仅 5 个，竞争最小）<br>备选：Agent智能体安全 / AI供应链安全 |
| 工具话题 | 安全工具、AI 人工智能、智能体安全、威胁检测 |
| 开发语言 | Python |
| GitHub 仓库 | `https://github.com/<你的账号>/cagesight` |
| 最新版本 | v0.1.0 |
| 开发者 | `<你的 ID / 团队>` |
| 开源协议 | MIT |

## 二、摘要（卡片用，约 110 字）

CageSight 是面向 AI Agent 沙箱的外传与逃逸检测工具：静态体检沙箱配置，运行时分析 auditd/strace 事件，流量侧解析 pcap，识别 DNS 隧道、凭据收集、逃逸原语与数据外带，并把零散告警关联成完整攻击链。零第三方依赖，支持 SARIF / Markdown 报告。

## 三、详细介绍（粘贴到「详细功能介绍」）

### 它解决什么问题

Agent 沙箱解决「不让它跑出去」，但很少回答三个问题：沙箱本身够不够硬、它运行时到底干了什么、数据是怎么出去的。CageSight 补的是检测与取证层，面向 Agent 行为模型做跨源关联。

### 三种模式

| 模式 | 输入 | 回答的问题 | 命令 |
| --- | --- | --- | --- |
| 静态体检 | docker inspect / K8s Pod / compose / seccomp | 沙箱配置能不能被直接逃逸 | `cagesight audit-config` |
| 事件检测 | auditd / strace / 归一化 JSONL | Agent 运行时做了哪些敏感动作 | `cagesight scan` |
| 流量检测 | pcap | 有没有数据正在通过 DNS / TLS 出去 | `cagesight pcap` |

### 检测能力

29 条运行时规则（映射 ATT&CK）+ 13 条配置体检规则，覆盖：

- **DNS 隧道**：高熵长子域、高频查询、TXT/NULL 滥用、唯一子域比例
- **出站行为**：非白名单目标、裸 IP 直连、Raw Socket、大流量上传、非常规端口
- **凭据收集**：SSH 私钥、云凭据、环境变量、容器/集群凭据、系统敏感文件
- **逃逸原语**：ptrace、setns/unshare、mount、内核模块、/proc 写入、运行时 Socket
- **数据暂存**：临时目录打包、敏感目录批量读取
- **执行链**：下载即执行、base64 解码执行、临时目录解释器、反弹 Shell

关键差异是**关联**：单条告警只是线索，CageSight 会把「读云凭据 → tar 打包 → DNS 外带」串成一条 critical 链路，并给出完整证据时间线。

### 快速验证

```bash
git clone https://github.com/<你的账号>/cagesight.git
cd cagesight
pip install -e .
cagesight demo
```

一条命令即可看到内置攻击链的完整检测结果，无需搭建环境。

### 工程特性

- 纯 Python 标准库，零第三方依赖，可离线运行
- pcap 解析自研（不依赖 scapy），支持 DNS / TLS SNI / HTTP Host
- 输出 table / JSON / SARIF / Markdown，退出码可接 CI 卡点
- 响应动作默认 dry-run，`--enforce` 才真正封禁/终止
- 91 个单元测试 + fuzz 用例，GitHub Actions CI

## 四、免责声明（必填）

本工具仅用于自有或已获授权环境的 Agent 沙箱安全检测与防御研究，不得用于未授权目标。工具只做检测与取证，不提供隔离或阻断能力；`--enforce` 相关动作需在确认日志可信后使用。

## 五、提交前 Checklist

- [ ] GitHub 仓库已公开，README 能正常渲染
- [ ] 打过 `v0.1.0` tag，Release 里附 zip
- [ ] 准备 2 张截图：`cagesight demo` 终端输出、Markdown 报告渲染效果
- [ ] 确认 `pip install -e .` 在干净环境可用
- [ ] 同步发一篇技术文章（工具卡 + 文章双入口互相导流）
- [ ] 表单里的「工具分类」选 **推理环境安全**

## 六、建议的联动文章

标题：**《从一条异常 DNS 到完整外带链：CageSight 的 Agent 沙箱检测设计》**

结构：Agent 沙箱的三类失守 → 为什么现网看不见 → 检测模型（事件归一化 + 7 类规则 + 链路关联）→ 三个可复现场景（DNS 隧道 / 凭据外带 / 逃逸尝试）→ 与 Falco、SkillGuard 的边界 → 误报调优。
