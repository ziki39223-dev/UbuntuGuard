# 生态调研与项目定位

日期：2026-11-17
用途：避免重复造轮子，明确 UbuntuGuard 的差异化边界；面向运维求职的简历价值评估。

## 1. GitHub 现有项目盘点

星标数据取自 2026-11-17 GitHub API。

| 项目 | 星标 | 语言/许可 | 覆盖能力 | 缺口 |
| ---- | ---- | ---- | ---- | ---- |
| CISOfy/lynis | 16.7k | Shell / GPL-3.0 | 主机安全审计、建议清单、报告 | 只审计不加固，无备份/回滚，报告非结构化优先 |
| OpenSCAP/openscap + ComplianceAsCode/content | 1.8k / 2.8k | C / LGPL-2.1 | SCAP/XCCDF 合规扫描与自动修复，CIS/STIG 内容 | 依赖重、XML 体系学习成本高，本地化与易用性差 |
| ansible-lockdown/UBUNTU22-CIS、UBUNTU24-CIS | 262 / 227 | YAML / MIT | CIS 基线 Ansible 修复剧本 | 需 Ansible 与中心化执行，无本地 CLI、无生效校验与回滚 |
| dev-sec/ansible-collection-hardening | 5.5k | Jinja/YAML / Apache-2.0 | OS/SSH/Nginx 加固参数与角色 | 同上，属于配置管理而非单机工具 |
| crowdsecurity/crowdsec | 15.7k | Go / MIT | 日志驱动的行为检测与封禁 | 与 Fail2ban 定位重叠，不解决基线审计与加固 |
| osquery/osquery | 23.8k | C++ | SQL 化主机可见性 | 采集能力强，但不做审计判定、加固与报告 |
| netdata/netdata | 81.4k | C / GPL-3.0 | 全栈监控与告警 | 重型，单机运维工具不宜内嵌 |
| prometheus/node_exporter | 13.9k | Go / Apache-2.0 | 指标暴露 | 仅指标出口，无判定与告警规则管理 |
| goss-org/goss | 6.0k | Go / Apache-2.0 | 声明式服务器状态校验与报告 | 校验强，但无加固执行、备份回滚 |
| inspec/inspec | 3.1k | Ruby / 商业许可风险 | 合规即代码 | 许可与运行环境成本高 |
| pytest-dev/pytest-testinfra | 2.5k | Python / Apache-2.0 | 服务器测试 | 测试框架，不是产品工具 |

## 2. 结论：可复用 vs 必须自建

### 直接复用（不重写）

| 能力 | 复用对象 | 接入方式 |
| ---- | ---- | ---- |
| 实际加固执行 | UFW、Fail2ban、Auditd、AIDE、unattended-upgrades | 调用系统组件，UbuntuGuard 只做编排与校验 |
| 事实采集 | `/proc`、`sshd -T`、`ss -tulpn`、`ufw status`、`systemctl`、`dpkg-query` | 命令输出解析，不引入 psutil 等额外依赖 |
| 基线知识 | CIS Ubuntu 22.04 / 24.04、dev-sec、ansible-lockdown | 只参考取值与规则编号，不复制代码 |
| 可选审计后端 | Lynis（`/var/log/lynis-report.dat`） | 子进程调用 + 报告解析，GPL 隔离，不链接其代码 |
| 可选指标源 | node_exporter `/metrics` | 若已部署则读取，未部署则回退 `/proc` |
| 测试 | pytest + pytest-testinfra | 集成测试与真实主机校验 |

### 必须自建（差异化核心）

1. **变更计划与预览**：把审计结论转成可审阅的 diff（before/after/影响/回滚方式）。
2. **可回滚加固**：快照 → 执行 → 生效校验 → 失败自动回滚，四步闭环。
3. **证据驱动报告**：每条 finding 带文件路径、行号、原始值，映射 CIS 编号。
4. **产品化交付**：`.deb`、systemd timer、双版本 Ubuntu 兼容、JSON/HTML 报告。
5. **对照评测**：与 Lynis 在相同主机上比对检出率与误报，形成可写进简历的量化结论。

### 明确不做（避免范围失控）

- 不做 IDS/行为检测（交给 CrowdSec / Fail2ban）。
- 不做监控后端与可视化（交给 Prometheus / Netdata）。
- 不重写 200+ 条基线规则（最终实现 40 条高价值规则，其余通过 Lynis 后端覆盖）。
- 不做中央管理平台与多主机编排（单机 CLI，Ansible 场景可通过导出 playbook 衔接）。

## 3. 与现有工具的能力对比

| 能力 | Lynis | OpenSCAP | Ansible 角色 | goss | UbuntuGuard |
| ---- | ---- | ---- | ---- | ---- | ---- |
| 基线审计 | 强 | 强（合规） | 弱 | 中 | 中（40 条 + 可接 Lynis） |
| 结构化证据 | 弱 | 强 | - | 中 | 强 |
| 加固执行 | 无 | 有（oscap） | 强 | 无 | 有（drop-in） |
| 变更预览 | 无 | 弱 | 无 | 无 | 有 |
| 备份与回滚 | 无 | 无 | 无 | 无 | 有 |
| 生效校验 | 无 | 有 | 无 | 有 | 有 |
| 单机零依赖使用 | 强 | 弱 | 弱 | 中 | 强 |
| 双版本 Ubuntu 产品化 | 中 | 中 | 强 | 中 | 强 |

## 4. 对原计划的修改点

| 原计划 | 调整 | 理由 |
| ---- | ---- | ---- |
| 安全基线规则库（未定量） | 明确 40 条高价值规则，按 CIS 章节映射 | 可控工作量，避免与 Lynis 正面重复 |
| 无外部引擎 | Phase 3 增加 `--engine lynis` 可选后端 | 复用成熟规则库，同时体现集成能力 |
| Phase 6 Node Exporter 接入 | 改为"可选指标源"，默认读 `/proc` | 避免为了监控而引入监控栈 |
| 无 CI | Phase 8 增加 GitHub Actions 双版本矩阵（ruff/mypy/pytest/deb 构建） | 求职展示工程化能力 |
| 无对比数据 | Phase 9 增加与 Lynis 的对照评测 | 量化说明差异，简历可直接引用 |
| 无 IaC 衔接 | Phase 8 增加 `export ansible` 可选产出 | 体现与 Ansible 生态协作而非对抗 |

## 5. 求职价值映射

| 岗位要求 | 项目体现 |
| ---- | ---- |
| Linux 系统与安全 | SSH/UFW/sysctl/Auditd/AIDE 实操与生效校验 |
| 脚本与自动化 | Python CLI、安全命令执行器、systemd timer |
| 工程化 | 打包 .deb、CI 矩阵、单测/集成/安全测试、文档体系 |
| 风险意识 | 预览确认、备份回滚、失败降级、退出码语义 |
| 排障与验证 | 证据驱动报告、与 Lynis 对照评测 |
