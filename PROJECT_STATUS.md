# PROJECT_STATUS

当前阶段：Phase 9（已完成并发布）
状态：v1.0.0 已发布（双版本 CI 通过，GitHub Release 已创建）
最近更新：2026-11-17

## 阶段进度

| 阶段 | 内容 | 周期 | 状态 | 验收结果 |
| ---- | ---- | ---- | ---- | ---- |
| Phase 0 | 项目调研与架构设计 | 第 1～2 天 | 已完成 | 通过（差异清单待 Phase 9 实机复核） |
| Phase 1 | 核心执行引擎 | 第 3～5 天 | 已完成 | 通过（33 项单测、ruff、mypy；可编辑安装） |
| Phase 2 | Linux 系统信息采集 | 第 6～8 天 | 已完成 | 通过（48 项单测；解析器固定样本；非 Linux 降级） |
| Phase 3 | 安全基线审计 | 第 9～12 天 | 已完成 | 通过（40 条规则、评分、text/json、Lynis 后端；93 项单测） |
| Phase 4 | 自动化安全加固 | 第 13～16 天 | 已完成 | 通过（预览/备份/执行/校验/回滚全链路；113 项单测） |
| Phase 5 | 系统审计与异常检测 | 第 17～20 天 | 已完成 | 通过（登录分析、auditd/AIDE、进程与文件基线、事件落盘；132 项单测） |
| Phase 6 | 系统健康监控 | 第 21～23 天 | 已完成 | 通过（proc/node_exporter 指标、阈值检查、Webhook；147 项单测） |
| Phase 7 | 备份与恢复 | 第 24～26 天 | 已完成 | 通过（压缩、保留、校验、差异预检、恢复与演练；155 项单测） |
| Phase 8 | 工程化与系统集成 | 第 27～29 天 | 已完成 | 通过（报告、systemd、deb 构建与安装/升级/卸载、CI、Ansible） |
| Phase 9 | 最终测试与发布 | 第 30～35 天 | 已完成 | 双版本 164 项测试通过；CIS 映射完成；deb 安装/升级/卸载验证；GitHub Actions 双版本矩阵通过（deb 构建+冒烟）；v1.0.0 tag 与 Release 已发布 |

## 已完成模块

| 模块 | 说明 |
| ---- | ---- |
| 项目骨架 | 已按规划创建 src / tests / scripts / configs / systemd / packaging / docs / examples 目录结构，空目录已放 .gitkeep |
| 管理文档 | ROADMAP、ARCHITECTURE、DECISIONS、TEST_REPORT、RISK_REGISTER、CHANGELOG 已建立 |
| Phase 0 架构设计 | ARCHITECTURE.md 定稿；docs/TECHNICAL_DESIGN.md 完成 CLI 规范、退出码、YAML schema、日志、报告 schema、评分、双版本差异、备份布局、权限模型、打包与测试策略 |
| 生态调研 | docs/ECOSYSTEM_AND_POSITIONING.md：盘点 Lynis / OpenSCAP / dev-sec / ansible-lockdown / goss 等 15+ 项目，确定复用清单、差异化能力与"明确不做"范围；计划同步调整（规则 40 条、Lynis 可选后端、CI 矩阵、对照评测） |
| Phase 1 核心引擎 | pyproject + 包结构；CLI（version/doctor/config）；YAML 配置加载与校验（含安全不变量）；结构化日志；安全命令执行器（argv 校验、超时 124、dry-run）；平台/权限/依赖检查；integrations 接口；33 项单测 + ruff + mypy 全部通过 |
| Phase 2 信息采集 | host/cpu/memory/disk/network/ports/users/processes/services/packages 九个采集器；纯解析函数可单测；单项失败隔离并写入 errors；`collect` 命令支持 table/json；48 项单测通过 |
| Phase 3 批次 1 | 规则引擎（Rule/Registry/优先级/跳过原因/异常隔离）、100 分制评分与 A–E 分级、`audit` 命令（text/json、`--fail-on` 退出码 4）；SSH 16 条 + 账号/权限/sudo/密码策略 14 条，共 30 条规则；SSH 采集优先 `sshd -T`，兜底解析主配置与 drop-in；无可评估项时显示 n/a 并退出 9，避免误报满分 |
| Phase 3 批次 2 | UFW 状态与默认策略解析（FW-001/002）、危险端口暴露检测（PORT-001，16 类服务）、7 条 sysctl 内核参数规则、Lynis 可选后端（子进程调用 + 报告解析 + 稳定 ID + 未安装降级）；规则总数 40；`audit --engine native\|lynis\|all` |
| Phase 4 加固引擎 | 加固动作：SSH drop-in、sysctl drop-in、UFW 策略、Fail2ban 安装+jail；快照存储（manifest + SHA256 + 恢复）；`harden plan`（unified diff 预览）与 `harden apply --apply --yes`（root 校验、失败自动回滚）；退出码 6/7 区分回滚结果；113 项单测通过 |
| Phase 5 检测模块 | `detect` 命令：auth.log/journald 登录事件解析与按 IP 聚合、暴力破解/枚举/root 密码登录判定、auditd 规则与服务状态、AIDE 安装与数据库状态、`/proc` 异常进程扫描、关键文件 SHA256 基线（`--init-baseline`）、events.jsonl 事件追加；132 项单测通过 |
| Phase 6 健康监控 | `monitor check`：CPU（/proc/stat 采样）、内存、磁盘、负载/核、systemd 服务状态；node_exporter 可选指标源（Prometheus 文本解析，失败回退 /proc）；阈值检查 HEALTH-001～005；Webhook 重试通知与 events.jsonl 记录；147 项单测通过 |
| Phase 7 备份恢复 | `backup create/list/verify/restore/drill`：路径展开（文件/目录/glob）、可选 tar.gz 压缩、manifest + SHA256、保留策略（N 份 + 天数并集）、恢复前差异预览、恢复后复检、临时目录演练；155 项单测通过 |
| Phase 8 工程化 | `report`（合并 JSON/自包含 HTML）、`export ansible`、`systemd install/uninstall`（4 个单元，audit 6h / monitor 5min）、debian/ 打包与安装脚本、GitHub Actions 双版本矩阵（ruff/mypy/pytest/wheel/deb）；162 项单测通过 |
| Phase 9 实机验证 | 建立 WSL2 Ubuntu 22.04.5（3.10）与 24.04.4（3.12）环境；双版本 164 项测试 + ruff/mypy；实机 audit/detect/monitor/backup/harden/report；SSH 与 sysctl 加固生效校验及恢复；24.04 构建 deb 并完成安装/升级/卸载；Lynis 对照（47 项）；CIS 映射写入 `docs/CIS_MAPPING.md`；修复 sshd 别名、/run/sshd、备份缺失目标、deb 依赖与权限等问题 |

## 进行中

无。v1.0.0 已发布：https://github.com/ziki39223-dev/UbuntuGuard/releases/tag/v1.0.0

## 后续可选事项

1. 在真实云主机补一轮 UFW/auditd/公网暴露验证（R-018）。
2. 关注 CIS 官方 PDF 版本更新，按需复核 `docs/CIS_MAPPING.md`。
3. 视需要补充 deb 签名与 PPA 发布。

## 待维护文档

| 文件 | 状态 |
| ---- | ---- |
| ROADMAP.md | 已创建，Phase 0 已勾选 |
| ARCHITECTURE.md | Phase 0 定稿 |
| docs/TECHNICAL_DESIGN.md | 已创建（v1.0，含外部引擎集成、CI、对照评测、不做清单） |
| docs/ECOSYSTEM_AND_POSITIONING.md | 已创建（生态调研与定位） |
| DECISIONS.md | 已创建（D-001～D-019） |
| TEST_REPORT.md | 已创建（Phase 0–9 记录齐全） |
| RISK_REGISTER.md | 已创建（R-001～R-018） |
| CHANGELOG.md | 已创建 |
