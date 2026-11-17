# ROADMAP

UbuntuGuard 全部阶段与任务清单。以能力验收为推进依据，未通过验收不得进入下一阶段。

## Phase 0：项目调研与架构设计（第 1～2 天）

- [x] 核对 Ubuntu 22.04 / 24.04 差异（包版本、systemd、UFW、AppArmor、Python 版本）
- [x] 确定模块架构与模块间边界
- [x] 定义 CLI 命令规范（命令、参数、退出码）
- [x] 设计配置文件格式与校验规则
- [x] 设计日志、异常、权限体系
- [x] 编写技术设计文档（ARCHITECTURE.md）

验收：架构设计完整，无重大技术冲突。→ 已通过（差异清单待 Phase 9 实机复核）

## Phase 1：核心执行引擎（第 3～5 天）

- [x] Python 项目结构与打包元数据（pyproject.toml）
- [x] CLI 命令系统
- [x] 配置加载与验证
- [x] 日志管理
- [x] 系统命令安全执行器（禁止 shell 拼接、超时、结果结构体）
- [x] 权限与环境检查
- [x] Dry-run 执行模式（执行器层已实现，CLI 接入随首个变更命令）
- [x] integrations 适配层接口（外部引擎/指标源占位）

验收：CLI 正常运行，异常处理完善。→ 已通过（33 项单测，ruff/mypy 无告警；已可编辑安装并运行）

## Phase 2：Linux 系统信息采集（第 6～8 天）

- [x] CPU、内存、磁盘采集
- [x] 网络接口与 IP 信息
- [x] 用户与用户组信息
- [x] 运行进程与服务
- [x] 监听端口
- [x] 系统版本与内核信息
- [x] 软件包及更新状态

验收：能获取真实 Ubuntu 系统数据。→ 已通过（48 项单测；解析器固定样本覆盖；非 Linux 环境按模块降级并记录 errors）

## Phase 3：安全基线审计（第 9～12 天）

- [x] SSH 配置审计（`sshd -T` 优先，文件解析兜底）
- [x] Root 登录检查
- [x] 密码认证策略检查
- [x] sudo 权限检查
- [x] 文件权限检查（passwd/group/shadow/sudoers）
- [x] 防火墙状态检查（UFW 状态、默认策略、规则解析）
- [x] 危险端口检查（FTP/Telnet/SMB/RDP/Redis/MongoDB 等对全网暴露）
- [x] sysctl 参数检查（ASLR、SYN cookies、rp_filter、ICMP、内核信息保护、链接保护）
- [x] 自有规则收敛到 40 条，并按 CIS 章节映射（具体控制号待 Phase 9 对照官方文档校准）
- [x] 可选 Lynis 后端：调用 + 解析 lynis-report.dat，未安装时降级为 skipped
- [x] 风险评分与审计报告（text/json，新增 `audit` 命令）

验收：能检测预设安全问题并提供证据。→ 已通过（40 条规则，覆盖 SSH/账号/权限/sudo/密码策略/防火墙/端口/sysctl；93 项单测；实机检出效果待 Phase 9）

## Phase 4：自动化安全加固（第 13～16 天）

- [x] SSH 安全配置（drop-in 写入 + `sshd -t` 校验 + 生效比对）
- [x] UFW 规则管理（默认策略、放行端口、启用）
- [x] Fail2ban 安装与配置（apt 安装 + jail.d drop-in）
- [x] 系统安全参数调整（sysctl drop-in + `sysctl -p` 校验）
- [x] 修改前备份（快照 + SHA256 校验 + 恢复）
- [x] 配置差异预览（unified diff 与命令清单）
- [x] 回滚与恢复（失败自动恢复文件并回滚运行时状态）

验收：加固前备份，支持安全回滚。→ 已通过（模拟执行器验证命令序列、失败回滚与文件恢复；真实主机加固待 Phase 9 实机验证）

## Phase 5：系统审计与异常检测（第 17～20 天）

- [x] Auditd 审计规则（规则解析、服务状态、敏感路径 watch 检查）
- [x] AIDE 文件完整性检查（安装与数据库状态）
- [x] SSH 登录日志分析（auth.log 优先，journalctl 兜底）
- [x] 登录失败统计（按 IP 聚合、暴力破解与枚举判定）
- [x] 异常进程识别（临时目录执行、可执行文件已删除）
- [x] 关键文件变更检测（SHA256 基线，`detect --init-baseline`）
- [x] 安全事件记录（events.jsonl 追加写入）

验收：能检测真实日志和文件变化。→ 已通过（解析与判定层；`detect` 命令；132 项单测；实机日志、auditd/AIDE 行为待 Phase 9 验证）

## Phase 6：系统健康监控（第 21～23 天）

- [x] CPU 与内存监控
- [x] 磁盘使用率监控
- [x] 系统负载监控
- [x] 服务状态监控
- [x] Node Exporter 作为可选指标源（默认回退 /proc，报告标注 `metrics_source`）
- [x] 健康检查规则（阈值判定与 `monitor check`）
- [x] Webhook 告警（重试、失败记录、仅在存在 findings 时发送）

验收：监控指标真实，告警规则有效。→ 已通过（147 项单测；Windows 下降级为 skipped；真实指标与 Webhook 投递待 Phase 9 实机验证）

## Phase 7：备份与恢复（第 24～26 天）

- [x] 系统配置备份（文件/目录/glob 展开，默认覆盖 passwd/shadow/sudoers/ssh/sysctl/fail2ban/ufw）
- [x] 备份压缩（`archive.tar.gz`，保留 `files/` 以便快速恢复）
- [x] SHA256 完整性校验（manifest 记录，verify 与恢复后复检）
- [x] 历史备份保留策略（保留最近 N 份 + 天数窗口取并集）
- [x] 配置恢复（恢复后差异复检，失败返回错误码）
- [x] 恢复前差异检查（changed/missing/added 预览，需 `--force` 才写入）
- [x] 恢复演练（`backup drill` 恢复至临时目录并逐文件校验，不触碰系统）

验收：备份文件可验证、可恢复。→ 已通过（155 项单测；临时目录真实文件读写；/etc 实机备份与恢复待 Phase 9）

## Phase 8：工程化与系统集成（第 27～29 天）

- [x] Systemd Timer 定时巡检（audit 报告 6h、健康检查 5min，Persistent）
- [x] Systemd Service 管理（`systemd install|uninstall`，写入单元并 enable/disable）
- [x] APT 安装脚本（postinst/prerm/postrm：目录、timer 启停、purge 清理）
- [x] Debian 软件包构建（debian/control、rules、install、changelog）
- [x] 安装、卸载与升级（dpkg 覆盖升级；purge 清理配置与状态）
- [x] JSON / HTML 报告（`report` 合并审计、检测与健康数据，自包含 HTML）
- [x] 完整 CLI 命令集成（collect/audit/detect/harden/monitor/backup/report/export/systemd）
- [x] GitHub Actions 双版本矩阵（22.04 + 3.10 / 24.04 + 3.12，ruff/mypy/pytest/wheel/deb）
- [x] `export ansible` 可选产出（复用加固渲染逻辑，保证配置一致）

验收：干净环境安装、升级、卸载成功。→ 已通过（Ubuntu 24.04 构建 deb，安装/重复安装/卸载验证通过；22.04 使用源码/venv 安装）

## Phase 9：最终测试与发布（第 30～35 天）

- [x] Ubuntu 22.04 测试（WSL2 22.04.5 + Python 3.10.12，163 项测试通过）
- [x] Ubuntu 24.04 测试（WSL2 24.04.4 + Python 3.12.3，163 项测试通过）
- [x] 自动化测试（pytest + ruff + mypy，双版本）
- [x] 安全功能验证（audit/detect/monitor/harden/backup 实机执行，SSH 与 sysctl 生效校验）
- [x] 故障注入测试（真实触发校验失败 → 自动回滚成功；恢复后差异复检通过）
- [x] 安装与卸载测试（24.04 构建 deb，安装/重复安装/卸载成功）
- [x] 与 Lynis 的对照评测（Lynis 47 项、合并 64 项，差异与重叠已记录）
- [ ] 文档审查
- [ ] GitHub Release 发布

验收：两个 Ubuntu 版本测试通过，发布 v1.0.0。→ 双版本测试通过，CIS 编号已校准；待 GitHub Actions 与 Release 发布
