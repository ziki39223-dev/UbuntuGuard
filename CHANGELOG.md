# CHANGELOG

格式参考 Keep a Changelog，版本遵循语义化版本。

## [1.0.1] - 2026-11-17

### Fixed

- **SSH 加固云端失效**：sshd 对同一关键字取首个值并按字典序加载 `sshd_config.d/*.conf`，原 `99-ubuntuguard.conf` 会被 `50-cloud-init.conf` 覆盖，导致生效校验失败并回滚。改为 `00-ubuntuguard.conf`，同步更新备份路径、文件基线与 Ansible 导出。
- **sshd 未运行时加固失败**：改为仅在服务 active 时 `systemctl reload ssh`，否则直接校验配置文件有效性；回滚同理。避免在未启用 SSH 的主机上误判失败。

### Added

- `scripts/integration-test.sh` 与 CI `integration` 任务：在 GitHub Runner（真实 systemd）启用 ufw/auditd/AIDE/sshd，执行 34 项端到端断言（审计→备份→加固→生效校验→检测→监控→systemd 单元→恢复→报告）。

## [1.0.0] - 2026-11-17

### Added

- 项目目录骨架（src / tests / scripts / configs / systemd / packaging / docs / examples）
- 项目管理文档：PROJECT_STATUS、ROADMAP、ARCHITECTURE、DECISIONS、TEST_REPORT、RISK_REGISTER
- 采用 MIT 许可证（LICENSE + pyproject license 元数据）
- 发布与签名：项目专用 GPG 密钥、`scripts/build-apt-repo.sh` 生成带 `InRelease`/`Release.gpg` 的 APT 仓库、`packaging/apt/`（公钥与 deb822 源）、`docs/PACKAGE_SIGNING.md`；仓库产物发布到 `gh-pages`（GitHub Pages）；CI 新增 `apt-repo` 任务验证签名与 `apt install`
- Phase 0 定稿：
  - ARCHITECTURE.md 架构设计（分层、核心抽象、数据流、安全边界、兼容策略）
  - docs/TECHNICAL_DESIGN.md 技术方案（CLI 规范与退出码、YAML 配置 schema、日志规范、报告 schema、风险评分、22.04/24.04 差异清单、备份布局、权限模型、打包与测试策略）
  - DECISIONS 新增 D-004～D-009（YAML、预览确认、文档中文、最小依赖、drop-in 变更、扣分制评分）
- 生态调研与计划修订：
  - docs/ECOSYSTEM_AND_POSITIONING.md（Lynis / OpenSCAP / dev-sec / ansible-lockdown / crowdsec / osquery / netdata / goss 对比，复用与不做清单）
  - 规则范围收敛为 30～40 条并映射 CIS；新增 Lynis 可选后端与 integrations 适配层
  - Phase 8 增加 GitHub Actions 双版本矩阵与 export ansible；Phase 9 增加与 Lynis 的对照评测
  - DECISIONS 新增 D-010～D-013；RISK_REGISTER 新增 R-008～R-011

### Phase 1

- 项目可安装：`pyproject.toml`（entry point `ubuntuguard`）、`python -m ubuntuguard`
- CLI：`version`、`doctor`、`config show|validate`；全局 `--config`、`--log-level`、`--json`
- 配置：YAML 加载、默认值深层合并、类型与取值校验、未知 section 告警、安全不变量强制
- 日志：文本与 JSON 行格式，可选文件日志（写失败自动降级）
- 执行器：argv 白名单式调用、禁止 shell 字符串、超时 124、dry-run、结构化结果、`check` 抛错
- 权限：root 判断、Ubuntu 版本探测、依赖缺失检测
- integrations：`AuditEngine` 协议与 `NullEngine` 占位
- 测试与质量：33 项 pytest、ruff、mypy 全部通过
- 示例配置：`configs/config.example.yaml`；README、Makefile

### Phase 2

- 采集器：主机/CPU/内存/磁盘/网络/端口/账号/进程/服务/软件包（只读，解析 /proc 与系统命令输出）
- 快照：`SystemSnapshot` 聚合，单采集器失败隔离并在 `errors` 中记录，其余数据仍可用
- CLI：`collect` 命令，`--output table|json`，配合全局 `--json`
- 测试：新增解析器固定样本用例，总计 48 项通过

### Phase 3（批次 1）

- 规则引擎：`Rule` 定义、注册表、跳过原因、单规则异常隔离、按严重度排序
- 评分：100 分制（critical 25 / high 15 / medium 7 / low 2），A–E 分级；无可评估项时输出 n/a 并退出 9
- 新命令：`audit`，支持文本/JSON 报告与 `--fail-on`（命中阈值退出 4）
- 采集：SSH 有效配置（`sshd -T` 优先，主配置 + drop-in 兜底）、shadow、sudoers、login.defs、关键文件权限
- 规则：SSH 16 条（root 登录、密码认证、空密码、X11、MaxAuthTries、弱算法等）；账号/权限/sudo/密码策略 14 条（UID 0、重复 UID、空密码、shadow 权限、NOPASSWD、UMASK 等）
- 测试：总计 76 项通过；ruff/mypy 无告警

### Phase 3（批次 2）

- 采集：UFW 状态/默认策略/规则、`/proc/sys` 内核参数
- 规则：防火墙 2 条（未启用、默认放行）、危险端口暴露 1 条（16 类非安全默认服务）、sysctl 7 条（ASLR、SYN cookies、rp_filter、ICMP 重定向/源路由/广播、内核信息保护、链接保护），规则总数 40
- 集成：Lynis 可选后端（`lynis audit system` + `lynis-report.dat` 解析，内容哈希稳定 ID，未安装降级为 skipped）
- CLI：`audit --engine native|lynis|all`
- 测试：总计 93 项通过；ruff/mypy 无告警

### Phase 4

- 加固动作：SSH（drop-in + `sshd -t` + `sshd -T` 生效比对）、sysctl（drop-in + 逐键校验）、UFW（默认策略/放行/启用 + 状态校验）、Fail2ban（apt 安装 + jail.d 配置 + jail 状态校验）
- 快照：`SnapshotStore`（manifest.json + SHA256 + 文件恢复，恢复会删除快照时不存在的新文件）
- 引擎：`harden plan` 生成 unified diff 与命令清单；`harden apply --apply --yes` 需 root，失败自动恢复文件并回滚运行时，退出码 6（回滚成功）/7（回滚失败）
- CLI：全局 `--dry-run`、`--yes`；`harden plan|apply --only ssh,sysctl,firewall,fail2ban`
- 测试：总计 113 项通过；ruff/mypy 无告警

### Phase 5

- 新命令：`detect`，检测登录异常、完整性状态、可疑进程与关键文件变化，支持 `--init-baseline` 与 `--fail-on`
- 登录分析：`/var/log/auth.log` 解析，`journalctl -u ssh` 兜底；按 IP 聚合失败次数、无效用户枚举、root 密码登录
- 完整性：auditd 规则/服务状态/敏感路径 watch、AIDE 安装与数据库状态
- 进程与文件：`/proc` 扫描临时目录执行与已删除可执行文件；SHA256 关键文件基线
- 事件：`events.jsonl` 追加写入安全事件；`detect` 输出 text/JSON
- 测试：总计 132 项通过；ruff/mypy 无告警

### Phase 6

- 指标：/proc 采样 CPU、内存、负载，磁盘使用率；node_exporter 可选指标源（Prometheus 文本解析），失败回退 /proc 并标注 `metrics_source`
- 健康检查：HEALTH-001～005（CPU/内存/磁盘/负载/服务），支持 `monitor check --fail-on`
- 告警：Webhook 通知（重试、失败原因、仅在存在 findings 时发送）；结果写入 events.jsonl
- 配置：`monitoring.disk_mounts`、`monitoring.node_exporter.{enabled,url}`
- CLI：`monitor check`、`--no-notify`
- 测试：总计 147 项通过；ruff/mypy 无告警

### Phase 7

- 新命令：`backup create|list|verify|restore|drill`
- 快照增强：可选 `archive.tar.gz`、manifest 记录工具版本/时间/归档、快照 ID 去重
- 保留策略：保留最近 N 份并对超期快照清理（N 与天数取并集）
- 恢复：恢复前输出 changed/missing/added 差异，需 `--force` 执行；恢复后自动复检并返回结果
- 演练：`backup drill` 恢复到临时目录并逐文件 SHA256 校验，不触碰系统
- 默认备份目标：passwd/group/shadow/sudoers/ssh/sysctl/fail2ban/ufw
- 测试：总计 155 项通过；ruff/mypy 无告警

### Phase 8

- 报告：`report --format json|html --out`，合并审计、检测与健康检查；HTML 自包含且转义
- systemd：`systemd install|uninstall`，内置 audit（6h）与 monitor（5min）service/timer
- 导出：`export ansible` 生成 SSH/sysctl/UFW/Fail2ban playbook
- 打包：`debian/`（control、rules、install、postinst/prerm/postrm、changelog）、`systemd/` 静态单元
- CI：GitHub Actions 双版本矩阵（ruff/mypy/pytest/wheel/deb + 安装冒烟）
- 依赖：HTML 渲染改为内置实现，移除 Jinja2 运行期依赖
- 测试：总计 162 项通过；ruff/mypy 无告警

### Phase 9（实机验证）

- 在 WSL2 Ubuntu 22.04.5（Python 3.10）与 24.04.4（Python 3.12）完成 163 项测试、ruff、mypy
- 实机验证 audit / detect / monitor / backup / report，以及 SSH 与 sysctl 加固后的生效校验与恢复
- 24.04 构建 `ubuntuguard_0.1.0-1_all.deb`，安装、重复安装、卸载通过
- 修复：
  - `sshd -T` 的 `without-password` 与 `prohibit-password` 别名导致误回滚
  - 全新安装缺少 `/run/sshd` 导致 `sshd -t` 失败
  - 备份未记录"当时不存在"的受管文件，恢复无法删除新增 drop-in
  - Linux root 下单元测试会真实执行加固（改为预览路径）
  - deb 构建缺失 `pybuild-plugin-pyproject`、单元/install 文件可执行位
  - Lynis 标题解析出测试 ID 与消息
  - deb 升级后 stale `__pycache__` 导致版本不生效；postinst 增加旧字节码清理
- deb 构建统一在 Ubuntu 24.04 执行（setuptools ≥ 68），22.04 使用源码/venv 安装
- 版本号统一升级为 1.0.0（pyproject、包 `__version__`、debian/changelog）
- CIS 映射：40 条规则对照 ComplianceAsCode 控制文件（24.04 v1.0.0 / 22.04 v2.0.0），运行时自动附加控制号，见 `docs/CIS_MAPPING.md`

## [0.1.0] - 2026-11-17

内部开发版本，对应 Phase 0–8 的实现过程。
