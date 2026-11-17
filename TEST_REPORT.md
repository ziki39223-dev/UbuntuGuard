# TEST_REPORT

记录每阶段测试环境、用例、结果与证据。

## 测试环境

| 项目 | 内容 |
| ---- | ---- |
| 开发环境 | Windows 11 + Python 3.12.10（逻辑与 CLI 验证） |
| Ubuntu 22.04 | WSL2 Ubuntu 22.04.5 LTS，Python 3.10.12（Phase 9 实机） |
| Ubuntu 24.04 | WSL2 Ubuntu 24.04.4 LTS，Python 3.12.3（Phase 9 实机） |
| Python | 目标兼容 ≥ 3.10；实机覆盖 3.10 / 3.12 |
| 测试框架 | pytest 8.x；静态检查 ruff + mypy |

## 阶段测试记录

### Phase 0

- 状态：已通过（文档评审，无运行时测试）
- 用例：
  - 架构分层与依赖方向自检（cli → 业务层 → core，无反向依赖设计）
  - 安全边界核对：非 root 拒绝、SSH 仅 drop-in、防火墙先 allow 后 enable、失败回滚
  - CLI 退出码覆盖：0/1/2/3/4/5/6/7/8/9 全部分支有明确语义
  - 配置安全不变量：`require_confirmation`、`backup_before_change` 不可关闭
  - 双版本差异清单覆盖 Python / OpenSSH / UFW / Fail2ban / Auditd / AIDE / systemd / 内核
- 结果：全部通过；22.04 / 24.04 实机验证顺延至 Phase 9
- 未决：无

### Phase 1

- 状态：已通过（开发环境 Windows 11 + Python 3.12.10）
- 用例：
  - 配置：文件缺失回退默认值；深层合并；未知 section 告警；9 类非法值（版本、超时、日志级别、引擎、安全不变量、端口格式、SSH 端口、阈值）；YAML 语法错误；根节点非 mapping
  - 执行器：dry-run 不实际执行；拒绝 shell 字符串与空 argv；命令不存在抛错；非零退出码与 check=True；超时返回 124
  - 权限：os-release 解析（引号/注释）；文件缺失返回空；未知依赖探测；环境状态结构
  - CLI：version（文本/JSON）；无子命令返回 2；config validate/show；非法配置映射退出码 2；doctor JSON
- 结果：33 passed；ruff All checks passed；mypy Success: no issues found in 20 source files
- 未决：Ubuntu 实机行为（/proc、ufw、sshd 等）待 Phase 2 与 Phase 9 验证

### Phase 2

- 状态：已通过（解析器层固定样本验证；真实主机数据待 Ubuntu 环境）
- 用例：
  - 主机：uptime、CPU model、loadavg 解析；缺失文件降级
  - 内存：MemAvailable 正常路径；缺失时按 MemFree+Buffers+Cached 回退；MemTotal 缺失抛错
  - 磁盘：/proc/mounts 解析与伪文件系统过滤、八进制转义、挂载点去重（statvfs 仅 Linux 生效）
  - 网络：`ip -o addr/link/route` 解析接口、IPv4/IPv6、MAC、state、默认网关
  - 端口：`ss -tulpn` 解析协议、地址、端口、状态、进程名与 PID
  - 进程与服务：`ps` 按 CPU 排序限量、`systemctl --plain` 输出解析
  - 账号：passwd/group 解析、主组与附加组归属
  - 软件包：dpkg 状态计数、apt 模拟升级数量解析
  - 快照：单采集器失败隔离，`errors` 记录且其余数据可用；CLI `collect` table/json
- 结果：48 passed；ruff All checks passed；mypy Success: no issues found in 30 source files
- 未决：`ip`/`ss`/`systemctl`/`dpkg-query` 在真实 Ubuntu 上的输出差异需 Phase 9 复核

### Phase 3（批次 1）

- 状态：已通过（规则与引擎层；实机检出效果仍待 Ubuntu 环境）
- 用例：
  - 评分：满分 100、critical/high/medium/low 扣分、下限 0、A–E 分级、阈值判断（none/low/high）
  - 引擎：无可评估项时 score=0/grade=N/A 且 CLI 退出 9；跳过原因记录；规则抛错隔离；findings 按严重度排序
  - SSH：16 条规则全通过基线、root 登录、密码认证、空密码（critical）、MaxAuthTries、Banner、弱 Ciphers、访问限制、配置不可用时的 prerequisite
  - 账号：额外 UID 0（critical）、重复 UID、系统账号登录 shell、root 组成员、空密码（critical）
  - 权限：/etc/passwd 组可写、/etc/shadow 非 root 可访问（critical）、sudoers 权限过宽
  - sudo：NOPASSWD 命中行号与文件
  - 密码策略：PASS_MAX_DAYS/MIN_DAYS/WARN_AGE/UMASK，缺失与非法值
  - 报告：JSON 结构与 schema_version、text 渲染包含证据/修复建议/跳过项
  - CLI：`audit`、`audit --fail-on critical`、`--json audit`
- 结果：76 passed；ruff All checks passed；mypy Success: no issues found in 44 source files
- 未决：
  - 真实 Ubuntu 上 `sshd -T` 的权限行为（非 root）需复核，失败时回退文件解析
  - CIS 具体控制号尚未逐条对照官方 Benchmark，当前按章节映射

### Phase 3（批次 2）

- 状态：已通过（解析与规则层；UFW/sysctl 实机输出待 Ubuntu 环境）
- 用例：
  - UFW：active/inactive 判定、默认 incoming/outgoing 解析、v6 规则归一化、命令缺失与无权限两种降级
  - sysctl：按 `/proc/sys` 路径读取、缺失键跳过（tmp 目录固定样本）
  - Lynis：warning→medium / suggestion→low 映射、ID 稳定（内容哈希）、报告缺失返回空
  - 规则：FW-001/002、PORT-001（危险端口/回环放行）、SYS-001～007（干净基线全通过、ASLR/rp_filter 异常命中、无数据时 prerequisite）
  - 引擎合并：外部 findings 参与评分、外部 skipped 记录、`extra_evaluated` 避免误判 n/a
- 结果：93 passed；ruff All checks passed；mypy Success: no issues found in 53 source files
- 未决：
  - 真实 UFW 输出格式（不同版本列宽）需 Phase 9 复核
  - `--engine lynis` 依赖本机安装 Lynis，报告字段随版本变化按 R-010 降级处理

### Phase 4

- 状态：已通过（模拟执行器 + 临时目录；未在真实主机执行 apply）
- 用例：
  - 快照：创建/校验/恢复，SHA256 记录，恢复删除"快照时不存在"的新文件
  - SSH：drop-in 内容生成、幂等（内容一致不再计划）、`sshd -t` 失败返回未验证、`sshd -T` 有效值逐项比对
  - sysctl：drop-in 生成、`sysctl -p` 成功、逐键 `sysctl -n` 校验
  - 防火墙：默认策略/放行/启用命令生成、状态校验、回滚执行 disable 与 delete allow
  - Fail2ban：未安装时生成安装 + jail 计划、安装命令含 `DEBIAN_FRONTEND=noninteractive`、jail 文件写入、服务与 jail 校验
  - 引擎：不支持平台拒绝规划、`--only` 过滤、失败自动恢复文件并回滚、回滚失败标记、成功保留改动
  - 报告：计划 diff（unified diff）、跳过原因、执行结果与快照 ID
  - CLI：`harden plan`、`harden apply` 默认预览、缺失 action 退出 2、未知 `--only` 退出 2
- 结果：113 passed；ruff All checks passed；mypy Success: no issues found in 64 source files
- 未决：
  - `sshd -t`、`systemctl reload ssh`、`ufw`、`sysctl -p` 的真实行为与权限要求需 Phase 9 实机验证
  - Fail2ban 通过 apt 安装，网络受限或 apt 锁占用时会失败；失败即回滚配置文件（软件包不回滚，见 D-014）
  - 当前交互确认以 `--apply --yes` 双开关表达，未实现 TTY 交互问答

### Phase 5

- 状态：已通过（解析器与判定层使用固定样本；实机日志与 auditd/AIDE 行为待 Phase 9）
- 用例：
  - auth.log：failed password / invalid user / accepted publickey / accepted password 解析；按 IP 聚合；journald 兜底
  - 判定：同一 IP 10 次失败 → LOG-001 high；root 密码登录 → LOG-002 high；≥10 个无效用户 → LOG-003 medium
  - auditd：规则计数与 `-w` 路径解析；服务 inactive → AUD-002；缺 sudoers/ssh watch → AUD-003
  - AIDE：安装状态与数据库存在性、数据库修改时间
  - 进程：临时目录执行、`(deleted)` 可执行文件分类；`/proc` 扫描
  - 文件基线：初始化、变更、缺失、新增；未初始化时给出 skipped 提示
  - 事件：events.jsonl 追加 JSON 行；检测结果落盘
  - CLI：`detect`、`--json detect`
- 结果：132 passed；ruff All checks passed；mypy Success: no issues found in 72 source files
- 未决：
  - auth.log 轮转导致可分析窗口有限；非 root 读取可能失败，已用 journalctl 兜底并在 skipped 中说明（R-016）
  - auditd/AIDE 的真实状态与 `systemctl is-active` 输出需 Phase 9 复核
  - 当前检测为一次性执行，尚无守护进程与告警联动（Phase 6 接 Webhook）

### Phase 6

- 状态：已通过（阈值与告警层使用固定指标；真实 CPU/内存采样与投递待 Phase 9）
- 用例：
  - /proc：stat 解析与 CPU 增量计算；meminfo 百分比；loadavg 均值/核数
  - node_exporter：Prometheus 文本解析、CPU/内存/负载/文件系统指标、拉取失败回退
  - 磁盘：注入 usage 函数计算百分比
  - 健康检查：CPU/磁盘阈值命中 HEALTH-001/003；服务 inactive → HEALTH-005；无指标时全部 skipped 且无 findings
  - Webhook：成功后返回尝试次数；失败重试；无 URL 直接报错；不抛出异常
  - 事件与报告：findings 写入 events.jsonl；text/JSON 报告结构
  - CLI：`monitor check`、`--no-notify`、`--json monitor check`、缺失 action 退出 2
- 结果：147 passed；ruff All checks passed；mypy Success: no issues found in 78 source files
- 未决：
  - 真实节点上 CPU 采样间隔与负载阈值需按机型调整
  - Webhook 出网在受限网络下会失败，已在输出中显示重试与失败原因（R-007）
  - 监控仍为一次性检查，systemd timer 周期执行在 Phase 8 接入

### Phase 7

- 状态：已通过（临时目录真实文件读写；/etc 实机备份与恢复待 Phase 9）
- 用例：
  - 路径展开：目录递归、单文件、glob、去重
  - 快照：压缩包生成、list 元数据、load 解析 manifest、SHA256 校验、破坏副本后 verify 失败
  - 快照 ID：同秒多次创建仍唯一
  - 差异：changed / missing / added 判定；恢复后全部 unchanged
  - 恢复：文件内容还原、缺失文件重建、快照时不存在的文件被删除
  - 演练：drill 复制到临时目录并逐文件校验；篡改副本后 drill 抛错
  - 保留：最新 N 份保留，超期快照被删除（通过 utime 模拟 100 天前）
  - CLI：`backup list/verify/drill` 使用配置文件路径，缺失 action 与方法名错误处理
- 结果：155 passed；ruff All checks passed；mypy Success: no issues found in 79 source files
- 未决：
  - 恢复 `--force` 与 create 需 root，Windows 下默认配置返回 9（需显式配置路径）
  - 真实 /etc 目录的权限、符号链接与 ACL 未覆盖（仅按内容与 SHA256 处理）
  - 恢复后未自动重载受影响服务（由 Phase 4 加固动作负责）

### Phase 8

- 状态：已通过（代码与打包文件；deb 构建/安装与 CI 待 Phase 9）
- 用例：
  - HTML 报告：自包含文档、严重度徽章、证据/修复建议、跳过项、HTML 转义（`<script>` 不执行）
  - Ansible 导出：SSH/sysctl drop-in、UFW 端口任务、Fail2ban 安装与 jail、handler；YAML 可序列化
  - systemd：4 个单元写入、自定义 interval 生效、daemon-reload 与 enable/disable 调用、uninstall 清理、interval 校验
  - CLI：`report --format json/html --out`、`export ansible`、缺失 action 退出 2
- 结果：162 passed；ruff All checks passed；mypy Success: no issues found in 83 source files
- 未决：
  - 本机为 Windows，未执行 `dpkg-buildpackage`、未运行 GitHub Actions
  - deb 安装脚本的 timer 启停与 purge 行为需 Phase 9 实机验证
  - systemd 单元中的二进制路径默认 `/usr/bin/ubuntuguard`，源码安装场景由 CLI 自动探测

### Phase 9（实机验证）

- 环境（WSL2 2.7.10.0，systemd 已接管 PID 1）：
  - `UbuntuGuard-22.04`：Ubuntu 22.04.5 LTS，Python 3.10.12
  - `UbuntuGuard-24.04`：Ubuntu 24.04.4 LTS，Python 3.12.3
  - 已安装：systemd、openssh-server、ufw、fail2ban、auditd、aide、iproute2、python3-venv
  - 项目副本 `/root/UbuntuGuard`，虚拟环境 `/root/venv`
- 自动化：两版本均 `164 passed`，ruff / mypy 通过
- 实机功能：
  - `audit`：16 findings（3 high / 8 medium / 5 low），22 passed，2 skipped，score 0（E）
  - `monitor check`：真实 CPU 0.4%、内存 10.5%、磁盘 0.1%、load 0.09；ssh 未运行时正确报 HEALTH-005
  - `detect --init-baseline`：基线记录 4 个文件，检测出 auditd inactive、AIDE 无数据库、auditd 缺 watch
  - `backup create`：17 个文件、压缩快照；`verify` 通过、`drill` 验证 17 个文件
  - `harden apply --only ssh`：`sshd -t` 通过、reload 成功、`sshd -T` 校验 `passwordauthentication no` / `maxauthtries 4`
  - `harden apply --only sysctl`：`sysctl -p` 与逐键校验通过
  - `backup restore --force`：恢复后 drop-in 被删除、`sshd -T` 恢复 `passwordauthentication yes`，复检 ok
  - `report --format html`：生成 9.5K 自包含报告（样例见 `examples/report-demo.html`）
  - Lynis：`--engine lynis` 47 findings（4 medium / 43 low）；`--engine all` 64 findings（原生 16 + Lynis 48），21 passed、2 skipped
  - CIS 映射：依据 ComplianceAsCode 控制文件校准 40 条规则，运行时自动附加控制号，详见 `docs/CIS_MAPPING.md`
  - deb：24.04 构建 `ubuntuguard_1.0.0-1_all.deb`（61K），安装、0.1.0 → 1.0.0 升级、卸载均成功
- 本轮发现并修复的问题：
  1. `sshd -T` 将 `prohibit-password` 输出为 `without-password`，导致校验误失败并触发回滚 → 增加取值别名归一化
  2. 全新安装缺少 `/run/sshd`，`sshd -t` 失败 → 加固执行前创建运行时目录
  3. 备份只收集已存在文件，无法在恢复时删除后来新增的 drop-in → `include_missing` 记录缺失目标，并补齐 SSH/sysctl/fail2ban drop-in 路径
  4. 单元测试在 Linux root 下会真实执行加固 → 改为无参数预览路径
  5. deb 构建缺少 `pybuild-plugin-pyproject`；`debian/install` 与 systemd 单元被标记可执行 → 补构建依赖并修正权限
  6. Lynis 标题包含原始 `|` 分隔字段 → 解析出测试 ID 与消息
  7. deb 升级后仍显示旧版本（stale `__pycache__`）→ 干净重建并在 postinst 清理旧字节码，0.1.0 → 1.0.0 升级验证通过
- 未决：
  - WSL2 与真实服务器差异：auditd 无法启动、AIDE 未初始化、UFW/公网暴露场景未覆盖（R-018）
  - Ubuntu 22.04 的 setuptools 低于 68，deb 仅在 24.04 构建；22.04 使用源码/venv 验证
  - CIS 具体控制号仍未逐条对照官方 Benchmark（R-012）
  - GitHub Actions 尚未首次运行，GitHub Release 未发布

> 后续阶段按 ROADMAP 顺序追加，未通过验收不得标注完成。
