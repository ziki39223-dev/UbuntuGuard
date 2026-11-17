# ARCHITECTURE

状态：Phase 0 已定稿（v1.0，2026-11-17）
配套文档：docs/TECHNICAL_DESIGN.md（CLI 规范、配置 schema、报告格式、评分与兼容性清单）

## 1. 系统定位

UbuntuGuard 是面向 Ubuntu 22.04 / 24.04 的自动化安全运维与主机健康保障 CLI 工具，能力覆盖：系统采集 → 安全基线审计 → 加固（预览/确认/回滚）→ 审计与异常检测 → 健康监控 → 备份恢复 → 定时巡检 → 报告输出。

**生态定位**：不自建审计引擎、监控栈与 IDS。审计可接 Lynis 作为可选后端，实际加固交给 UFW / Fail2ban / Auditd / AIDE / sysctl 等系统组件，UbuntuGuard 的价值在"编排 + 产品化 + 可回滚 + 证据"。调研结论见 docs/ECOSYSTEM_AND_POSITIONING.md。

## 2. 设计原则

1. **检测与修改分离**：审计只读；加固必须先产出变更计划，再经显式确认执行；恢复独立成命令。
2. **先备份后修改，改后校验生效**：任何配置写入前生成快照，写入后做生效校验，失败自动回滚。
3. **命令执行统一入口**：所有系统命令经 `core/executor` 执行，禁止业务代码直接调用 subprocess。
4. **结论必须带证据**：每条 finding 附文件路径、行号、原始值或命令输出。
5. **能力探测优先于版本判断**：通过 `/etc/os-release`、`command -v`、`sshd -T` 等探测能力，仅在配置格式确有差异处做版本分支。
6. **最小依赖**：运行时仅依赖 `PyYAML`，HTML 报告使用标准库渲染，其余使用标准库。

## 3. 分层结构与依赖

```
cli/                    命令解析（argparse 子命令）、参数校验、退出码、输出渲染
  │
业务层
  ├── collectors/       只读采集，产出 SystemSnapshot
  ├── security/         基线规则与加固动作
  │     ├── ssh/        SSH 审计与 drop-in 配置
  │     ├── firewall/   UFW 规则
  │     ├── network/    端口暴露规则
  │     ├── system/     sysctl 内核参数规则
  │     ├── users/      账号、sudo、密码策略
  │     ├── fail2ban/   Fail2ban 安装与 jail 配置
  │     ├── hardening/  加固编排（计划、执行、校验、回滚）
  │     └── baseline/   规则引擎、评分
  ├── audit/           系统审计与异常检测
  │     ├── authlog     登录事件解析（auth.log / journalctl）
  │     ├── integrity   auditd 规则与 AIDE 状态
  │     ├── processes   可疑进程扫描（/proc）
  │     ├── file_baseline 关键文件 SHA256 基线
  │     └── events      events.jsonl 事件记录
  ├── monitoring/       指标、健康规则、Webhook 告警
  ├── backup/           快照、压缩、保留策略、SHA256 校验、恢复与演练
  ├── reporting/        JSON / HTML / text 渲染
  ├── notifications/    Webhook 发送与重试
  └── integrations/     外部引擎适配（lynis 报告解析、node_exporter 指标源）
  │
core/
  ├── executor/         安全命令执行、dry-run、超时、结构化结果
  ├── config/           配置加载、默认值合并、schema 校验
  ├── logger/           结构化日志与运维审计日志
  └── permissions/      root / 环境 / 依赖前置检查
```

依赖方向严格单向：`cli → 业务层 → core`。业务模块之间不互相 import，共享数据结构定义在 `src/ubuntuguard/models.py`（Phase 1 落地），避免循环依赖。

## 4. 核心抽象

| 抽象 | 职责 | 关键接口 |
| ---- | ---- | ---- |
| `CommandExecutor` | 执行系统命令 | `run(argv: list[str], timeout, check) -> CommandResult` |
| `Collector` | 只读采集 | `collect() -> SystemSnapshot` |
| `Rule` | 单条基线判定 | `evaluate(snapshot, config) -> Finding \| None` |
| `Action` | 单个可回滚变更 | `plan(ctx) -> ChangePlan` / `apply(plan, snapshot_id) -> ActionResult` / `rollback(snapshot_id)` |
| `SnapshotStore` | 备份与恢复 | `create(paths) -> snapshot_id` / `verify(id)` / `restore(id)` |
| `Reporter` | 报告渲染 | `render(result, fmt) -> str` |

`ChangePlan` 至少包含：目标文件、变更方式（drop-in 写入 / 参数设置 / 服务操作）、before 内容、after 内容、影响说明、回滚方式。

## 5. 关键数据流

1. **审计流**：collectors 采集 → baseline 规则逐条判定 → 评分 → reporting 输出（含证据）。
2. **加固流**：审计结果 → `Action.plan` 生成 ChangePlan → CLI 打印 diff → 用户显式确认（`--apply --yes`）→ SnapshotStore 快照 → executor 执行 → 生效校验（如 `sshd -T`、`ufw status`、`sysctl -n`）→ 失败则自动回滚。
3. **巡检流**：systemd timer 触发 `ubuntuguard audit --format json` + 健康检查 → 报告写入 state 目录 → 超阈值经 notifications 发 Webhook。
4. **恢复流**：列出快照 → 恢复前 diff 检查 → 用户确认 → 恢复 → 校验恢复后配置 → 记录事件。

## 6. 执行模式与安全边界

| 模式 | 触发 | 行为 |
| ---- | ---- | ---- |
| dry-run（默认） | 直接运行 harden | 只输出计划与 diff，不写任何文件 |
| apply | `harden apply --apply --yes` | 备份后写入，校验生效，失败回滚 |
| rollback | `backup restore <id>` | 恢复快照并校验 |

强制约束：

- 非 root 执行 apply / restore 直接拒绝（退出码 3）。
- SSH 相关变更只写 `/etc/ssh/sshd_config.d/00-ubuntuguard.conf`，不修改主配置，保留既有会话；`00-` 前缀用于在 sshd 的“首个取值生效”规则下优先于 `50-cloud-init.conf`。
- 防火墙变更先追加 allow 规则再 enable，禁止一次性替换全部规则。
- 变更前校验依赖（ufw / fail2ban / auditd / aide）存在，缺失返回退出码 8 而非静默跳过。

## 7. 配置、日志与状态

- 配置：`/etc/ubuntuguard/config.yaml`，YAML 格式，schema 见技术设计文档；支持 `--config` 覆盖。
- 日志：`/var/log/ubuntuguard/ubuntuguard.log`，文本 + 可选 JSON 行；变更加固审计日志 `changes.log` 单独记录。
- 状态：`/var/lib/ubuntuguard/`（快照、巡检结果、运行锁）。
- 锁：apply / restore / backup create 使用文件锁互斥，避免并发修改。

## 8. 双版本兼容策略

统一按"能力探测"分支，仅在三处保留显式版本差异：

1. Fail2ban 1.x 与 0.11 的 jail 配置与 backend 取值。
2. OpenSSH 9.6 与 8.9 的 `sshd -T` 输出字段差异。
3. Auditd 规则加载方式（`service auditd restart` 与 `auditctl -R` 的兜底）。

差异清单详见 docs/TECHNICAL_DESIGN.md 第 7 节；双版本实机验证挂在 Phase 9。

## 9. 模块边界红线

- `security/` 不得直接读日志或做监控；`audit/` 不得修改系统配置。
- `collectors/` 只读，禁止任何写操作与命令副作用。
- `backup/` 只负责文件级快照，不解释业务语义。
- 报告渲染只消费结构化结果，不在 reporting 层做判定。
- `integrations/` 只做外部数据适配（Lynis 报告、node_exporter 指标），不承载业务判定；与 GPL 项目仅通过子进程 + 文件输出交互，不复制、不链接其代码。
