# UbuntuGuard 技术设计文档

版本：v1.0（Phase 0 定稿）
日期：2026-11-17
配套：ARCHITECTURE.md（分层与边界）

## 1. 技术选型

| 项 | 选择 | 说明 |
| ---- | ---- | ---- |
| 语言 | Python ≥ 3.10 | 覆盖 22.04（3.10）与 24.04（3.12） |
| CLI | argparse 子命令 | 标准库，无额外依赖 |
| 配置 | YAML（PyYAML） | 可注释、层级清晰 |
| 模板 | 内置 HTML 渲染器 | 自包含 HTML，无模板引擎依赖 |
| 测试 | pytest | 单测 + 集成 + 安全用例 |
| 打包 | pyproject.toml + debhelper | 源码安装与 .deb 双通道 |
| 日志 | logging + 文本/JSON 行 | 支持 logrotate |

## 2. CLI 规范

可执行名：`ubuntuguard`（简写别名 `ug`）。

### 2.1 全局参数

| 参数 | 说明 |
| ---- | ---- |
| `--config PATH` | 指定配置文件，默认 `/etc/ubuntuguard/config.yaml` |
| `--log-level LEVEL` | debug/info/warning/error，默认 info |
| `--json` | 机器可读输出（stdout 只输出 JSON） |
| `--yes` | 跳过交互确认（仅对已显式 `--apply` 的操作生效） |
| `--dry-run` | 强制预览，覆盖配置中的执行开关 |
| `--version` | 版本信息 |

### 2.2 子命令

| 命令 | 作用 | 关键参数 |
| ---- | ---- | ---- |
| `collect` | 采集系统资产 | `--output table\|json` |
| `audit` | 基线安全审计 | `--rules baseline`、`--engine native\|lynis\|all`、`--format text\|json\|html`、`--fail-on high` |
| `detect` | 登录 / 完整性 / 进程 / 文件基线检测 | `--init-baseline`、`--fail-on high` |
| `monitor check` | 健康检查与告警 | `--no-notify`、`--fail-on high` |
| `harden plan` | 生成变更计划与 diff | `--only ssh,firewall,sysctl` |
| `harden apply` | 执行加固 | `--apply`、`--yes`、`--snapshot-id` |
| `backup create` | 创建快照 | `--paths`、`--label` |
| `backup list` | 列出快照 | - |
| `backup verify` | 校验快照 SHA256 | `snapshot_id` |
| `backup restore` | 恢复快照 | `snapshot_id`、`--force` |
| `backup drill` | 恢复演练（临时目录 + 校验） | `snapshot_id` |
| `monitor check` | 健康检查 | `--no-notify`、`--fail-on high` |
| `report` | 生成合并报告 | `--format html\|json`、`--out PATH` |
| `export ansible` | 导出 Ansible playbook | `--out PATH` |
| `systemd install\|uninstall` | 安装/卸载 timer 与 service | `--interval 6h` |
| `web` | 启动本地 Web 控制台 | `--host 127.0.0.1`、`--port 8080` |

### 2.3 退出码

| 码 | 含义 |
| ---- | ---- |
| 0 | 成功 |
| 1 | 未预期的内部错误 |
| 2 | 参数或配置错误 |
| 3 | 权限或环境不满足（如非 root） |
| 4 | 审计发现问题达到 `--fail-on` 阈值 |
| 5 | 操作部分失败 |
| 6 | 操作失败，已回滚成功 |
| 7 | 操作失败且回滚失败（最高优先级告警） |
| 8 | 依赖缺失（ufw / fail2ban / auditd / aide） |
| 9 | 平台不支持（非 Ubuntu 22.04/24.04） |

退出码语义固定，报告与 CI 依赖此约定。

## 3. 配置 schema（YAML）

```yaml
version: 1

general:
  log_level: info                 # debug|info|warning|error
  log_dir: /var/log/ubuntuguard
  state_dir: /var/lib/ubuntuguard
  timeout_seconds: 30             # 单条命令超时

audit:
  fail_on: high                   # none|low|medium|high|critical
  include: [ssh, users, firewall, sysctl, permissions, ports]
  engine: native                  # native|lynis|all；lynis 需本机已安装

harden:
  require_confirmation: true      # 固定为 true，禁止配置为 false
  backup_before_change: true      # 固定为 true
  verify_after_apply: true
  rollback_on_failure: true

ssh:
  port: 22
  permit_root_login: prohibit-password
  password_authentication: false
  allow_users: []

firewall:
  enabled: true
  default_incoming: deny
  allow_ports: ["22/tcp"]

fail2ban:
  enabled: true
  maxretry: 5
  bantime: 1h

sysctl:
  net.ipv4.conf.all.rp_filter: 1
  net.ipv4.tcp_syncookies: 1
  net.ipv6.conf.all.disable_ipv6: 0

monitoring:
  thresholds:
    cpu_percent: 85
    memory_percent: 85
    disk_percent: 85
    load_per_core: 1.5
  disk_mounts: ["/"]
  services: [ssh]
  node_exporter:
    enabled: false
    url: "http://127.0.0.1:9100/metrics"
  webhook:
    enabled: false
    url: ""
    timeout_seconds: 5

backup:
  dir: /var/lib/ubuntuguard/backups
  compress: true
  retention_days: 30
  retention_count: 20

notifications:
  retry: 2
  retry_interval_seconds: 3
```

校验规则：

- 未知顶层键 → 警告并继续（前向兼容）；已知键类型错误 → 退出码 2。
- `harden.require_confirmation` / `backup_before_change` 为安全不变量，配置为 false 时拒绝启动。
- 缺失项使用内置默认值，`--json` 输出时附 `config_sources` 便于排查。

## 4. 日志规范

| 日志 | 路径 | 内容 |
| ---- | ---- | ---- |
| 运行日志 | `/var/log/ubuntuguard/ubuntuguard.log` | 时间、级别、模块、消息、耗时 |
| 变更审计 | `/var/log/ubuntuguard/changes.log` | 快照 ID、动作、目标文件、before/after 摘要、结果 |
| 安全事件 | `/var/lib/ubuntuguard/events.jsonl` | 登录失败、完整性异常、告警发送结果 |

文本格式：`ts=<ISO8601> level=<lvl> mod=<module> msg="..."`；`--json` 或配置开启时输出 JSON 行。日志按 10MB × 5 轮转。

## 5. 报告 schema（JSON，schema_version 1.0）

```json
{
  "schema_version": "1.0",
  "tool_version": "1.0.0",
  "generated_at": "2026-11-17T10:00:00+08:00",
  "host": {
    "hostname": "",
    "os": "Ubuntu 24.04",
    "kernel": "",
    "uptime_seconds": 0
  },
  "summary": {
    "score": 82,
    "grade": "B",
    "total": 15,
    "by_severity": {"critical": 0, "high": 1, "medium": 4, "low": 10}
  },
  "findings": [
    {
      "id": "SSH-002",
      "title": "Password authentication enabled",
      "severity": "high",
      "category": "ssh",
      "evidence": {"path": "/etc/ssh/sshd_config", "line": 58, "value": "yes"},
      "remediation": "Set PasswordAuthentication no in /etc/ssh/sshd_config.d/00-ubuntuguard.conf",
      "references": ["CIS Ubuntu 24.04 5.2.4"]
    }
  ],
  "checks": {"passed": 40, "failed": 15, "skipped": 3}
}
```

`findings[].id` 规则：`<域>-<三位序号>`，一旦发布不得复用或改义。

## 6. 风险评分

- 满分 100，按严重度扣分：critical 25、high 15、medium 7、low 2，下限 0。
- 等级：A 90–100，B 75–89，C 60–74，D 40–59，E <40。
- 评分是启发式指标，报告必须同时给出证据与扣分明细，避免只给结论。

## 7. Ubuntu 22.04 / 24.04 差异清单

| 组件 | 22.04 | 24.04 | 影响与处理 |
| ---- | ---- | ---- | ---- |
| Python | 3.10 | 3.12 | 代码兼容 ≥3.10；禁用 3.11+ 独有语法 |
| OpenSSH | 8.9p1 | 9.6p1 | `sshd -T` 字段差异；仅写 drop-in，不解析主配置改值 |
| sshd 配置 | 主配置 + `sshd_config.d/*.conf` | 同 | 统一写 `00-ubuntuguard.conf`：sshd 对同一关键字取首个值，按字典序先加载才不会被 50-cloud-init 等文件覆盖 |
| UFW | 0.36.1 | 0.36.2 | `ufw status verbose` 输出解析需容错 |
| Fail2ban | 0.11.2 | 1.0.2 | jail 配置与 backend 取值不同，按版本能力分支 |
| Auditd | 3.0.7 | 3.1.2 | 规则语法一致；重载用 `service auditd restart`，必要时 `auditctl -R` 兜底 |
| AIDE | 0.18 | 0.18.6 | 命令参数一致 |
| systemd | 249 | 255 | timer 语法一致；`systemd-analyze verify` 校验 |
| AppArmor | 3.0.4 | 4.0 | 仅状态检测，不做策略修改 |
| 内核 | 5.15 | 6.8 | sysctl 键名一致 |
| APT 交互 | 低 | 有 needrestart 提示 | 非交互执行统一 `DEBIAN_FRONTEND=noninteractive` |

统一策略：以 `VERSION_ID` 与能力探测为分支依据，禁止用版本号猜测功能。

## 8. 备份与快照布局

```
<backup.dir>/
└── 20261117T100000Z-apply-ssh/
    ├── manifest.json          # schema_version、created_at、tool_version、items[]
    ├── files/etc/ssh/sshd_config.d/00-ubuntuguard.conf
    └── archive.tar.gz         # 开启压缩时生成
```

`manifest.json` 的 `items[]` 含 `source`、`relative_path`、`sha256`、`size`、`mode`、`uid/gid`。校验以 manifest 为准；恢复前默认做差异检查，`--force` 跳过。保留策略：同时满足 `retention_count` 与 `retention_days`，优先保留最近一次成功快照。

## 9. 权限模型

| 操作 | 要求 |
| ---- | ---- |
| collect / audit（只读） | 普通用户可运行，受限文件跳过并标记 skipped |
| harden apply / backup restore / systemd install | 必须 root，否则退出码 3 |
| backup create | 必须 root（涉及 /etc 读取） |

## 10. 打包与部署

- `pyproject.toml` 声明依赖与入口点：`ubuntuguard = ubuntuguard.cli.main:main`。
- 安装路径：程序 `/usr/lib/python3/dist-packages/ubuntuguard`，配置 `/etc/ubuntuguard/`，unit `/lib/systemd/system/`。
- systemd：`ubuntuguard-audit.service`（oneshot）+ `ubuntuguard-audit.timer`（默认每 6 小时）。
- `.deb` 构建使用 debhelper，安装后执行 `systemctl daemon-reload` 并启用 timer，卸载保留配置与快照目录。

## 11. 测试策略

| 层 | 范围 | 方式 |
| ---- | ---- | ---- |
| 单元 | 规则判定、评分、配置校验、执行器 | pytest + 固化样本数据 |
| 集成 | 备份/恢复、drop-in 写入、报告生成 | 临时目录 + 假命令桩 |
| 安全 | 命令注入、路径穿越、权限拒绝、回滚 | 恶意输入用例 + 退出码断言 |
| 系统 | 真实 Ubuntu 22.04 / 24.04 | 快照虚拟机，验证配置生效与恢复 |

安全用例必须覆盖：非 root 拒绝、失败自动回滚、损坏快照拒绝恢复、Webhook 失败重试。

## 12. 外部引擎集成

不自建完整规则库，按需复用成熟项目；集成方式统一为"子进程调用 + 解析输出"，不复制代码、不链接库。

| 对象 | 集成点 | 降级策略 |
| ---- | ---- | ---- |
| Lynis | `--engine lynis`，执行 `lynis audit system --quiet --report-file`，解析 `/var/log/lynis-report.dat` 的 `warning` / `suggestion` 行，映射为 Finding | 未安装则提示"跳过 lynis 后端"，退出码仍为 0（审计本身成功），报告标注 skipped |
| OpenSCAP / USG | 不运行时集成；仅在规则文档中引用 CIS 编号与条目 | - |
| node_exporter | 若 `:9100/metrics` 可访问则读取 cpu/mem/disk/load，否则回退 `/proc` 与 `ps` | 两种来源在报告中标注 `metrics_source` |
| Auditd / AIDE / UFW / Fail2ban | 作为整改与检测的执行组件，调用其原生命令 | 缺失依赖返回退出码 8 |

**自有规则范围**：40 条，覆盖 SSH（16）、账号/权限/sudo/密码策略（14）、防火墙（2）、端口暴露（1）、sysctl（7）。每条规则必须带参考资料、证据字段与修复建议；不追求数量对标 Lynis。

## 13. CI 与质量门禁

GitHub Actions 矩阵：`ubuntu-22.04` / `ubuntu-24.04`。

| 检查 | 工具 | 门禁 |
| ---- | ---- | ---- |
| 代码风格 | ruff | 阻断 |
| 类型检查 | mypy | 阻断 |
| 单元 + 集成 + 安全测试 | pytest + coverage | 覆盖率 ≥ 80% |
| 打包 | `dpkg-buildpackage` | 构建成功 |
| 安装冒烟 | 容器内安装 .deb 后执行 `ubuntuguard --version` 与 `audit` | 退出码符合预期 |

## 14. 对照评测（求职展示）

Phase 9 在相同干净虚拟机上分别运行 Lynis 与 UbuntuGuard：

- 记录检出项数量、双方交集与差异项，人工判定误报。
- 记录加固前后复查结果（配置是否真正生效）。
- 结论写入 TEST_REPORT.md 与 README 的"与 Lynis 对比"章节，作为差异化证据。

## 15. 明确不做

- 不做 IDS / 行为检测（CrowdSec、Fail2ban 已覆盖）。
- 不做监控存储与可视化（Prometheus、Netdata 已覆盖）。
- 不做中央管控与多主机编排，仅提供 `export ansible` 可选产出。
- 不复制 GPL 项目代码，不做 Lynis 的功能等价替代。

## 16. Web 控制台

启动：`ubuntuguard web --host 127.0.0.1 --port 8080`。仅使用标准库 `http.server`，不引入 Flask/FastAPI；页面为单个自包含 HTML，无外部 CDN。

### 16.1 视图

总览（评分、风险分布、CPU/内存/磁盘/负载）、基线审计（筛选、搜索、展开证据）、安全加固（动作选择、计划 diff、`APPLY` 确认）、异常检测、健康监控、备份恢复（verify/drill）、报告（生成并内嵌预览）。

### 16.2 API

| 方法 | 路径 | 说明 |
| ---- | ---- | ---- |
| GET | `/api/status` | doctor 输出 + hostname / kernel / OS |
| GET | `/api/audit` | 审计 JSON |
| GET | `/api/detect` | 检测 JSON |
| GET | `/api/monitor` | 健康检查 JSON（不发送 Webhook） |
| GET | `/api/backups` | 快照列表 |
| POST | `/api/harden/plan` | `{only:[...]}`，返回计划与 unified diff |
| POST | `/api/harden/apply` | 需 `confirm:"APPLY"`，走 CLI 的快照/校验/回滚 |
| POST | `/api/backup/create` | 创建快照 |
| POST | `/api/backup/verify\|drill` | 校验/演练 |
| POST | `/api/detect/baseline` | 初始化 SHA256 文件基线 |
| POST | `/api/report` | 生成 HTML 报告 |
| GET | `/report/latest.html` | 最近一次报告 |

### 16.3 安全模型

- 默认绑定 `127.0.0.1`；绑定非回环地址时启动打印警告。控制台无登录认证，不得暴露公网。
- POST 必须携带页面注入的随机 `X-UG-Token`，防跨站请求；token 使用 `secrets.token_urlsafe`，比较使用 `hmac.compare_digest`。
- 动作白名单固定为 `ssh`、`sysctl`、`firewall`、`fail2ban`；不执行用户传入的任意命令。
- 子进程统一 `argv` 列表 + `shell=False` + 超时；申请加固仍需 `APPLY` 文本确认。
- HTML 响应附加 CSP、`X-Content-Type-Options`、`Referrer-Policy`，并禁用缓存。
- 报告仅从固定的 state 路径读取，不接受任意文件路径。

### 16.4 主题与语言

- 黑白主题通过 CSS 变量实现，`data-theme` 切换，`localStorage` 持久化。
- 中英文通过页面内字典 + DOM 文本遍历实现，`data-lang` 切换，`localStorage` 持久化；技术数据（finding 标题、证据、命令）保持原文。
- 两套开关都不改变后端行为，仅影响渲染层。

### 16.5 测试

`tests/unit/test_web.py` 覆盖路由、token、`APPLY` 确认、动作过滤、diff 生成、快照 ID 校验、CSP 与主题/语言控件存在性；完整套件 174 项。

