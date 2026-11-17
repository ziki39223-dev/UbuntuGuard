# UbuntuGuard

[![CI](https://github.com/ziki39223-dev/UbuntuGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/ziki39223-dev/UbuntuGuard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ziki39223-dev/UbuntuGuard)](https://github.com/ziki39223-dev/UbuntuGuard/releases/tag/v1.0.0)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

面向 Ubuntu 22.04 / 24.04 的自动化安全运维与主机健康保障 CLI 工具。

当前版本：**v1.0.0**。收集 → 审计 → 加固 → 检测 → 监控 → 备份 → 报告全链路可用；40 条规则对齐 CIS，加固支持快照、生效校验与回滚。

## 设计边界

UbuntuGuard 不重写审计引擎、监控栈与 IDS：

- 审计以自有 40 条高价值规则为主，可选接入 Lynis 作为后端。
- 加固交给 UFW / Fail2ban / Auditd / AIDE / sysctl，本项目负责编排、预览、备份、校验与回滚。
- 监控只做阈值判定与告警，指标源可选 node_exporter，默认读 `/proc`。

调研与对比见 [docs/ECOSYSTEM_AND_POSITIONING.md](docs/ECOSYSTEM_AND_POSITIONING.md)。

## 安装

```bash
# 源码
python3 -m pip install -e ".[dev]"

# deb（Ubuntu 24.04，从 Release 下载）
sudo apt install ./ubuntuguard_1.0.0-1_all.deb
```

要求 Python ≥ 3.10，运行期仅依赖 PyYAML；HTML 报告使用内置渲染器，无需模板引擎。

## 测试环境（本机 WSL2）

已导入两个独立发行版用于双版本验证：

```powershell
wsl -d UbuntuGuard-22.04 -- bash -lc "cd /root/UbuntuGuard && /root/venv/bin/python -m pytest -q"
wsl -d UbuntuGuard-24.04 -- bash -lc "cd /root/UbuntuGuard && /root/venv/bin/python -m pytest -q"
```

- `UbuntuGuard-22.04`：Ubuntu 22.04.5，Python 3.10.12
- `UbuntuGuard-24.04`：Ubuntu 24.04.4，Python 3.12.3
- 两个环境均已启用 systemd，并安装 openssh-server / ufw / fail2ban / auditd / aide
- 项目副本：`/root/UbuntuGuard`；虚拟环境：`/root/venv`

## 使用

```bash
ubuntuguard version
ubuntuguard doctor                        # 平台 / 权限 / 依赖检查
ubuntuguard collect                       # 采集主机信息（表格）
ubuntuguard collect --output json         # 采集主机信息（JSON）
ubuntuguard audit                         # 安全基线审计（40 条规则）
ubuntuguard audit --fail-on high          # findings 达到 high 时退出码 4
ubuntuguard audit --engine all            # 自有规则 + Lynis 后端
ubuntuguard --json audit                  # 机器可读审计报告
ubuntuguard harden plan                   # 预览加固变更（默认只读）
ubuntuguard harden plan --only ssh,sysctl # 只预览指定动作
ubuntuguard --yes harden apply --apply    # 实际执行（需 root，先预览）
ubuntuguard detect                        # 登录异常 / 完整性 / 可疑进程
ubuntuguard detect --init-baseline        # 初始化关键文件哈希基线
ubuntuguard --json detect                 # 机器可读检测报告
ubuntuguard monitor check                 # CPU / 内存 / 磁盘 / 负载 / 服务
ubuntuguard monitor check --no-notify     # 不发送 Webhook
ubuntuguard backup list                   # 列出备份快照
ubuntuguard backup create                 # 备份关键配置（需 root）
ubuntuguard backup verify <snapshot-id>   # 校验 SHA256
ubuntuguard backup drill <snapshot-id>    # 恢复到临时目录做演练
ubuntuguard backup restore <snapshot-id>  # 预览差异，--force 执行（需 root）
ubuntuguard report --format html --out report.html   # 合并报告
ubuntuguard export ansible --out harden.yml          # 导出 Ansible playbook
ubuntuguard systemd install               # 安装并启用定时器（需 root）
ubuntuguard systemd uninstall             # 停止并移除定时器（需 root）
ubuntuguard config validate               # 使用默认配置时仅提示，不报错
ubuntuguard --config configs/config.example.yaml config show
ubuntuguard --json doctor                 # 机器可读输出
```

全局参数需写在子命令之前：`--config`、`--log-level`、`--json`。

审计提示：`audit` 以普通用户运行时会跳过 `/etc/shadow`、`/etc/sudoers` 等需 root 的检查，并在报告中列出 `skipped` 原因；若没有任何检查可执行，输出 `score: n/a` 并以退出码 9 结束，避免误判为满分。

加固提示：`harden plan` 只输出 diff 与命令清单；`harden apply` 必须同时给出 `--apply --yes` 且需要 root。执行前会写入快照（`<state_dir>/snapshots`，含 manifest 与 SHA256），任一步校验失败会自动恢复文件并回滚运行时，退出码 6 表示已回滚、7 表示回滚失败。由 apt 安装的软件包不会自动卸载（见 DECISIONS D-014）。

## 配置

默认路径 `/etc/ubuntuguard/config.yaml`，可用 `--config` 或环境变量 `UBUNTUGUARD_CONFIG` 覆盖；文件缺失时使用内置默认值。

示例见 [configs/config.example.yaml](configs/config.example.yaml)，完整 schema 见 [docs/TECHNICAL_DESIGN.md](docs/TECHNICAL_DESIGN.md)。

安全不变量：`harden.require_confirmation` 与 `harden.backup_before_change` 必须为 `true`，配置为 `false` 会直接拒绝启动。

## 开发

```bash
make test        # pytest
make lint        # ruff
make typecheck   # mypy
```

## 打包

```bash
pip install build && python -m build --wheel
sudo apt-get install -y debhelper devscripts dh-python pybuild-plugin-pyproject
chmod +x debian/rules debian/postinst debian/prerm debian/postrm
chmod -x debian/install systemd/*
dpkg-buildpackage -us -uc -b
```

`debian/control` 使用 PEP 621 元数据，构建 deb 需要 setuptools ≥ 68（Ubuntu 24.04）；Ubuntu 22.04 上用 `pip install -e .` 或 wheel 安装，或使用 24.04 构建出的 `all` 架构包。

生成的 `.deb` 安装后写入 `/lib/systemd/system` 并启用 `ubuntuguard-audit.timer` 与 `ubuntuguard-monitor.timer`；`purge` 会清理 `/etc/ubuntuguard`、`/var/lib/ubuntuguard` 与 `/var/log/ubuntuguard`。CI 在 Ubuntu 22.04 / 24.04 上执行 ruff、mypy、pytest 与 wheel 构建；deb 构建与安装冒烟在 24.04 执行。

## 文档

| 文档 | 内容 |
| ---- | ---- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | 分层架构、核心抽象、安全边界 |
| [docs/TECHNICAL_DESIGN.md](docs/TECHNICAL_DESIGN.md) | CLI / 配置 / 报告规范、兼容性、CI |
| [docs/ECOSYSTEM_AND_POSITIONING.md](docs/ECOSYSTEM_AND_POSITIONING.md) | 生态调研与差异化定位 |
| [docs/CIS_MAPPING.md](docs/CIS_MAPPING.md) | 40 条规则与 CIS 控制编号对照 |
| [ROADMAP.md](ROADMAP.md) | 阶段任务清单 |
| [PROJECT_STATUS.md](PROJECT_STATUS.md) | 当前进度 |
| [RISK_REGISTER.md](RISK_REGISTER.md) | 风险与应对 |
| [DECISIONS.md](DECISIONS.md) | 技术决策记录 |

## 退出码

`0` 成功；`2` 参数/配置错误；`3` 权限不足；`4` 审计超阈值；`8` 依赖缺失；`9` 平台不支持。完整定义见技术设计文档。
