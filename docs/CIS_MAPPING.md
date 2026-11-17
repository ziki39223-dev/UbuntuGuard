# CIS 控制映射

本项目 40 条基线规则与 CIS Ubuntu Linux Benchmark 的对应关系。

## 依据与版本

- CIS 官方基准页：https://www.cisecurity.org/benchmark/ubuntu_linux
  - 当前最新：Ubuntu Linux 24.04 LTS (2.0.0)、22.04 LTS (3.0.0)
- 控制编号取自公开的 ComplianceAsCode 控制文件（可审计、可复现）：
  - `controls/cis_ubuntu2404.yml`，CIS Ubuntu 24.04 LTS v1.0.0
  - `controls/cis_ubuntu2204.yml`，CIS Ubuntu 22.04 LTS v2.0.0
- 说明：CIS 官方 PDF 需在 CIS WorkBench 注册后下载，本项目未分发基准原文。若需对齐最新 2.0.0 / 3.0.0 编号，请以官方 PDF 复核下表。

规则运行时由 `security/baseline/cis_map.py` 自动附加对应编号，报告中的 `references` 即来源于此。

## SSH 服务（5.1）

| 规则 | 主题 | 24.04 | 22.04 |
| ---- | ---- | ---- | ---- |
| SSH-001 | PermitRootLogin | 5.1.20 | 5.1.20 |
| SSH-002 | PasswordAuthentication | 5.1.4（无独立控制，归入访问控制） | 5.1.4 |
| SSH-003 | PermitEmptyPasswords | 5.1.19 | 5.1.19 |
| SSH-004 | X11Forwarding | 5.1.8（DisableForwarding） | 5.1.8 |
| SSH-005 | MaxAuthTries | 5.1.16 | 5.1.16 |
| SSH-006 | IgnoreRhosts | 5.1.11 | 5.1.11 |
| SSH-007 | HostbasedAuthentication | 5.1.10 | 5.1.10 |
| SSH-008 | PermitUserEnvironment | 5.1.21 | 5.1.21 |
| SSH-009 | StrictModes | 5.1（无独立控制） | 5.1 |
| SSH-010 | LoginGraceTime | 5.1.13 | 5.1.13 |
| SSH-011 | ClientAliveInterval | 5.1.7 | 5.1.7 |
| SSH-012 | AllowUsers/AllowGroups | 5.1.4 | 5.1.4 |
| SSH-013 | Banner | 5.1.5 | 5.1.5 |
| SSH-014 | Ciphers | 5.1.6 | 5.1.6 |
| SSH-015 | MACs | 5.1.15 | 5.1.15 |
| SSH-016 | KexAlgorithms | 5.1.12 | 5.1.12 |

## 账号、sudo 与密码策略

| 规则 | 主题 | 24.04 | 22.04 |
| ---- | ---- | ---- | ---- |
| ACC-001 | 仅 root 为 UID 0 | 5.4.2.1 | 5.4.2.1 |
| ACC-002 | 重复 UID | 5.4.2.1（最接近） | 5.4.2.1 |
| ACC-003 | 系统账号登录 shell | 5.4.2.7 | 5.4.2.7 |
| ACC-004 | root 组成员 | 5.4.2.3 | 5.4.2.3 |
| ACC-005 | 空密码 | 5.3.3.4.1, 5.4.2.8 | 5.3.3.4.1, 5.4.2.8 |
| SUDO-001 | NOPASSWD | 5.2.4 | 5.2.4 |
| SUDO-002 | sudoers 权限 | 5.2（无独立控制） | 5.2 |
| LOGIN-001 | PASS_MAX_DAYS | 5.4.1.1 | 5.4.1.1 |
| LOGIN-002 | PASS_MIN_DAYS | 5.4.1.2 | 5.4.1.2 |
| LOGIN-003 | PASS_WARN_AGE | 5.4.1.3 | 5.4.1.3 |
| LOGIN-004 | UMASK 027 | 5.4.3.3 | 5.4.3.3 |

## 文件权限（7.1）

| 规则 | 主题 | 24.04 | 22.04 |
| ---- | ---- | ---- | ---- |
| PERM-001 | /etc/passwd | 7.1.1 | 7.1.1 |
| PERM-002 | /etc/group | 7.1.3 | 7.1.3 |
| PERM-003 | /etc/shadow | 7.1.5 | 7.1.5 |

## 防火墙与服务暴露

| 规则 | 主题 | 24.04 | 22.04 |
| ---- | ---- | ---- | ---- |
| FW-001 | UFW 已启用 | 4.2.3 | 4.1.3 |
| FW-002 | 默认拒绝入站 | 4.2.7 | 4.1.7 |
| PORT-001 | 危险服务未对全网开放 | 2.1.6, 2.1.12, 2.1.14, 2.1.16 | 同左 |

PORT-001 覆盖 FTP/Telnet/TFTP/rpcbind/SMB/RDP/VNC/Redis/MongoDB 等；CIS 对每种服务有独立控制，此处列出最直接的四项。

## 内核参数

| 规则 | 主题 | 24.04 | 22.04 |
| ---- | ---- | ---- | ---- |
| SYS-001 | ASLR | 1.5.1 | 1.5.1 |
| SYS-002 | SYN cookies | 3.3.10 | 3.3.10 |
| SYS-003 | rp_filter | 3.3.7 | 3.3.7 |
| SYS-004 | ICMP 重定向 | 3.3.2, 3.3.5 | 3.3.2, 3.3.5 |
| SYS-005 | 源路由/异常包/广播 ICMP | 3.3.4, 3.3.8, 3.3.9 | 3.3.4, 3.3.8, 3.3.9 |
| SYS-006 | dmesg/kptr 限制 | 1.5（这两个基准版本无独立控制） | 1.5 |
| SYS-007 | 链接保护 | 1.5（同上） | 1.5 |

## 审计、完整性与检测

| 规则 | 主题 | 24.04 | 22.04 |
| ---- | ---- | ---- | ---- |
| AUD-001 | auditd 已安装 | 6.2.1.1 | 6.3.1.1 |
| AUD-002 | auditd 已启用 | 6.2.1.2 | 6.3.1.2 |
| AUD-003 | 敏感路径审计 | 6.2.3.1 | 6.3.3.1 |
| AID-001 | AIDE 已安装 | 6.3.1 | 6.1.1 |
| AID-002 | 完整性定期检查 | 6.3.2 | 6.1.2 |
| LOG-001 | 登录失败聚合 | 6.2 | 6.3 |
| LOG-002 | root 密码登录 | 5.1.20 | 5.1.20 |
| LOG-003 | 用户枚举 | 5.1.4 | 5.1.4 |
| PROC-001 | 可疑进程 | 6.2 | 6.3 |
| FILE-001/002 | 关键文件变更 | 6.3.2 | 6.1.2 |

## 未覆盖项

以下 CIS 控制不在本项目 40 条规则内，可交由 Lynis 后端或后续版本覆盖：内核模块黑名单（1.1.x）、分区与挂载选项（1.1.x）、PAM 细粒度策略（5.3.3.x）、日志服务配置（6.1.x）、审计规则全量覆盖（6.2.3.x）、服务最小化（2.1.x 全量）。
