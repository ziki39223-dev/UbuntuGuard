# 包签名与 APT 仓库

UbuntuGuard 采用 **APT 仓库元数据签名**：用 GPG 对 `dists/<codename>/Release` 生成 `InRelease` 与 `Release.gpg`，`.deb` 的完整性由 `Release` 中的 SHA256 记录保证。这是 Debian/Ubuntu 的标准做法；`dpkg-sig` 逐包签名已废弃，本项目不使用。

## 签名密钥

| 项目 | 值 |
| ---- | ---- |
| UID | `UbuntuGuard Release Signing <release@ubuntuguard.local>` |
| 指纹 | `8BF8FCCAED0FBB4143551C962ED6CE4E611E22A9` |
| 算法 | RSA 4096，用途仅签名（`Key-Usage: sign`） |
| 有效期 | 5 年（至 2031-11-16） |
| 公钥（入库） | `packaging/apt/ubuntuguard-archive-keyring.gpg` / `.asc` |
| 私钥（不入库） | WSL `UbuntuGuard-24.04` 的 `/root/ubuntuguard-signing-secret.asc`（0600） |

私钥仅保存在验证环境与本机备份中，`.gitignore` 不覆盖 `dist/`，因此发布流程只提交公钥与仓库产物。切勿把 `ubuntuguard-signing-secret.asc` 推送到任何仓库；如需 CI 自动发布，使用 `GPG_PRIVATE_KEY` 仓库 Secret 导入临时 keyring。

## 构建签名仓库

依赖：`dpkg-dev`（`dpkg-scanpackages`）、`apt-utils`（`apt-ftparchive`）、`gnupg`。

```bash
# 从 dist/ 下的 .deb 构建，输出到 dist/apt-repo（默认生成 noble）
GPG_KEY_ID=8BF8FCCAED0FBB4143551C962ED6CE4E611E22A9 \
  scripts/build-apt-repo.sh --pool dist --out dist/apt-repo
```

产物结构：

```text
apt-repo/
├── dists/noble/{InRelease,Release,Release.gpg}
├── dists/noble/main/binary-amd64/{Packages,Packages.gz}
├── pool/main/u/ubuntuguard/ubuntuguard_1.1.0-1_all.deb
└── ubuntuguard-archive-keyring.{gpg,asc}
```

> 仓库只提供 noble 包：noble 构建的 deb 会安装到 `/usr/lib/python3.12/dist-packages`，Ubuntu 22.04 的 Python 3.10 无法导入，因此 22.04 请使用源码/venv 安装。

脚本参数：`--pool DIR` 指定 .deb 目录，`--out DIR` 指定仓库根，`--codename NAME` 可重复指定发行版代号（默认 `noble`）。退出码沿用项目约定：缺工具返回 8，无 .deb 或参数错误返回 1/2。

## 发布到 GitHub Pages

仓库已发布到 `gh-pages` 分支，Pages 源为 `gh-pages` 根目录，访问地址 `https://ziki39223-dev.github.io/UbuntuGuard/`。

```bash
# 重建并更新 gh-pages（在临时目录构造提交，避免污染主分支）
GPG_KEY_ID=<指纹> scripts/build-apt-repo.sh --pool dist --out dist/apt-repo
git worktree add --detach /tmp/uguard-ghp          # 或使用独立 clone
cp -r dist/apt-repo/. /tmp/uguard-ghp/
touch /tmp/uguard-ghp/.nojekyll
cd /tmp/uguard-ghp && git checkout --orphan gh-pages && git add -A \
  && git commit -m "chore: publish signed APT repository" \
  && git push origin gh-pages
```

`.nojekyll` 必须存在，否则 Jekyll 会改变部分路径行为。

## 用户安装

```bash
# 1. 导入公钥
sudo curl -fsSL https://ziki39223-dev.github.io/UbuntuGuard/ubuntuguard-archive-keyring.gpg \
  -o /usr/share/keyrings/ubuntuguard-archive-keyring.gpg

# 2. 添加源（deb822，Ubuntu 24.04）
sudo cp packaging/apt/ubuntuguard.sources /etc/apt/sources.list.d/ubuntuguard.sources

# 3. 安装
sudo apt update && sudo apt install ubuntuguard
```

单行 sources 写法（仅 noble；22.04 使用源码/venv）：

```text
deb [signed-by=/usr/share/keyrings/ubuntuguard-archive-keyring.gpg] \
  https://ziki39223-dev.github.io/UbuntuGuard noble main
```

## 签名验证

```bash
# 本地校验 Release 与分离签名
gpg --verify dist/apt-repo/dists/noble/Release.gpg dist/apt-repo/dists/noble/Release

# apt 视角：InRelease 通过后才会读取 Packages
sudo apt update   # 出现 Get:… InRelease 且无 NO_PUBKEY/Hash Sum mismatch
```

Phase 9 已在 WSL 24.04 完成端到端验证：`file:` 源导入公钥后 `apt update` 正常，`apt install ubuntuguard` 安装成功；手动篡改 `Packages` 后 `apt update` 立即报哈希不匹配。

## 密钥轮换与撤销

1. 生成新密钥并导出公钥，替换 `packaging/apt/ubuntuguard-archive-keyring.{gpg,asc}`。
2. 用新密钥重新执行 `scripts/build-apt-repo.sh` 并发布 `gh-pages`。
3. 在 Release 说明与 README 中公告新指纹；旧密钥可保留在 keyring 中一段时间以便平滑升级。
4. 私钥泄露时立即使用 `/root/.gnupg/openpgp-revocs.d/` 下的撤销证书发布撤销，并重新轮换（见 R-019）。

## 未采用方案

- **Launchpad PPA**：需要 Launchpad 账号、注册 GPG 公钥并 `dput` 上传源码包；本项目改用自建签名仓库，源码包仍可通过 `dpkg-buildpackage -S -sa -k<指纹>` 生成 `.dsc`/`.changes` 供后续 PPA 使用。
- **逐包 `dpkg-sig`**：已废弃，APT 不再依赖该签名；仓库元数据签名覆盖面更完整。
