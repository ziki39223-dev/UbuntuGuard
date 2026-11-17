# Launchpad PPA 发布

仓库已能生成可直接上传的**签名的源码包**，但 `dput` 上传仍需要你的 Launchpad 账号与已注册的 GPG 公钥；这一步无法由第三方代为完成。

## 1. 前置条件

1. 注册 Launchpad 账号：https://launchpad.net/
2. 在该账号的 "OpenPGP keys" 页面导入并验证你的 GPG 公钥（Launchpad 会发加密邮件，需用对应私钥解密确认）。
3. 本地安装 `dput`：`sudo apt install dput`。
4. 确认 `gpg --list-secret-keys <指纹>` 能看到签名私钥。

本项目签名密钥：`UbuntuGuard Release Signing <release@ubuntuguard.local>`，指纹 `8BF8FCCAED0FBB4143551C962ED6CE4E611E22A9`。若使用自己的密钥，替换下方命令中的指纹即可。

## 2. 创建 PPA

在 Launchpad 个人页面选择 "Create a new PPA"，记下 `ppa:<launchpad-id>/<ppa-name>`。

## 3. 构建签名源码包

在仓库根目录执行：

```bash
GPG_KEY_ID=8BF8FCCAED0FBB4143551C962ED6CE4E611E22A9 \
  scripts/build-ppa-source.sh --distro noble --out dist/ppa
```

脚本会：

1. 导出当前 git HEAD 到临时目录（不包含 `.git`、`dist`、缓存）；
2. 将 `debian/changelog` 首行发行版改为目标系列（Launchpad 要求与目标系列一致）；
3. 生成 `ubuntuguard_<版本>.orig.tar.gz`；
4. 执行 `dpkg-buildpackage -S -sa -k<指纹>`，签名 `.dsc` 与 `_source.changes`。

产物（`dist/ppa/`）：

```text
ubuntuguard_1.0.2.orig.tar.gz
ubuntuguard_1.0.2-1.debian.tar.xz
ubuntuguard_1.0.2-1.dsc
ubuntuguard_1.0.2-1_source.changes
```

验证：

```bash
gpg --verify dist/ppa/ubuntuguard_1.0.2-1_source.changes
grep '^Distribution:' dist/ppa/ubuntuguard_1.0.2-1_source.changes   # noble
```

## 4. 上传

```bash
dput ppa:<launchpad-id>/<ppa-name> dist/ppa/ubuntuguard_1.0.2-1_source.changes
```

上传后 Launchpad 会回信并在 PPA 页面构建；构建失败可查看 "Build status" 日志，通常是缺少 `Build-Depends` 或 changelog 格式问题。

## 5. 用户安装

```bash
sudo add-apt-repository ppa:<launchpad-id>/<ppa-name>
sudo apt update && sudo apt install ubuntuguard
```

## 6. 与自建仓库的关系

- **自建签名仓库**（GitHub Pages，`noble`）：已可用，适合立即安装，无账号依赖。
- **Launchpad PPA**：面向 Ubuntu 用户的标准分发渠道，需要账号与公钥验证；本项目只提供签名源码包与流程，上传动作由你完成。

## 7. 注意

- 版本号必须递增；重复上传同一版本会被 Launchpad 拒绝。
- 目标系列（noble/jammy）必须与 `debian/changelog` 首行一致。
- 22.04 目前不提供包（noble 构建的 deb 依赖 `python3.12` 路径），如需 jammy 包应在 22.04 构建环境中执行同样的 `dpkg-buildpackage -b`。
