# 可信安装

README 推荐命令包含三个可独立审查的阶段，不会因为代码和 checksum 来自同一个 TLS 来源就直接
执行代码。

1. README 把 `bootstrap-install.sh` 固定到提交
   `3fa12244dfb70e0588ccf0e645bf5c75b6148b01`，并在交给 `sh` 前验证 SHA-256
   `22df4c865d01f51b64066c8e53beaa9bb3cb3c29ef431c6b8a3aa56074dab65c`。
2. bootstrap 把 `install-verified.mjs` 固定到提交
   `b3e77a87cc5ee16195c0965012217416ee3a935d`，并在交给 Node 前验证 SHA-256
   `4e3c6ce6c8c3ec0cfa7972edbc85b93885bae64cb714a87c926e81fc49410422`。
3. verifier 只从内置信任表选择显式版本；要求 archive、release manifest、SPDX SBOM 和
   `SHA256SUMS` 各自匹配固定 SHA-256，并交叉检查仓库、产品、tag、源码提交、版本、资产集合、
   归档根目录和路径，最后才调用现有原子 lifecycle installer。

`--attestation auto` 会在 GitHub CLI 已安装且登录时额外运行 `gh attestation verify`，未运行时会
明确输出原因。需要缺少认证验证就停止安装时，使用 `--attestation required`。SHA-256、manifest、
SBOM 和归档验证始终执行，不能关闭。

## 显式版本和安装入口

使用 README 命令下载并验证 bootstrap 后，可把它保留在已知路径：

```bash
sh ./bootstrap-install.sh --version 0.7.0 --target codex
sh ./bootstrap-install.sh --version 0.7.0 --target claude
sh ./bootstrap-install.sh --version 0.7.0 --target cli
```

内置信任表中不存在的版本会被拒绝。安装器不会解析 `latest`、移动分支或移动 major tag。

## 离线或完全人工路径

在联网机器下载以下文件，保持文件名不变并转移到离线机器：

```text
SHA256SUMS
web-app-security-skill-0.7.0.release.json
web-app-security-skill-0.7.0.spdx.json
web-app-security-skill-0.7.0.tar.gz
```

另从提交 `b3e77a87cc5ee16195c0965012217416ee3a935d` 下载
`scripts/install-verified.mjs`，用上方固定值验证其 SHA-256。然后在离线机器运行：

```bash
node ./install-verified.mjs --version 0.7.0 --from-dir ./release-assets --attestation skip
```

离线路径不会发出 HTTP 请求。`--attestation skip` 只记录有意跳过可选 GitHub attestation，
不会跳过资产、manifest、SBOM 或归档检查。

## 升级、强制替换和卸载

```bash
sh ./bootstrap-install.sh --version 0.7.0 --mode upgrade
sh ./bootstrap-install.sh --version 0.7.0 --force
webapp-security uninstall
```

`upgrade` 要求存在可识别安装。`--force` 只适用于安装，并在替换可识别路径前保留备份。未知目录
或 launcher 会在任何选定入口改变之前被拒绝，避免部分安装。

## 验证能证明什么

该信任链证明字节与仓库记录的固定信任锚及 release 身份一致。attestation 验证实际执行时，还能
证明 GitHub Actions provenance 声明。它不能证明每个安全结论或实现选择一定正确；该判断仍需检查
源码提交、签名 tag、release evidence 和威胁模型。
