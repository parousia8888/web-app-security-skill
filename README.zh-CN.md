<h1 align="center">Web App Security Skill</h1>
<h3 align="center">用 AI coding agent 和可复现证据完成 Web 项目范围确认、检查、加固与复测</h3>

<p align="center">
  <a href="https://github.com/parousia8888/web-app-security-skill/tags"><img src="https://img.shields.io/github/v/tag/parousia8888/web-app-security-skill?sort=semver" alt="latest tag"></a>
  <a href="https://github.com/parousia8888/web-app-security-skill/actions/workflows/ci.yml"><img src="https://github.com/parousia8888/web-app-security-skill/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/parousia8888/web-app-security-skill/actions/workflows/codeql.yml"><img src="https://github.com/parousia8888/web-app-security-skill/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://www.npmjs.com/package/web-app-security-skill"><img src="https://img.shields.io/npm/v/web-app-security-skill" alt="npm version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT license"></a>
  <a href="#信任与-release-证据"><img src="https://img.shields.io/badge/SBOM-SPDX%202.3-5965d8" alt="SPDX 2.3 SBOM"></a>
</p>

<p align="center">
  <a href="#查看结果">Demo</a> ·
  <a href="#v080-新增内容">v0.8.0</a> ·
  <a href="#安装">安装</a> ·
  <a href="#执行第一个项目">首个项目</a> ·
  <a href="docs/tutorial.zh-CN.md">完整教程</a> ·
  <a href="#github-action">GitHub Action</a> ·
  <a href="#5-个普通项目旅程">项目旅程</a> ·
  <a href="README.md">English</a>
</p>

<p align="center">
  面向使用 AI coding agent 的 Web 产品作者与开发者，不要求具备攻防背景。先查看下方本地结果，
  在你有权检查的项目根目录先执行一次本地源码检查。
</p>

> 把 Web 项目交给 AI coding agent，完成范围确认、风险检查、最小加固、复测和证据交付。

```bash
npx --yes web-app-security-skill audit . --fail-on never
```

`--fail-on never` 让第一次报告完整生成，不会把 suspected 线索直接当成 CI 失败。该命令只读取本地
项目文件，不访问部署实例，也不修改代码。每条可处理结果都会告诉你：

- 行业术语、白话解释，以及问题成立时可能造成的实际后果；
- 当前证据证明了什么，还有什么需要人工或运行时确认；
- 可审查的修改建议、可能影响的正常功能、回滚条件，以及分开的安全复测和功能复测。

对受支持的 JavaScript/TypeScript 框架，同一条命令还会生成 `route-security.json`、
`route-security.md` 和 SHA-256 校验文件。它会分开列出 HTTP 路由与 Next.js Server Action，
全局控制只列一次，并给出人工审查顺序：

| 安全术语 | 白话意思 | 路由视图能说明什么 |
|---|---|---|
| Application control（应用级控制） | 整个应用注册了什么控制？ | 全局 guard 或 middleware 只列一次；不能据此证明每条路由都受保护。 |
| Authentication（authn，身份认证） | 发请求的人是谁？ | 看到了受支持的登录/session 来源、没看到，或当前无法解析。 |
| Route-level authorization（路由级授权） | 这个身份能不能调用这个操作？ | 看到了受支持的 policy/guard，或只看到仍需人工确认的路由控制。 |
| Object-level authorization（BOLA/IDOR，对象级授权） | 这个身份能不能访问这一条具体记录？ | 可把用户传入的 ID 经最多四条精确项目内调用边跟到 Prisma/Drizzle 操作，并把 query 约束、加载后比较、未看到受支持约束和不完整路径分开。 |

`review_first`、`review_next`、`review_later` 是工作排序，不是漏洞严重性。源码里没看到控制，
也不会被自动写成 confirmed 漏洞。

白话说，访问控制链现在能表达：“这条接口接收项目 ID，通过 Auth.js 取得当前用户，把两个值经过
两个能精确定位的本地函数送进 Prisma 查询，但可见过滤条件里没有当前用户。”它也能把查询里的
owner/tenant 条件和加载记录后的明确比较分开。它不能证明运行时一定走到这里、比较一定控制了拒绝
分支、部署策略一定正确。Supabase 结果始终保留“还需检查外部 RLS 策略”。

路由清单覆盖率和访问路径覆盖率是两套独立计数。`completed` 只表示这套静态模型走完一条受支持
路径，不代表路由安全，也不代表已确认漏洞。route-security v1/v2 baseline 与 v3 不可比较；要先
生成新的 v3 baseline，才能解释后续路由 regression。

Express 的 stable 清单支持直接 ESM/CommonJS `express()` 与 `Router()` receiver、
`require('express').Router()`、inline route、精确静态 mount 和精确本地 CommonJS router mount。
如果发现导入的本地路由注册函数但还不能解析，报告会写出
`express_registration_function_unresolved` 并把覆盖率设为 partial。此时退出码 `3` 表示证据不完整，
工具拒绝给出“路由检查干净”的结论，不是发现了 3 个漏洞；如果 finding policy 同时触发，退出码
`1` 仍可优先。

需要目前维护范围内最广的一次本地检查时，使用不下载工具的 deep profile。它运行内置规则，并
调用用户已经安装的固定版本 Checkov、Gitleaks、Opengrep 与 OSV-Scanner；缺少的工具会记录为
带安装指引的 `unknown`：

```bash
npx --yes web-app-security-skill audit . --profile deep --fail-on never
```

<p align="center">
  <a href="docs/demo-evidence.md"><img src="docs/assets/demo.gif" alt="自有本地源码 fixture：发现一条 suspected HIGH 命令注入线索，用专业术语和白话解释，提出取消 shell 解析的修改，再分别复测安全条件和正常产品行为"></a>
</p>

<p align="center"><a href="docs/demo-evidence.md">查看该演示对应的生成报告与补丁证据。</a></p>

## 查看结果

命令会检查一个故意留下不安全写法的本地源码文件，展示解释和修改提案，再分别执行安全复测与正常
功能测试。全程不访问外网，也不安装项目依赖。

| 输入 | Finding | 证据 | 可审查变更 | 复测 |
|---|---|---|---|---|
| `src/export-report.mjs` | OS command injection lead (CWE-78)，HIGH | `suspected`；未证明输入流和可达性 | 用 `execFile` 和分离参数取消 shell 解析；命令 quoting 与跨平台行为可能改变 | security `fixed`；functional `passed` |

```bash
git clone https://github.com/parousia8888/web-app-security-skill.git
cd web-app-security-skill
npm run demo -- --out ./demo-output
```

阅读[生成的加固前 / 变更建议 / 复测证据](docs/demo-evidence.md)，再检查
`demo-output/demo-result.json`、`summary.md`、`before.json`、`hardening.patch`、`after.json` 与
`functional-retest.txt`。所有公开 demo 事实都来自 `demo-result.json`；仓库门禁会重跑 fixture，
并在任一公开面不一致时失败。

完整的安装到卸载流程见经过测试的[第一个项目教程](docs/tutorial.zh-CN.md)。

## v0.8.0 新增内容

v0.8.0 是限定范围的跨函数访问控制 release。它把同一份 route-security 访问路径从一次本地调用
扩展到最多四条精确项目内调用边。
它支持精确 route/query/body/Server Action selector，分开传播 object、principal 与 tenant，并区分
Prisma/Drizzle 查询约束和受支持的加载后比较。调用歧义、参数/返回值变换、无法证明的 provider
构造和预算耗尽继续保持 partial，不会靠函数名猜测。

在四个固定公开 commit 的 14 条冻结路径中，13 条完成：Drizzle 6/6、Prisma 7/8。唯一 miss 是
Formbricks `ACTION getMembershipRole`，因 `argument_mapping_ambiguous` 与
`call_target_unresolved` 保持 partial；另有四条 completed 路径仍公开保留 supporting limitation。
这些数字只说明固定语料上的限定能力，不是生产 precision/recall、漏洞确认或部署授权证明。详见
[复核](docs/reviews/v0.8.0-access-control-review.md)、
[provenance](docs/reviews/v0.8.0-access-control-review-provenance.md)、
[真实回归](docs/regressions/v0.8.0-access-control-real-world-regression.md)与
[工程计划](docs/V0.8.0_ENGINEERING_PLAN.md)。

stable 规则清单仍是 25 条 built-in risk、3 条 evidence-integrity 和 16 条 opt-in 外部 adapter risk，
共 44 条；访问路径是独立能力，不算新增漏洞规则。模式命中继续保持 `suspected`；不完整分析保持
`unknown`，并可能退出 3。v0.8.0 签名 tag、GitHub Release、npm 包与可信安装器已经公开，并共同指向
源码提交 `119cbcc7f8d327482df8abfa50a4af0b69fcceee`。v0.8.0 不可变 consumer 与 guarded promotion
lease 已通过，移动的 `v1` Action 现指向同一源码。组合公开 consumer 也已通过，逐字节一致的持久
live-verification 记录已随 release 发布。

## 安装

### npx 零安装试用

不保留安装，直接试跑 CLI：

```bash
npx --yes web-app-security-skill audit . --fail-on never
```

### Claude Code plugin

一条 shell 命令从本仓库 marketplace 安装 Claude Code plugin：

```bash
claude plugin marketplace add parousia8888/web-app-security-skill --scope user && claude plugin install web-app-security-skill@web-app-security --scope user
```

已经进入 Claude Code session 时，对应的 slash command 是：

```text
/plugin marketplace add parousia8888/web-app-security-skill
/plugin install web-app-security-skill@web-app-security
```

### 可信多入口安装

如需强制 checksum 验证、并在条件满足时验证 GitHub attestation 的多入口安装，下面的命令会同时安装 Claude Code skill、Codex skill 和
`~/.local/bin/webapp-security` 普通 CLI。
若已有安装会直接拒绝；只有显式加入 `--force` 才会先生成带时间戳的备份再替换。该命令下载不可变
bootstrap 并在执行前验证 SHA-256，然后验证选定 release 的 manifest、checksums、SBOM、源码提交和
归档，再进入安装。
已安装且登录 GitHub CLI 时会执行 attestation 验证；需要把 attestation 缺失或失败作为安装失败时，
显式传入 `--attestation required`。

```bash
( set -eu; p="$(mktemp "${TMPDIR:-/tmp}/web-app-security-bootstrap.XXXXXX")"; trap 'rm -f "$p"' EXIT HUP INT TERM; curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location --output "$p" 'https://raw.githubusercontent.com/parousia8888/web-app-security-skill/12cb085d7f3a21c2b6ffb6cb2758ee4247e2af9f/scripts/bootstrap-install.sh?immutable=12cb085d7f3a21c2b6ffb6cb2758ee4247e2af9f'; node -e 'const c=require("node:crypto"),f=require("node:fs"),p=process.argv[1],e=process.argv[2],a=c.createHash("sha256").update(f.readFileSync(p)).digest("hex");if(a!==e){console.error(`bootstrap SHA-256 mismatch: ${a}`);process.exit(1)}' "$p" '137b5d8fdf6f616be3aa2631e0134b354fd9142ce19419bad6c37e5b0409480f'; sh "$p" )
```

也可以只装单一入口：

```bash
sh bootstrap-install.sh --target claude
sh bootstrap-install.sh --target codex
sh bootstrap-install.sh --target cli
sh bootstrap-install.sh --target both   # Claude Code + Codex
```

简写示例以已经通过上方命令下载并验证 `bootstrap-install.sh` 为前提。显式版本、离线/人工验证、
attestation 及信任锚说明见[可信安装](docs/verified-installation.zh-CN.md)。系统支持范围与当前限制见
[兼容矩阵](docs/compatibility.md)。

查看版本、升级或卸载：

```bash
webapp-security version
# 对可识别的现有安装运行已验证 bootstrap，并选择 upgrade 模式。
sh bootstrap-install.sh --mode upgrade
webapp-security uninstall
```

`upgrade` 只替换带有 Web App Security Skill 可识别 marker（或已记录旧 Skill 身份）的安装，并保留
时间戳备份。`uninstall` 删除可识别的当前安装但保留这些备份。未知目录或 launcher 即使配合
`install --force` 也会被拒绝。

## 执行第一个项目

在 Claude Code 或 Codex 中打开目标仓库，然后发送：

```bash
webapp-security start .
```

命令会创建私有项目身份及 `.webapp-security/runs/<run-id>/security-scope.yml`，记录检测到的框架、
包管理器、lockfile 与部署/配置路径，全程不访问网络。检查 scope 后，再发送：

```text
在这个仓库使用 $web-app-security。先只执行源码与本地检查，记录范围和假设；把每项结果标为 confirmed、suspected、unknown 或 not_applicable；准备最小且可审查的加固补丁，未经批准不应用高风险或生产变更；复测每项已应用修复，最后列出已修复、仍存在和未覆盖的风险。
```

随后可运行确定性源码路径：

```bash
webapp-security audit .webapp-security/runs/<run-id> --fail-on high
webapp-security explain <finding-id> --report .webapp-security/runs/<run-id>/report.json
webapp-security repair-plan <finding-id> \
  --report .webapp-security/runs/<run-id>/report.json --out ./repair-review
webapp-security start . --run-id <retest-run-id>
webapp-security retest .webapp-security/runs/<retest-run-id> \
  --baseline .webapp-security/runs/<run-id>/report.json

# 仅用于 built-in adapter 的审查降噪
webapp-security audit . --since HEAD~1 --fail-on never
webapp-security audit . --staged --fail-on never
```

`--since` 不包含 untracked 文件；`--staged` 读取 Git index，不读取 unstaged 工作区内容。两种模式
都不能与外部 adapter 或 baseline/retest 对比组合。

默认使用内置、无网络的源码 adapter。外部 adapter 必须显式选择：

```bash
webapp-security doctor . --adapter all --json
webapp-security audit . --profile deep --fail-on never
```

已测试版本为 Checkov `3.3.9`、Gitleaks `8.30.1`、Opengrep `1.27.0` 和 OSV-Scanner `2.5.0`；CLI 与
Action 都不会自动下载。Checkov 只运行三条固定的根目录 Dockerfile/GitHub Actions 规则，并使用
`--skip-download`；它可能向 PyPI 查询版本元数据，但不会上传项目源码。Opengrep 只使用内置、摘要
固定的十条本地规则且不访问网络；OSV-Scanner 可能查询公共 OSV 数据库。所有 adapter 都不会执行
项目依赖。Compose、Terraform、Kubernetes 和 Checkov 的其他规则不属于 stable 覆盖。外部结果要影响阻断退出码前，还必须在使用方仓库接受
[`docs/alert-policy.md`](docs/alert-policy.md) 中的责任，并传入
`--acknowledge-alert-policy`。版本、失败与脱敏语义见
[`adapter protocol`](docs/adapter-protocol.md)。

每次源码 audit 会写出 v3 JSON、Markdown、HTML、SARIF、JUnit、SHA-256 sidecar 和
`proposed.patch`。每条源码 finding 同时保留专业术语和通俗解释，并说明可能后果、证据边界、待审查
提案、副作用、安全复测、功能复测、回滚条件与需要用户决定的事项。直接对项目执行的一次性 audit
使用 ephemeral identity，不能作为复测 baseline。`fixed` 必须同时满足 persisted subject/scope
相同、rule 兼容、本次 coverage 已完成且条件明确不存在。命令不会应用补丁，也不授予部署探测权限。

报告先按风险 domain，再按 evidence state，最后按 severity 汇总。默认 CI policy 会 gate
`security_exposure` 与 `supply_chain` 中 HIGH 级的 `confirmed` 和 `suspected` finding。
`suspected` 在所有产物中仍是待复核线索；CI 阻断表示必须先处理或审查，并不表示已证明可利用。
第一次非阻断式检查可使用 `--fail-on never`。现有 `--fail-on` 继续同时设置这两个 domain；
如需 gate 其他 domain，必须显式指定，例如：

```bash
webapp-security crawl --site https://example.com --out ./security-report \
  --fail-on high --fail-on-domain search_discoverability=high
```

可以组合多个 `--fail-on-domain <domain=threshold>`。有效 threshold 会写入 report。
[生成的 rule taxonomy](docs/rule-taxonomy.md)把 source rule 的 kind、family、language、domain、
severity、默认证据状态与标准引用分开记录。精确 stable source 数量和完整解释元数据来自机器可读的
[`stable-source-rules.json`](docs/stable-source-rules.json)：`main` 当前是 25 条 built-in 风险规则、
3 条 built-in 证据完整性规则和 16 条外部适配器风险规则，合计 44 条 stable 源码与部署策略规则。
JavaScript/TypeScript 与 Python 各有 10 条 built-in 风险规则，覆盖危险执行、浏览器或框架配置、
传输、认证/session 设置与反序列化；另有 5 条共享的仓库和项目配置检查。模式命中不能证明输入流
或运行时可达性，未经独立复现保持 `suspected`；只有规则明确限定的可观察事实才会是 `confirmed`。
内置词法分析同时受单文件 token、单文件 operation 与全局 operation 预算约束。触顶会生成
`source-evidence-incomplete / unknown`，coverage 降为 partial 或 unavailable，并记录实际生效的
limit；不会被写成干净结果。

## 能力边界

能力使用两个互相独立的维度，避免把支撑工具计入漏洞检测覆盖：

- **类别：** 检测；证据与报告；生命周期与分发；或 Agent 方法论。
- **成熟度：** `stable`、`experimental`、`agent_guided` 或 `planned`。

当前 stable 检测家族包括窄范围内置源码 audit、显式启用的 Checkov、Gitleaks、Opengrep 与 OSV-Scanner
adapter、crawl boundary、crawler 身份验证、edge 验证和
只读 AWS inventory helper。项目识别、demo、报告 renderer、复测基础设施、安装器与 GitHub
Action 虽然都有测试，但不构成更多 detector 家族。API 授权、业务逻辑、LLM/OAuth、数据层和
更广的 AWS 审查仍属于 Agent
方法论，直到具体 adapter 获得回归证据。

[生成的能力矩阵](docs/capabilities.md)为每项类别与成熟度声明链接证据。结果只使用 `confirmed`、
`suspected`、`unknown`、`not_applicable`；无法执行的检查不是通过。安装 Skill 不代表项目已经安全。
当前检测盲区、预期误报类别和增量模式限制公开在
[`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md)。MCP 和 stable 规则扩张的进入条件记录在
[`docs/architecture/mcp-and-rule-expansion.md`](docs/architecture/mcp-and-rule-expansion.md)。

## 确定性工具

可以让 Claude Code 或 Codex 调用 `web-app-security`，也可以直接运行相同的确定性工具：

```bash
# 无网络项目识别与版本化 scope
webapp-security start .

# 只读源码 audit、finding 解释与强制 baseline 复测
webapp-security audit .webapp-security/runs/<run-id> --fail-on high
webapp-security doctor . --adapter all
webapp-security audit . --profile deep --fail-on never
webapp-security explain <finding-id> --report <report.json>
webapp-security start . --run-id <retest-run-id>
webapp-security retest .webapp-security/runs/<retest-run-id> \
  --baseline <report.json> --fail-on high

# 只看某个 commit 之后新增行，或只审 Git index 中已暂存的内容
webapp-security audit . --since HEAD~1 --fail-on never
webapp-security audit . --staged --fail-on never

# 历史 v1 报告保持不可比较；移动/clone 的项目必须显式绑定
webapp-security migrate-report <v1-report.json> --scope <security-scope.yml> \
  --acknowledge-subject <subject-id> --out <new-directory>
webapp-security rebind <moved-project> --scope <security-scope.yml> \
  --acknowledge-subject <subject-id>

# 默认被动：爬取边界与 crawler 可达性
webapp-security crawl --site https://example.com --out ./security-report

# localhost/RFC1918 默认拒绝；审计已获授权的本地目标时必须显式开启
webapp-security crawl --site http://127.0.0.1:3000 --out ./security-report \
  --allow-private-network

# 敏感路径主动探测：必须同时具备所有权/书面授权并显式确认
webapp-security crawl --site https://example.com --out ./security-report \
  --active-probe --acknowledge-authorization

# crawler 身份：精确产品 IP 段或 FCrDNS，不能只信 UA 字符串
webapp-security verify-crawler --ip 66.249.66.1 --ua Googlebot --ranges

# 默认被动：header、跳转、证书和 TLS 策略
webapp-security verify-edge --site https://example.com

# 只读 AWS 姿态清点
webapp-security aws --profile default --region us-east-1 --out ./security-report
```

主动限流复测同样要求 `--acknowledge-authorization`。网络或证据源失败会得到 `unknown` 和非零退出，
不会被描述成安全。
Crawl 客户端只停留在初始 origin，每一跳 redirect 都重新校验并固定 DNS；默认拒绝 localhost、私网、
link-local 与保留地址，并同时限制请求总数、压缩前字节和解压后字节。`--allow-private-network` 只允许
显式选择的 localhost/私网 origin，link-local metadata 与保留地址仍然拒绝。

Source 结论使用 finding/report v3，新 demo 内部的 before/after 源码报告也使用 v3。Crawl、crawler
identity、edge 与 AWS 仍使用 v2；demo 的小型 `demo-result.json` 事实 schema 与两种 report schema
分开。两个 report 版本保留相同的 coverage、证据状态、policy 与退出码语义。Report bundle 和各工具的
observation 会先在内存中脱敏，再以私有 staging 文件写入目标目录并整套提交，不覆盖已有证据；
renderer 或可处理的写入失败会回滚，不留下半套新 bundle。历史 v1 报告只用于展示、release 校验
与显式的不可比较迁移，不能作为可比较 baseline。符合 subject、scope、rule 和 coverage 兼容条件的
persisted v2 源码 baseline 可继续读取，并只在内存中升级后参与 v3 对比，原文件不会被改写。

## GitHub Action

Composite Action 保持 v0.3 crawl 输入与输出兼容。Crawl mode 默认被动，且必须确认部署授权：

```yaml
- name: Audit public crawl boundary
  uses: parousia8888/web-app-security-skill@119cbcc7f8d327482df8abfa50a4af0b69fcceee
  with:
    site: https://example.com
    acknowledge-authorization: true
    active-probe: false
    fail-on: high
```

需要可重复 CI 时使用上面的 v0.8.0 不可变 commit。签名的稳定大版本别名现在指向同一个 v0.8.0
源码 commit；这个别名仍会有意移动：

```yaml
uses: parousia8888/web-app-security-skill@v1
```

Source mode 默认只用内置 adapter。v0.8.0 不可变 Action 运行 v3 源码合同、25 条 built-in risk、
3 条证据完整性规则、有边界的 Express/NestJS/Next.js 路由与 Server Action 清单，以及有边界的
访问控制链审查。外部二进制必须由调用方固定版本并安装，Action 不会下载：

```yaml
- name: Audit source
  uses: parousia8888/web-app-security-skill@119cbcc7f8d327482df8abfa50a4af0b69fcceee
  with:
    mode: source
    project: .
    adapters: builtin
    fail-on: high
```

移动的 `v1` tag 已在 v0.8.0 不可变 Action consumer 通过后，用精确 guarded lease 提升到
v0.8.0。以后接受更新前应检查 release note；工作流不能随版本移动时使用上面的完整 commit。

## 信任与 release 证据

- CI 覆盖 Ubuntu/macOS x Node 22/24、确定性 HTTP/HTTPS fixture 和 Bash 3.2 smoke test。
- release 与 CodeQL workflow 的第三方 Action 使用完整 commit SHA。
- tag 必须同时匹配 `VERSION`、changelog 和该版本的证据文件；tag 带签名，release 记录来源 commit。
- release 产物包含可复现源码包、SPDX 2.3 SBOM、`SHA256SUMS` 与 GitHub build provenance attestation。
  CI 会构建两次并逐字节比较全部产物，再在禁止网络的隔离 HOME 中从解包产物执行完整生命周期。
- [v0.8.0 公开验证](https://github.com/parousia8888/web-app-security-skill/actions/runs/33265256940)
  同时消费不可变 release commit 与签名 `v1`，强制验证 installer attestation，并把同一份
  live-verification 记录作为 workflow artifact 与 Release asset 发布；两份字节一致。
- [`SECURITY.md`](SECURITY.md)、[威胁模型](docs/threat-model.md)、
  [误报政策](docs/false-positive-policy.md)和[兼容矩阵](docs/compatibility.md)可供独立复核。

验证下载的 release 产物：

```bash
sha256sum -c SHA256SUMS
gh attestation verify web-app-security-skill-*.tar.gz \
  --repo parousia8888/web-app-security-skill
git -c gpg.ssh.allowedSignersFile=.github/release-signers verify-tag v0.8.0
```

`.github/release-signers` 是仓库内 signer policy：本地验签通过只证明 tag 与当前检出的仓库政策
一致，不能单独证明 GitHub 账户所有权。GitHub 对精确 tag object 的 verification 需要另行检查；
npm OIDC provenance 是另一条独立信号，只覆盖 npm 包。各信号边界和跨渠道源码身份核对方法见
[release 信任边界](docs/release-trust-boundaries.md)。

## 5 个普通项目旅程

原 v0.4.0 旅程保留完整 v2 built-in/Gitleaks/OSV 证据。独立的
[v0.5.0 built-in 复核](docs/case-studies/journeys/v0.5.0-review.md)对同一批固定 commit 执行更广的
v3 JavaScript/TypeScript 与 Python 规则，并人工归类每条 finding。两个版本都没有探测线上实例或执行
项目依赖。

| 项目 | 证据结果 | 人工结论 |
|---|---|---|
| [Linkwarden](docs/case-studies/journeys/linkwarden.md) | v3：6 suspected | 复核 JSDOM、DOMPurify 和常量内容后，6 条为预期良性命中 |
| [Healthchecks](docs/case-studies/journeys/healthchecks.md) | v3：5 suspected | 4 条 response encoding 有用线索；1 条 opt-in shell 为预期良性命中 |
| [Open WebUI](docs/case-studies/journeys/open-webui.md) | v3：6 suspected；1 unknown | 3 条有用线索；3 条预期良性；tokenizer 失败保留 unknown |
| [Uptime Kuma](docs/case-studies/journeys/uptime-kuma.md) | v3：4 confirmed fact；21 suspected | 4 条有用线索；17 条预期良性；confirmed 只是 lockfile 卫生事实，不是 4 个应用漏洞 |
| [Mealie](docs/case-studies/journeys/mealie.md) | v3：0 finding | 没有配置中的 pattern 命中，不等于项目安全 |

阅读[结构化旅程、精确命令与证据边界](docs/case-studies/journeys/README.md)。零 finding 与误报关闭
同样保留；这里不计算 precision 分数。Uptime Kuma 与 Mealie 和下方方法论 corpus 使用相同 commit，
因此是两种证据视图，不是 10 个互不重复的项目。

另有 **5 个既有源码方法论案例**：三个故意脆弱基准与两个生产项目，作为独立 corpus 保留。

| 项目 | 证据结果 |
|---|---|
| [OWASP Juice Shop](docs/case-studies/juice-shop.md) | 确认故意存在的 SQL 注入，并对应到上游 prepared statement 修复 |
| [OWASP NodeGoat](docs/case-studies/nodegoat.md) | 确认故意存在的服务端 `eval`、IDOR、开放跳转 |
| [DVWA](docs/case-studies/dvwa.md) | 确认 low/impossible 两档 SQLi、XSS、命令注入控制对照 |
| [Uptime Kuma](docs/case-studies/uptime-kuma.md) | SSRF 形态的出站 sink 被判为产品能力，不计漏洞 |
| [Mealie](docs/case-studies/mealie.md) | URL 抓取线索追踪到鉴权与私网 IP guard，不计漏洞 |

完整方法与限制见[案例总览](docs/case-studies/README.md)。这些案例验证方法论，不虚构一个尚非通用
SAST 引擎的 CLI 精度分数。

## 项目结构

阶段顺序是：Phase 0 授权范围 → 前端 → API → LLM/OAuth → 服务端源码 → 数据库隔离 → 供应链 →
蓝队检测 → 报告/补丁证据/复测。横向专题覆盖爬取边界、crawler 身份、source map/dotfile、
执行层、AWS、遗漏攻击面、回归门禁与安全部署。入口在 [`SKILL.md`](SKILL.md)。

公开 [roadmap](ROADMAP.md) 将正确性建设与传播建设分开。新贡献者可从
[Good First Issues](docs/GOOD_FIRST_ISSUES.md)、issue forms 和 [`CONTRIBUTING.md`](CONTRIBUTING.md)
开始。误报报告必须提供脱敏的最小 fixture 和期望分类；敏感信息走 private vulnerability reporting。

[生成式 launch evidence](docs/launch-evidence.md)只汇集可复现的能力、demo、项目旅程、方法论案例和
release 事实。[发布素材包](docs/adoption/launch-brief.zh-CN.md)提供带证据链接的中英文渠道草稿，
以及可复用的公开案例/私下披露流程，但不声称外部发布已经发生。

MIT License。
