# 第一个项目教程

本教程覆盖从干净环境安装，到范围记录、源码检查、补丁审查、复测、升级和卸载的完整流程。产品承诺是：
**把 Web 项目交给 AI coding agent，完成范围确认、风险检查、最小加固、复测和证据交付。**

这里的确定性路径只读取本地源码，不访问部署实例。已发布的 v0.8.0 会运行 25 条 built-in risk 与
3 条证据完整性规则，并加深 JavaScript/TypeScript 和 Python 覆盖。受支持的 Express、NestJS 与
Next.js App Router 项目还会得到带有边界访问控制链的路由安全审查，并单独列出 Next.js Server
Action。它仍然是范围明确的首次检查，不是通用 SAST、自动 BOLA 证明，也不证明项目已经安全。
实际生效的词法 token 与 operation 预算会写入报告；预算触顶属于证据不完整并退出 `3`，不是通过。

当前 v0.8.0 release 会写出 route-security v3。对精确且受支持的 selector，它可把 object、
principal 和 tenant 事实经最多四条项目内调用边带到限定的 Prisma/Drizzle 操作，再区分可见 query
predicate 与受支持的加载后比较。框架清单覆盖率和 `accessPathCoverage` 必须分开阅读；`completed`
只表示限定分析走完，不表示授权正确或存在 BOLA/IDOR。route-security v1/v2 与 v3 对比时只会得到
`not_comparable / route_schema_changed`；启用路由 regression gate 前要先建立新的 v3 baseline。

## 环境要求

- macOS 或 Linux；
- Node.js 22 或 24；
- Git；
- 你有权检查和修改的项目。

完整边界见[兼容矩阵](compatibility.md)。

## 安装

### 稳定 release

下载 v0.8.0 的全部产物，验证 checksum，解包并从已验证的 payload 安装：

```bash
mkdir web-app-security-release && cd web-app-security-release
gh release download v0.8.0 --repo parousia8888/web-app-security-skill
sha256sum -c SHA256SUMS
tar -xzf web-app-security-skill-0.8.0.tar.gz
node web-app-security-skill-0.8.0/scripts/webapp-security.mjs install
webapp-security version
```

macOS 没有 GNU `sha256sum` 时，使用 `shasum -a 256 -c SHA256SUMS`。Release 还提供 SPDX SBOM、
源码 manifest、build provenance attestation 和签名 tag：
[v0.8.0 release](https://github.com/parousia8888/web-app-security-skill/releases/tag/v0.8.0)。

### 当前 checkout

评估当前 `main` 或参与开发时使用：

```bash
git clone https://github.com/parousia8888/web-app-security-skill.git
cd web-app-security-skill
node scripts/webapp-security.mjs install
webapp-security version
```

默认安装 Claude Code、Codex 和普通 CLI。可用 `--target claude`、`codex`、`cli` 或 `both`
选择安装面。安装器拒绝未知的既有路径；`--force` 也只替换可识别的当前或旧版本 payload，并先创建
带时间戳的备份。

## 复现本地教程

在当前 checkout 中，对故意配置错误的 fixture 执行完整流程：

```bash
tutorial_output="$(mktemp -d)"
node scripts/run-clean-room-tutorial.mjs --out "$tutorial_output"
cat "$tutorial_output/tutorial-result.json"
```

Runner 会创建隔离 HOME、安装 CLI、禁止网络、生成 persisted scope、检查 `before` fixture、解释
一个线索、显式 rebind 加固后的 fixture、复测、升级并卸载。预期基线为 4 个 finding：1 个
`confirmed`、3 个 `suspected`；复测必须在十分钟预算内把 4 个都记录为 `fixed`。

## 开始你的项目

进入你拥有或获准检查的项目根目录：

```bash
cd /path/to/your-project
webapp-security start . --run-id first-review
```

检查 `.webapp-security/runs/first-review/security-scope.yml`。它记录 privacy-preserving persisted
subject ID、scope digest、识别到的框架、包管理器、lockfile、部署/配置路径、假设以及被阻止的
远程模式。私有 identity 保存在 `.webapp-security/project.json`；两者都不授予访问部署实例的权限。

在这个 scope 下运行源码检查：

```bash
webapp-security audit .webapp-security/runs/first-review \
  --name report --fail-on never
```

输出包括 `report.json`、`report.sha256`、`report.md`、`report.html`、`report.sarif`、
`report.junit.xml` 和 `proposed.patch`。JSON 用于自动化，sidecar 用于本地完整性检查，
Markdown/HTML 用于审查，SARIF/JUnit 用于 CI；patch 只是提案。

如果项目属于受支持的 Express、NestJS 或 Next.js App Router，在修改授权逻辑前还要阅读
`route-security.md`。顺序是：框架与访问路径覆盖率、应用级 control、没有路由级 control 的状态变更/
对象路由、未观察到受支持约束的 completed 路径、partial 路径，最后是单独的 Server Action 清单。
配套 JSON 与 Markdown 在 `route-security.sha256` 中各有独立 digest。

默认 policy 会 gate HIGH 级的 confirmed 与 suspected security/supply-chain finding。
suspected 证据不会被升级；退出码 `1` 表示这条线索必须先审查，并不表示已经证明可利用。
第一次非阻断式报告可用 `--fail-on never`。报告依次按 domain、evidence state 和 severity 汇总。
`--fail-on` 保持兼容的 security/supply-chain threshold；只有当其他 domain 确实属于 CI gate 时，
再添加可重复的 domain override：

```bash
webapp-security audit .webapp-security/runs/first-review \
  --fail-on high --fail-on-domain reliability=high
```

## 解释结果

| 状态 | 含义 | 后续动作 |
|---|---|---|
| `confirmed` | 已用充分、脱敏的证据复现 | 优先修复并复测 |
| `suspected` | 源码或 scanner 线索缺少运行时/上下文证据 | 复现或用证据关闭 |
| `unknown` | 检查或证据源不可用 | 恢复证据能力，不能当作通过 |
| `not_applicable` | 不在已记录范围内或组件不存在 | 保留范围理由 |

在不修改项目的情况下解释一个 finding：

```bash
webapp-security explain <finding-id> \
  --report .webapp-security/runs/first-review/report.json
```

不能把文件名匹配、静态 pattern 或 AI 建议升级为 `confirmed`。例如，生产 source map 配置只能形成
`suspected` 线索，直到构建产物或自有部署证明它被公开交付。

默认解释先讲人话，再展开技术细节。每条可处理的 v3 finding 按这个顺序阅读：

1. `technicalTerm` 与 `state`：行业名称，以及检查实际证明到了哪一步。
2. `plainLanguage` 与 `consequence`：代码在做什么；如果缺失条件确实成立，可能造成什么后果。
3. `evidenceBoundary`：规则没有证明的部分，例如输入流或运行时可达性。
4. `proposal`、`alternatives` 与 `sideEffects`：准备怎么改、还有什么方案、正常功能可能怎么变化。
5. `userDecisions`、`securityRetest`、`functionalRetest` 与 `rollback`：必须由项目所有者决定什么，
   以及保留修改前需要哪些证据。

## 审查并应用补丁

同时阅读报告和 `.webapp-security/runs/first-review/proposed.patch`。Patch 可能包含可应用 diff 和
人工处理说明；`audit` 从不自动应用它，它也可能不覆盖全部 finding，更不构成修复证明。

修改源码前：

1. 确认证据对应预期组件。
2. 判断变更是否影响生产流量、鉴权、数据、SEO 或 crawler。
3. 保持最小且可审查的修改，并保留原始报告作为 baseline。
4. 修改后运行项目自身测试。

为单条 finding 创建私有、只供审查的 repair record：

```bash
webapp-security repair-plan <finding-id> \
  --report .webapp-security/runs/first-review/report.json \
  --out .webapp-security/runs/first-review/repair-review
webapp-security repair-validate \
  .webapp-security/runs/first-review/repair-review/repair-record.json
```

初始记录保持 `review_required`、approval pending、patch not applied。CLI 不会自行把记录改成 approved
或 applied，也不会修改项目文件。鉴权、授权、公开路由、CORS、cookie/session、存储数据和生产基础设施
必须由所有者显式决定。只有指定的安全复测和受影响的正常产品流程都通过，repair 才能进入 `retested`。

使用 AI coding agent 时，采用仓库 README 或 [`README_AI.md`](../README_AI.md) 的 canonical prompt，
并明确 agent 可以应用修改，还是只能交付 patch。高风险和生产变更需要单独批准。

## 复测

审查并应用选定修改后，创建新 run 并把新证据写入其中：

```bash
webapp-security start . --run-id first-review-retest
webapp-security retest .webapp-security/runs/first-review-retest \
  --name report \
  --baseline .webapp-security/runs/first-review/report.json \
  --fail-on high
```

检查新 JSON 报告中的 `summary.byBaseline`。只有 subject/scope 相同、rule identity 兼容、本次
coverage 完成且条件明确不存在时才记为 `fixed`。未执行或不可用检查记为 `unretested`，不兼容
revision 记为 `not_comparable`。源码层的 `suspected` 仍需运行时或部署证据。

项目移动或 fresh clone 后，先检查原 scope，再显式绑定：

```bash
webapp-security rebind /path/to/moved-project \
  --scope /path/to/prior/security-scope.yml \
  --acknowledge-subject <exact-subject-id>
```

历史 v1 报告不能变成可比较 baseline。`migrate-report` 只在新的 v2 文档中保留原始字节 digest
与显式 lineage，且不修改原文件；第一份可信的可比较 baseline 必须来自新的 v2 audit。

## 授权边界

本地源码检查不授权远程测试。发出任何主动请求前，要记录所有权或书面授权、精确 origin/account、
时间窗口、禁止动作和停止条件。不能拿第三方线上实例作为教程目标。

被动 crawl 检查也会发送 HTTP 请求。敏感路径探测和主动 rate-limit 检查还要求
`--acknowledge-authorization`。范围扩大、出现第三方数据、生产健康下降或证据会泄露 secret 时立即停止。

## 故障排查

| 现象 | 处理 |
|---|---|
| `webapp-security: command not found` | 把 `~/.local/bin` 加入 `PATH`，或运行 checkout 中的 `node scripts/webapp-security.mjs` |
| 退出码 `1` | Finding 达到 `--fail-on` 阈值；证据仍会写出 |
| 退出码 `2` | 用法、范围、授权或证据准备失败；不能当作通过 |
| 退出码 `3` | 必需证据为 unknown、partial 或 unavailable，且没有优先级更高的 actionable 阈值 finding |
| `refusing to overwrite existing evidence` | 使用新的 `--out` 或报告名，并保留原 baseline |
| Stack 不支持或有歧义 | 保留 `unknown`，转入 agent-guided 方法 |
| 远程检查被阻止 | 仅对自有目标补充已记录授权和显式确认 |

## 报告误报

使用[误报 issue form](https://github.com/parousia8888/web-app-security-skill/issues/new?template=false-positive.yml)，
提供版本、finding ID、最小脱敏 fixture、实际/预期状态和环境。不能包含 token、cookie、账户标识、
私有源码或真实客户 IP。若报告本身敏感，使用 [`SECURITY.md`](../SECURITY.md) 中的私密渠道。

[误报政策](false-positive-policy.md)要求先得到可复现的失败回归，再修改规则。

## 升级或卸载

生命周期命令不会自行下载代码。先获取并验证新 release，再运行它的 payload：

```bash
node /path/to/new-release/scripts/webapp-security.mjs upgrade
webapp-security version
webapp-security uninstall
```

升级会在替换可识别安装前备份。卸载只删除可识别的当前 payload 和 launcher，保留旧备份；未知目录会被拒绝。
