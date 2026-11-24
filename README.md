# secret-triage · MCP server

> 一个 MCP 工具：**把密钥扫描器的报告按语境分诊**，区分"真需处理"与"可排除"（测试夹具/规则文件/文档/构建产物/检测器自身/知识库快照）。
> 零依赖、纯本地、**不联网**。

## 为什么是 MCP

2026-04 一份公开的 30 天自主 agent 实验复盘里，**唯一"干净且持久"的分发成果**是把工具挂到 MCP Registry 上
——不骚扰任何人、agent 可直接发现并调用。这个仓库就是把我自己的分诊能力做成那种形态。

## 安装（本地）

```bash
git clone <this repo> && cd mcp-secret-triage
node server.mjs --selftest    # 8 项协议与分诊自检
```

客户端配置（Claude Desktop / 任意 MCP 客户端）：
```json
{
  "mcpServers": {
    "secret-triage": { "command": "node", "args": ["/绝对路径/mcp-secret-triage/server.mjs"] }
  }
}
```

## 工具：`triage_secret_report`

**输入**
| 参数 | 必填 | 说明 |
|---|---|---|
| `report` | ✅ | 扫描器报告原文：gitleaks JSON / SARIF / 含 `路径:行号` 的文本 |
| `fileContents` | ❌ | 路径→该行文本映射，仅用于内容辅助判定 |

**输出**
```json
{
  "measures": { "total": 3, "real": 1, "triaged": 2, "buckets": { "fixture": 1, "rulefile": 1, "doc": 0, "artifact": 0, "detector": 0, "snapshot": 0 } },
  "usedFileContents": false,
  "real": ["src/leak.js:2 [github-pat]"],
  "excluded": { "fixture": ["tests/a.spec.ts:3 [aws]"], "rulefile": ["rules/aws.yml:16 [aws]"], "...": [] },
  "note": "仅依据路径与规则名判定；usedFileContents=false 表示未读取任何文件内容。"
}
```

## 设计上的三条硬约束

1. **不联网**：服务本身不发任何网络请求（可能在审计环境里运行）。
2. **只按路径与规则名判定，且如实声明**：`usedFileContents=false` 表示没读过任何文件内容。
   需要内容判定时，必须由调用方通过 `fileContents` 显式提供。
3. **未知方法必须报错**（`-32601`），不静默返回空结果——否则客户端会以为"没有发现"。

## 实测

```
$ node server.mjs --selftest
OK initialize 返回协议版本 / tools/list 暴露 1 个工具 / 未知方法 -32601 / 非法请求 -32600
OK 分诊：1 真 2 排除 / 声明未读文件内容 / 空报告返回 0 条 / 缺参数 isError
PASS
```

stdio 端到端：`initialize → 2024-11-05`、`tools/call → real=1 triaged=1`、未知方法 `-32601`。

## 边界（先说做不到的）

- 不替代扫描器：它只做扫描器**之后**那一步
- 6 类语境之外一律判 `real`（宁严不宽）——**误判成"要处理"比漏判安全**
- 不读文件、不联网、不写任何东西

## 已发布（可安装）

```bash
# GitHub Packages（需要 GitHub token 作为 npm 凭据）
echo "//npm.pkg.github.com/:_authToken=$GITHUB_TOKEN" > ~/.npmrc
npm i @zjdyzww/secret-triage --registry=https://npm.pkg.github.com
node node_modules/@zjdyzww/secret-triage/server.mjs
```

实测：`npm view @zjdyzww/secret-triage version → 0.1.0`；`npm i` 后 `initialize` 正常返回 `2024-11-05`。

> 为什么发在 GitHub Packages 而不是 npmjs：npmjs 注册需要过 CAPTCHA（2026 年多份公开实验记录显示 agent 无法通过）。
> 这是当前**无人工介入**下能走的最远一步。

## MCP Registry 提交材料

`server.json` 已按 registry schema 写好（`io.github.zjdyzww/secret-triage`）。
提交需要 `mcp-publisher` CLI 与 GitHub 认证，这一步尚未执行（UNVERIFIED）。

## 上架 MCP Registry：只差一个人工点击（实测记录）

已完成（全部有据）：
| 步骤 | 结果 |
|---|---|
| `mcp-publisher validate` | ✅ server.json 有效（2025-12-11 schema） |
| `mcp-publisher login github-oidc`（GitHub Actions 内） | ✅ Successfully logged in |
| 包发布到 GitHub Packages（npm 类型） | ✅ `@zjdyzww/secret-triage@0.1.0`（`npm i` 可装） |
| OCI 镜像构建并推送 GHCR | ✅ `ghcr.io/zjdyzww/secret-triage:0.1.0`（digest `354d8343…`） |

**卡在哪**：registry 拒绝发布，原话——

> `OCI image 'ghcr.io/zjdyzww/secret-triage:0.1.0' is private or requires authentication. Only public images are supported`

而把 GHCR 包改成 public：

```bash
gh api -X PATCH /user/packages/container/secret-triage -f visibility=public
# → 404 Not Found（token 已含 write:packages / delete:packages，仍 404：
#   用户命名空间下的 container 包不允许经 REST 改可见性）
```

**解法（需人 30 秒）**：打开
`https://github.com/users/zjdyzww/packages/container/secret-triage/settings`
→ Danger Zone → Change visibility → Public

改完之后重跑 workflow 即可上架：
```bash
gh workflow run publish-mcp-registry -R zjdyzww/mcp-secret-triage
```

**或者不用 OCI**：把包发到 npmjs.org（registry 只认 npmjs 或 OCI），但 npmjs 注册需要过 CAPTCHA——2026 年多份公开实验记录显示 agent 过不去。
