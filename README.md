# codebuddy-search-mcp

把腾讯 CodeBuddy 的**联网搜索**与**网页抓取**提取成独立 MCP server——纯 HTTP 直连，无需 codebuddy CLI、无 agent 进程、零模型 token 消耗，单次搜索约 2 秒。

逆向自 CodeBuddy CLI v2.160.0（Bun SEA 二进制），全部端点均经实测验证。

## 特性

- **零依赖**：单文件 Node 脚本（`index.js`），无 npm install
- **三个工具**：
  - `cb_login` — 鉴权管理：状态报告 / 触发完整 OAuth 浏览器登录
  - `cb_web_search` — 联网搜索（中文质量好，支持域名过滤、时间过滤）
  - `cb_web_fetch` — 网页正文抓取（服务端渲染/提取，返回 markdown）
- **鉴权全自治**：
  - OAuth 登录（浏览器一次，与 codebuddy CLI 同协议同登录态文件）
  - accessToken 过期自动 refresh（token 轮换写回，只要在 refresh 有效期内用过一次即永续）
  - API key 兜底（`ck_` 前缀 key 直接当 Bearer）
- **与 CLI 互操作**：登录态文件与 codebuddy CLI 完全共享（双方都带文件 watcher，外部修改自动同步）

## 安装

### 前置要求

- Node.js >= 18（有内置 fetch）
- 一个 CodeBuddy 账号（腾讯 SSO / 微信 / 邮箱均可，即能登录 [copilot.tencent.com](https://copilot.tencent.com) 的账号）

### 方式一：npx 直跑（推荐，零安装）

公开仓库无需 clone，MCP 客户端直接注册：

```json
"codebuddy-search": {
  "type": "stdio",
  "command": "npx",
  "args": ["-y", "github:zzjcool/codebuddy-search-mcp"]
}
```

首次启动时 npx 自动拉取并缓存到 `~/.npm/_npx/`，之后每次直接跑缓存。

> ⚠️ 私有仓库：npx 默认拒绝 git 依赖。两种解法：
> 1. `npm config set allow-git all`（全局放行）
> 2. 保持 clone 方式（见方式二）

> 📌 锁版本：把 `github:zzjcool/codebuddy-search-mcp` 换成 `github:zzjcool/codebuddy-search-mcp#v1.2.0`（用 tag），避免上游更新引入意外变化。

### 方式二：clone 安装

```bash
git clone git@github.com:zzjcool/codebuddy-search-mcp.git
cd codebuddy-search-mcp
```

### 注册到 MCP 客户端

**pi**（`~/.pi/agent/mcp.json`）：

```json
{
  "mcpServers": {
    "codebuddy-search": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "github:zzjcool/codebuddy-search-mcp"]
    }
  }
}
```

（clone 方式则用 `"command": "node", "args": ["/绝对路径/codebuddy-search-mcp/index.js"]`）

**Claude Code**：

```bash
# npx 方式
claude mcp add codebuddy-search -- npx -y github:zzjcool/codebuddy-search-mcp
# clone 方式
claude mcp add codebuddy-search -- node /绝对路径/codebuddy-search-mcp/index.js
```

**Cursor / 其他 MCP 客户端**：同 stdio 方式注册。

### 登录（二选一）

**方式 A：MCP 内置 OAuth 登录（推荐）**——不依赖 codebuddy CLI：

重启 MCP 客户端后，让 agent 调用：

```json
{"name": "cb_login", "arguments": {"trigger_browser_login": true}}
```

浏览器会自动打开授权页（SSO 会话存活时自动完成，无需手动点击）。登录态写入 CLI 同款文件，之后自动续期。

**方式 B：复用 codebuddy CLI 登录态**——如果本机已经 `codebuddy login` 过，直接就能用，无需任何配置。

**方式 C：API key 兜底**：

```bash
mkdir -p ~/.codebuddy-search-mcp
echo "ck_你的key" > ~/.codebuddy-search-mcp/key
chmod 600 ~/.codebuddy-search-mcp/key
# 或者环境变量：export CODEBUDDY_API_KEY=ck_你的key
```

### 验证

```
> 用 codebuddy 搜一下 "Model Context Protocol 最新规范"
```

agent 会调用 `cb_web_search`，约 2 秒返回结果列表（title / url / snippet）。

## 工具说明

### cb_web_search

| 参数 | 类型 | 说明 |
|---|---|---|
| `query` | string | 搜索词（必填，≥2 字符） |
| `maxResults` | number | 结果数上限，默认 5，最大 10 |
| `allowedDomains` | string[] | 只搜这些域名 |
| `blockedDomains` | string[] | 排除这些域名 |
| `freshness` | string | 时间过滤：`d`=当天，`m`=近一月，`y`=近一年（可带数字：`d7`/`m6`/`y2`） |

### cb_web_fetch

| 参数 | 类型 | 说明 |
|---|---|---|
| `url` | string | 目标 URL（必填） |
| `maxLength` | number | 返回正文最大长度，默认 4000 |

### cb_login

无参数：报告鉴权状态（账号、token 有效期、实际凭据来源）。
`trigger_browser_login: true`：触发完整 OAuth 浏览器登录。

## 配置项（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `CODEBUDDY_API_KEY` | - | API key（OAuth 不可用时兜底） |
| `CODEBUDDY_API_BASE` | `https://copilot.tencent.com` | API 端点（海外版用 `https://www.codebuddy.ai`） |
| `CODEBUDDY_AUTH_DIR` | 按平台自动推导 | OAuth 登录态目录（见下） |
| `CODEBUDDY_AUTH_ID` | `Tencent-Cloud.coding-copilot` | 登录态文件名（authentication.id） |

OAuth 登录态默认路径（与 codebuddy CLI 共享）：

- macOS: `~/Library/Application Support/CodeBuddyExtension/Data/Public/auth/`
- Linux: `~/.local/share/CodeBuddyExtension/Data/Public/auth/`
- Windows: `%LOCALAPPDATA%/CodeBuddyExtension/Data/Public/auth/`

## 鉴权链路

```
未登录 ──cb_login{trigger_browser_login}──→ OAuth 浏览器登录（一次）
登录态有效 ──────────────────────────→ Bearer accessToken 直调
access 过期（自动）──→ POST /v2/plugin/auth/token/refresh（token 轮换写回）
refresh 也过期（长期未用）──→ 重新触发登录，或降级 API key
```

## 工作原理（逆向摘要）

| 端点 | 用途 |
|---|---|
| `POST /agenttool/v1/search` | 搜索（WebSearch 工具后端） |
| `POST /agenttool/v1/webfetch` | 网页抓取（WebFetch 工具后端） |
| `POST /v2/plugin/auth/state?platform=CLI` | OAuth 登录：拿 state + authUrl |
| `GET /v2/plugin/auth/token?state=…` | OAuth 登录：轮询换 token（pending=11217） |
| `GET /v2/plugin/account` | 账号信息 |
| `POST /v2/plugin/auth/token/refresh` | token 续期（X-Refresh-Token + X-Domain） |

CodeBuddy CLI 的 WebSearch/WebFetch 工具本身就是标准 `fetch` 调用这些端点（不像 Cursor 把搜索锁在服务端 agent loop 里），且鉴权豁免逻辑允许任何合法 Bearer——这就是能绕过 CLI 直连的原因。

详细逆向过程与证据：见 SOP `codebuddy-search-api-extraction`。

## 常见问题

**Q: 401 Authorization Required？**
OAuth token 过期且 refresh 失效（长期未用），重新 `cb_login{trigger_browser_login:true}`；或检查 API key。

**Q: 搜索报 `code=15003` 之类错误？**
15001/15002/15003/15005 是 agenttool 配额类错误码，说明当月搜索额度用完或并发超限，等待或换账号。

**Q: 和 codebuddy CLI 会互相登出吗？**
不会。登录态文件共享且双方都监听文件变化，谁刷新 token 另一方自动同步。唯一注意：CLI 的 `codebuddy logout` 会把登录态改名存档，MCP 下次调用会提示重新登录。

**Q: 海外版（codebuddy.ai）能用吗？**
能。设 `CODEBUDDY_API_BASE=https://www.codebuddy.ai`，登录流一样（浏览器会跳 codebuddy.ai 的授权页）。

## License

MIT
