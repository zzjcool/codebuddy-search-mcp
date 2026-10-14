#!/usr/bin/env node
/**
 * codebuddy-search-mcp — CodeBuddy 的联网搜索/网页抓取，提炼成独立 MCP server（零依赖）。
 *
 * 与 cursor-search-mcp 的本质区别（全部经 v2.160.0 二进制逆向 + 实测验证）：
 *   Cursor: RunWebSearch 是 agent-loop 内部 RPC，403 拒绝独立调用 → 只能 CLI fork 代理（慢，烧额度）。
 *   CodeBuddy: WebSearch/WebFetch 是独立 HTTP API（工具类是标准 fetch 调用），可直接调用。
 *
 * 鉴权（两路，OAuth 优先，API key 兜底）：
 *   A. OAuth（推荐，永续）: 读 CodeBuddy CLI 的登录态文件
 *      ~/Library/Application Support/CodeBuddyExtension/Data/Public/auth/*.info（明文 JSON，
 *      CLI 的 FileAuthenticationStorage 存储，带 watcher 同步外部修改）。
 *      accessToken 3 天有效；过期时自动调
 *      POST /v2/plugin/auth/token/refresh（X-Refresh-Token + X-Domain 头，逆向自 refreshSession）
 *      换新（refreshToken 7 天轮换）。只要 <7 天用一次即永续。
 *      ★ 完整登录流也已内置（逆向自 createSession/fetchAuthState/loopGetToken）:
 *        cb_login({trigger_browser_login:true}) → POST /v2/plugin/auth/state?platform=CLI
 *        拿 authUrl → 开浏览器 → 轮询 GET /v2/plugin/auth/token?state=（pending code=11217）
 *        → GET /v2/plugin/account → 写入 CLI 同款登录态文件。全程无需 CLI 参与。
 *      CLI 自己调搜索用的就是这个 accessToken（performWebSearch: Bearer auth.accessToken）。
 *   B. API key: CODEBUDDY_API_KEY / ~/.codebuddy-search-mcp/key（ck_ 前缀，实测直接可用）。
 *
 *   POST https://copilot.tencent.com/agenttool/v1/search
 *     Body: {query, type:"text2text", max_results, allowed_domains?, blocked_domains?, freshness?}
 *     响应: {provider, results:[{title,url,snippet,site?,favicon?}], total_results, response_time_ms}
 *     freshness 格式: "d"|"d1".."d30"|"m"|"m1".."m12"|"y"|"y1".."y5"
 *
 *   POST https://copilot.tencent.com/agenttool/v1/webfetch
 *     Body: {url, format:"markdown", prompt, timeout, max_length, model_name?}
 *     响应: {url, title, content, content_type, context?}
 *
 * 工具:
 *   cb_login        — 报告鉴权状态；trigger_browser_login=true 触发完整 OAuth 登录（开浏览器）
 *   cb_web_search   — 联网搜索
 *   cb_web_fetch    — 网页正文抓取（markdown）
 *
 * HTTP server 模式（codebuddy-search-mcp serve）— 实现标准 MCP OAuth（RFC 9728/7591/7636），
 * 使 `pi mcp login` 等宿主原生登录可用：
 *   POST /mcp                          Streamable HTTP MCP 端点（Bearer 鉴权）
 *   GET  /.well-known/oauth-protected-resource
 *   GET  /.well-known/oauth-authorization-server
 *   POST /register                     动态客户端注册（RFC 7591，public client）
 *   GET  /authorize                    授权码端点（PKCE S256），背后调 CodeBuddy 浏览器登录
 *   POST /token                        授权码换 token / refresh_token 续期（转发 CodeBuddy refresh）
 *
 * 登录态感知（stdio server 无法走宿主的 `pi mcp login`，那只支持 HTTP+OAuth server）：
 *   - initialize 返回 instructions，首行含当前鉴权状态；pi 等宿主会把它放进 system prompt，
 *     模型开机即知是否已登录。
 *   - 终端直登: npx codebuddy-search-mcp login / status。
 */
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const { exec } = require("node:child_process");

const API_BASE =
  process.env.CODEBUDDY_API_BASE ||
  (process.env.CODEBUDDY_INTERNET_ENVIRONMENT === "international"
    ? "https://www.codebuddy.ai"
    : "https://copilot.tencent.com");
const CLI_VERSION = process.env.CODEBUDDY_CLI_VERSION || "2.160.0";
const VERSION = (() => {
  try {
    return require("./package.json").version;
  } catch {
    return "1.3.0";
  }
})();
const STATE_DIR =
  process.env.CODEBUDDY_SEARCH_STATE_DIR || path.join(os.homedir(), ".codebuddy-search-mcp");
const KEY_FILE = path.join(STATE_DIR, "key");
const FRESHNESS_RE = /^(?:d(?:[1-9]|[12]\d|30)?|m(?:[1-9]|1[0-2])?|y[1-5]?)$/;

/* serve 模式配置（提前声明：cliMain 在模块加载完成前即被调用） */
const HTTP_PORT = parseInt(process.env.PORT || "3435", 10);
const HTTP_HOST = process.env.HOST || "127.0.0.1";

/* ---------------- OAuth 登录态（CLI 共享） ---------------- */

// CLI FileAuthenticationStorage: {sharedDataPath}/auth/{authId}.info（macOS: Application Support/CodeBuddyExtension/Data/Public）
function oauthDir() {
  if (process.env.CODEBUDDY_AUTH_DIR) return process.env.CODEBUDDY_AUTH_DIR;
  if (process.platform === "darwin")
    return path.join(os.homedir(), "Library/Application Support/CodeBuddyExtension/Data/Public/auth");
  if (process.platform === "win32")
    return path.join(os.homedir(), "AppData/Local/CodeBuddyExtension/Data/Public/auth");
  return path.join(os.homedir(), ".local/share/CodeBuddyExtension/Data/Public/auth");
}

function readOauthInfo() {
  try {
    const files = fs
      .readdirSync(oauthDir())
      .filter((f) => f.endsWith(".info") && !/\.\d{4}-\d{2}-\d{2}T/.test(f)); // 排除时间戳备份
    for (const f of files) {
      try {
        const d = JSON.parse(fs.readFileSync(path.join(oauthDir(), f), "utf8"));
        if (d?.auth?.accessToken) return { file: path.join(oauthDir(), f), data: d };
      } catch {}
    }
  } catch {}
  return null;
}

function writeOauthInfo(file, data) {
  try {
    const tmp = file + ".mcp-tmp";
    fs.writeFileSync(tmp, JSON.stringify(data, null, 1));
    fs.renameSync(tmp, file); // 原子写；CLI 有 watcher 会自动同步外部修改
    return true;
  } catch {
    return false;
  }
}

/* ---------------- 完整 OAuth 登录流（逆向自 CLI createSession） ---------------- */

const AUTH_ID = process.env.CODEBUDDY_AUTH_ID || "Tencent-Cloud.coding-copilot"; // embed 配置 authentication.id
const LOGIN_POLL_INTERVAL_MS = 2000; // CLI 用常量 v（实测 2s 量级），轮询间隔
const LOGIN_TIMEOUT_MS = 5 * 60_000;
const LOGIN_TOKEN_PENDING = 11217; // "login ing..."

function noAuthHeaders() {
  // CLI 登录轮询时带的豁免头（阻止 restOperations 拦截器注入默认鉴权）
  return {
    "X-No-Authorization": "true",
    "X-No-User-Id": "true",
    "X-No-Enterprise-Id": "true",
    "X-No-Department-Info": "true",
  };
}

function openBrowser(url) {
  const cmd =
    process.platform === "darwin"
      ? `open "${url}"`
      : process.platform === "win32"
        ? `start "" "${url}"`
        : `xdg-open "${url}"`;
  exec(cmd, () => {});
}

function readLoginEnvelopeCode(body) {
  if (!body || typeof body !== "object") return undefined;
  if (typeof body.code === "number") return body.code;
  const n = body.response?.data?.code ?? body.response?.code;
  return typeof n === "number" ? n : undefined;
}

async function restCall(method, apiPath, { headers = {}, timeoutMs = 15_000 } = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(`${API_BASE}${apiPath}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        "User-Agent": `CLI/${CLI_VERSION} CodeBuddy/${CLI_VERSION}`,
        ...headers,
      },
      ...(method === "POST" ? { body: "{}" } : {}),
      signal: ctl.signal,
    });
    const j = await res.json().catch(() => ({}));
    if (!res.ok) throw Object.assign(new Error(`HTTP ${res.status}: ${JSON.stringify(j).slice(0, 200)}`), { status: res.status });
    return j;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * 完整 OAuth 浏览器登录（与 codebuddy login 同放）：
 * auth/state 拿 authUrl → 开浏览器 → 轮询 auth/token（pending=11217）→ account → 写入 CLI 登录态文件。
 */
async function browserLogin({ onAuthUrl } = {}) {
  // 1. fetchAuthState
  const stateResp = await restCall("POST", "/v2/plugin/auth/state?platform=CLI", {
    headers: noAuthHeaders(),
  });
  const st = stateResp?.data?.data || stateResp?.data;
  if (!st?.state || !st?.authUrl) {
    throw new Error(`auth/state 响应异常: ${JSON.stringify(stateResp).slice(0, 300)}`);
  }

  // 2. 开浏览器（终端模式下先把 URL 打出来，浏览器没自动开时可手动复制）
  if (onAuthUrl) onAuthUrl(st.authUrl);
  openBrowser(st.authUrl);

  // 3. 轮询 token（浏览器授权完成后服务端放行）
  const deadline = Date.now() + LOGIN_TIMEOUT_MS;
  let auth;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, LOGIN_POLL_INTERVAL_MS));
    let resp;
    try {
      resp = await restCall("GET", `/v2/plugin/auth/token?state=${encodeURIComponent(st.state)}`, {
        headers: noAuthHeaders(),
      });
    } catch {
      continue; // 网络抖动重试
    }
    const d = resp?.data?.data ?? resp?.data;
    if (d && typeof d.accessToken === "string" && d.accessToken) {
      auth = d;
      break;
    }
    const code = readLoginEnvelopeCode(resp) ?? readLoginEnvelopeCode(d);
    if (code !== LOGIN_TOKEN_PENDING && code !== 0) {
      throw new Error(`登录轮询失败 code=${code}: ${resp?.msg || "unknown"}`);
    }
    // 11217 = pending，继续等
  }
  if (!auth) throw new Error(`登录超时（${LOGIN_TIMEOUT_MS / 1000}s 内未完成浏览器授权）`);

  auth.lastRefreshTime = Date.now();
  if (!auth.expiresAt && auth.expiresIn) auth.expiresAt = Date.now() + auth.expiresIn * 1000;
  if (!auth.refreshExpiresAt && auth.refreshExpiresIn)
    auth.refreshExpiresAt = Date.now() + auth.refreshExpiresIn * 1000;

  // 4. fetchCurrentAccount
  let account = {};
  try {
    const accResp = await restCall("GET", "/v2/plugin/account", {
      headers: {
        Authorization: `Bearer ${auth.accessToken}`,
        ...(auth.domain ? { "X-Domain": auth.domain } : {}),
      },
    });
    account = accResp?.data?.data || accResp?.data || {};
  } catch {}

  // 5. 写入 CLI 同款登录态文件（CLI watcher 自动同步，等于完成了 codebuddy login）
  const target = path.join(oauthDir(), `${AUTH_ID}.info`);
  const info = { account, auth, accounts: [account] };
  fs.mkdirSync(oauthDir(), { recursive: true });
  if (!writeOauthInfo(target, info)) throw new Error(`登录态写入失败: ${target}`);
  return { account: account.nickname || account.uid || "unknown", authUrl: st.authUrl };
}

/** 过期 OAuth token 自动续期（逆向自 CLI refreshSession: /v2/plugin/auth/token/refresh）。 */
async function refreshOauth(info) {
  const a = info.data.auth;
  if (!a.refreshToken)
    throw new Error("OAuth refreshToken 缺失，请调用 cb_login（trigger_browser_login:true）重新登录");
  if (a.refreshExpiresAt && a.refreshExpiresAt < Date.now())
    throw new Error(
      `OAuth refresh token 已于 ${new Date(a.refreshExpiresAt).toISOString()} 过期，请调用 cb_login（trigger_browser_login:true）重新登录`
    );
  const res = await fetch(`${API_BASE}/v2/plugin/auth/token/refresh`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Refresh-Token": a.refreshToken,
      "X-Auth-Refresh-Source": "plugin",
      ...(a.domain ? { "X-Domain": a.domain } : {}),
      "User-Agent": `CLI/${CLI_VERSION} CodeBuddy/${CLI_VERSION}`,
    },
    body: "{}",
  });
  const j = await res.json().catch(() => ({}));
  const auth = j?.data?.data || j?.data; // restOperations 响应格式 {data:{data:auth}}
  if (!res.ok || !auth?.accessToken) {
    throw new Error(`refresh 失败 (HTTP ${res.status}): ${j?.msg || j?.error_msg || JSON.stringify(j).slice(0, 200)}`);
  }
  auth.lastRefreshTime = Date.now();
  if (!auth.expiresAt && auth.expiresIn) auth.expiresAt = Date.now() + auth.expiresIn * 1000;
  if (!auth.refreshExpiresAt && auth.refreshExpiresIn)
    auth.refreshExpiresAt = Date.now() + auth.refreshExpiresIn * 1000;
  info.data.auth = auth;
  writeOauthInfo(info.file, info.data);
  return auth;
}

/**
 * 解析 Bearer：OAuth 优先（有效或可刷新），否则 API key。
 * 返回 {token, source}。
 */
async function resolveBearer() {
  const info = readOauthInfo();
  if (info) {
    const a = info.data.auth;
    if (a.expiresAt > Date.now() + 60_000) return { token: a.accessToken, source: "oauth" };
    try {
      const fresh = await refreshOauth(info);
      return { token: fresh.accessToken, source: "oauth-refreshed" };
    } catch (e) {
      const key = readApiKey();
      if (key) return { token: key, source: `api-key（OAuth 不可用: ${e.message}）` };
      throw e;
    }
  }
  const key = readApiKey();
  if (key) return { token: key, source: "api-key" };
  throw new Error(
    "无可用凭据：请调用 cb_login 工具并传 trigger_browser_login:true 完成 OAuth 登录" +
      "（或在终端运行 npx codebuddy-search-mcp login），也可配置 CODEBUDDY_API_KEY / ~/.codebuddy-search-mcp/key"
  );
}

/* ---------------- key ---------------- */

function readApiKey() {
  if (process.env.CODEBUDDY_API_KEY) return process.env.CODEBUDDY_API_KEY.trim();
  try {
    return fs.readFileSync(KEY_FILE, "utf8").trim() || null;
  } catch {
    return null;
  }
}

/* ---------------- API 调用 ---------------- */

async function apiCall(apiPath, body, timeoutMs = 25_000, bearer = null) {
  const { token, source } = bearer ?? (await resolveBearer());
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(`${API_BASE}${apiPath}`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": `CLI/${CLI_VERSION} CodeBuddy/${CLI_VERSION}`,
      },
      body: JSON.stringify(body),
      signal: ctl.signal,
    });
  } catch (e) {
    if (e.name === "AbortError") throw new Error(`请求超时（${timeoutMs / 1000}s）: ${apiPath}`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
  if (res.status === 401) {
    throw new Error(
      `401: 凭据无效或过期（${source}）。请调用 cb_login（trigger_browser_login:true）重新登录；或配置 API key。`
    );
  }
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`HTTP ${res.status} 非 JSON 响应: ${text.slice(0, 200)}`);
  }
  if (data.code) {
    throw new Error(`API 错误 code=${data.code}: ${data.msg || "unknown"}`);
  }
  return data;
}

/* ---------------- 工具实现 ---------------- */

async function toolLogin(args = {}) {
  // trigger_browser_login: 走完整 OAuth 浏览器登录（无需 CLI）
  if (args.trigger_browser_login || args.login) {
    const r = await browserLogin();
    return {
      ok: true,
      logged_in: true,
      account: r.account,
      login_url: r.authUrl, // 浏览器未自动打开时，把此 URL 给用户手动打开
      note: "登录态已写入 CLI 同款文件，OAuth 自动续期已接管",
    };
  }
  // 鉴权链路报告：OAuth 状态 + 实际生效的凭据来源
  const report = { api_base: API_BASE };
  const info = readOauthInfo();
  if (info) {
    const a = info.data.auth;
    report.oauth = {
      account: info.data.account?.nickname || info.data.account?.uid || "unknown",
      access_expires_at: a.expiresAt ? new Date(a.expiresAt).toISOString() : null,
      refresh_expires_at: a.refreshExpiresAt ? new Date(a.refreshExpiresAt).toISOString() : null,
      access_valid: a.expiresAt > Date.now(),
      refresh_valid: !a.refreshExpiresAt || a.refreshExpiresAt > Date.now(),
    };
    if (!report.oauth.refresh_valid) {
      report.hint = "OAuth 已过期，调用 cb_login 时传 trigger_browser_login: true 可直接重新登录（无需 CLI）";
    }
  } else {
    report.oauth = "未找到 CodeBuddy 登录态";
    report.hint = "调用 cb_login 时传 trigger_browser_login: true 可完成 OAuth 登录（无需 CLI）";
  }
  if (readApiKey()) report.api_key = (readApiKey() || "").slice(0, 10) + "…";
  const t0 = Date.now();
  try {
    const { token, source } = await resolveBearer();
    const d = await apiCall(
      "/agenttool/v1/search",
      { query: "test", type: "text2text", max_results: 1 },
      undefined,
      { token, source }
    );
    report.credential_source = source;
    report.provider = d.provider;
    report.latency_ms = Date.now() - t0;
    report.ok = true;
  } catch (e) {
    // 验证失败也要把状态报告和 hint 带回去，让模型知道下一步该调 cb_login（而不是丢掉整个报告）
    report.verification_error = e.message;
    report.ok = false;
    report.hint ||= "调用 cb_login 时传 trigger_browser_login: true 可完成 OAuth 登录（无需 CLI）";
  }
  return report;
}

async function toolSearch(args) {
  const query = (args.query || args.searchTerm || "").trim();
  if (!query || query.length < 2) throw new Error("query 不能为空（至少 2 字符）");
  const body = {
    query,
    type: "text2text",
    max_results: Math.min(Math.max(args.maxResults || 5, 1), 10),
  };
  if (Array.isArray(args.allowedDomains) && args.allowedDomains.length)
    body.allowed_domains = args.allowedDomains;
  if (Array.isArray(args.blockedDomains) && args.blockedDomains.length)
    body.blocked_domains = args.blockedDomains;
  if (args.freshness) {
    if (!FRESHNESS_RE.test(args.freshness)) {
      throw new Error('freshness 格式: "d"/"d1".."d30"/"m"/"m1".."m12"/"y"/"y1".."y5"');
    }
    body.freshness = args.freshness;
  }
  const d = await apiCall("/agenttool/v1/search", body);
  const results = (d.results || []).map((r) => ({
    title: r.title,
    url: r.url,
    snippet: r.snippet,
    ...(r.site ? { site: r.site } : {}),
  }));
  return {
    query,
    provider: d.provider ?? "",
    total_results: d.total_results ?? results.length,
    response_time_ms: d.response_time_ms ?? null,
    results,
  };
}

async function toolFetch(args) {
  if (!args.url) throw new Error("url 不能为空");
  const body = {
    url: args.url,
    format: "markdown",
    prompt: args.prompt || "extract the main content",
    timeout: 20,
    max_length: Math.min(Math.max(args.maxLength || 4000, 500), 20000),
  };
  const d = await apiCall("/agenttool/v1/webfetch", body, 40_000);
  let content = d.content || "";
  if (args.maxLength && content.length > args.maxLength) content = content.slice(0, args.maxLength) + "\n…[truncated]";
  return {
    url: d.url || args.url,
    title: d.title || "",
    content_type: d.content_type || "",
    content,
  };
}

/* ---------------- MCP stdio 协议 ---------------- */

const TOOLS = [
  {
    name: "cb_login",
    description:
      "CodeBuddy 鉴权管理：默认报告鉴权状态（OAuth 优先/API key 兜底）并验证；" +
      "传 trigger_browser_login:true 时触发完整 OAuth 浏览器登录（自动开浏览器、轮询拿 token、写入登录态），全程无需 codebuddy CLI。",
    inputSchema: {
      type: "object",
      properties: {
        trigger_browser_login: {
          type: "boolean",
          description: "触发 OAuth 浏览器登录（等同 codebuddy login，但由本 MCP 独立完成）",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "cb_web_search",
    description:
      "联网搜索（腾讯 CodeBuddy 服务端搜索，中文支持好，~2s 响应）。" +
      'freshness: "d"=当天,"m"=近一月,"y"=近一年（可带数字如 d7/m6/y2）。',
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "搜索词" },
        maxResults: { type: "number", description: "结果数上限，默认 5，最大 10" },
        allowedDomains: { type: "array", items: { type: "string" }, description: "只搜这些域名" },
        blockedDomains: { type: "array", items: { type: "string" }, description: "排除这些域名" },
        freshness: { type: "string", description: '时间过滤: "d"/"d1".."d30"/"m"/"m1".."m12"/"y"/"y1".."y5"' },
      },
      required: ["query"],
      additionalProperties: false,
    },
  },
  {
    name: "cb_web_fetch",
    description: "抓取网页正文（服务端渲染/提取，返回 markdown）。适合搜索后读全文。",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "目标 URL" },
        prompt: { type: "string", description: "处理提示（当前服务端忽略此参数）" },
        maxLength: { type: "number", description: "返回正文最大长度，默认 4000" },
      },
      required: ["url"],
      additionalProperties: false,
    },
  },
];

function rpcSend(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

/* ---------------- 登录态感知（instructions + CLI） ---------------- */

/** 本地鉴权状态（只读文件，不发网络请求）。 */
function authStatus() {
  const info = readOauthInfo();
  const key = readApiKey();
  const now = Date.now();
  if (info) {
    const a = info.data.auth;
    const account = info.data.account?.nickname || info.data.account?.uid || "unknown";
    if (a.expiresAt > now + 60_000)
      return { state: "ok", account, access_until: a.expiresAt, refresh_until: a.refreshExpiresAt };
    if (!a.refreshExpiresAt || a.refreshExpiresAt > now)
      return { state: "refreshable", account, access_until: a.expiresAt, refresh_until: a.refreshExpiresAt };
    return { state: "expired", account, access_until: a.expiresAt, refresh_until: a.refreshExpiresAt };
  }
  if (key) return { state: "api-key" };
  return { state: "none" };
}

function fmtDate(ms) {
  return ms ? new Date(ms).toISOString().slice(0, 10) : "?";
}

/**
 * initialize 返回的 instructions：宿主（pi 等）会取首行放进 system prompt 的 mcp_servers 区，
 * 模型开机即知登录状态。这是 stdio server 告知宿主鉴权状态的唯一通道。
 */
function buildInstructions() {
  const s = authStatus();
  let line;
  if (s.state === "ok")
    line = `鉴权: OAuth 有效（${s.account}，access 至 ${fmtDate(s.access_until)}）`;
  else if (s.state === "refreshable")
    line = `鉴权: OAuth 待续期（${s.account}，refresh 至 ${fmtDate(s.refresh_until)}，调用时自动续期）`;
  else if (s.state === "expired")
    line = "鉴权: ⚠ OAuth 已过期 — 调用 cb_login(trigger_browser_login=true) 重新登录";
  else if (s.state === "api-key") line = "鉴权: API key（无 OAuth 登录态）";
  else line = "鉴权: ⚠ 未登录 — 调用 cb_login(trigger_browser_login=true) 登录，或配置 CODEBUDDY_API_KEY";
  return (
    `CodeBuddy 联网搜索/网页抓取（中文优化）。${line}。\n` +
    "工具: cb_web_search(搜索) / cb_web_fetch(抓网页) / cb_login(鉴权状态与浏览器登录)。"
  );
}

/**
 * 终端模式（stdio server 走不了宿主的 `pi mcp login`——那只支持 HTTP+OAuth server，
 * 需要自带登录入口）:
 *   codebuddy-search-mcp login    发起 OAuth 浏览器登录（等同 codebuddy login）
 *   codebuddy-search-mcp status   查看本地鉴权状态
 */
async function cliMain() {
  const cmd = process.argv[2];
  if (cmd === "status") {
    const s = authStatus();
    console.log("CodeBuddy 鉴权状态:");
    if (s.state === "ok" || s.state === "refreshable" || s.state === "expired") {
      const label =
        { ok: "有效 ✅", refreshable: "待续期（调用时自动 refresh）", expired: "已过期 ⚠️" }[s.state];
      console.log(`  OAuth: ${label}`);
      console.log(`    账号: ${s.account}`);
      if (s.access_until) console.log(`    access token 至 ${new Date(s.access_until).toISOString()}`);
      if (s.refresh_until) console.log(`    refresh token 至 ${new Date(s.refresh_until).toISOString()}`);
      if (s.state === "expired") console.log("  → 重新登录: npx codebuddy-search-mcp login");
    } else if (s.state === "api-key") {
      console.log("  OAuth: 未找到登录态");
      console.log("  API key: 已配置 ✅");
    } else {
      console.log("  OAuth: 未找到登录态");
      console.log("  API key: 未配置");
      console.log("  → 登录: npx codebuddy-search-mcp login");
    }
    process.exit(0);
  }
  if (cmd === "login") {
    console.log("发起 CodeBuddy OAuth 登录…");
    const r = await browserLogin({
      onAuthUrl: (url) => {
        console.log(`登录 URL: ${url}`);
        console.log("（已尝试打开系统浏览器；未自动打开时手动复制上面的 URL）");
      },
    });
    const a = readOauthInfo()?.data?.auth || {};
    console.log(`✅ 登录成功: ${r.account}`);
    if (a.expiresAt) console.log(`  access token 至 ${new Date(a.expiresAt).toISOString()}`);
    if (a.refreshExpiresAt)
      console.log(`  refresh token 至 ${new Date(a.refreshExpiresAt).toISOString()}`);
    process.exit(0);
  }
  if (cmd === "serve") {
    startHttpServer(); // 常驻
    return;
  }
  if (cmd === "help" || cmd === "--help" || cmd === "-h") {
    console.log("用法: codebuddy-search-mcp [status|login|serve]  (无参数 = MCP stdio server 模式)");
    console.log("  serve  启动 HTTP MCP server（含标准 MCP OAuth，供 `pi mcp login` 等宿主登录）");
    process.exit(0);
  }
  console.error(`未知子命令: ${cmd}。用法: codebuddy-search-mcp [status|login|serve]`);
  process.exit(1);
}

async function handleCall(name, args) {
  if (name === "cb_login") return await toolLogin(args);
  if (name === "cb_web_search") return await toolSearch(args);
  if (name === "cb_web_fetch") return await toolFetch(args);
  throw new Error(`未知工具: ${name}`);
}

let buf = "";

function startMcp() {
  // 启动预检：无任何凭据时警告（stderr）。协议层的鉴权状态报告在 initialize 的 instructions 里。
  const info = readOauthInfo();
  const key = readApiKey();
  if (!info && !key) {
    process.stderr.write(
      `[codebuddy-search-mcp] 警告: 无 OAuth 登录态也无 API key。` +
        `请运行 npx codebuddy-search-mcp login（或在 agent 里调用 cb_login 工具传 trigger_browser_login:true）\n`
    );
  }
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (!line) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      handleRpc(msg).catch((e) => {
        if (msg.id !== undefined) {
          rpcSend({ jsonrpc: "2.0", id: msg.id, error: { code: -32603, message: String(e.message || e) } });
        }
      });
    }
  });
}

if (process.argv.length > 2) {
  cliMain().catch((e) => {
    console.error(`错误: ${e.message || e}`);
    process.exit(1);
  });
} else {
  startMcp();
}

/** 统一处理一条 MCP 消息，返回响应对象（通知返回 null）。stdio 与 HTTP 两种传输共用。 */
async function mcpResponse(msg) {
  if (msg.method === "initialize") {
    return {
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        instructions: buildInstructions(), // 首行含鉴权状态，宿主会放进 system prompt
        serverInfo: { name: "codebuddy-search-mcp", version: VERSION },
      },
    };
  }
  if (msg.method === "notifications/initialized") return null;
  if (msg.method === "tools/list") {
    return { jsonrpc: "2.0", id: msg.id, result: { tools: TOOLS } };
  }
  if (msg.method === "tools/call") {
    const { name, arguments: args = {} } = msg.params || {};
    try {
      const result = await handleCall(name, args);
      return {
        jsonrpc: "2.0",
        id: msg.id,
        result: { content: [{ type: "text", text: JSON.stringify(result, null, 1) }] },
      };
    } catch (e) {
      return {
        jsonrpc: "2.0",
        id: msg.id,
        result: { content: [{ type: "text", text: `错误: ${e.message}` }], isError: true },
      };
    }
  }
  if (msg.id !== undefined) {
    return { jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `method not found: ${msg.method}` } };
  }
  return null;
}

async function handleRpc(msg) {
  const r = await mcpResponse(msg);
  if (r) rpcSend(r);
}

/* ---------------- HTTP server 模式（标准 MCP OAuth，供 pi mcp login 等宿主） ----------------
 *
 * 设计要点：
 *   - 本地 HTTP MCP server（默认 127.0.0.1:3435，--port/--host 可调），Streamable HTTP，单 JSON-RPC 消息。
 *   - OAuth：对外是标准 RFC 9728 + 7591 + 7636（PKCE S256）授权服务器；对内把
 *     授权码流桥接到 CodeBuddy 私有浏览器登录（auth/state → auth/token 轮询 → 写 .info 文件）。
 *     宿主（pi 等）拿到的 access/refresh token 即 CodeBuddy token，与 CLI 登录态同源。
 *   - /token 的 refresh_token grant 转发 CodeBuddy /v2/plugin/auth/token/refresh，
 *     并同步写回 .info，使 HTTP 与 stdio/CLI 三端共享同一登录态。
 *   - 凭据为 opaque 随机 token，服务端映射验证；注册客户端/授权请求存内存，
 *     access/refresh token 本身无状态存储。serve 重启后需重新 login（pi 会自动提示）。
 *     （持久化 CLIENTS 可选：注册信息也可重新注册获得，代价只是 pi 端 sign-in 一次。）
 */

const AS_ISSUER = `http://${HTTP_HOST === "0.0.0.0" ? "127.0.0.1" : HTTP_HOST}:${HTTP_PORT}`;

// 内存态：已注册客户端 / 进行中的授权请求 / 已签发 token
const CLIENTS = new Map(); // clientId -> {client_id, client_name, redirect_uris, created_at}

// 注册客户端落盘（重启 serve 后 pi 复用旧 client_id 时仍可验证）
const CLIENT_STORE = path.join(STATE_DIR, "oauth-clients.json");
function saveClient(c) {
  try {
    const all = readClientStore();
    all[c.client_id] = c;
    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.writeFileSync(CLIENT_STORE, JSON.stringify(all));
  } catch {}
}
function readClientStore() {
  try {
    return JSON.parse(fs.readFileSync(CLIENT_STORE, "utf8")) || {};
  } catch {
    return {};
  }
}
function loadClient(clientId) {
  const c = readClientStore()[clientId];
  if (c) CLIENTS.set(clientId, c);
  return c || null;
}
const PENDING = new Map(); // state -> {code_challenge, redirect_uri, scope, client_id, expires}
const TOKENS = new Map(); // access token -> {codeBuddyAccessToken, expiresAt}

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function logSrv(...a) {
  process.stderr.write(a.join(" ") + "\n");
}

function validateRedirect(uri) {
  // RFC 8252 loopback：host 必须是 localhost / 127.0.0.1 / [::1]，且 http
  let u;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (u.protocol !== "http:") return false;
  return ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname === "::1" ? "[::1]" : u.hostname) ||
    u.hostname === "localhost";
}

function baseMetadata() {
  return {
    issuer: AS_ISSUER,
    authorization_endpoint: `${AS_ISSUER}/authorize`,
    token_endpoint: `${AS_ISSUER}/token`,
    registration_endpoint: `${AS_ISSUER}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
  };
}

/** 从 .info 提取 CodeBuddy auth（必须可用，否则登录失败） */
async function ensureCodeBuddyAuth() {
  const info = readOauthInfo();
  if (!info) throw new Error("无 CodeBuddy 登录态（先在终端完成一次 npx codebuddy-search-mcp login）");
  const a = info.data.auth;
  if (a.expiresAt > Date.now() + 60_000) return { info, auth: a };
  const fresh = await refreshOauth(info);
  return { info, auth: fresh };
}

function tokenTTL(auth) {
  const ms = auth.expiresAt ? auth.expiresAt - Date.now() - 60_000 : 3600_000;
  return Math.max(300_000, Math.min(ms, 3600_000)); // 5min ~ 1h
}

function startHttpServer() {
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const p = url.pathname;
    try {
      // ---------- discovery（RFC 9728 / RFC 8414，MCP 客户端兼容 OpenID 风格字段名） ----------
      if (req.method === "GET" && p === "/.well-known/oauth-protected-resource") {
        return sendJson(res, 200, {
          resource: `${AS_ISSUER}/mcp`,
          authorization_servers: [AS_ISSUER],
          scopes_supported: ["codebuddy:search"],
          resource_documentation: `${AS_ISSUER}/help`,
          resource_name: "codebuddy-search-mcp",
        });
      }
      if (req.method === "GET" && (p === "/.well-known/oauth-authorization-server" || p === "/.well-known/openid-configuration")) {
        const m = {
          ...baseMetadata(),
          registration_endpoint: `${AS_ISSUER}/register`,
        };
        return sendJson(res, 200, m);
      }

      // ---------- 动态客户端注册（RFC 7591，public client） ----------
      if (p === "/register" && req.method === "POST") {
        const body = await readBody(req);
        const redirect = Array.isArray(body.redirect_uris) ? body.redirect_uris.filter(validateRedirect) : [];
        if (!redirect.length) return sendJson(res, 400, { error: "invalid_redirect_uri", error_description: "redirect_uris 必须是 http(s) loopback" });
        const clientId = "cbmcp-" + b64url(crypto.randomBytes(16));
        const c = {
          client_id: clientId,
          client_name: body.client_name || "MCP client",
          redirect_uris: redirect,
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
          token_endpoint_auth_method: "none",
          client_id_issued_at: Math.floor(Date.now() / 1000),
        };
        CLIENTS.set(clientId, c);
        saveClient(c);
        return sendJson(res, 201, c);
      }

      // ---------- 授权端点（GET /authorize，PKCE S256） ----------
      if (p === "/authorize" && req.method === "GET") {
        const q = url.searchParams;
        const clientId = q.get("client_id");
        const redirectUri = q.get("redirect_uri");
        const challenge = q.get("code_challenge");
        const method = q.get("code_challenge_method") || "S256";
        const state = q.get("state") || "";
        const scope = q.get("scope") || "";
        let client = CLIENTS.get(clientId) || loadClient(clientId);
        if (!client && redirectUri && validateRedirect(redirectUri)) {
          // 兜底：客户端缓存了注册信息但本进程/存储丢失（loopback redirect 本地可信），自动补注册
          client = {
            client_id: clientId,
            client_name: "MCP client",
            redirect_uris: [redirectUri],
            grant_types: ["authorization_code", "refresh_token"],
            response_types: ["code"],
            token_endpoint_auth_method: "none",
          };
          CLIENTS.set(clientId, client);
          saveClient(client);
        }
        if (!client || !redirectUri || !client.redirect_uris.includes(redirectUri)) {
          return sendJson(res, 400, { error: "invalid_request", error_description: "client_id/redirect_uri 未注册或不匹配" });
        }
        if (!challenge || method !== "S256") {
          // 必须带 PKCE；错误回传给已验证的 redirect_uri
          const errUrl = new URL(redirectUri);
          errUrl.searchParams.set("error", "invalid_request");
          errUrl.searchParams.set("error_description", "code_challenge (S256) required");
          if (state) errUrl.searchParams.set("state", state);
          res.writeHead(302, { Location: errUrl.toString() });
          return res.end();
        }
        const txn = "tx-" + b64url(crypto.randomBytes(16));
        PENDING.set(txn, {
          code_challenge: challenge,
          redirect_uri: redirectUri,
          state,
          scope,
          client_id: clientId,
          expires: Date.now() + 300_000,
        });
        const authUrl = `${AS_ISSUER}/authorize/confirm?txn=${encodeURIComponent(txn)}`;
        if (q.get("response_type") !== "code") {
          const errUrl = new URL(redirectUri);
          errUrl.searchParams.set("error", "unsupported_response_type");
          if (state) errUrl.searchParams.set("state", state);
          res.writeHead(302, { Location: errUrl.toString() });
          return res.end();
        }
        // 302 到登录确认页（该页自动发起 CodeBuddy 浏览器登录）
        res.writeHead(302, { Location: authUrl });
        return res.end();
      }

      // ---------- 登录确认页：自动触发 CodeBuddy OAuth 浏览器登录 ----------
      if (p === "/authorize/confirm" && req.method === "GET") {
        const txn = url.searchParams.get("txn");
        const t = PENDING.get(txn);
        if (!t || t.expires < Date.now()) {
          return sendHtml(res, 400, "<h3>登录请求已过期，请重试 pi mcp login</h3>");
        }
        if (t.error) {
          return sendHtml(res, 500, `<h3>CodeBuddy 登录失败：${t.error}</h3><p>请重试 pi mcp login</p>`);
        }
        if (t.done && !t.code) {
          // 登录完成：生成授权码，302 回宿主 callback（同机 loopback 可达）
          t.code = "ac-" + b64url(crypto.randomBytes(24));
          t.codeExpires = Date.now() + 120_000;
          const cb = new URL(t.redirect_uri);
          cb.searchParams.set("code", t.code);
          if (t.state) cb.searchParams.set("state", t.state);
          res.writeHead(302, { Location: cb.toString() });
          return res.end();
        }
        if (t.started) {
          return sendHtml(res, 200, "<h3>CodeBuddy 登录处理中…（浏览器完成授权后此页自动刷新）</h3><script>setTimeout(()=>location.reload(),3000)</script>");
        }
        // 快路径：已有有效 CodeBuddy 登录态（含可刷新）则直接复用，不再开浏览器
        try {
          await ensureCodeBuddyAuth();
          t.done = true;
        } catch {
          t.started = false;
        }
        if (t.done) {
          // 登录完成：生成授权码，302 回宿主 callback（同机 loopback 可达）
          t.code = "ac-" + b64url(crypto.randomBytes(24));
          t.codeExpires = Date.now() + 120_000;
          const cb = new URL(t.redirect_uri);
          cb.searchParams.set("code", t.code);
          if (t.state) cb.searchParams.set("state", t.state);
          res.writeHead(302, { Location: cb.toString() });
          return res.end();
        }
        t.started = true;
        browserLogin({
          onAuthUrl: (authUrl) =>
            logSrv(`[serve] ${new Date().toISOString().slice(11, 19)} 浏览器登录 URL: ${authUrl}`),
        })
          .then(() => {
            t.done = true;
          })
          .catch((e) => {
            t.error = e.message || String(e);
          });
        return sendHtml(res, 200, "<h3>已打开浏览器进行 CodeBuddy 登录…完成后此页会自动跳转</h3><script>setTimeout(()=>location.reload(),3000)</script>");
      }

      // ---------- token 端点（授权码 + refresh_token） ----------
      if (p === "/token" && req.method === "POST") {
        const body = await readBody(req);
        const grant = body.grant_type;
        if (grant === "authorization_code") {
          const code = body.code || "";
          const entry = [...PENDING.entries()].find(([, v]) => v.code === code && v.codeExpires > Date.now());
          if (!entry) return sendJson(res, 400, { error: "invalid_grant" });
          const [txn, t] = entry;
          if (body.redirect_uri !== t.redirect_uri) return sendJson(res, 400, { error: "invalid_grant", error_description: "redirect_uri 不匹配" });
          if (!body.code_verifier) return sendJson(res, 400, { error: "invalid_request", error_description: "code_verifier required" });
          const expect = b64url(crypto.createHash("sha256").update(body.code_verifier).digest());
          if (expect !== t.code_challenge) return sendJson(res, 400, { error: "invalid_grant", error_description: "PKCE 校验失败" });
          if (t.error) {
            PENDING.delete(txn);
            return sendJson(res, 400, { error: "server_error", error_description: `CodeBuddy 登录失败: ${t.error}` });
          }
          if (!t.done) return sendJson(res, 400, { error: "authorization_pending", error_description: "CodeBuddy 浏览器登录尚未完成" });
          PENDING.delete(txn);
          return await issueToken(res);
        }
        if (grant === "refresh_token") {
          const rt = body.refresh_token || "";
          try {
            const payload = JSON.parse(Buffer.from(rt.replace(/^cbmcp-/, ""), "base64url").toString("utf8"));
            if (payload.p !== "rt" || payload.k !== "cb") throw new Error("bad");
            await ensureCodeBuddyAuth(); // 先确保 CodeBuddy 侧可用（顺带触发转发 refresh）
            return await issueToken(res);
          } catch {
            return sendJson(res, 400, { error: "invalid_grant", error_description: "refresh token 无效或 CodeBuddy 登录态不可用" });
          }
        }
        return sendJson(res, 400, { error: "unsupported_grant_type" });
      }

      // ---------- MCP 端点（Streamable HTTP，Bearer 鉴权） ----------
      if (p === "/mcp" || p === "/") {
        if (p !== "/mcp") {
          if (req.method === "GET") {
            return sendJson(res, 200, {
              server: "codebuddy-search-mcp",
              mode: "http",
              mcp_endpoint: "/mcp",
              oauth: true,
              usage: "pi mcp add codebuddy-search --url http://127.0.0.1:" + HTTP_PORT + "/mcp && pi mcp login codebuddy-search",
            });
          }
        }
        if (req.method === "POST") {
          const auth = req.headers.authorization || "";
          const m = /^Bearer\s+(.+)$/.exec(auth);
          const tok = m && TOKENS.get(m[1]);
          if (!tok) {
            res.writeHead(401, {
              "WWW-Authenticate": `Bearer resource_metadata="${AS_ISSUER}/.well-known/oauth-protected-resource"`,
              "Content-Type": "application/json",
            });
            return res.end(JSON.stringify({ error: "unauthorized", hint: "请通过宿主执行 pi mcp login codebuddy-search" }));
          }
          if (tok.expiresAt < Date.now()) {
            TOKENS.delete(m[1]);
            res.writeHead(401, {
              "WWW-Authenticate": `Bearer resource_metadata="${AS_ISSUER}/.well-known/oauth-protected-resource"`,
              "Content-Type": "application/json",
            });
            return res.end(JSON.stringify({ error: "invalid_token" }));
          }
          const msg = await readBody(req);
          const r = await mcpResponse(msg);
          res.writeHead(200, { "Content-Type": "application/json" });
          return res.end(JSON.stringify(r ?? { jsonrpc: "2.0", result: {} }));
        }
        res.writeHead(405);
        return res.end();
      }

      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("not found");
    } catch (e) {
      logSrv(`[serve] 处理 ${req.method} ${p} 出错:`, e.message || e);
      if (!res.headersSent) sendJson(res, 500, { error: "server_error", error_description: String(e.message || e) });
      else res.end();
    }
  });

  server.listen(HTTP_PORT, HTTP_HOST, () => {
    logSrv(
      `[serve] HTTP MCP server 已启动: http://${HTTP_HOST}:${HTTP_PORT}/mcp` +
        `（OAuth issuer: ${AS_ISSUER}）`
    );
    logSrv(`[serve] 接入示例: pi mcp add codebuddy-search --url http://127.0.0.1:${HTTP_PORT}/mcp`);
  });
  server.on("error", (e) => {
    if (e.code === "EADDRINUSE") {
      logSrv(`[serve] 端口 ${HTTP_PORT} 被占用，请用 PORT=xxx 指定其他端口`);
    } else {
      logSrv(`[serve] server error:`, e.message || e);
    }
    process.exit(1);
  });
}

/** 用当前 CodeBuddy 登录态签发一对 token 给宿主。 */
async function issueToken(res) {
  let auth;
  try {
    ({ auth } = await ensureCodeBuddyAuth());
  } catch (e) {
    return sendJson(res, 400, { error: "invalid_grant", error_description: `CodeBuddy 登录态不可用: ${e.message}` });
  }
  const access = b64url(crypto.randomBytes(32));
  const ttl = tokenTTL(auth);
  TOKENS.set(access, { codeBuddyAccessToken: auth.accessToken, expiresAt: Date.now() + ttl });
  const refreshToken = "cbmcp-" + b64url(JSON.stringify({ p: "rt", k: "cb", t: Date.now() }));
  return sendJson(res, 200, {
    access_token: access,
    token_type: "Bearer",
    expires_in: Math.floor(ttl / 1000),
    refresh_token: refreshToken,
    scope: "codebuddy:search",
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.setEncoding("utf8");
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      try {
        if (!data) return resolve({});
        const ct = req.headers["content-type"] || "";
        if (ct.includes("application/x-www-form-urlencoded") && !ct.includes("json")) {
          return resolve(Object.fromEntries(new URLSearchParams(data)));
        }
        resolve(JSON.parse(data)); // 默认当 JSON（MCP 端点等）
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(body);
}

function sendHtml(res, status, html) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
}
