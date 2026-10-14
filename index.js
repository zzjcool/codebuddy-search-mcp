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
 * 登录态感知（stdio server 无法走宿主的 `pi mcp login`，那只支持 HTTP+OAuth server）：
 *   - initialize 返回 instructions，首行含当前鉴权状态；pi 等宿主会把它放进 system prompt，
 *     模型开机即知是否已登录。
 *   - 终端直登: npx codebuddy-search-mcp login / status。
 */
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
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
  if (cmd === "help" || cmd === "--help" || cmd === "-h") {
    console.log("用法: codebuddy-search-mcp [status|login]  (无参数 = MCP stdio server 模式)");
    process.exit(0);
  }
  console.error(`未知子命令: ${cmd}。用法: codebuddy-search-mcp [status|login]`);
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

async function handleRpc(msg) {
  if (msg.method === "initialize") {
    return rpcSend({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        instructions: buildInstructions(), // 首行含鉴权状态，宿主会放进 system prompt
        serverInfo: { name: "codebuddy-search-mcp", version: VERSION },
      },
    });
  }
  if (msg.method === "notifications/initialized") return;
  if (msg.method === "tools/list") {
    return rpcSend({ jsonrpc: "2.0", id: msg.id, result: { tools: TOOLS } });
  }
  if (msg.method === "tools/call") {
    const { name, arguments: args = {} } = msg.params || {};
    try {
      const result = await handleCall(name, args);
      rpcSend({
        jsonrpc: "2.0",
        id: msg.id,
        result: { content: [{ type: "text", text: JSON.stringify(result, null, 1) }] },
      });
    } catch (e) {
      rpcSend({
        jsonrpc: "2.0",
        id: msg.id,
        result: { content: [{ type: "text", text: `错误: ${e.message}` }], isError: true },
      });
    }
    return;
  }
  if (msg.id !== undefined) {
    return rpcSend({
      jsonrpc: "2.0",
      id: msg.id,
      error: { code: -32601, message: `method not found: ${msg.method}` },
    });
  }
}
