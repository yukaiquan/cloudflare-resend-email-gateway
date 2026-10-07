import { createRemoteJWKSet, jwtVerify } from "jose";

const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
};

const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024;
const MAX_SUBJECT_BYTES = 998;
// JWKS 实例按 teamDomain 缓存；teamDomain 来自 env 通常只有一个 key，故无需主动清理。
// createRemoteJWKSet 内部会自动轮换密钥，缓存仅用于避免每次请求重建 RemoteJWKSet。
const ACCESS_JWKS_CACHE = new Map();

// 简单内存速率限制：基于发件人邮箱的滑动窗口计数。仅在同一 isolate 内生效，
// Worker 实例可能在多个边缘节点各自计数，因此是尽力而为的兜底，非强保证。
// 如需强一致限流，请改用 KV 或 Durable Object。
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 10;
const rateLimitBuckets = new Map();

export default {
  async fetch (request, env) {
    const url = new URL(request.url);

    // CORS 预检：所有路由统一处理。允许任意来源，但鉴权仍由各路由强制执行。
    // 注意：携带凭证（Cookie/JWT）时浏览器要求 ACAO 不能为 *；这里 Access JWT
    // 走 cf-access-jwt-assertion 头（Cloudflare 边缘注入），不依赖浏览器凭证，
    // 因此 * 是安全的。legacy API 用 Authorization 头，也不依赖 cookie。
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(),
      });
    }

    // 健康检查：不鉴权，仅返回存活状态，供 Cloudflare/外部监控探测。
    // 加 ?upstream=1 时额外探测 Resend API 联通性（GET /domains，验证 API key 且不发邮件），
    // 用于深度健康检查；默认不探测以避免消耗 Resend 配额。
    if (request.method === "GET" && url.pathname === "/health") {
      const base = { ok: true, ts: Date.now() };
      if (url.searchParams.get("upstream") === "1" && env.RESEND_API_KEY) {
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 5_000);
          const upstream = await fetch("https://api.resend.com/domains", {
            method: "GET",
            headers: { Authorization: `Bearer ${env.RESEND_API_KEY}` },
            signal: controller.signal,
          });
          clearTimeout(timeout);
          // 2xx 表示 API key 有效且 Resend 在线；4xx 也说明 Resend 可联通（只是 key 有问题）。
          return jsonResponse({
            ...base,
            upstream: "reachable",
            upstreamStatus: upstream.status,
            upstreamOk: upstream.ok,
          }, 200, corsHeaders());
        } catch (err) {
          const isTimeout = err && (err.name === "AbortError" || /abort/i.test(err.message || ""));
          return jsonResponse({
            ...base,
            upstream: isTimeout ? "timeout" : "unreachable",
            error: err.message || String(err),
          }, 200, corsHeaders());
        }
      }
      return jsonResponse(base, 200, corsHeaders());
    }

    if (request.method === "GET" && url.pathname === "/") {
      const access = await requireAccess(request, env);
      if (!access.ok) return access.response;
      // 每次请求生成随机 nonce，授权内联 style/script；CSP 阻止其他注入。
      const nonce = crypto.randomUUID();
      return htmlResponse(renderComposePage(request, env, access.userEmail, nonce), nonce);
    }

    if (request.method === "POST" && url.pathname === "/api/send") {
      const access = await requireAccess(request, env);
      if (!access.ok) return access.response;
      return handleSendRequest(request, env, {
        requireClientToken: false,
        accessUser: access.userEmail,
      });
    }

    // Legacy JSON API：与写信页路径分离，便于 Cloudflare Access 单独放行该路径
    // （Access 仅按路径排除，不区分方法；同路径下 GET / 是写信页，无法只放 POST /）。
    // 仅当显式配置 CLIENT_TOKEN 时启用；未配置时返回 404，避免成为开放中继。
    if (request.method === "POST" && url.pathname === "/api/legacy") {
      if (!env.CLIENT_TOKEN) {
        return jsonResponse({ error: "Not Found" }, 404, corsHeaders());
      }
      return handleSendRequest(request, env, { requireClientToken: true });
    }

    // 旧路径 POST / 保留 404，避免误用；引导调用方迁移到 /api/legacy。
    if (request.method === "POST" && url.pathname === "/") {
      return jsonResponse({ error: "Not Found. Use POST /api/legacy with CLIENT_TOKEN." }, 404, corsHeaders());
    }

    return jsonResponse({ error: "Not Found" }, 404, corsHeaders());
  },
};

function corsHeaders () {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, cf-access-jwt-assertion",
    "Access-Control-Max-Age": "86400",
  };
}

async function requireAccess (request, env) {
  const teamDomain = normalizeAccessTeamDomain(env.ACCESS_TEAM_DOMAIN);
  const audience = String(env.ACCESS_AUD || "").trim();

  if (!teamDomain || !audience) {
    return {
      ok: false,
      response: jsonResponse({
        error: "Cloudflare Access is not configured. Set ACCESS_TEAM_DOMAIN and ACCESS_AUD.",
      }, 403),
    };
  }

  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) {
    return {
      ok: false,
      response: jsonResponse({ error: "Cloudflare Access authentication is required." }, 401),
    };
  }

  try {
    const jwks = getAccessJwks(teamDomain);
    const { payload } = await jwtVerify(token, jwks, {
      issuer: teamDomain,
      audience,
    });

    // email 只信任 JWT payload，绝不 fallback 到请求头（Cf-Access-Authenticated-User-Email
    // 是请求头，客户端可伪造）。
    if (!payload.email) {
      return {
        ok: false,
        response: jsonResponse({ error: "Cloudflare Access token missing email claim." }, 403),
      };
    }
    return {
      ok: true,
      userEmail: String(payload.email),
    };
  } catch {
    return {
      ok: false,
      response: jsonResponse({ error: "Invalid Cloudflare Access token." }, 403),
    };
  }
}

function normalizeAccessTeamDomain (value) {
  const raw = String(value || "").trim().replace(/\/+$/, "");
  if (!raw) return "";
  if (raw.startsWith("https://")) return raw;
  if (raw.startsWith("http://")) return raw.replace(/^http:\/\//, "https://");
  return `https://${raw}`;
}

function getAccessJwks (teamDomain) {
  const certsUrl = `${teamDomain}/cdn-cgi/access/certs`;
  let jwks = ACCESS_JWKS_CACHE.get(certsUrl);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(certsUrl));
    ACCESS_JWKS_CACHE.set(certsUrl, jwks);
  }
  return jwks;
}

async function handleSendRequest (request, env, options) {
  try {
    let authenticatedUser = null;

    if (options.requireClientToken) {
      const authHeader = request.headers.get("Authorization");
      // 恒定时间比较 CLIENT_TOKEN，规避时序攻击。
      if (!authHeader || !await safeEqualBearer(authHeader, env.CLIENT_TOKEN)) {
        return jsonResponse({ error: "Unauthorized" }, 401);
      }
      authenticatedUser = "legacy-client-token";
    }

    const payload = await request.json();
    const normalized = normalizeEmailPayload(payload);
    if (normalized.error) {
      return jsonResponse({ error: normalized.error }, 400);
    }

    const fromEmail = env.FROM_EMAIL;
    if (!fromEmail) {
      return jsonResponse({
        error: "Configuration Error: FROM_EMAIL environment variable is not defined.",
      }, 500);
    }

    if (!env.RESEND_API_KEY) {
      return jsonResponse({
        error: "Configuration Error: RESEND_API_KEY secret is not defined.",
      }, 500);
    }

    if (options.accessUser) authenticatedUser = options.accessUser;

    // 速率限制（按发件人 + isolate 内滑动窗口，尽力而为）。
    const rateLimitKey = authenticatedUser || "anonymous";
    if (!checkRateLimit(rateLimitKey)) {
      return jsonResponse({
        error: "Rate limit exceeded. Please retry shortly.",
      }, 429);
    }

    // 给 Resend 加 15s 超时，避免下游慢响应拖垮 Worker。
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
    let response;
    try {
      response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: fromEmail,
          to: normalized.to,
          cc: normalized.cc,
          bcc: normalized.bcc,
          reply_to: normalized.replyTo,
          subject: normalized.subject,
          text: normalized.text,
          html: normalized.html,
          attachments: normalized.attachments,
        }),
        signal: controller.signal,
      });
    } catch (err) {
      clearTimeout(timeout);
      const isTimeout = err && (err.name === "AbortError" || /abort/i.test(err.message || ""));
      console.warn(JSON.stringify({
        event: "send_failed",
        user: authenticatedUser,
        to: normalized.to,
        subject: normalized.subject.slice(0, 80),
        status: "upstream_error",
        error: err.message || String(err),
      }));
      return jsonResponse({
        error: isTimeout ? "Upstream timeout. Please retry." : (err.message || "Upstream request failed"),
      }, 502, corsHeaders());
    } finally {
      clearTimeout(timeout);
    }

    const data = await safeReadJson(response);
    if (!response.ok) {
      console.warn(JSON.stringify({
        event: "send_failed",
        user: authenticatedUser,
        to: normalized.to,
        subject: normalized.subject.slice(0, 80),
        status: response.status,
        resendError: data,
      }));
      return jsonResponse({ success: false, error: data }, response.status);
    }

    console.info(JSON.stringify({
      event: "send_ok",
      user: authenticatedUser,
      to: normalized.to,
      cc: normalized.cc,
      bcc: normalized.bcc,
      subject: normalized.subject.slice(0, 80),
      resendId: data.id,
    }));

    return jsonResponse({ success: true, id: data.id });
  } catch (error) {
    return jsonResponse({ error: error.message || "Unexpected error" }, 500);
  }
}

async function safeEqualBearer (headerValue, expected) {
  const prefix = "Bearer ";
  if (!headerValue.startsWith(prefix)) return false;
  const provided = headerValue.slice(prefix.length);
  if (!provided || !expected) return false;
  const a = new TextEncoder().encode(provided);
  const b = new TextEncoder().encode(expected);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function safeReadJson (response) {
  const contentType = response.headers.get("Content-Type") || "";
  const text = await response.text();
  if (!contentType.toLowerCase().includes("application/json") || !text) {
    return { message: text || `HTTP ${response.status} with non-JSON body` };
  }
  try {
    return JSON.parse(text);
  } catch {
    return { message: text };
  }
}

function checkRateLimit (key) {
  const now = Date.now();
  const bucket = rateLimitBuckets.get(key);
  if (!bucket || now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
    // 顺手清理过期 bucket，避免长期运行的 isolate 累积陈旧 key。
    if (rateLimitBuckets.size > 1000) {
      for (const [k, v] of rateLimitBuckets) {
        if (now - v.windowStart > RATE_LIMIT_WINDOW_MS) rateLimitBuckets.delete(k);
      }
    }
    rateLimitBuckets.set(key, { windowStart: now, count: 1 });
    return true;
  }
  if (bucket.count >= RATE_LIMIT_MAX) return false;
  bucket.count += 1;
  return true;
}

function normalizeEmailPayload (payload) {
  const to = normalizeAddressList(payload.to);
  const cc = normalizeAddressList(payload.cc);
  const bcc = normalizeAddressList(payload.bcc);
  const replyTo = normalizeAddressList(payload.replyTo || payload.reply_to);
  // Subject 不允许 CR/LF，防止邮件头注入；并限制总字节数。
  const subject = String(payload.subject || "").replace(/[\r\n\u0000-\u001F\u007F]/g, " ").trim();
  if (subject && new TextEncoder().encode(subject).length > MAX_SUBJECT_BYTES) {
    return { error: "Subject is too long." };
  }
  const html = sanitizeHtml(String(payload.html || "").trim());
  const text = String(payload.text || "").trim();
  const attachments = normalizeAttachments(payload.attachments);

  if (!to.length) return { error: "At least one recipient is required." };
  if (!subject) return { error: "Subject is required." };
  if (!html && !text) return { error: "Email content is required." };
  if (to.length + cc.length + bcc.length + replyTo.length > 50) {
    return { error: "Too many recipients. Please keep To, Cc, Bcc, and Reply-To under 50 total addresses." };
  }

  const invalid = [...to, ...cc, ...bcc, ...replyTo].find((email) => !isValidEmail(email));
  if (invalid) return { error: `Invalid email address: ${invalid}` };

  if (attachments.error) return { error: attachments.error };

  return {
    to,
    cc: cc.length ? cc : undefined,
    bcc: bcc.length ? bcc : undefined,
    replyTo: replyTo.length ? replyTo : undefined,
    subject,
    html: html || undefined,
    text: text || stripHtml(html),
    attachments: attachments.files.length ? attachments.files : undefined,
  };
}

function normalizeAddressList (value) {
  if (!value) return [];
  const values = Array.isArray(value) ? value : String(value).split(/[,\n;]/);
  // 去重，避免重复收件人触发 Resend 配额或被收件方判定为垃圾邮件。
  const seen = new Set();
  const result = [];
  for (const item of values) {
    const addr = String(item).trim();
    if (addr && !seen.has(addr.toLowerCase())) {
      seen.add(addr.toLowerCase());
      result.push(addr);
    }
  }
  return result;
}

function normalizeAttachments (value) {
  if (!Array.isArray(value)) return { files: [] };

  let totalBytes = 0;
  const files = [];
  for (const item of value) {
    // 剥离路径分隔符与控制字符，防止路径穿越或非法文件名进入 Resend/收件方。
    const filename = String(item.filename || "")
      .replace(/[\\/]/g, "_")
      .replace(/[\r\n\t\u0000-\u001F\u007F]/g, "")
      .trim();
    const content = String(item.content || "");
    if (!filename || !content) continue;

    // 不信任客户端提供的 size；按 base64 实际长度计算解码后字节数。
    const base64Len = content.length;
    const padding = content.endsWith("==") ? 2 : content.endsWith("=") ? 1 : 0;
    const size = Math.max(0, Math.floor(base64Len * 3 / 4) - padding);
    totalBytes += size;
    if (totalBytes > MAX_ATTACHMENT_BYTES) {
      return { error: "Attachments are too large. Please keep the total under 10 MB." };
    }

    files.push({
      filename,
      content,
      content_type: String(item.contentType || item.content_type || "application/octet-stream"),
    });
  }

  return { files };
}

function isValidEmail (email) {
  // 严格化：本地段与域段长度限制、禁止首尾点、禁止连续点、域段至少一个点。
  // 本地段允许的字符中省略 backtick（邮箱地址本就不合法），与前端保持一致。
  // 仍为近似校验；最终合法性由 Resend/SMTP 判定，但能挡住明显的脏数据。
  const value = String(email || "");
  if (value.length > 254) return false;
  return /^[a-zA-Z0-9.!#$%&'*+/=?^_{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/.test(value)
    && !/\.\./.test(value)
    && !value.startsWith(".")
    && !/\.@/.test(value);
}

function stripHtml (html) {
  // 注意：必须先转 &amp; 再转其他实体，否则 &amp;lt; 会被双重解码成 <。
  // 这里用一次性 map 替换避免顺序依赖问题。
  const entities = { "&amp;": "&", "&nbsp;": " ", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#39;": "'" };
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|h[1-6]|li|tr)>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&(amp|nbsp|lt|gt|quot|#39);/g, (m) => entities[m] || m)
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

// 邮件 html 正文轻量 sanitize：保留常见格式标签与 inline style（邮件样式必需），
// 但移除 <script>、<iframe>、<object>、<embed>、on* 事件处理器、javascript:/data: URL 等
// 可被用于 XSS 或 BEC 攻击的载体。这不是完整的 sanitizer（完整方案需 DOM 解析），
// 但能挡住最常见的注入。发件人本身已通过 Access 鉴权，这里是纵深防御。
const SAFE_HTML_TAGS = /^(a|abbr|b|bdi|bdo|blockquote|br|caption|cite|code|dd|del|dfn|div|dl|dt|em|figcaption|figure|font|h[1-6]|hr|i|img|ins|kbd|li|mark|ol|p|pre|q|s|samp|small|span|strong|sub|sup|table|tbody|td|tfoot|th|thead|tr|u|ul|var|wbr)$/i;
const DANGEROUS_URL_PROTOCOLS = /^(javascript|data|vbscript|file):/i;

function sanitizeHtml (html) {
  if (!html) return "";
  let out = html;
  // 移除危险整块标签及其内容。
  out = out.replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<iframe[\s\S]*?<\/iframe>/gi, "")
    .replace(/<object[\s\S]*?<\/object>/gi, "")
    .replace(/<embed[\s\S]*?<\/embed>/gi, "")
    .replace(/<applet[\s\S]*?<\/applet>/gi, "")
    .replace(/<form[\s\S]*?<\/form>/gi, "");
  // 逐标签处理：移除非白名单标签（保留内容）与 on* 事件处理器、危险属性。
  out = out.replace(/<\/?([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>/g, (whole, tag, attrs) => {
    if (!SAFE_HTML_TAGS.test(tag)) return ""; // 非白名单标签：删除标签本身（保留内部文本）
    if (whole.startsWith("</")) return `</${tag.toLowerCase()}>`;
    // 过滤属性：移除 on* 事件、javascript:/data: URL、style 中的 expression。
    const cleanedAttrs = attrs.replace(/\s+on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "")
      .replace(/(href|src)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, (m, attr, val) => {
        const v = val.replace(/^["']|["']$/g, "");
        if (/^\s*javascript:/i.test(v) || /^\s*data:/i.test(v) || /^\s*vbscript:/i.test(v) || /^\s*file:/i.test(v)) {
          return "";
        }
        return m;
      })
      .replace(/expression\s*\(/gi, "expression(");
    return `<${tag.toLowerCase()}${cleanedAttrs}>`;
  });
  // 移除残留的注释（IE 条件注释可执行脚本）。
  out = out.replace(/<!--[\s\S]*?-->/g, "");
  return out.trim();
}

function jsonResponse (body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...extraHeaders },
  });
}

function htmlResponse (body, nonce) {
  const headers = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
  };
  if (nonce) {
    // 内联 style/script 用 nonce 授权；其余资源走 default-src 'none'，
    // 不加载任何外部资源（无 CDN、无外链字体、无图片），connect-src 仅放行本机 API。
    headers["Content-Security-Policy"] =
      `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; ` +
      `img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`;
  }
  return new Response(body, { headers });
}

function renderComposePage (request, env, accessUser, nonce) {
  const fromEmail = env.FROM_EMAIL || "未配置 FROM_EMAIL";

  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>写邮件</title>
  <style nonce="${nonce}">
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --line: #d8dee8;
      --line-strong: #bac5d3;
      --text: #1d2733;
      --muted: #637083;
      --accent: #1463ff;
      --accent-weak: #e8f0ff;
      --danger: #b42318;
      --success: #067647;
      --shadow: 0 16px 36px rgba(22, 34, 51, 0.10);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      background:
        linear-gradient(180deg, #eef3fa 0, var(--bg) 260px),
        var(--bg);
    }

    button,
    input,
    textarea,
    select {
      font: inherit;
    }

    .app {
      display: grid;
      grid-template-rows: auto 1fr;
      min-height: 100vh;
    }

    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 14px 24px;
      border-bottom: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.86);
      backdrop-filter: blur(16px);
      position: sticky;
      top: 0;
      z-index: 5;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      min-width: 0;
    }

    .brand-mark {
      display: grid;
      place-items: center;
      width: 36px;
      height: 36px;
      border-radius: 8px;
      color: #fff;
      background: #111827;
      font-weight: 800;
    }

    .brand-title {
      display: grid;
      gap: 1px;
      min-width: 0;
    }

    .brand-title strong {
      font-size: 15px;
      line-height: 1.2;
    }

    .brand-title span,
    .identity {
      color: var(--muted);
      font-size: 12px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .identity {
      text-align: right;
      max-width: 40vw;
    }

    .workspace {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 320px;
      gap: 18px;
      width: min(1360px, 100%);
      margin: 0 auto;
      padding: 20px 24px 24px;
    }

    .composer,
    .side {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      min-width: 0;
    }

    .composer {
      display: grid;
      grid-template-rows: auto auto auto minmax(360px, 1fr) auto;
      min-height: calc(100vh - 110px);
    }

    .message-row {
      display: grid;
      grid-template-columns: 86px minmax(0, 1fr);
      gap: 12px;
      align-items: start;
      min-height: 54px;
      padding: 10px 16px;
      border-bottom: 1px solid var(--line);
    }

    .message-row label {
      color: var(--muted);
      font-size: 13px;
      padding-top: 9px;
    }

    .recipient-box {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
      min-height: 34px;
      padding: 2px 0;
    }

    .chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      max-width: 100%;
      min-height: 28px;
      padding: 3px 8px;
      border-radius: 6px;
      background: var(--accent-weak);
      color: #0d3f9f;
      font-size: 13px;
    }

    .chip[data-invalid="true"] {
      background: #fff0ef;
      color: var(--danger);
    }

    .chip span {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .chip button,
    .icon-button {
      border: 0;
      background: transparent;
      color: inherit;
      cursor: pointer;
    }

    .chip button {
      width: 18px;
      height: 18px;
      padding: 0;
      line-height: 18px;
      border-radius: 4px;
    }

    .address-input,
    .subject-input,
    .reply-input {
      min-width: 160px;
      flex: 1 1 180px;
      height: 32px;
      border: 0;
      outline: 0;
      color: var(--text);
      background: transparent;
    }

    .subject-input,
    .reply-input {
      width: 100%;
      flex: none;
      font-size: 15px;
    }

    .field-actions {
      display: flex;
      align-items: center;
      gap: 8px;
      justify-content: flex-end;
    }

    .link-button {
      border: 0;
      padding: 0;
      background: transparent;
      color: var(--accent);
      cursor: pointer;
      font-size: 13px;
    }

    .optional-row[hidden] {
      display: none;
    }

    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      background: #fbfcfe;
    }

    .toolbar-group {
      display: inline-flex;
      align-items: center;
      gap: 2px;
      padding-right: 7px;
      margin-right: 1px;
      border-right: 1px solid var(--line);
    }

    .toolbar-group:last-child {
      border-right: 0;
    }

    .icon-button {
      display: inline-grid;
      place-items: center;
      width: 32px;
      height: 32px;
      border-radius: 6px;
      color: #2f3a4a;
    }

    .icon-button:hover,
    .icon-button.is-active {
      background: #e9edf5;
    }

    .icon-button svg {
      width: 17px;
      height: 17px;
      stroke: currentColor;
      stroke-width: 2;
      fill: none;
      stroke-linecap: round;
      stroke-linejoin: round;
    }

    .toolbar-select,
    .color-input {
      height: 32px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
    }

    .toolbar-select {
      max-width: 132px;
      padding: 0 8px;
    }

    .color-input {
      width: 34px;
      padding: 3px;
      cursor: pointer;
    }

    .editor-wrap {
      min-height: 360px;
      overflow: auto;
    }

    .editor {
      min-height: 100%;
      padding: 24px 28px 40px;
      outline: 0;
      line-height: 1.6;
      font-size: 15px;
      word-break: break-word;
    }

    .editor:empty::before {
      content: attr(data-placeholder);
      color: #9aa5b5;
    }

    .editor blockquote {
      margin: 1em 0;
      padding-left: 14px;
      border-left: 3px solid var(--line-strong);
      color: #4b596b;
    }

    .modal-backdrop {
      position: fixed;
      inset: 0;
      display: grid;
      place-items: center;
      background: rgba(15, 23, 42, 0.45);
      z-index: 50;
    }

    .modal-backdrop[hidden] { display: none; }

    .modal {
      width: min(420px, 92vw);
      padding: 18px 18px 14px;
      border-radius: 10px;
      background: var(--panel);
      box-shadow: var(--shadow);
      display: grid;
      gap: 12px;
    }

    .modal h3 {
      margin: 0;
      font-size: 15px;
    }

    .modal label {
      display: grid;
      gap: 4px;
      font-size: 12px;
      color: var(--muted);
    }

    .modal input {
      height: 34px;
      padding: 0 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      color: var(--text);
      background: #fff;
    }

    .modal-actions {
      display: flex;
      justify-content: flex-end;
      gap: 8px;
    }

    .composer-footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 12px 16px;
      border-top: 1px solid var(--line);
      background: #fbfcfe;
      border-radius: 0 0 8px 8px;
    }

    .send-group {
      display: flex;
      align-items: center;
      gap: 10px;
      min-width: 0;
    }

    .send-button {
      min-width: 116px;
      height: 38px;
      border: 0;
      border-radius: 7px;
      color: #fff;
      background: var(--accent);
      font-weight: 700;
      cursor: pointer;
    }

    .send-button:disabled {
      cursor: wait;
      opacity: 0.65;
    }

    .secondary-button {
      height: 34px;
      border: 1px solid var(--line);
      border-radius: 7px;
      color: #253247;
      background: #fff;
      cursor: pointer;
    }

    .status {
      min-width: 0;
      color: var(--muted);
      font-size: 13px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .status.error { color: var(--danger); }
    .status.success { color: var(--success); }

    .side {
      display: flex;
      flex-direction: column;
      align-self: start;
      overflow: hidden;
    }

    .side-section {
      padding: 16px;
      border-bottom: 1px solid var(--line);
    }

    .side-section:last-child {
      border-bottom: 0;
    }

    .side-section h2 {
      margin: 0 0 10px;
      font-size: 13px;
      line-height: 1.3;
      color: #344054;
    }

    .side-section p,
    .meta-list {
      margin: 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }

    .meta-list {
      display: grid;
      gap: 8px;
    }

    .meta-list div {
      display: grid;
      gap: 2px;
    }

    .meta-list strong {
      color: var(--text);
      font-weight: 650;
      overflow-wrap: anywhere;
    }

    .file-input {
      width: 100%;
      color: var(--muted);
      font-size: 13px;
    }

    .dropzone {
      margin-top: 10px;
      padding: 14px;
      border: 1px dashed var(--line-strong);
      border-radius: 7px;
      color: var(--muted);
      font-size: 12px;
      text-align: center;
      transition: background 0.15s, border-color 0.15s;
    }

    .dropzone.is-dragover {
      background: var(--accent-weak);
      border-color: var(--accent);
      color: var(--accent);
    }

    .attachments {
      display: grid;
      gap: 8px;
      margin-top: 12px;
    }

    .attachment {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 8px;
      align-items: center;
      padding: 8px;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: #fbfcfe;
      font-size: 13px;
    }

    .attachment span {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .attachment button {
      border: 0;
      background: transparent;
      color: var(--danger);
      cursor: pointer;
    }

    @media (max-width: 980px) {
      .workspace {
        grid-template-columns: 1fr;
      }

      .composer {
        min-height: 680px;
      }

      .side {
        order: -1;
      }
    }

    @media (max-width: 640px) {
      .topbar {
        align-items: flex-start;
        padding: 12px 14px;
      }

      .identity {
        display: none;
      }

      .workspace {
        padding: 12px;
      }

      .message-row {
        grid-template-columns: 1fr;
        gap: 4px;
        padding: 10px 12px;
      }

      .message-row label {
        padding-top: 0;
      }

      .composer-footer {
        align-items: stretch;
        flex-direction: column;
      }

      .send-group {
        width: 100%;
      }

      .send-button,
      .secondary-button {
        flex: 1;
      }
    }
  </style>
</head>
<body>
  <div class="app">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">M</div>
        <div class="brand-title">
          <strong>写邮件</strong>
          <span>Cloudflare Access 保护的发信入口</span>
        </div>
      </div>
      <div class="identity">${escapeHtml(accessUser || "Access 用户")}</div>
    </header>

    <main class="workspace">
      <form class="composer" id="composeForm">
        <div class="message-row">
          <label for="toInput">收件人</label>
          <div>
            <div class="recipient-box" data-field="to">
              <input class="address-input" id="toInput" autocomplete="off" placeholder="输入邮箱后按 Enter">
            </div>
            <div class="field-actions">
              <button class="link-button" type="button" data-toggle="ccRow">Cc</button>
              <button class="link-button" type="button" data-toggle="bccRow">Bcc</button>
            </div>
          </div>
        </div>

        <div class="message-row optional-row" id="ccRow" hidden>
          <label for="ccInput">Cc</label>
          <div class="recipient-box" data-field="cc">
            <input class="address-input" id="ccInput" autocomplete="off" placeholder="抄送">
          </div>
        </div>

        <div class="message-row optional-row" id="bccRow" hidden>
          <label for="bccInput">Bcc</label>
          <div class="recipient-box" data-field="bcc">
            <input class="address-input" id="bccInput" autocomplete="off" placeholder="密送">
          </div>
        </div>

        <div class="message-row">
          <label for="subjectInput">主题</label>
          <input class="subject-input" id="subjectInput" autocomplete="off" placeholder="邮件主题">
        </div>

        <div class="toolbar" aria-label="格式工具栏">
          <div class="toolbar-group">
            <select class="toolbar-select" id="blockFormat" title="段落格式">
              <option value="P">正文</option>
              <option value="H1">标题 1</option>
              <option value="H2">标题 2</option>
              <option value="H3">标题 3</option>
              <option value="BLOCKQUOTE">引用</option>
            </select>
          </div>
          <div class="toolbar-group">
            <button class="icon-button" type="button" data-command="bold" title="加粗"><strong>B</strong></button>
            <button class="icon-button" type="button" data-command="italic" title="斜体"><em>I</em></button>
            <button class="icon-button" type="button" data-command="underline" title="下划线"><u>U</u></button>
            <button class="icon-button" type="button" data-command="strikeThrough" title="删除线"><s>S</s></button>
          </div>
          <div class="toolbar-group">
            <button class="icon-button" type="button" data-command="insertUnorderedList" title="项目符号">
              <svg viewBox="0 0 24 24"><path d="M8 6h13M8 12h13M8 18h13"/><path d="M3 6h.01M3 12h.01M3 18h.01"/></svg>
            </button>
            <button class="icon-button" type="button" data-command="insertOrderedList" title="编号列表">
              <svg viewBox="0 0 24 24"><path d="M10 6h11M10 12h11M10 18h11"/><path d="M4 6h1v4M4 10h2M4 14h2l-2 4h2"/></svg>
            </button>
            <button class="icon-button" type="button" data-command="outdent" title="减少缩进">
              <svg viewBox="0 0 24 24"><path d="M11 6h10M11 12h10M11 18h10"/><path d="m7 8-4 4 4 4"/></svg>
            </button>
            <button class="icon-button" type="button" data-command="indent" title="增加缩进">
              <svg viewBox="0 0 24 24"><path d="M11 6h10M11 12h10M11 18h10"/><path d="m3 8 4 4-4 4"/></svg>
            </button>
          </div>
          <div class="toolbar-group">
            <button class="icon-button" type="button" data-command="justifyLeft" title="左对齐">
              <svg viewBox="0 0 24 24"><path d="M3 6h18M3 12h12M3 18h16"/></svg>
            </button>
            <button class="icon-button" type="button" data-command="justifyCenter" title="居中">
              <svg viewBox="0 0 24 24"><path d="M3 6h18M7 12h10M5 18h14"/></svg>
            </button>
            <button class="icon-button" type="button" data-command="justifyRight" title="右对齐">
              <svg viewBox="0 0 24 24"><path d="M3 6h18M9 12h12M5 18h16"/></svg>
            </button>
          </div>
          <div class="toolbar-group">
            <input class="color-input" id="foreColor" type="color" value="#1d2733" title="文字颜色">
            <input class="color-input" id="backColor" type="color" value="#fff2a8" title="背景颜色">
            <button class="icon-button" type="button" id="linkButton" title="插入链接">
              <svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
            </button>
            <button class="icon-button" type="button" data-command="removeFormat" title="清除格式">
              <svg viewBox="0 0 24 24"><path d="m4 7 7 7"/><path d="m9 5 10 10"/><path d="M6 19h12"/><path d="m14 4-9 9 5 5 9-9z"/></svg>
            </button>
          </div>
          <div class="toolbar-group">
            <button class="icon-button" type="button" data-command="undo" title="撤销">
              <svg viewBox="0 0 24 24"><path d="M9 14 4 9l5-5"/><path d="M4 9h10a6 6 0 0 1 0 12h-1"/></svg>
            </button>
            <button class="icon-button" type="button" data-command="redo" title="重做">
              <svg viewBox="0 0 24 24"><path d="m15 14 5-5-5-5"/><path d="M20 9H10a6 6 0 0 0 0 12h1"/></svg>
            </button>
          </div>
        </div>

        <div class="editor-wrap">
          <div class="editor" id="editor" contenteditable="true" data-placeholder="输入邮件正文..."></div>
        </div>

        <footer class="composer-footer">
          <div class="send-group">
            <button class="send-button" id="sendButton" type="submit">发送</button>
            <button class="secondary-button" id="clearButton" type="button">清空</button>
          </div>
          <div class="status" id="status" role="status">准备就绪</div>
        </footer>
      </form>

      <aside class="side">
        <section class="side-section">
          <h2>发件信息</h2>
          <div class="meta-list">
            <div>
              <span>From</span>
              <strong>${escapeHtml(fromEmail)}</strong>
            </div>
            <div>
              <span>Reply-To</span>
              <input class="reply-input" id="replyToInput" autocomplete="off" placeholder="可选">
            </div>
          </div>
        </section>

        <section class="side-section">
          <h2>附件</h2>
          <input class="file-input" id="fileInput" type="file" multiple>
          <div class="dropzone" id="dropzone">或将文件拖到此处</div>
          <div class="attachments" id="attachments"></div>
        </section>

        <section class="side-section">
          <h2>发送说明</h2>
          <p>此页面已要求 Cloudflare Access JWT 验证；页面提交到同一个 Worker 的 <strong>/api/send</strong>，不会要求填写 CLIENT_TOKEN。</p>
        </section>
      </aside>
    </main>
  </div>

  <script nonce="${nonce}">
    const state = {
      to: [],
      cc: [],
      bcc: [],
      attachments: [],
    };

    const editor = document.getElementById("editor");
    const statusEl = document.getElementById("status");
    const sendButton = document.getElementById("sendButton");
    const subjectInput = document.getElementById("subjectInput");
    const replyToInput = document.getElementById("replyToInput");
    const fileInput = document.getElementById("fileInput");
    const attachmentsEl = document.getElementById("attachments");

    document.querySelectorAll("[data-toggle]").forEach((button) => {
      button.addEventListener("click", () => {
        const row = document.getElementById(button.dataset.toggle);
        row.hidden = false;
        const input = row.querySelector("input");
        input.focus();
        button.hidden = true;
      });
    });

    document.querySelectorAll(".recipient-box").forEach((box) => {
      const field = box.dataset.field;
      const input = box.querySelector("input");

      input.addEventListener("keydown", (event) => {
        if (["Enter", "Tab", ",", ";"].includes(event.key)) {
          event.preventDefault();
          addAddresses(field, input.value);
          input.value = "";
        }

        if (event.key === "Backspace" && !input.value && state[field].length) {
          state[field].pop();
          renderRecipients(field);
        }
      });

      input.addEventListener("paste", (event) => {
        const text = event.clipboardData.getData("text");
        if (/[\\n,;]/.test(text)) {
          event.preventDefault();
          addAddresses(field, text);
          input.value = "";
        }
      });

      input.addEventListener("blur", () => {
        addAddresses(field, input.value);
        input.value = "";
      });
    });

    document.querySelectorAll("[data-command]").forEach((button) => {
      button.addEventListener("click", () => runCommand(button.dataset.command));
    });

    document.getElementById("blockFormat").addEventListener("change", (event) => {
      runCommand("formatBlock", event.target.value);
      event.target.value = "P";
    });

    document.getElementById("foreColor").addEventListener("input", (event) => {
      runCommand("foreColor", event.target.value);
    });

    document.getElementById("backColor").addEventListener("input", (event) => {
      runCommand("hiliteColor", event.target.value);
    });

    document.getElementById("linkButton").addEventListener("click", () => openLinkModal());

    document.getElementById("clearButton").addEventListener("click", () => {
      if (!confirm("清空当前邮件内容？")) return;
      state.to = [];
      state.cc = [];
      state.bcc = [];
      state.attachments = [];
      ["to", "cc", "bcc"].forEach(renderRecipients);
      renderAttachments();
      subjectInput.value = "";
      replyToInput.value = "";
      editor.innerHTML = "";
      fileInput.value = "";
      setStatus("已清空");
    });

    fileInput.addEventListener("change", async () => {
      const selected = Array.from(fileInput.files || []);
      if (selected.length) await addAttachmentFiles(selected);
      fileInput.value = "";
    });

    // 附件添加公共逻辑：fileInput change 与 drop 共用，含大小校验。
    async function addAttachmentFiles(files) {
      const existingBytes = state.attachments.reduce((sum, file) => sum + file.size, 0);
      const selectedBytes = files.reduce((sum, file) => sum + file.size, 0);
      if (existingBytes + selectedBytes > ${MAX_ATTACHMENT_BYTES}) {
        setStatus("附件总大小不能超过 10 MB", "error");
        return;
      }
      for (const file of files) {
        const content = await readFileAsBase64(file);
        state.attachments.push({
          filename: file.name,
          content,
          contentType: file.type || "application/octet-stream",
          size: file.size,
        });
      }
      renderAttachments();
    }

    // Ctrl/Cmd + Enter 快速发送。
    document.addEventListener("keydown", (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
        event.preventDefault();
        document.getElementById("composeForm").requestSubmit();
      }
    });

    // 附件拖拽上传。
    const dropzone = document.getElementById("dropzone");
    ["dragenter", "dragover"].forEach((evt) => {
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        dropzone.classList.add("is-dragover");
      });
    });
    ["dragleave", "drop"].forEach((evt) => {
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        dropzone.classList.remove("is-dragover");
      });
    });
    dropzone.addEventListener("drop", async (e) => {
      const dropped = Array.from(e.dataTransfer.files || []);
      if (!dropped.length) return;
      await addAttachmentFiles(dropped);
    });

    let isSending = false;
    document.getElementById("composeForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      // 重入守卫：Ctrl+Enter 快连按 / 双击提交时避免并发发出多封。
      if (isSending) return;
      flushAddressInputs();

      const payload = {
        to: state.to,
        cc: state.cc,
        bcc: state.bcc,
        replyTo: replyToInput.value.trim(),
        subject: subjectInput.value.trim(),
        html: normalizeHtml(editor.innerHTML),
        text: editor.textContent.trim(),
        attachments: state.attachments,
      };

      if (!payload.to.length) return setStatus("请至少填写一个收件人", "error");
      if (!payload.subject) return setStatus("请填写主题", "error");
      if (!payload.text && !payload.html) return setStatus("请填写正文", "error");

      isSending = true;
      sendButton.disabled = true;
      setStatus("正在发送...");

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 20_000);
      try {
        const response = await fetch("/api/send", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });
        const data = await response.json();
        if (!response.ok || !data.success) {
          throw new Error(readableError(data));
        }
        setStatus("发送成功" + (data.id ? "：" + data.id : ""), "success");
        resetComposeForm();
      } catch (error) {
        const msg = error && error.name === "AbortError"
          ? "发送超时，请稍后重试"
          : (error.message || "发送失败");
        setStatus(msg, "error");
      } finally {
        clearTimeout(timeout);
        isSending = false;
        sendButton.disabled = false;
      }
    });

    function resetComposeForm() {
      state.to = [];
      state.cc = [];
      state.bcc = [];
      state.attachments = [];
      ["to", "cc", "bcc"].forEach(renderRecipients);
      renderAttachments();
      subjectInput.value = "";
      replyToInput.value = "";
      editor.innerHTML = "";
      fileInput.value = "";
    }

    // 链接插入：自定义弹窗，并仅允许 http/https/mailto 协议，
    // 拒绝 javascript:/data:/file: 等可被用于 XSS 的危险协议。
    const SAFE_LINK_PROTOCOLS = new Set(["http:", "https:", "mailto:"]);

    function openLinkModal() {
      let backdrop = document.getElementById("linkModal");
      if (!backdrop) {
        backdrop = document.createElement("div");
        backdrop.id = "linkModal";
        backdrop.className = "modal-backdrop";
        backdrop.hidden = true;
        backdrop.innerHTML = '<div class="modal" role="dialog" aria-modal="true">' +
          '<h3>插入链接</h3>' +
          '<label>链接地址<input id="linkUrl" type="url" placeholder="https://example.com"></label>' +
          '<label>显示文本（可选）<input id="linkText" type="text" placeholder="点击查看"></label>' +
          '<div class="modal-actions">' +
          '<button class="secondary-button" id="linkCancel" type="button">取消</button>' +
          '<button class="send-button" id="linkOk" type="button" style="min-width:80px">插入</button>' +
          '</div></div>';
        document.body.append(backdrop);
        backdrop.addEventListener("click", (e) => {
          if (e.target === backdrop) closeModal(backdrop);
        });
        document.getElementById("linkCancel").addEventListener("click", () => closeModal(backdrop));
        document.getElementById("linkOk").addEventListener("click", applyLinkFromModal);
        document.getElementById("linkUrl").addEventListener("keydown", (e) => {
          if (e.key === "Enter") { e.preventDefault(); applyLinkFromModal(); }
          if (e.key === "Escape") closeModal(backdrop);
        });
      }
      const urlInput = document.getElementById("linkUrl");
      const textInput = document.getElementById("linkText");
      // 预填选中文本作为链接文本。
      const selection = editor.ownerDocument.getSelection().toString();
      textInput.value = selection || "";
      urlInput.value = "";
      backdrop.hidden = false;
      urlInput.focus();
    }

    function applyLinkFromModal() {
      let raw = document.getElementById("linkUrl").value.trim();
      const text = document.getElementById("linkText").value.trim();
      if (!raw) return;
      // 没有 protocol 时（如 example.com 或 example.com/path），URL 构造会判定为相对路径，
      // 此处默认补 https://；已有协议的保持原样。
      if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(raw)) raw = "https://" + raw;
      let parsed;
      try { parsed = new URL(raw); } catch { return setStatus("链接地址无效", "error"); }
      if (!SAFE_LINK_PROTOCOLS.has(parsed.protocol)) {
        return setStatus("仅允许 http/https/mailto 链接", "error");
      }
      editor.focus();
      if (text) {
        // 用 insertHTML 同时设置链接文本与 href，避免 createLink 不更新文本。
        document.execCommand("insertHTML", false,
          '<a href="' + escapeAttr(parsed.href) + '">' + escapeHtml(text) + '</a>');
      } else {
        document.execCommand("createLink", false, parsed.href);
      }
      closeModal(document.getElementById("linkModal"));
      setStatus("已插入链接", "success");
    }

    function closeModal(backdrop) {
      if (backdrop) backdrop.hidden = true;
    }

    function escapeAttr(value) {
      return String(value).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    function escapeHtml(value) {
      return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    }

    function runCommand(command, value = null) {
      editor.focus();
      document.execCommand(command, false, value);
    }

    function addAddresses(field, raw) {
      const items = String(raw || "")
        .split(/[\\n,;]/)
        .map((item) => item.trim())
        .filter(Boolean);
      let added = 0;
      for (const item of items) {
        // 去重（大小写不敏感），避免重复收件人。
        if (!state[field].some((e) => e.toLowerCase() === item.toLowerCase())) {
          state[field].push(item);
          added++;
        }
      }
      renderRecipients(field);
      return added;
    }

    function renderRecipients(field) {
      const box = document.querySelector('[data-field="' + field + '"]');
      const input = box.querySelector("input");
      box.querySelectorAll(".chip").forEach((chip) => chip.remove());
      for (const email of state[field]) {
        const chip = document.createElement("span");
        chip.className = "chip";
        chip.dataset.invalid = String(!isValidEmail(email));

        const text = document.createElement("span");
        text.textContent = email;

        const remove = document.createElement("button");
        remove.type = "button";
        remove.textContent = "×";
        remove.title = "移除";
        remove.addEventListener("click", () => {
          state[field] = state[field].filter((item) => item !== email);
          renderRecipients(field);
        });

        chip.append(text, remove);
        box.insertBefore(chip, input);
      }
    }

    function flushAddressInputs() {
      document.querySelectorAll(".recipient-box").forEach((box) => {
        const input = box.querySelector("input");
        addAddresses(box.dataset.field, input.value);
        input.value = "";
      });
    }

    function renderAttachments() {
      attachmentsEl.innerHTML = "";
      state.attachments.forEach((file, index) => {
        const row = document.createElement("div");
        row.className = "attachment";

        const name = document.createElement("span");
        name.textContent = file.filename + " · " + formatBytes(file.size);

        const remove = document.createElement("button");
        remove.type = "button";
        remove.textContent = "移除";
        remove.addEventListener("click", () => {
          state.attachments.splice(index, 1);
          renderAttachments();
        });

        row.append(name, remove);
        attachmentsEl.append(row);
      });
    }

    function readFileAsBase64(file) {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result).split(",")[1] || "");
        reader.onerror = () => reject(reader.error);
        reader.readAsDataURL(file);
      });
    }

    function normalizeHtml(html) {
      const cleaned = String(html || "").trim();
      if (!cleaned || cleaned === "<br>") return "";
      return '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.6;color:#1d2733">' + cleaned + "</div>";
    }

    function isValidEmail(email) {
      // 与后端严格校验保持一致：长度≤254、RFC 风格正则、禁首尾点、禁连续点、域段至少含一个点。
      // 模板字面量内不能用反引号字符，故正则省略 backtick（邮箱地址本就不允许该字符）。
      const value = String(email || "");
      if (value.length > 254) return false;
      return /^[a-zA-Z0-9.!#$%&'*+/=?^_{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/.test(value)
        && !/\.\./.test(value)
        && !value.startsWith(".")
        && !/\.@/.test(value);
    }

    function setStatus(message, type = "") {
      statusEl.textContent = message;
      statusEl.className = "status" + (type ? " " + type : "");
    }

    function readableError(data) {
      if (!data) return "发送失败（无响应体）";
      if (typeof data.error === "string") return data.error;
      if (data.error && data.error.message) return data.error.message;
      try { return JSON.stringify(data.error || data); } catch { return "发送失败"; }
    }

    function formatBytes(bytes) {
      if (bytes < 1024) return bytes + " B";
      if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
      return (bytes / 1024 / 1024).toFixed(1) + " MB";
    }
  </script>
</body>
</html>`;
}

function escapeHtml (value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
