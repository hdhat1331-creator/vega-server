const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};
const enc = new TextEncoder();

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}
function fail(error, status = 400) { return json({ ok: false, error }, status); }
function uid(prefix) { return `${prefix}${crypto.randomUUID()}`; }
function isoNow() { return new Date().toISOString(); }
function token() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
async function digest(value) {
  return b64(await crypto.subtle.digest("SHA-256", enc.encode(value)));
}
async function makePasswordHash(password, salt = token().slice(0, 22)) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 210000, hash: "SHA-256" },
    key, 256
  );
  return { salt, hash: b64(bits) };
}
async function checkPassword(password, salt, expected) {
  if (!salt || !expected) return false;
  const result = await makePasswordHash(password, salt);
  return result.hash === expected;
}
async function readBody(request) {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch { return null; }
}
function validUsername(value) {
  return typeof value === "string" && /^[a-zA-Z0-9_]{5,24}$/.test(value);
}
function validPassword(value) {
  return typeof value === "string" && value.length >= 10 && value.length <= 128;
}
async function rateLimit(env, key, limit = 60, windowMs = 60000) {
  // One atomic D1 statement per request; no full-table DELETE on every API call.
  const now = Date.now();
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits(key,count,expires_at) VALUES(?,?,?)
     ON CONFLICT(key) DO UPDATE SET
       count=CASE WHEN rate_limits.expires_at<=? THEN 1 ELSE rate_limits.count+1 END,
       expires_at=CASE WHEN rate_limits.expires_at<=? THEN excluded.expires_at ELSE rate_limits.expires_at END
     RETURNING count`
  ).bind(key, 1, now + windowMs, now, now).first();

  // Opportunistic cleanup keeps the table bounded without adding a DELETE to every request.
  if (Math.random() < 0.01) {
    await env.DB.prepare("DELETE FROM rate_limits WHERE expires_at <= ?").bind(now).run();
  }
  return !!row && row.count <= limit;
}

async function createSession(env, userId) {
  const plainToken = token();
  const created = isoNow();
  const expires = new Date(Date.now() + 30 * 86400000).toISOString();
  await env.DB.prepare(
    "INSERT INTO sessions(id,user_id,token_hash,created_at,expires_at) VALUES(?,?,?,?,?)"
  ).bind(uid("ses_"), userId, await digest(plainToken), created, expires).run();
  return { token: plainToken, expires_at: expires };
}
async function getUser(request, env) {
  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Bearer ")) return null;
  const plainToken = header.slice(7).trim();
  if (!plainToken || plainToken.length > 200) return null;

  return await env.DB.prepare(
    `SELECT u.id AS user_id,u.username,u.display_name,u.bio,u.avatar_key,u.role,u.gold_until
     FROM sessions s JOIN users u ON u.id=s.user_id
     WHERE s.token_hash=? AND s.expires_at>?`
  ).bind(await digest(plainToken), isoNow()).first();
}
async function route(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (!env.DB) return fail("اتصال D1 تنظیم نشده است", 503);
  if (path === "/" || path === "/health") {
    return json({ ok: true, service: "VEGA", status: "ok", version: "1.1.0-test" });
  }
  if (path === "/api/v1/health") {
    try {
      await env.DB.prepare("SELECT 1").first();
      return json({ ok: true, service: "VEGA", database: "connected", version: "1.1.0-test" });
    } catch {
      return fail("اتصال دیتابیس برقرار نیست", 503);
    }
  }

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const limit = path.startsWith("/api/v1/auth/") ? 10 : 90;
  if (!await rateLimit(env, `${ip}:${path}`, limit)) {
    return fail("تعداد درخواست‌ها بیش از حد مجاز است", 429);
  }

  if (path === "/api/v1/auth/register" && method === "POST") {
    const data = await readBody(request);
    if (!data || !validUsername(data.username) || !validPassword(data.password)) {
      return fail("نام کاربری باید ۳ تا ۲۴ نویسه و رمز عبور حداقل ۱۰ نویسه باشد");
    }
    const exists = await env.DB.prepare(
      "SELECT id FROM users WHERE username=? COLLATE NOCASE"
    ).bind(username).first();
    if (exists) return fail("این نام کاربری قبلاً ثبت شده است", 409);

    const username = data.username.toLowerCase();
    const displayName = typeof data.display_name === "string"
      ? data.display_name.trim().slice(0, 20) || username
      : username;
    const { salt, hash } = await makePasswordHash(data.password);
    const id = uid("usr_");
    const now = isoNow();

    await env.DB.prepare(
      `INSERT INTO users(id,username,display_name,password_hash,password_salt,role,created_at,updated_at)
       VALUES(?,?,?,?,?,'user',?,?)`
    ).bind(id, username, displayName, hash, salt, now, now).run();

    const session = await createSession(env, id);
    return json({
      ok: true,
      user: { id, username, display_name: displayName, role: "user" },
      ...session
    }, 201);
  }

  if (path === "/api/v1/auth/login" && method === "POST") {
    const data = await readBody(request);
    if (!data || typeof data.username !== "string" || typeof data.password !== "string") {
      return fail("اطلاعات ورود نامعتبر است");
    }
    const user = await env.DB.prepare(
      `SELECT id,username,display_name,password_hash,password_salt,role
       FROM users WHERE username=? COLLATE NOCASE`
    ).bind(data.username).first();

    if (!user || !(await checkPassword(data.password, user.password_salt, user.password_hash))) {
      return fail("نام کاربری یا رمز عبور اشتباه است", 401);
    }
    const session = await createSession(env, user.id);
    return json({
      ok: true,
      user: { id: user.id, username: user.username, display_name: user.display_name, role: user.role },
      ...session
    });
  }

  if (path === "/api/v1/auth/logout" && method === "POST") {
    const header = request.headers.get("Authorization") || "";
    const plainToken = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
    if (plainToken) {
      await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?")
        .bind(await digest(plainToken)).run();
    }
    return json({ ok: true });
  }

  const user = await getUser(request, env);
  if (!user) return fail("ابتدا وارد حساب کاربری شوید", 401);

  if (path === "/api/v1/me" && method === "GET") {
    return json({ ok: true, user });
  }
  if (path === "/api/v1/me" && method === "PATCH") {
    const data = await readBody(request);
    if (!data) return fail("بدنه درخواست نامعتبر است");
    const displayName = typeof data.display_name === "string"
      ? data.display_name.trim().slice(0, 60) : user.display_name;
    const bio = typeof data.bio === "string" ? data.bio.slice(0, 160) : user.bio;
    await env.DB.prepare(
      "UPDATE users SET display_name=?,bio=?,updated_at=? WHERE id=?"
    ).bind(displayName, bio, isoNow(), user.user_id).run();
    return json({ ok: true });
  }

  if (path === "/api/v1/users/search" && method === "GET") {
    const q = (url.searchParams.get("q") || "").trim().slice(0, 40);
    if (q.length < 2) return json({ ok: true, users: [] });
    const rows = await env.DB.prepare(
      `SELECT id,username,display_name,bio,avatar_key FROM users
       WHERE (username LIKE ? OR display_name LIKE ?) AND id<>? LIMIT 20`
    ).bind(`%${q}%`, `%${q}%`, user.user_id).all();
    return json({ ok: true, users: rows.results || [] });
  }

  if (path === "/api/v1/conversations" && method === "GET") {
    const rows = await env.DB.prepare(
      `SELECT c.id,c.type,c.title,c.created_by,c.created_at,
       (SELECT body FROM messages m WHERE m.conversation_id=c.id
        ORDER BY m.created_at DESC LIMIT 1) AS last_message,
       (SELECT created_at FROM messages m WHERE m.conversation_id=c.id
        ORDER BY m.created_at DESC LIMIT 1) AS last_message_at
       FROM conversations c JOIN conversation_members cm ON cm.conversation_id=c.id
       WHERE cm.user_id=?
       ORDER BY COALESCE(last_message_at,c.created_at) DESC LIMIT 100`
    ).bind(user.user_id).all();
    return json({ ok: true, conversations: rows.results || [] });
  }

  if (path === "/api/v1/conversations" && method === "POST") {
    const data = await readBody(request);
    // Current production schema allows only private/group. Channel support needs a separate table migration.
    if (!data || !["private", "group"].includes(data.type)) {
      return fail("در این نسخه فقط گفتگوی خصوصی و گروه پشتیبانی می‌شود");
    }
    const title = typeof data.title === "string" ? data.title.trim().slice(0, 80) : "";
    const members = Array.isArray(data.member_ids)
      ? [...new Set(data.member_ids.filter(x => typeof x === "string"))].slice(0, 100) : [];

    if (data.type === "group" && !title) return fail("عنوان گروه الزامی است");
    if (data.type === "private" && members.length !== 1) {
      return fail("برای گفتگوی خصوصی باید دقیقاً یک شناسه کاربر ارسال شود");
    }
    if (members.includes(user.user_id)) return fail("شناسه اعضا نامعتبر است");

    const id = uid("cnv_");
    const now = isoNow();
    // Reject unknown member IDs instead of silently creating an incomplete conversation.
    for (const memberId of members) {
      const found = await env.DB.prepare("SELECT id FROM users WHERE id=?").bind(memberId).first();
      if (!found) return fail("یکی از اعضای انتخاب‌شده پیدا نشد", 404);
    }
    const statements = [
      env.DB.prepare(
        "INSERT INTO conversations(id,type,title,created_by,created_at) VALUES(?,?,?,?,?)"
      ).bind(id, data.type, title || null, user.user_id, now),
      env.DB.prepare(
        "INSERT INTO conversation_members(conversation_id,user_id,member_role,joined_at) VALUES(?,?,?,?)"
      ).bind(id, user.user_id, "owner", now),
      ...members.map(memberId => env.DB.prepare(
        "INSERT INTO conversation_members(conversation_id,user_id,member_role,joined_at) VALUES(?,?,?,?)"
      ).bind(id, memberId, "member", now))
    ];
    await env.DB.batch(statements);
    return json({ ok: true, conversation_id: id }, 201);
  }

  const messagesMatch = path.match(/^\/api\/v1\/conversations\/([^/]+)\/messages$/);
  if (messagesMatch && (method === "GET" || method === "POST")) {
    const conversationId = messagesMatch[1];
    const membership = await env.DB.prepare(
      "SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?"
    ).bind(conversationId, user.user_id).first();
    if (!membership) return fail("به این گفتگو دسترسی ندارید", 403);

    if (method === "GET") {
      const before = url.searchParams.get("before") || "9999-12-31T23:59:59.999Z";
      const rows = await env.DB.prepare(
        `SELECT id,sender_id,body,content_type,reply_to,created_at,edited_at
         FROM messages WHERE conversation_id=? AND created_at<?
         ORDER BY created_at DESC LIMIT 50`
      ).bind(conversationId, before).all();
      return json({ ok: true, messages: (rows.results || []).reverse() });
    }

    const data = await readBody(request);
    if (!data || typeof data.body !== "string" || data.body.length < 1 || data.body.length > 20000) {
      return fail("محتوای پیام نامعتبر است");
    }
    const contentType = ["text", "encrypted"].includes(data.content_type) ? data.content_type : "text";
    let replyTo = null;
    if (data.reply_to !== undefined && data.reply_to !== null) {
      if (typeof data.reply_to !== "string" || data.reply_to.length > 100) return fail("شناسه پیام پاسخ نامعتبر است");
      const parent = await env.DB.prepare(
        "SELECT id FROM messages WHERE id=? AND conversation_id=?"
      ).bind(data.reply_to, conversationId).first();
      if (!parent) return fail("پیام موردنظر برای پاسخ پیدا نشد", 404);
      replyTo = data.reply_to;
    }
    const id = uid("msg_");
    const now = isoNow();
    await env.DB.prepare(
      "INSERT INTO messages(id,conversation_id,sender_id,body,content_type,reply_to,created_at) VALUES(?,?,?,?,?,?,?)"
    ).bind(id, conversationId, user.user_id, data.body, contentType, replyTo, now).run();
    return json({
      ok: true,
      message: { id, conversation_id: conversationId, sender_id: user.user_id, body: data.body, content_type: contentType, reply_to: replyTo, created_at: now }
    }, 201);
  }

  const messageMatch = path.match(/^\/api\/v1\/messages\/([^/]+)$/);
  if (messageMatch && (method === "PATCH" || method === "DELETE")) {
    const id = messageMatch[1];
    const msg = await env.DB.prepare("SELECT id,sender_id FROM messages WHERE id=?").bind(id).first();
    if (!msg) return fail("پیام پیدا نشد", 404);
    if (msg.sender_id !== user.user_id && user.role !== "admin") {
      return fail("اجازه انجام این کار را ندارید", 403);
    }
    if (method === "DELETE") {
      await env.DB.prepare("DELETE FROM messages WHERE id=?").bind(id).run();
    } else {
      const data = await readBody(request);
      if (!data || typeof data.body !== "string" || data.body.length > 20000) {
        return fail("متن پیام نامعتبر است");
      }
      await env.DB.prepare("UPDATE messages SET body=?,edited_at=? WHERE id=?")
        .bind(data.body, isoNow(), id).run();
    }
    return json({ ok: true });
  }

  if (path === "/api/v1/sync" && method === "GET") {
    const since = url.searchParams.get("since") || "0001-01-01T00:00:00.000Z";
    const rows = await env.DB.prepare(
      `SELECT m.id,m.conversation_id,m.sender_id,m.body,m.content_type,m.reply_to,m.created_at,m.edited_at
       FROM messages m JOIN conversation_members cm ON cm.conversation_id=m.conversation_id
       WHERE cm.user_id=? AND m.created_at>?
       ORDER BY m.created_at ASC LIMIT 200`
    ).bind(user.user_id, since).all();
    return json({ ok: true, messages: rows.results || [], server_time: isoNow() });
  }

  return fail("مسیر پیدا نشد", 404);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");
    const allowedOrigin = env.ALLOWED_ORIGIN || "*";
    const corsHeaders = {
      "access-control-allow-origin": allowedOrigin,
      "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
      "access-control-allow-headers": "Content-Type,Authorization",
      "access-control-max-age": "86400",
      "vary": "Origin",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer"
    };
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
    try {
      const response = await route(request, env);
      const headers = new Headers(response.headers);
      for (const [key, value] of Object.entries(corsHeaders)) headers.set(key, value);
      return new Response(response.body, { status: response.status, headers });
    } catch (error) {
      console.error("VEGA API error:", error?.message || "unknown");
      return json({ ok: false, error: "خطای داخلی سرور" }, 500);
    }
  }
};
