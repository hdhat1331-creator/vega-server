import { handleCommunityRequest } from "./community_routes.js";
import { handleAdminRequest } from "./admin_routes.js";
import { handleSyncRequest } from "./sync_routes.js";

const corsHeaders = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "content-type,authorization,x-vega-admin-session",
  "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS"
};

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", ...corsHeaders }
});
const uid = () => crypto.randomUUID();
const now = () => new Date().toISOString();
const enc = new TextEncoder();

async function hashPassword(password, salt) {
  const material = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 150000, hash: "SHA-256" },
    material, 256
  );
  return [...new Uint8Array(bits)].map(x => x.toString(16).padStart(2, "0")).join("");
}

function b64url(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function fromB64url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(
    atob(normalized + "=".repeat((4 - normalized.length % 4) % 4)),
    c => c.charCodeAt(0)
  );
}
async function sign(payload, secret) {
  if (!secret) throw new Error("JWT_SECRET is not configured");
  const head = b64url(enc.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(head + "." + body));
  return head + "." + body + "." + b64url(sig);
}
async function auth(req, env) {
  const token = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token || !env.JWT_SECRET) return null;
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [head, payload, signature] = parts;
    const key = await crypto.subtle.importKey(
      "raw", enc.encode(env.JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );
    if (!await crypto.subtle.verify(
      "HMAC", key, fromB64url(signature), enc.encode(head + "." + payload)
    )) return null;
    const data = JSON.parse(new TextDecoder().decode(fromB64url(payload)));
    if (!data.sub || !Number.isFinite(data.exp) || data.exp <= Math.floor(Date.now() / 1000)) return null;
    return data;
  } catch {
    return null;
  }
}
async function body(req) {
  try {
    const value = await req.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
  } catch {
    return {};
  }
}
function withCors(response) {
  if (!response) return response;
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(corsHeaders)) headers.set(key, value);
  return new Response(response.body, {
    status: response.status, statusText: response.statusText, headers
  });
}
function normalizeTimestamp(value) {
  if (typeof value === "string" && value.trim()) {
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
  }
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    const milliseconds = value < 100000000000 ? value * 1000 : value;
    const date = new Date(milliseconds);
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
  }
  return null;
}
function publicUser(row, viewerId) {
  const user = { ...row };
  if (user.id !== viewerId && user.last_seen_privacy !== "everyone") user.last_seen_at = null;
  delete user.last_seen_privacy;
  return user;
}

export default {
  async fetch(req, env) {
    try {
      if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });

      const url = new URL(req.url);
      const path = url.pathname;

      if (path === "/" || path === "/health") {
        return json({ service: "VEGA", status: "ok", version: "0.2.2" });
      }
      if (path === "/api/v1/health") {
        try {
          await env.DB.prepare("SELECT 1").first();
          return json({ service: "VEGA", database: "connected" });
        } catch {
          return json({ service: "VEGA", database: "error" }, 503);
        }
      }

      if (path === "/api/v1/register" && req.method === "POST") {
        if (!env.JWT_SECRET) return json({ error: "تنظیمات احراز هویت سرور کامل نیست." }, 503);
        const input = await body(req);
        const username = String(input.username || "").trim().toLowerCase();
        const displayName = String(input.displayName || "").trim();
        const password = String(input.password || "");
        if (!/^[a-z0-9_]{5,24}$/.test(username) ||
            displayName.length < 2 || displayName.length > 20 ||
            password.length < 10 || password.length > 256) {
          return json({
            error: "نام کاربری باید ۵ تا ۲۴ نویسه انگلیسی باشد، نام نمایشی ۲ تا ۲۰ نویسه و گذرواژه حداقل ۱۰ نویسه."
          }, 400);
        }

        const id = uid();
        const salt = uid();
        const passwordHash = salt + ":" + await hashPassword(password, salt);
        try {
          await env.DB.prepare(
            "INSERT INTO users(id,username,display_name,password_hash,created_at) VALUES(?,?,?,?,?)"
          ).bind(id, username, displayName, passwordHash, now()).run();
        } catch (error) {
          const message = String(error?.message || "");
          if (/unique|constraint/i.test(message)) {
            return json({ error: "این نام کاربری قبلاً استفاده شده است." }, 409);
          }
          throw error;
        }
        const token = await sign(
          { sub: id, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 14 },
          env.JWT_SECRET
        );
        return json({ token, user: { id, username, displayName } }, 201);
      }

      if (path === "/api/v1/login" && req.method === "POST") {
        if (!env.JWT_SECRET) return json({ error: "تنظیمات احراز هویت سرور کامل نیست." }, 503);
        const input = await body(req);
        const username = String(input.username || "").trim().toLowerCase();
        const password = String(input.password || "");
        if (!username || !password) return json({ error: "نام کاربری و گذرواژه الزامی است." }, 400);

        const user = await env.DB.prepare(
          "SELECT id,username,display_name,bio,password_hash FROM users WHERE username=?"
        ).bind(username).first();
        if (!user?.password_hash) return json({ error: "نام کاربری یا گذرواژه اشتباه است." }, 401);
        const [salt, stored] = user.password_hash.split(":");
        if (!salt || !stored || await hashPassword(password, salt) !== stored) {
          return json({ error: "نام کاربری یا گذرواژه اشتباه است." }, 401);
        }
        const token = await sign(
          { sub: user.id, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 14 },
          env.JWT_SECRET
        );
        return json({
          token,
          user: { id: user.id, username: user.username, displayName: user.display_name, bio: user.bio }
        });
      }

      const session = await auth(req, env);
      if (!session) return json({ error: "ابتدا وارد حساب شوید." }, 401);
      const userId = session.sub;

      // Route handlers return null when the path does not belong to them.
      const communityResponse = await handleCommunityRequest(req, env, userId);
      if (communityResponse) return withCors(communityResponse);

      const adminResponse = await handleAdminRequest(req, env, userId);
      if (adminResponse) return withCors(adminResponse);

      const syncResponse = await handleSyncRequest(req, env, { id: userId });
      if (syncResponse) return withCors(syncResponse);

      if (path === "/api/v1/me" && req.method === "GET") {
        const me = await env.DB.prepare(
          "SELECT id,username,display_name,bio,avatar_key,role,created_at,last_seen_at,last_seen_privacy FROM users WHERE id=?"
        ).bind(userId).first();
        return me ? json({ user: publicUser(me, userId) }) : json({ error: "کاربر پیدا نشد." }, 404);
      }

      if (path === "/api/v1/me" && req.method === "PATCH") {
        const input = await body(req);
        const display = typeof input.displayName === "string" ? input.displayName.trim() : null;
        const bio = typeof input.bio === "string" ? input.bio.trim() : null;
        const avatar = typeof input.avatarKey === "string" ? input.avatarKey.trim() : null;
        const privacyValue = input.lastSeenPrivacy ?? input.lastSeenVisibility;
        const privacy = typeof privacyValue === "string" ? privacyValue : null;

        if (privacy !== null && !["everyone", "contacts", "nobody"].includes(privacy)) {
          return json({ error: "تنظیم حریم خصوصی نامعتبر است." }, 400);
        }
        if (display !== null && (display.length < 2 || display.length > 20)) {
          return json({ error: "نام نمایشی باید بین ۲ تا ۲۰ نویسه باشد." }, 400);
        }
        if (bio !== null && bio.length > 160) return json({ error: "بیوگرافی حداکثر ۱۶۰ نویسه است." }, 400);
        if (avatar !== null && avatar.length > 512) return json({ error: "شناسه تصویر نامعتبر است." }, 400);

        const sets = [];
        const values = [];
        if (display !== null) { sets.push("display_name=?"); values.push(display); }
        if (bio !== null) { sets.push("bio=?"); values.push(bio); }
        if (avatar !== null) { sets.push("avatar_key=?"); values.push(avatar || null); }
        if (privacy !== null) { sets.push("last_seen_privacy=?"); values.push(privacy); }
        if (!sets.length) return json({ error: "هیچ تغییری ارسال نشده است." }, 400);

        values.push(userId);
        await env.DB.prepare(`UPDATE users SET ${sets.join(",")} WHERE id=?`).bind(...values).run();
        const me = await env.DB.prepare(
          "SELECT id,username,display_name,bio,avatar_key,role,created_at,last_seen_at,last_seen_privacy FROM users WHERE id=?"
        ).bind(userId).first();
        return json({ user: publicUser(me, userId), updated: true });
      }

      const publicUserMatch = path.match(/^\/api\/v1\/users\/([a-f0-9-]+)$/i);
      if (publicUserMatch && req.method === "GET") {
        const targetId = publicUserMatch[1];
        const user = await env.DB.prepare(
          "SELECT id,username,display_name,bio,avatar_key,role,last_seen_at,last_seen_privacy FROM users WHERE id=?"
        ).bind(targetId).first();
        if (!user) return json({ error: "کاربر پیدا نشد." }, 404);
        return json({ user: publicUser(user, userId) });
      }

      if (path === "/api/v1/presence/heartbeat" && req.method === "POST") {
        const at = now();
        await env.DB.prepare("UPDATE users SET last_seen_at=? WHERE id=?").bind(at, userId).run();
        return json({ ok: true, at });
      }

      if (path === "/api/v1/conversations" && req.method === "GET") {
        const rows = await env.DB.prepare(`
          SELECT c.id,c.type,c.title,c.created_at,
            (SELECT COUNT(*) FROM conversation_members m WHERE m.conversation_id=c.id) AS member_count,
            (SELECT COUNT(*) FROM messages unread
              WHERE unread.conversation_id=c.id AND unread.sender_id<>?
              AND unread.created_at>COALESCE(cm.last_read_at,'')
            ) AS unread_count,
            (SELECT MAX(last_message.created_at) FROM messages last_message
              WHERE last_message.conversation_id=c.id) AS last_message_at
          FROM conversations c
          JOIN conversation_members cm ON cm.conversation_id=c.id
          WHERE cm.user_id=?
          ORDER BY COALESCE(last_message_at,c.created_at) DESC
          LIMIT 100
        `).bind(userId, userId).all();
        return json({ items: rows.results || [] });
      }

      if (path === "/api/v1/conversations" && req.method === "POST") {
        const input = await body(req);
        const type = input.type === "group" ? "group" : "private";
        const title = String(input.title || "").trim().slice(0, 80);
        const conversationId = uid();
        const at = now();
        await env.DB.batch([
          env.DB.prepare(
            "INSERT INTO conversations(id,type,title,created_by,created_at) VALUES(?,?,?,?,?)"
          ).bind(conversationId, type, title, userId, at),
          env.DB.prepare(
            "INSERT INTO conversation_members(conversation_id,user_id,member_role,joined_at) VALUES(?,?,?,?)"
          ).bind(conversationId, userId, "owner", at)
        ]);
        return json({ id: conversationId, type, title, createdAt: at }, 201);
      }

      const readMatch = path.match(/^\/api\/v1\/conversations\/([a-f0-9-]+)\/read$/i);
      if (readMatch && req.method === "POST") {
        const conversationId = readMatch[1];
        const member = await env.DB.prepare(
          "SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?"
        ).bind(conversationId, userId).first();
        if (!member) return json({ error: "دسترسی ندارید." }, 403);

        const input = await body(req);
        const through = normalizeTimestamp(input.through) || now();
        const at = now();
        await env.DB.batch([
          env.DB.prepare(
            "UPDATE conversation_members SET last_read_at=CASE WHEN last_read_at IS NULL OR last_read_at<? THEN ? ELSE last_read_at END WHERE conversation_id=? AND user_id=?"
          ).bind(through, through, conversationId, userId),
          env.DB.prepare(`
            INSERT OR IGNORE INTO message_reads(message_id,user_id,read_at)
            SELECT id,?,? FROM messages
            WHERE conversation_id=? AND sender_id<>? AND created_at<=?
          `).bind(userId, at, conversationId, userId, through)
        ]);
        return json({ ok: true, readThrough: through });
      }

      const messagesMatch = path.match(/^\/api\/v1\/conversations\/([a-f0-9-]+)\/messages$/i);
      if (messagesMatch) {
        const conversationId = messagesMatch[1];
        const member = await env.DB.prepare(
          "SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?"
        ).bind(conversationId, userId).first();
        if (!member) return json({ error: "دسترسی ندارید." }, 403);

        if (req.method === "GET") {
          const beforeRaw = url.searchParams.get("before");
          const before = beforeRaw ? normalizeTimestamp(beforeRaw) : null;
          const rows = before
            ? await env.DB.prepare(`
                SELECT m.id,m.conversation_id,m.sender_id,m.body,m.created_at,m.edited_at,
                  EXISTS(SELECT 1 FROM message_reads mr
                    WHERE mr.message_id=m.id AND mr.user_id<>m.sender_id) AS read_by_recipient,
                  (SELECT COUNT(*) FROM message_reads mr2 WHERE mr2.message_id=m.id) AS read_count
                FROM messages m
                WHERE m.conversation_id=? AND m.created_at<?
                ORDER BY m.created_at DESC LIMIT 50
              `).bind(conversationId, before).all()
            : await env.DB.prepare(`
                SELECT m.id,m.conversation_id,m.sender_id,m.body,m.created_at,m.edited_at,
                  EXISTS(SELECT 1 FROM message_reads mr
                    WHERE mr.message_id=m.id AND mr.user_id<>m.sender_id) AS read_by_recipient,
                  (SELECT COUNT(*) FROM message_reads mr2 WHERE mr2.message_id=m.id) AS read_count
                FROM messages m
                WHERE m.conversation_id=?
                ORDER BY m.created_at DESC LIMIT 50
              `).bind(conversationId).all();
          return json({ items: (rows.results || []).reverse() });
        }

        if (req.method === "POST") {
          const input = await body(req);
          const messageText = String(input.body || "").trim();
          if (!messageText || messageText.length > 8000) {
            return json({ error: "متن پیام نامعتبر است." }, 400);
          }
          const id = uid();
          const at = now();
          await env.DB.prepare(
            "INSERT INTO messages(id,conversation_id,sender_id,body,created_at) VALUES(?,?,?,?,?)"
          ).bind(id, conversationId, userId, messageText, at).run();
          return json({
            id, conversationId, senderId: userId, body: messageText, createdAt: at,
            editedAt: null, readByRecipient: false
          }, 201);
        }
        return json({ error: "روش درخواست پشتیبانی نمی‌شود." }, 405);
      }

      const messageMatch = path.match(/^\/api\/v1\/messages\/([a-f0-9-]+)$/i);
      if (messageMatch) {
        const messageId = messageMatch[1];
        const message = await env.DB.prepare(
          "SELECT id,conversation_id,sender_id,body,created_at FROM messages WHERE id=?"
        ).bind(messageId).first();
        if (!message) return json({ error: "پیام پیدا نشد." }, 404);

        const member = await env.DB.prepare(
          "SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?"
        ).bind(message.conversation_id, userId).first();
        if (!member) return json({ error: "دسترسی ندارید." }, 403);
        if (message.sender_id !== userId) {
          return json({ error: "فقط فرستنده می‌تواند پیام را تغییر دهد." }, 403);
        }

        if (req.method === "PATCH") {
          const input = await body(req);
          const messageText = String(input.body || "").trim();
          if (!messageText || messageText.length > 8000) {
            return json({ error: "متن پیام نامعتبر است." }, 400);
          }
          const at = now();
          await env.DB.prepare(
            "UPDATE messages SET body=?,edited_at=? WHERE id=? AND sender_id=?"
          ).bind(messageText, at, messageId, userId).run();

          const recipients = await env.DB.prepare(
            "SELECT user_id FROM conversation_members WHERE conversation_id=? AND user_id<>?"
          ).bind(message.conversation_id, userId).all();
          const eventAt = Math.floor(Date.now() / 1000);
          const eventStatements = (recipients.results || []).map(recipient => env.DB.prepare(
            "INSERT INTO sync_events (user_id,event_type,payload_json,created_at) VALUES (?,?,?,?)"
          ).bind(recipient.user_id, "message_updated", JSON.stringify({
            conversationId: message.conversation_id, messageId
          }), eventAt));
          if (eventStatements.length) await env.DB.batch(eventStatements);
          return json({ id: messageId, body: messageText, editedAt: at, updated: true });
        }

        if (req.method === "DELETE") {
          await env.DB.prepare(
            "DELETE FROM messages WHERE id=? AND sender_id=?"
          ).bind(messageId, userId).run();
          const recipients = await env.DB.prepare(
            "SELECT user_id FROM conversation_members WHERE conversation_id=? AND user_id<>?"
          ).bind(message.conversation_id, userId).all();
          const eventAt = Math.floor(Date.now() / 1000);
          const eventStatements = (recipients.results || []).map(recipient => env.DB.prepare(
            "INSERT INTO sync_events (user_id,event_type,payload_json,created_at) VALUES (?,?,?,?)"
          ).bind(recipient.user_id, "message_deleted", JSON.stringify({
            conversationId: message.conversation_id, messageId
          }), eventAt));
          if (eventStatements.length) await env.DB.batch(eventStatements);
          return json({ deleted: true, id: messageId });
        }
        return json({ error: "روش درخواست پشتیبانی نمی‌شود." }, 405);
      }

      return json({ error: "مسیر پیدا نشد." }, 404);
    } catch (error) {
      // Keep server internals out of client responses; details remain in Worker logs.
      console.error("VEGA request failed:", error);
      return json({ error: "خطای داخلی سرور رخ داد." }, 500);
    }
  }
};
