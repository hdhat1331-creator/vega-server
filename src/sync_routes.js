const MAX_ENVELOPE_CHARS = 256 * 1024;
const QUEUE_TTL_SECONDS = 60 * 60 * 24 * 7;
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" }
  });

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

async function readJson(request) {
  try { return await request.json(); } catch { return null; }
}

/*
 * Integration contract:
 *   import { handleSyncRequest } from "./sync_routes.js";
 *   const user = await requireUser(request, env); // your existing auth middleware
 *   const response = await handleSyncRequest(request, env, user);
 *   if (response) return response;
 *
 * `user.id` must come from a verified session, never from request JSON.
 */
export async function handleSyncRequest(request, env, user) {
  if (!user?.id) return json({ error: "unauthorized" }, 401);
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const db = env.DB;
  const uid = String(user.id);
  const now = nowSeconds();

  if (method === "POST" && path === "/api/v1/sync/queue") {
    const body = await readJson(request);
    if (!body || typeof body.conversationId !== "string" ||
        typeof body.recipientUserId !== "string" ||
        typeof body.encryptedPayload !== "string" ||
        typeof body.idempotencyKey !== "string") {
      return json({ error: "invalid_request" }, 400);
    }
    if (body.encryptedPayload.length < 16 ||
        body.encryptedPayload.length > MAX_ENVELOPE_CHARS ||
        body.idempotencyKey.length < 8 || body.idempotencyKey.length > 128) {
      return json({ error: "invalid_envelope_or_key" }, 400);
    }
    if (body.recipientUserId === uid) return json({ error: "invalid_recipient" }, 400);

    // Both parties must belong to this conversation. The sender identity is session-derived.
    const senderMember = await db.prepare(
      "SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ? LIMIT 1"
    ).bind(body.conversationId, uid).first();
    const recipientMember = await db.prepare(
      "SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ? LIMIT 1"
    ).bind(body.conversationId, body.recipientUserId).first();
    if (!senderMember || !recipientMember) return json({ error: "not_conversation_member" }, 403);

    const id = crypto.randomUUID();
    const expiresAt = now + QUEUE_TTL_SECONDS;
    try {
      await db.prepare(
        `INSERT INTO offline_message_queue
         (id, conversation_id, sender_user_id, recipient_user_id, encrypted_payload,
          idempotency_key, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(id, body.conversationId, uid, body.recipientUserId,
        body.encryptedPayload, body.idempotencyKey, now, expiresAt).run();
    } catch (e) {
      // Idempotent retry: return the previously queued item without duplicating it.
      const existing = await db.prepare(
        "SELECT id, expires_at FROM offline_message_queue WHERE sender_user_id = ? AND idempotency_key = ?"
      ).bind(uid, body.idempotencyKey).first();
      if (existing) return json({ ok: true, id: existing.id, expiresAt: existing.expires_at, duplicate: true });
      return json({ error: "queue_write_failed" }, 500);
    }
    return json({ ok: true, id, expiresAt });
  }

  if (method === "GET" && path === "/api/v1/sync/pending") {
    // Expired envelopes are purged before returning the recipient's pending items.
    await db.prepare("DELETE FROM offline_message_queue WHERE expires_at <= ?").bind(now).run();
    const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 50), 1), 100);
    const result = await db.prepare(
      `SELECT id, conversation_id, sender_user_id, encrypted_payload, created_at, expires_at
       FROM offline_message_queue
       WHERE recipient_user_id = ? AND expires_at > ?
       ORDER BY created_at ASC, id ASC LIMIT ?`
    ).bind(uid, now, limit).all();
    return json({ items: result.results || [] });
  }

  if (method === "POST" && path === "/api/v1/sync/ack") {
    const body = await readJson(request);
    if (!Array.isArray(body?.messageIds) || body.messageIds.length < 1 || body.messageIds.length > 100 ||
        body.messageIds.some(x => typeof x !== "string" || x.length > 80)) {
      return json({ error: "invalid_message_ids" }, 400);
    }
    let acknowledged = 0;
    for (const id of [...new Set(body.messageIds)]) {
      const result = await db.prepare(
        "DELETE FROM offline_message_queue WHERE id = ? AND recipient_user_id = ?"
      ).bind(id, uid).run();
      acknowledged += result.meta?.changes || 0;
    }
    return json({ ok: true, acknowledged });
  }

  if (method === "GET" && path === "/api/v1/sync/changes") {
    const raw = url.searchParams.get("after") || "0";
    const cursor = Number(raw);
    if (!Number.isSafeInteger(cursor) || cursor < 0) return json({ error: "invalid_cursor" }, 400);
    const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 100), 1), 200);
    const result = await db.prepare(
      `SELECT id, event_type, payload_json, created_at
       FROM sync_events WHERE user_id = ? AND id > ?
       ORDER BY id ASC LIMIT ?`
    ).bind(uid, cursor, limit).all();
    const events = (result.results || []).map(row => ({
      id: row.id, type: row.event_type, payload: safeParse(row.payload_json), createdAt: row.created_at
    }));
    const nextCursor = events.length ? events[events.length - 1].id : cursor;
    return json({ events, nextCursor, hasMore: events.length === limit });
  }

  if (method === "GET" && path === "/api/v1/notifications/preferences") {
    let row = await db.prepare(
      "SELECT direct_messages, group_messages, channel_posts, sound_enabled FROM notification_preferences WHERE user_id = ?"
    ).bind(uid).first();
    if (!row) {
      await db.prepare(
        `INSERT OR IGNORE INTO notification_preferences
         (user_id, direct_messages, group_messages, channel_posts, sound_enabled, updated_at)
         VALUES (?, 1, 1, 1, 1, ?)`
      ).bind(uid, now).run();
      row = { direct_messages: 1, group_messages: 1, channel_posts: 1, sound_enabled: 1 };
    }
    return json({
      directMessages: !!row.direct_messages,
      groupMessages: !!row.group_messages,
      channelPosts: !!row.channel_posts,
      soundEnabled: !!row.sound_enabled
    });
  }

  if (method === "PUT" && path === "/api/v1/notifications/preferences") {
    const body = await readJson(request);
    const keys = ["directMessages", "groupMessages", "channelPosts", "soundEnabled"];
    if (!body || keys.some(k => typeof body[k] !== "boolean")) return json({ error: "invalid_preferences" }, 400);
    await db.prepare(
      `INSERT INTO notification_preferences
       (user_id, direct_messages, group_messages, channel_posts, sound_enabled, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET
       direct_messages=excluded.direct_messages,
       group_messages=excluded.group_messages,
       channel_posts=excluded.channel_posts,
       sound_enabled=excluded.sound_enabled,
       updated_at=excluded.updated_at`
    ).bind(uid, +body.directMessages, +body.groupMessages, +body.channelPosts,
      +body.soundEnabled, now).run();
    return json({ ok: true });
  }

  if (method === "POST" && path === "/api/v1/notifications/devices") {
    const body = await readJson(request);
    if (!body || !["android", "ios"].includes(body.platform) ||
        typeof body.pushToken !== "string" || body.pushToken.length < 16 || body.pushToken.length > 4096) {
      return json({ error: "invalid_device" }, 400);
    }
    const id = crypto.randomUUID();
    await db.prepare(
      `INSERT INTO push_devices (id, user_id, platform, push_token, device_label, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id, push_token) DO UPDATE SET
       platform=excluded.platform, device_label=excluded.device_label, updated_at=excluded.updated_at`
    ).bind(id, uid, body.platform, body.pushToken,
      typeof body.deviceLabel === "string" ? body.deviceLabel.slice(0, 80) : null, now, now).run();
    return json({ ok: true, registered: true });
  }

  if (method === "DELETE" && path === "/api/v1/notifications/devices") {
    const body = await readJson(request);
    if (typeof body?.pushToken !== "string") return json({ error: "invalid_device" }, 400);
    await db.prepare("DELETE FROM push_devices WHERE user_id = ? AND push_token = ?")
      .bind(uid, body.pushToken).run();
    return json({ ok: true });
  }

  return null;
}

function safeParse(value) {
  try { return JSON.parse(value || "{}"); } catch { return {}; }
}

// Call from message/community routes after a change. Never pass plaintext message bodies.
export async function addSyncEvent(db, userId, eventType, payload = {}) {
  const allowed = new Set([
    "message_available", "message_updated", "message_deleted",
    "conversation_updated", "group_updated", "channel_post_available",
    "membership_updated"
  ]);
  if (!allowed.has(eventType)) throw new Error("unsupported_sync_event");
  const serialized = JSON.stringify(payload);
  if (serialized.length > 8192) throw new Error("sync_event_too_large");
  await db.prepare(
    "INSERT INTO sync_events (user_id, event_type, payload_json, created_at) VALUES (?, ?, ?, ?)"
  ).bind(String(userId), eventType, serialized, nowSeconds()).run();
    }
        
