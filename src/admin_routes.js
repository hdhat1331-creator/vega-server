const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { "content-type": "application/json; charset=utf-8" }
});
const fail = (message, status = 400) => json({ error: message }, status);
const uuid = () => crypto.randomUUID();
const enc = new TextEncoder();

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(value));
  return [...new Uint8Array(digest)].map(x => x.toString(16).padStart(2, "0")).join("");
}
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
const parse = async req => { try { return await req.json(); } catch { return null; } };

async function adminLevel(db, userId) {
  const row = await db.prepare("SELECT role FROM admin_roles WHERE user_id=?").bind(userId).first();
  return row?.role ?? null;
}
async function hasAdminSession(db, request, userId) {
  const token = request.headers.get("x-vega-admin-session") || "";
  if (!token || token.length < 32) return false;
  const tokenHash = await sha256(token);
  const row = await db.prepare(
    "SELECT user_id FROM admin_sessions WHERE token_hash=? AND expires_at>?"
  ).bind(tokenHash, Math.floor(Date.now() / 1000)).first();
  return row?.user_id === userId;
}
async function audit(db, actor, action, target, details = "") {
  await db.prepare(
    "INSERT INTO admin_audit_log (id,actor_user_id,action,target_user_id,details) VALUES (?,?,?,?,?)"
  ).bind(uuid(), actor, action, target ?? null, String(details).slice(0, 1000)).run();
}

export async function handleAdminRequest(request, env, userId) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // This handler is called for every authenticated request by index.js.
  // Non-admin routes must pass through untouched.
  if (!path.startsWith("/api/v1/admin/")) return null;
  if (!userId) return fail("Authentication required.", 401);

  const db = env.DB;

  if (path === "/api/v1/admin/unlock" && method === "POST") {
    if (!env.VEGA_OWNER_USER_ID || userId !== env.VEGA_OWNER_USER_ID)
      return fail("Owner account required.", 403);
    const body = await parse(request);
    if (!body || typeof body.secret !== "string" || !env.VEGA_ADMIN_SECRET)
      return fail("Invalid admin credentials.", 401);
    const expected = await sha256(env.VEGA_ADMIN_SECRET);
    const supplied = await sha256(body.secret);
    if (!safeEqual(expected, supplied)) return fail("Invalid admin credentials.", 401);

    const rawToken = [...crypto.getRandomValues(new Uint8Array(32))]
      .map(x => x.toString(16).padStart(2, "0")).join("");
    const expires = Math.floor(Date.now() / 1000) + 30 * 60;
    await db.prepare("INSERT INTO admin_sessions (token_hash,user_id,expires_at) VALUES (?,?,?)")
      .bind(await sha256(rawToken), userId, expires).run();
    await audit(db, userId, "owner_unlock", userId);
    return json({ adminSession: rawToken, expiresAt: expires });
  }

  const owner = Boolean(env.VEGA_OWNER_USER_ID && userId === env.VEGA_OWNER_USER_ID);
  const sessionOk = owner && await hasAdminSession(db, request, userId);
  const level = await adminLevel(db, userId);
  if (!sessionOk && !level) return fail("Admin access required.", 403);

  if (path === "/api/v1/admin/overview" && method === "GET") {
    const [users, groups, channels, reports] = await Promise.all([
      db.prepare("SELECT COUNT(*) AS count FROM users").first(),
      db.prepare("SELECT COUNT(*) AS count FROM groups").first(),
      db.prepare("SELECT COUNT(*) AS count FROM channels").first(),
      db.prepare("SELECT COUNT(*) AS count FROM user_reports WHERE status='open'").first()
    ]);
    return json({
      users: users?.count ?? 0,
      groups: groups?.count ?? 0,
      channels: channels?.count ?? 0,
      openReports: reports?.count ?? 0
    });
  }

  if (path === "/api/v1/admin/users" && method === "GET") {
    const q = (url.searchParams.get("query") || "").trim().slice(0, 80);
    if (!q) return json({ items: [] });
    const rows = await db.prepare(
      "SELECT id, username, display_name FROM users WHERE id=? OR username LIKE ? OR display_name LIKE ? LIMIT 50"
    ).bind(q, `%${q}%`, `%${q}%`).all();
    return json({ items: rows.results ?? [] });
  }

  if (path === "/api/v1/admin/roles" && method === "POST") {
    if (!owner || !sessionOk) return fail("Owner session required.", 403);
    const b = await parse(request);
    if (!b || typeof b.userId !== "string" || !b.userId.trim() ||
        !["admin", "moderator", "support", "remove"].includes(b.role))
      return fail("Invalid role operation.");
    if (b.role === "remove") {
      await db.prepare("DELETE FROM admin_roles WHERE user_id=?").bind(b.userId).run();
    } else {
      await db.prepare(
        "INSERT INTO admin_roles (user_id,role,granted_by) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET role=excluded.role, granted_by=excluded.granted_by"
      ).bind(b.userId, b.role, userId).run();
    }
    await audit(db, userId, "role_update", b.userId, b.role);
    return json({ updated: true });
  }

  // VEGA has no Gold tier or Gold badge. Only the ADMIN badge is supported.
  if (path === "/api/v1/admin/badges" && method === "POST") {
    if (!owner || !sessionOk) return fail("Owner session required.", 403);
    const b = await parse(request);
    if (!b || typeof b.userId !== "string" || !b.userId.trim() || b.badge !== "ADMIN")
      return fail("Invalid badge operation.");
    if (b.remove === true) {
      await db.prepare("DELETE FROM user_badges WHERE user_id=? AND badge='ADMIN'")
        .bind(b.userId).run();
    } else {
      await db.prepare("INSERT OR IGNORE INTO user_badges (user_id,badge,granted_by) VALUES (?,'ADMIN',?)")
        .bind(b.userId, userId).run();
    }
    await audit(db, userId, b.remove ? "badge_remove" : "badge_grant", b.userId, "ADMIN");
    return json({ updated: true });
  }

  if (path === "/api/v1/admin/bans" && method === "POST") {
    if (!owner && level !== "admin" && level !== "moderator")
      return fail("Insufficient permission.", 403);
    const b = await parse(request);
    if (!b || typeof b.userId !== "string" || !b.userId.trim())
      return fail("userId is required.");
    if (b.remove === true) {
      await db.prepare("DELETE FROM user_bans WHERE user_id=?").bind(b.userId).run();
    } else {
      const expiresAt = typeof b.expiresAt === "string" ? b.expiresAt : null;
      await db.prepare(
        "INSERT INTO user_bans (user_id,reason,expires_at,created_by) VALUES (?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET reason=excluded.reason, expires_at=excluded.expires_at, created_by=excluded.created_by"
      ).bind(b.userId, String(b.reason ?? "").slice(0, 500), expiresAt, userId).run();
    }
    await audit(db, userId, b.remove ? "ban_remove" : "ban_set", b.userId, b.reason ?? "");
    return json({ updated: true });
  }

  if (path === "/api/v1/admin/reports" && method === "GET") {
    const rows = await db.prepare(
      "SELECT id,reporter_user_id AS reporterUserId,target_user_id AS targetUserId,target_message_id AS targetMessageId,reason,details,status,assigned_to AS assignedTo,created_at AS createdAt FROM user_reports ORDER BY created_at DESC LIMIT 100"
    ).all();
    return json({ items: rows.results ?? [] });
  }

  if (path === "/api/v1/admin/reports" && method === "PATCH") {
    const b = await parse(request);
    if (!b || typeof b.id !== "string" ||
        !["open", "reviewing", "resolved", "dismissed"].includes(b.status))
      return fail("Invalid report update.");
    await db.prepare(
      "UPDATE user_reports SET status=?,assigned_to=?,updated_at=CURRENT_TIMESTAMP WHERE id=?"
    ).bind(b.status, userId, b.id).run();
    await audit(db, userId, "report_update", null, `${b.id}:${b.status}`);
    return json({ updated: true });
  }

  if (path === "/api/v1/admin/test-stats" && method === "GET") {
    const row = await db.prepare(
      "SELECT sample_views AS views,sample_reactions AS reactions,updated_at AS updatedAt FROM admin_test_stats WHERE id=1"
    ).first();
    return json({ simulated: true, label: "آمار آزمایشی — واقعی نیست", stats: row ?? {} });
  }

  if (path === "/api/v1/admin/test-stats" && method === "PUT") {
    if (!owner || !sessionOk) return fail("Owner session required.", 403);
    const b = await parse(request);
    const views = Number(b?.views), reactions = Number(b?.reactions);
    if (!Number.isSafeInteger(views) || !Number.isSafeInteger(reactions) ||
        views < 0 || reactions < 0 || views > 1000000000 || reactions > 1000000000)
      return fail("Invalid simulated values.");
    await db.prepare(
      "UPDATE admin_test_stats SET sample_views=?,sample_reactions=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=1"
    ).bind(views, reactions, userId).run();
    await audit(db, userId, "test_stats_update", null, `${views}:${reactions}`);
    return json({ updated: true, simulated: true });
  }

  return fail("Admin route not found.", 404);
}
