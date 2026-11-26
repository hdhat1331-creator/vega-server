const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8" }
});
const fail = (message, status = 400) => json({ error: message }, status);
const id = () => crypto.randomUUID();
const code = () => crypto.randomUUID().replaceAll("-", "").slice(0, 16);
const parse = async (request) => {
  try { return await request.json(); } catch { return null; }
};
const isAdmin = (role, type) =>
  type === "group" ? role === "owner" || role === "admin"
                   : role === "owner" || role === "admin";

async function roleFor(db, type, targetId, userId) {
  const table = type === "group" ? "group_members" : "channel_subscribers";
  const key = type === "group" ? "group_id" : "channel_id";
  const row = await db.prepare(
    `SELECT role FROM ${table} WHERE ${key} = ? AND user_id = ?`
  ).bind(targetId, userId).first();
  return row?.role ?? null;
}

export async function handleCommunityRequest(request, env, userId) {
  if (!userId) return fail("Authentication required.", 401);
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const db = env.DB;

  if (path === "/api/v1/community/groups" && method === "POST") {
    const b = await parse(request);
    if (!b || typeof b.title !== "string" || !b.title.trim() || b.title.length > 80)
      return fail("A group title (1–80 chars) is required.");
    const groupId = id(), invite = code();
    await db.batch([
      db.prepare("INSERT INTO groups (id,title,description,owner_user_id,invite_code) VALUES (?,?,?,?,?)")
        .bind(groupId, b.title.trim(), String(b.description ?? "").slice(0, 500), userId, invite),
      db.prepare("INSERT INTO group_members (group_id,user_id,role) VALUES (?,?, 'owner')")
        .bind(groupId, userId)
    ]);
    return json({ id: groupId, title: b.title.trim(), inviteCode: invite }, 201);
  }

  if (path === "/api/v1/community/groups" && method === "GET") {
    const rows = await db.prepare(
      `SELECT g.id,g.title,g.description,g.owner_user_id AS ownerUserId,gm.role
       FROM groups g JOIN group_members gm ON gm.group_id=g.id
       WHERE gm.user_id=? ORDER BY g.created_at DESC LIMIT 100`
    ).bind(userId).all();
    return json({ items: rows.results ?? [] });
  }

  if (path === "/api/v1/community/channels" && method === "POST") {
    const b = await parse(request);
    if (!b || typeof b.title !== "string" || !b.title.trim() || b.title.length > 80)
      return fail("A channel title (1–80 chars) is required.");
    const visibility = b.visibility === "public" ? "public" : "private";
    const channelId = id(), invite = code();
    await db.batch([
      db.prepare("INSERT INTO channels (id,title,description,owner_user_id,visibility,invite_code) VALUES (?,?,?,?,?,?)")
        .bind(channelId, b.title.trim(), String(b.description ?? "").slice(0, 500), userId, visibility, invite),
      db.prepare("INSERT INTO channel_subscribers (channel_id,user_id,role) VALUES (?,?, 'owner')")
        .bind(channelId, userId)
    ]);
    return json({ id: channelId, title: b.title.trim(), visibility, inviteCode: invite }, 201);
  }

  if (path === "/api/v1/community/channels" && method === "GET") {
    const rows = await db.prepare(
      `SELECT c.id,c.title,c.description,c.visibility,c.owner_user_id AS ownerUserId,cs.role
       FROM channels c JOIN channel_subscribers cs ON cs.channel_id=c.id
       WHERE cs.user_id=? ORDER BY c.created_at DESC LIMIT 100`
    ).bind(userId).all();
    return json({ items: rows.results ?? [] });
  }

  if (path === "/api/v1/community/join" && method === "POST") {
    const b = await parse(request);
    if (!b || typeof b.code !== "string") return fail("Invite code is required.");
    const invite = await db.prepare(
      "SELECT * FROM community_invites WHERE code=? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) AND (max_uses IS NULL OR uses < max_uses)"
    ).bind(b.code).first();
    let targetType = invite?.target_type;
    let targetId = invite?.target_id;

    // Owner-generated initial invite codes are also accepted.
    if (!invite) {
      const g = await db.prepare("SELECT id FROM groups WHERE invite_code=?").bind(b.code).first();
      const c = g ? null : await db.prepare("SELECT id FROM channels WHERE invite_code=?").bind(b.code).first();
      if (g) { targetType = "group"; targetId = g.id; }
      else if (c) { targetType = "channel"; targetId = c.id; }
    }
    if (!targetType) return fail("Invite is invalid or expired.", 404);

    if (targetType === "group") {
      await db.prepare("INSERT OR IGNORE INTO group_members (group_id,user_id) VALUES (?,?)")
        .bind(targetId, userId).run();
    } else {
      await db.prepare("INSERT OR IGNORE INTO channel_subscribers (channel_id,user_id) VALUES (?,?)")
        .bind(targetId, userId).run();
    }
    if (invite) await db.prepare("UPDATE community_invites SET uses=uses+1 WHERE code=?").bind(b.code).run();
    return json({ joined: true, type: targetType, id: targetId });
  }

  if (path === "/api/v1/community/invites" && method === "POST") {
    const b = await parse(request);
    if (!b || !["group","channel"].includes(b.type) || typeof b.id !== "string")
      return fail("A valid target type and id are required.");
    const role = await roleFor(db, b.type, b.id, userId);
    if (!isAdmin(role, b.type)) return fail("Admin permission required.", 403);
    const inviteCode = code();
    const maxUses = Number.isInteger(b.maxUses) && b.maxUses > 0 ? b.maxUses : null;
    const expiresAt = typeof b.expiresAt === "string" ? b.expiresAt : null;
    await db.prepare(
      "INSERT INTO community_invites (code,target_type,target_id,created_by,expires_at,max_uses) VALUES (?,?,?,?,?,?)"
    ).bind(inviteCode, b.type, b.id, userId, expiresAt, maxUses).run();
    return json({ code: inviteCode }, 201);
  }

  if (path === "/api/v1/community/members" && method === "GET") {
    const type = url.searchParams.get("type");
    const targetId = url.searchParams.get("id");
    if (!["group","channel"].includes(type) || !targetId) return fail("type and id are required.");
    if (!await roleFor(db, type, targetId, userId)) return fail("Not a member.", 403);
    const table = type === "group" ? "group_members" : "channel_subscribers";
    const key = type === "group" ? "group_id" : "channel_id";
    const rows = await db.prepare(
      `SELECT user_id AS userId, role, joined_at AS joinedAt FROM ${table} WHERE ${key}=? ORDER BY joined_at LIMIT 500`
    ).bind(targetId).all();
    return json({ items: rows.results ?? [] });
  }

  if (path === "/api/v1/community/members/role" && method === "PATCH") {
    const b = await parse(request);
    if (!b || !["group","channel"].includes(b.type) || !b.id || !b.userId ||
        !["admin","member","subscriber"].includes(b.role)) return fail("Invalid role update.");
    const actorRole = await roleFor(db, b.type, b.id, userId);
    if (actorRole !== "owner") return fail("Only the owner can change admin roles.", 403);
    const table = b.type === "group" ? "group_members" : "channel_subscribers";
    const key = b.type === "group" ? "group_id" : "channel_id";
    const newRole = b.role === "admin" ? "admin" :
      (b.type === "group" ? "member" : "subscriber");
    const result = await db.prepare(
      `UPDATE ${table} SET role=? WHERE ${key}=? AND user_id=? AND role!='owner'`
    ).bind(newRole, b.id, b.userId).run();
    if (!result.meta?.changes) return fail("Member not found or cannot modify owner.", 404);
    return json({ updated: true });
  }

  if (path === "/api/v1/community/members" && method === "DELETE") {
    const type = url.searchParams.get("type");
    const targetId = url.searchParams.get("id");
    const memberId = url.searchParams.get("userId");
    if (!["group","channel"].includes(type) || !targetId || !memberId) return fail("Missing parameters.");
    const actorRole = await roleFor(db, type, targetId, userId);
    if (!isAdmin(actorRole, type)) return fail("Admin permission required.", 403);
    const table = type === "group" ? "group_members" : "channel_subscribers";
    const key = type === "group" ? "group_id" : "channel_id";
    await db.prepare(`DELETE FROM ${table} WHERE ${key}=? AND user_id=? AND role!='owner'`)
      .bind(targetId, memberId).run();
    return json({ removed: true });
  }

  if (path === "/api/v1/community/posts" && method === "POST") {
    const b = await parse(request);
    if (!b || typeof b.channelId !== "string" ||
        (typeof b.body !== "string" || !b.body.trim()) && !b.mediaDescriptor)
      return fail("channelId and post content are required.");
    const role = await roleFor(db, "channel", b.channelId, userId);
    if (!isAdmin(role, "channel")) return fail("Channel admin permission required.", 403);
    const postId = id();
    await db.prepare(
      "INSERT INTO channel_posts (id,channel_id,author_user_id,body,media_descriptor) VALUES (?,?,?,?,?)"
    ).bind(postId, b.channelId, userId, String(b.body ?? "").slice(0, 10000),
      b.mediaDescriptor ? JSON.stringify(b.mediaDescriptor) : null).run();
    return json({ id: postId }, 201);
  }

  if (path === "/api/v1/community/posts" && method === "GET") {
    const channelId = url.searchParams.get("channelId");
    if (!channelId) return fail("channelId is required.");
    if (!await roleFor(db, "channel", channelId, userId)) return fail("Not subscribed.", 403);
    const rows = await db.prepare(
      "SELECT id,author_user_id AS authorUserId,body,media_descriptor AS mediaDescriptor,views_count AS viewsCount,pinned,created_at AS createdAt FROM channel_posts WHERE channel_id=? ORDER BY created_at DESC LIMIT 100"
    ).bind(channelId).all();
    return json({ items: rows.results ?? [] });
  }

  if (path === "/api/v1/community/reactions" && method === "POST") {
    const b = await parse(request);
    if (!b || typeof b.postId !== "string" || typeof b.reaction !== "string" ||
        !/^[\\p{Emoji}\\p{Emoji_Component}]{1,8}$/u.test(b.reaction)) return fail("Invalid reaction.");
    const post = await db.prepare("SELECT channel_id FROM channel_posts WHERE id=?").bind(b.postId).first();
    if (!post || !await roleFor(db, "channel", post.channel_id, userId)) return fail("Post not found.", 404);
    if (b.remove === true) {
      await db.prepare("DELETE FROM channel_post_reactions WHERE post_id=? AND user_id=? AND reaction=?")
        .bind(b.postId, userId, b.reaction).run();
    } else {
      await db.prepare("INSERT OR IGNORE INTO channel_post_reactions (post_id,user_id,reaction) VALUES (?,?,?)")
        .bind(b.postId, userId, b.reaction).run();
    }
    return json({ updated: true });
  }

  return null;
          }
      
