import { handleCommunityRequest } from "./community_routes.js";
import { handleAdminRequest } from "./admin_routes.js";
import { handleSyncRequest } from "./sync_routes.js";

const json = (data, status=200) => new Response(JSON.stringify(data), {
  status, headers: { "content-type":"application/json; charset=utf-8",
    "access-control-allow-origin":"*", "access-control-allow-headers":"content-type,authorization,x-vega-admin-session",
    "access-control-allow-methods":"GET,POST,PUT,PATCH,DELETE,OPTIONS" }
});
const uid = () => crypto.randomUUID();
const now = () => Date.now();
const enc = new TextEncoder();

async function hashPassword(password, salt) {
  const material = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2", salt:enc.encode(salt), iterations:150000, hash:"SHA-256"}, material, 256);
  return [...new Uint8Array(bits)].map(x=>x.toString(16).padStart(2,"0")).join("");
}
function b64url(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_"); }
async function sign(payload, secret) {
  const head=b64url(enc.encode(JSON.stringify({alg:"HS256",typ:"JWT"})));
  const body=b64url(enc.encode(JSON.stringify(payload)));
  const key=await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const sig=await crypto.subtle.sign("HMAC",key,enc.encode(head+"."+body));
  return head+"."+body+"."+b64url(sig);
}
async function auth(req, env) {
  const token=(req.headers.get("authorization")||"").replace(/^Bearer\s+/i,"");
  if(!token || !env.JWT_SECRET) return null;
  try {
    const [h,p,s]=token.split(".");
    const key=await crypto.subtle.importKey("raw",enc.encode(env.JWT_SECRET),{name:"HMAC",hash:"SHA-256"},false,["verify"]);
    const raw=Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"===".slice((s.length+3)%4)),c=>c.charCodeAt(0));
    if(!await crypto.subtle.verify("HMAC",key,raw,enc.encode(h+"."+p))) return null;
    const data=JSON.parse(atob(p.replace(/-/g,"+").replace(/_/g,"/")));
    if(data.exp < Math.floor(Date.now()/1000)) return null;
    return data;
  } catch { return null; }
}
async function body(req) { try { return await req.json(); } catch { return {}; } }

export default {
 async fetch(req, env) {
  if(req.method==="OPTIONS") return new Response(null,{status:204,headers:{
    "access-control-allow-origin":"*","access-control-allow-headers":"content-type,authorization,x-vega-admin-session",
    "access-control-allow-methods":"GET,POST,PUT,PATCH,DELETE,OPTIONS"}});
  const u=new URL(req.url), p=u.pathname;
  if(p==="/" || p==="/health") return json({service:"VEGA",status:"ok",version:"0.2.0"});
  if(p==="/api/v1/health") {
    try { await env.DB.prepare("SELECT 1").first(); return json({service:"VEGA",database:"connected"}); }
    catch { return json({service:"VEGA",database:"error"},503); }
  }
  if(p==="/api/v1/register" && req.method==="POST") {
    const x=await body(req), username=String(x.username||"").trim().toLowerCase();
    const display=String(x.displayName||"").trim(), password=String(x.password||"");
    if(!/^[a-z0-9_]{3,24}$/.test(username) || display.length<2 || display.length>50 || password.length<10)
      return json({error:"اطلاعات نامعتبر است؛ نام کاربری ۳ تا ۲۴ حرف و گذرواژه حداقل ۱۰ کاراکتر باشد."},400);
    const id=uid(), salt=uid(), ph= salt+":"+await hashPassword(password,salt);
    try {
      await env.DB.prepare("INSERT INTO users(id,username,display_name,password_hash,created_at) VALUES(?,?,?,?,?)")
       .bind(id,username,display,ph,now()).run();
      const token=await sign({sub:id,exp:Math.floor(Date.now()/1000)+60*60*24*14},env.JWT_SECRET);
      return json({token,user:{id,username,displayName:display}});
    } catch { return json({error:"این نام کاربری قبلاً استفاده شده است."},409); }
  }
  if(p==="/api/v1/login" && req.method==="POST") {
    const x=await body(req), username=String(x.username||"").trim().toLowerCase(), password=String(x.password||"");
    const user=await env.DB.prepare("SELECT * FROM users WHERE username=?").bind(username).first();
    if(!user) return json({error:"نام کاربری یا گذرواژه اشتباه است."},401);
    const [salt,stored]=user.password_hash.split(":");
    if(await hashPassword(password,salt)!==stored) return json({error:"نام کاربری یا گذرواژه اشتباه است."},401);
    const token=await sign({sub:user.id,exp:Math.floor(Date.now()/1000)+60*60*24*14},env.JWT_SECRET);
    return json({token,user:{id:user.id,username:user.username,displayName:user.display_name,bio:user.bio}});
  }
  const session=await auth(req,env);
  if(!session) return json({error:"ابتدا وارد حساب شوید."},401);

  const userId = session.sub;
  const addCors = (response) => {
    if (!response) return response;
    const headers = new Headers(response.headers);
    headers.set("access-control-allow-origin", "*");
    headers.set("access-control-allow-headers", "content-type,authorization,x-vega-admin-session");
    headers.set("access-control-allow-methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  };
  const communityResponse = await handleCommunityRequest(req, env, userId);
  if (communityResponse) return addCors(communityResponse);
  const adminResponse = await handleAdminRequest(req, env, userId);
  if (adminResponse) return addCors(adminResponse);
  const syncResponse = await handleSyncRequest(req, env, { id: userId });
  if (syncResponse) return addCors(syncResponse);
  if(p==="/api/v1/me" && req.method==="GET") {
    const me=await env.DB.prepare("SELECT id,username,display_name,bio,avatar_key,role,created_at,last_seen_at,last_seen_visibility FROM users WHERE id=?").bind(userId).first();
    return me?json({user:me}):json({error:"کاربر پیدا نشد."},404);
  }
  if(p==="/api/v1/me" && req.method==="PATCH") {
    const x=await body(req);
    const display=typeof x.displayName==="string"?x.displayName.trim():null;
    const bio=typeof x.bio==="string"?x.bio.trim():null;
    const avatar=typeof x.avatarKey==="string"?x.avatarKey.trim():null;
    const visibility=typeof x.lastSeenVisibility==="string"?x.lastSeenVisibility:null;
    if(visibility!==null && !["everyone","nobody"].includes(visibility)) return json({error:"تنظیم حریم خصوصی نامعتبر است."},400);
    if(display!==null && (display.length<2 || display.length>50)) return json({error:"نام نمایشی باید بین ۲ تا ۵۰ نویسه باشد."},400);
    if(bio!==null && bio.length>160) return json({error:"بیوگرافی حداکثر ۱۶۰ نویسه است."},400);
    if(avatar!==null && avatar.length>512) return json({error:"شناسه تصویر نامعتبر است."},400);
    const sets=[], vals=[];
    if(display!==null){sets.push("display_name=?");vals.push(display);}
    if(bio!==null){sets.push("bio=?");vals.push(bio);}
    if(avatar!==null){sets.push("avatar_key=?");vals.push(avatar||null);}
    if(visibility!==null){sets.push("last_seen_visibility=?");vals.push(visibility);}
    if(!sets.length) return json({error:"هیچ تغییری ارسال نشده است."},400);
    vals.push(userId);
    await env.DB.prepare(`UPDATE users SET ${sets.join(",")} WHERE id=?`).bind(...vals).run();
    const me=await env.DB.prepare("SELECT id,username,display_name,bio,avatar_key,role,created_at,last_seen_at,last_seen_visibility FROM users WHERE id=?").bind(userId).first();
    return json({user:me,updated:true});
  }
  const publicUserMatch=p.match(/^\/api\/v1\/users\/([a-f0-9-]+)$/);
  if(publicUserMatch && req.method==="GET") {
    const targetId=publicUserMatch[1];
    const user=await env.DB.prepare("SELECT id,username,display_name,bio,avatar_key,role,last_seen_at,last_seen_visibility FROM users WHERE id=?").bind(targetId).first();
    if(!user) return json({error:"کاربر پیدا نشد."},404);
    if(user.last_seen_visibility==="nobody" && targetId!==userId) user.last_seen_at=null;
    delete user.last_seen_visibility;
    return json({user});
  }
  if(p==="/api/v1/presence/heartbeat" && req.method==="POST") {
    const at=now();
    await env.DB.prepare("UPDATE users SET last_seen_at=? WHERE id=?").bind(at,userId).run();
    return json({ok:true,at});
  }
  if(p==="/api/v1/conversations" && req.method==="GET") {
    const rows=await env.DB.prepare(`SELECT c.id,c.type,c.title,c.created_at,
      (SELECT COUNT(*) FROM conversation_members m WHERE m.conversation_id=c.id) member_count,
      (SELECT COUNT(*) FROM messages unread WHERE unread.conversation_id=c.id AND unread.sender_id<>? AND unread.created_at>COALESCE(cm.last_read_at,0)) unread_count,
      (SELECT MAX(last_message.created_at) FROM messages last_message WHERE last_message.conversation_id=c.id) last_message_at
      FROM conversations c JOIN conversation_members cm ON cm.conversation_id=c.id
      WHERE cm.user_id=? ORDER BY COALESCE(last_message_at,c.created_at) DESC LIMIT 100`).bind(userId,userId).all();
    return json({items:rows.results||[]});
  }
  if(p==="/api/v1/conversations" && req.method==="POST") {
    const x=await body(req), type=x.type==="group"?"group":"private";
    const title=String(x.title||"").trim().slice(0,80);
    const id=uid();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO conversations(id,type,title,created_by,created_at) VALUES(?,?,?,?,?)").bind(id,type,title,session.sub,now()),
      env.DB.prepare("INSERT INTO conversation_members(conversation_id,user_id,member_role,joined_at) VALUES(?,?,?,?)").bind(id,session.sub,"owner",now())
    ]);
    return json({id,type,title},201);
  }
  const readMatch=p.match(/^\/api\/v1\/conversations\/([a-f0-9-]+)\/read$/);
  if(readMatch && req.method==="POST") {
    const cid=readMatch[1], member=await env.DB.prepare("SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?").bind(cid,userId).first();
    if(!member) return json({error:"دسترسی ندارید."},403);
    const x=await body(req), through=Number.isSafeInteger(Number(x.through)) && Number(x.through)>0?Number(x.through):now();
    const at=now();
    await env.DB.batch([
      env.DB.prepare("UPDATE conversation_members SET last_read_at=MAX(COALESCE(last_read_at,0),?) WHERE conversation_id=? AND user_id=?").bind(through,cid,userId),
      env.DB.prepare(`INSERT OR IGNORE INTO message_reads(message_id,user_id,read_at)
        SELECT id,?,? FROM messages WHERE conversation_id=? AND sender_id<>? AND created_at<=?`).bind(userId,at,cid,userId,through)
    ]);
    return json({ok:true,readThrough:through});
  }

  const msgMatch=p.match(/^\/api\/v1\/conversations\/([a-f0-9-]+)\/messages$/);
  if(msgMatch) {
    const cid=msgMatch[1];
    const member=await env.DB.prepare("SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?").bind(cid,session.sub).first();
    if(!member) return json({error:"دسترسی ندارید."},403);
    if(req.method==="GET") {
      const before=Number(u.searchParams.get("before")||Number.MAX_SAFE_INTEGER);
      const rows=await env.DB.prepare(`SELECT m.id,m.conversation_id,m.sender_id,m.body,m.created_at,m.edited_at,
        EXISTS(SELECT 1 FROM message_reads mr WHERE mr.message_id=m.id AND mr.user_id<>m.sender_id) AS read_by_recipient,
        (SELECT COUNT(*) FROM message_reads mr2 WHERE mr2.message_id=m.id) AS read_count
        FROM messages m WHERE m.conversation_id=? AND m.created_at<? ORDER BY m.created_at DESC LIMIT 50`).bind(cid,before).all();
      return json({items:(rows.results||[]).reverse()});
    }
    if(req.method==="POST") {
      const x=await body(req), text=String(x.body||"").trim();
      if(!text || text.length>8000) return json({error:"متن پیام نامعتبر است."},400);
      const id=uid(), at=now();
      await env.DB.prepare("INSERT INTO messages(id,conversation_id,sender_id,body,created_at) VALUES(?,?,?,?,?)")
       .bind(id,cid,session.sub,text,at).run();
      return json({id,conversationId:cid,senderId:session.sub,body:text,createdAt:at},201);
    }
  }
  const messageMatch=p.match(/^\/api\/v1\/messages\/([a-f0-9-]+)$/);
  if(messageMatch) {
    const messageId=messageMatch[1];
    const message=await env.DB.prepare("SELECT id,conversation_id,sender_id,body,created_at FROM messages WHERE id=?").bind(messageId).first();
    if(!message) return json({error:"پیام پیدا نشد."},404);
    const member=await env.DB.prepare("SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?").bind(message.conversation_id,userId).first();
    if(!member) return json({error:"دسترسی ندارید."},403);
    if(message.sender_id!==userId) return json({error:"فقط فرستنده می‌تواند پیام را تغییر دهد."},403);
    if(req.method==="PATCH") {
      const x=await body(req), text=String(x.body||"").trim();
      if(!text || text.length>8000) return json({error:"متن پیام نامعتبر است."},400);
      const at=now();
      await env.DB.prepare("UPDATE messages SET body=?,edited_at=? WHERE id=? AND sender_id=?").bind(text,at,messageId,userId).run();
      const recipients=await env.DB.prepare("SELECT user_id FROM conversation_members WHERE conversation_id=? AND user_id<>?").bind(message.conversation_id,userId).all();
      const eventAt=Math.floor(at/1000);
      const eventStatements=(recipients.results||[]).map(r=>env.DB.prepare(
        "INSERT INTO sync_events (user_id,event_type,payload_json,created_at) VALUES (?,?,?,?)"
      ).bind(r.user_id,"message_updated",JSON.stringify({conversationId:message.conversation_id,messageId}),eventAt));
      if(eventStatements.length) await env.DB.batch(eventStatements);
      return json({id:messageId,body:text,editedAt:at,updated:true});
    }
    if(req.method==="DELETE") {
      await env.DB.prepare("DELETE FROM messages WHERE id=? AND sender_id=?").bind(messageId,userId).run();
      const recipients=await env.DB.prepare("SELECT user_id FROM conversation_members WHERE conversation_id=? AND user_id<>?").bind(message.conversation_id,userId).all();
      const eventAt=Math.floor(now()/1000);
      const eventStatements=(recipients.results||[]).map(r=>env.DB.prepare(
        "INSERT INTO sync_events (user_id,event_type,payload_json,created_at) VALUES (?,?,?,?)"
      ).bind(r.user_id,"message_deleted",JSON.stringify({conversationId:message.conversation_id,messageId}),eventAt));
      if(eventStatements.length) await env.DB.batch(eventStatements);
      return json({deleted:true,id:messageId});
    }
  }

  return json({error:"مسیر پیدا نشد."},404);
 }
};
      
