const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "Content-Type, Authorization"
  }
});

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      return new Response(null, {status: 204, headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET,POST,OPTIONS",
        "access-control-allow-headers": "Content-Type, Authorization"
      }});
    }
    if (url.pathname === "/" || url.pathname === "/health") {
      return json({service: "VEGA", status: "ok", version: "0.1.0",
        message: "VEGA server is running"});
    }
    if (url.pathname === "/api/v1/health") {
      if (!env.DB) return json({service: "VEGA", status: "ok",
        database: "not_connected"});
      try {
        await env.DB.prepare("SELECT 1").first();
        return json({service: "VEGA", status: "ok", database: "connected"});
      } catch {
        return json({service: "VEGA", status: "error",
          database: "unavailable"}, 503);
      }
    }
    return json({error: "not_found",
      message: "This VEGA API endpoint does not exist."}, 404);
  }
};
