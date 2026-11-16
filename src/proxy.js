// mcp-proxy: a pass-through reverse proxy for remote MCP servers.
//
// Each configured route ("/notion-work", "/notion-personal", ...) maps onto one
// upstream MCP server. The proxy forwards MCP traffic unchanged except for:
//   1. OAuth discovery documents, whose upstream URLs are rewritten to point
//      back through the route, so the client signs in once per route.
//   2. Dynamic client registration and the authorization redirect, which are
//      wrapped so the upstream sends the browser back to the proxy, letting the
//      proxy report its own issuer (RFC 9207) to the client.
//   3. The `serverInfo.name` in the `initialize` result, renamed per route,
//      because some clients deduplicate connectors by that name.
//
// The proxy stores nothing. Upstream tokens travel to the client exactly as the
// upstream issued them; registration and state blobs are HMAC-signed with
// PROXY_SECRET so they cannot be forged or used as an open redirect.

const CALLBACK_PATH = "/__mcp_proxy/callback";
const CLIENT_PREFIX = "mcpp1.";
const STATE_PREFIX = "mcpps1.";
const STATE_TTL_SECONDS = 15 * 60;
const WELL_KNOWN = [
  "oauth-protected-resource",
  "oauth-authorization-server",
  "openid-configuration",
];
const ROUTE_RE = /^[a-z0-9][a-z0-9_-]{0,62}$/;
const HOP_BY_HOP = [
  "host",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "cookie",
  "content-length",
];

// ---------------------------------------------------------------- config ---

export function parseRoutes(raw) {
  const obj = typeof raw === "string" ? JSON.parse(raw) : raw;
  if (!obj || typeof obj !== "object") throw new Error("ROUTES must be a JSON object");
  const routes = new Map();
  for (const [name, cfg] of Object.entries(obj)) {
    if (!ROUTE_RE.test(name)) throw new Error(`Invalid route name: ${name}`);
    const upstream = new URL(typeof cfg === "string" ? cfg : cfg.upstream);
    if (upstream.protocol !== "https:" && !(cfg.allowInsecure === true)) {
      throw new Error(`Route ${name}: upstream must be https`);
    }
    const extraHosts = (cfg.authHosts || []).map((h) => h.toLowerCase());
    routes.set(name, {
      name,
      upstreamOrigin: upstream.origin,
      upstreamProtocol: upstream.protocol,
      upstreamPath: upstream.pathname.replace(/\/$/, "") || "",
      displayName: typeof cfg === "object" ? cfg.name : undefined,
      // Hosts the route may forward to: the MCP host plus any separate
      // authorization-server hosts the upstream uses.
      allowedHosts: new Set([upstream.host.toLowerCase(), ...extraHosts]),
    });
  }
  return routes;
}

// ----------------------------------------------------------- base64/hmac ---

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64url(s) {
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

async function seal(prefix, payload, key) {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(prefix + body)));
  return `${prefix}${body}.${b64url(sig)}`;
}

async function unseal(prefix, token, key) {
  if (typeof token !== "string" || !token.startsWith(prefix)) return null;
  const rest = token.slice(prefix.length);
  const dot = rest.lastIndexOf(".");
  if (dot < 0) return null;
  const body = rest.slice(0, dot);
  let sig;
  try {
    sig = unb64url(rest.slice(dot + 1));
  } catch {
    return null;
  }
  const ok = await crypto.subtle.verify("HMAC", key, sig, enc.encode(prefix + body));
  if (!ok) return null;
  try {
    return JSON.parse(dec.decode(unb64url(body)));
  } catch {
    return null;
  }
}

// ------------------------------------------------------------ URL mapping ---

// The proxy-side base URL for a route, e.g. https://proxy.example/notion-work
function routeBase(proxyOrigin, route) {
  return `${proxyOrigin}/${route.name}`;
}

// Map an upstream absolute URL to its proxy equivalent, or return null when the
// URL is on a host this route does not proxy.
function toProxyUrl(value, ctx) {
  let u;
  try {
    u = new URL(value);
  } catch {
    return null;
  }
  const host = u.host.toLowerCase();
  if (!ctx.route.allowedHosts.has(host)) return null;
  const base = routeBase(ctx.proxyOrigin, ctx.route);
  const prefix = u.origin === ctx.route.upstreamOrigin ? base : `${base}/~${host}`;
  // Keep a bare origin bare (an issuer like "https://mcp.notion.com" must map
  // to ".../notion-work", not ".../notion-work/").
  const path = value.replace(/^[a-z]+:\/\/[^/?#]+/i, "");
  return prefix + path;
}

// Map a proxy URL (absolute) back to upstream, or null if it isn't one of ours.
function toUpstreamUrl(value, ctx) {
  const base = routeBase(ctx.proxyOrigin, ctx.route);
  if (typeof value !== "string" || !(value === base || value.startsWith(base + "/") || value.startsWith(base + "?"))) {
    return null;
  }
  const rest = value.slice(base.length);
  const m = rest.match(/^\/~([^/?#]+)(.*)$/);
  if (m) {
    const host = m[1].toLowerCase();
    if (!ctx.route.allowedHosts.has(host)) return null;
    return `${ctx.route.upstreamProtocol}//${host}${m[2]}`;
  }
  return ctx.route.upstreamOrigin + rest;
}

// Deep-rewrite every upstream URL string in a JSON value.
function rewriteJsonUrls(value, ctx) {
  if (typeof value === "string") return toProxyUrl(value, ctx) ?? value;
  if (Array.isArray(value)) return value.map((v) => rewriteJsonUrls(v, ctx));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = rewriteJsonUrls(v, ctx);
    return out;
  }
  return value;
}

function rewriteHeaderUrls(header, ctx) {
  return header.replace(/https?:\/\/[^\s",]+/g, (m) => toProxyUrl(m, ctx) ?? m);
}

// Split an incoming path into { route, rest }. Handles the RFC 8414 / RFC 9728
// "path insertion" form, where the well-known segment comes first:
//   /.well-known/oauth-protected-resource/notion-work/mcp
//   -> route notion-work, rest /.well-known/oauth-protected-resource/mcp
export function splitPath(pathname, routes) {
  const parts = pathname.split("/");
  if (parts[1] === ".well-known" && WELL_KNOWN.includes(parts[2])) {
    const route = routes.get(parts[3]);
    if (!route) return null;
    // Upstream host override inside the inserted path: /.well-known/x/route/~host/...
    if (parts[4] && parts[4].startsWith("~")) {
      const tail = parts.slice(5).join("/");
      return { route, rest: `/${parts[4]}/.well-known/${parts[2]}${tail ? "/" + tail : ""}` };
    }
    const tail = parts.slice(4).join("/");
    return { route, rest: `/.well-known/${parts[2]}${tail ? "/" + tail : ""}` };
  }
  const route = routes.get(parts[1]);
  if (!route) return null;
  return { route, rest: "/" + parts.slice(2).join("/") };
}

function isWellKnown(rest) {
  return /^(\/~[^/]+)?\/\.well-known\//.test(rest);
}

// ------------------------------------------------------------- handlers ---

export function createHandler({ routes, secret, fetchImpl = fetch }) {
  if (!secret || secret.length < 32) {
    throw new Error("PROXY_SECRET must be set to at least 32 characters");
  }
  const keyPromise = hmacKey(secret);

  return async function handle(request) {
    const url = new URL(request.url);
    if (url.pathname === "/" || url.pathname === "/healthz") {
      return new Response("mcp-proxy ok\n", { headers: { "content-type": "text/plain" } });
    }
    const split = splitPath(url.pathname, routes);
    if (!split) return new Response("Not found\n", { status: 404 });

    const ctx = { route: split.route, proxyOrigin: url.origin, key: await keyPromise };
    const upstreamUrl = toUpstreamUrl(routeBase(ctx.proxyOrigin, ctx.route) + split.rest + url.search, ctx);
    if (!upstreamUrl) return new Response("Forbidden host\n", { status: 403 });

    if (split.rest === CALLBACK_PATH) return handleCallback(url, ctx);

    // Browser-facing authorization request: redirect, never fetch.
    if (
      request.method === "GET" &&
      url.searchParams.has("response_type") &&
      url.searchParams.has("client_id")
    ) {
      return handleAuthorize(url, upstreamUrl, ctx);
    }

    return forward(request, split.rest, upstreamUrl, ctx, fetchImpl);
  };
}

async function handleAuthorize(url, upstreamUrl, ctx) {
  const params = new URLSearchParams(url.search);
  const client = await unseal(CLIENT_PREFIX, params.get("client_id"), ctx.key);
  if (!client || client.rt !== ctx.route.name) {
    return oauthError(400, "invalid_client", "Unknown client_id for this route");
  }
  const redirectUri = params.get("redirect_uri") || (client.r.length === 1 ? client.r[0] : null);
  if (!redirectUri || !client.r.includes(redirectUri)) {
    return oauthError(400, "invalid_request", "redirect_uri is not registered for this client");
  }
  const state = await seal(
    STATE_PREFIX,
    { s: params.get("state"), u: redirectUri, rt: ctx.route.name, exp: Math.floor(Date.now() / 1000) + STATE_TTL_SECONDS },
    ctx.key,
  );
  params.set("client_id", client.c);
  params.set("redirect_uri", routeBase(ctx.proxyOrigin, ctx.route) + CALLBACK_PATH);
  params.set("state", state);
  rewriteResourceParams(params, ctx);
  const target = new URL(upstreamUrl);
  target.search = params.toString();
  return new Response(null, { status: 302, headers: { location: target.toString(), "cache-control": "no-store" } });
}

async function handleCallback(url, ctx) {
  const params = new URLSearchParams(url.search);
  const st = await unseal(STATE_PREFIX, params.get("state"), ctx.key);
  if (!st || st.rt !== ctx.route.name || st.exp < Math.floor(Date.now() / 1000)) {
    return new Response("Invalid or expired state\n", { status: 400 });
  }
  const back = new URL(st.u);
  for (const k of ["code", "error", "error_description", "error_uri"]) {
    if (params.has(k)) back.searchParams.set(k, params.get(k));
  }
  if (st.s !== null && st.s !== undefined) back.searchParams.set("state", st.s);
  // RFC 9207: report the issuer the client discovered, i.e. the proxy's.
  if (params.has("iss")) back.searchParams.set("iss", toProxyUrl(params.get("iss"), ctx) ?? params.get("iss"));
  return new Response(null, { status: 302, headers: { location: back.toString(), "cache-control": "no-store" } });
}

function rewriteResourceParams(params, ctx) {
  const resources = params.getAll("resource");
  if (!resources.length) return;
  params.delete("resource");
  for (const r of resources) params.append("resource", toUpstreamUrl(r, ctx) ?? r);
}

async function forward(request, rest, upstreamUrl, ctx, fetchImpl) {
  const headers = new Headers();
  for (const [k, v] of request.headers) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.includes(lk) || lk.startsWith("cf-") || lk.startsWith("x-forwarded-")) continue;
    headers.set(k, v);
  }

  let body;
  let initializeIds = null;
  if (request.method !== "GET" && request.method !== "HEAD") {
    const ct = (request.headers.get("content-type") || "").toLowerCase();
    if (ct.startsWith("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(await request.text());
      await rewriteTokenRequest(params, headers, ctx);
      body = params.toString();
    } else if (ct.startsWith("application/json")) {
      const text = await request.text();
      let json;
      try {
        json = JSON.parse(text);
      } catch {
        json = undefined;
      }
      if (json && !Array.isArray(json) && Array.isArray(json.redirect_uris)) {
        return handleRegister(json, headers, upstreamUrl, ctx, fetchImpl);
      }
      initializeIds = findInitializeIds(json);
      body = text;
    } else {
      body = request.body;
    }
  }

  const upstreamRes = await fetchImpl(upstreamUrl, {
    method: request.method,
    headers,
    body,
    redirect: "manual",
    ...(body && typeof body !== "string" ? { duplex: "half" } : {}),
  });

  return rewriteResponse(upstreamRes, rest, ctx, initializeIds);
}

// Token, revocation and introspection requests: swap our wrapped client_id
// for the upstream one, restore the redirect_uri the upstream saw, and map
// the resource indicator back to the upstream URL.
async function rewriteTokenRequest(params, headers, ctx) {
  if (params.has("client_id")) {
    const client = await unseal(CLIENT_PREFIX, params.get("client_id"), ctx.key);
    if (client && client.rt === ctx.route.name) params.set("client_id", client.c);
  }
  const auth = headers.get("authorization");
  if (auth && /^basic /i.test(auth)) {
    try {
      const decoded = atob(auth.slice(6).trim());
      const i = decoded.indexOf(":");
      const id = decodeURIComponent(i < 0 ? decoded : decoded.slice(0, i));
      const pw = i < 0 ? "" : decoded.slice(i + 1);
      const client = await unseal(CLIENT_PREFIX, id, ctx.key);
      if (client && client.rt === ctx.route.name) {
        headers.set("authorization", "Basic " + btoa(`${encodeURIComponent(client.c)}:${pw}`));
      }
    } catch {
      // leave the header as sent
    }
  }
  if (params.get("grant_type") === "authorization_code") {
    params.set("redirect_uri", routeBase(ctx.proxyOrigin, ctx.route) + CALLBACK_PATH);
  }
  rewriteResourceParams(params, ctx);
}

// Dynamic client registration (RFC 7591). Register the proxy's callback with
// the upstream, then hand the client a signed client_id that carries the
// upstream client_id and the client's own redirect URIs.
async function handleRegister(json, headers, upstreamUrl, ctx, fetchImpl) {
  const clientRedirects = json.redirect_uris.filter((u) => typeof u === "string");
  const upstreamBody = { ...json, redirect_uris: [routeBase(ctx.proxyOrigin, ctx.route) + CALLBACK_PATH] };
  headers.set("content-type", "application/json");
  const res = await fetchImpl(upstreamUrl, {
    method: "POST",
    headers,
    body: JSON.stringify(upstreamBody),
    redirect: "manual",
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = null;
  }
  if (!res.ok || !data || typeof data.client_id !== "string") {
    return new Response(text, { status: res.status, headers: { "content-type": res.headers.get("content-type") || "application/json" } });
  }
  const out = rewriteJsonUrls(data, ctx);
  out.client_id = await seal(CLIENT_PREFIX, { c: data.client_id, r: clientRedirects, rt: ctx.route.name }, ctx.key);
  out.redirect_uris = clientRedirects;
  return Response.json(out, { status: res.status, headers: { "cache-control": "no-store" } });
}

function findInitializeIds(json) {
  const msgs = Array.isArray(json) ? json : json ? [json] : [];
  const ids = msgs.filter((m) => m && m.method === "initialize" && "id" in m).map((m) => m.id);
  return ids.length ? new Set(ids.map((id) => JSON.stringify(id))) : null;
}

async function rewriteResponse(res, rest, ctx, initializeIds) {
  const headers = new Headers(res.headers);
  headers.delete("content-length");
  headers.delete("content-encoding");
  for (const h of ["www-authenticate", "location", "link"]) {
    const v = headers.get(h);
    if (v) headers.set(h, rewriteHeaderUrls(v, ctx));
  }
  const ct = (res.headers.get("content-type") || "").toLowerCase();

  if (isWellKnown(rest) && ct.includes("json") && res.ok) {
    const json = await res.json();
    const out = rewriteJsonUrls(json, ctx);
    if (/oauth-authorization-server|openid-configuration/.test(rest)) {
      // Clients must register through the proxy so their redirect URIs can
      // be wrapped; a URL-based client ID document would bypass that.
      delete out.client_id_metadata_document_supported;
    }
    return Response.json(out, { status: res.status, headers });
  }

  if (initializeIds && ct.includes("application/json")) {
    const json = await res.json();
    return Response.json(renameServer(json, initializeIds, ctx), { status: res.status, headers });
  }

  if (ct.includes("text/event-stream") && res.body) {
    return new Response(res.body.pipeThrough(sseRewriter(ctx, initializeIds)), { status: res.status, headers });
  }

  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

function renameServer(json, ids, ctx) {
  const name = ctx.route.displayName;
  if (!name) return json;
  const fix = (m) => {
    if (m && ids.has(JSON.stringify(m.id)) && m.result && m.result.serverInfo) {
      m.result.serverInfo = { ...m.result.serverInfo, name, title: name };
    }
    return m;
  };
  return Array.isArray(json) ? json.map(fix) : fix(json);
}

// Line-based SSE transformer. Renames the server in an initialize result and
// maps the legacy SSE transport's `endpoint` event onto the route.
function sseRewriter(ctx, initializeIds) {
  let buffer = "";
  let event = "message";
  const base = `/${ctx.route.name}`;
  const rewriteLine = (line) => {
    if (line === "" || line === "\r") {
      event = "message";
      return line;
    }
    if (line.startsWith("event:")) {
      event = line.slice(6).trim();
      return line;
    }
    if (!line.startsWith("data:")) return line;
    const data = line.slice(5).replace(/^ /, "");
    if (event === "endpoint") {
      if (data.startsWith("/")) return `data: ${base}${data}`;
      const mapped = toProxyUrl(data, ctx);
      return mapped ? `data: ${mapped}` : line;
    }
    if (initializeIds && ctx.route.displayName && data.includes("serverInfo")) {
      try {
        return `data: ${JSON.stringify(renameServer(JSON.parse(data), initializeIds, ctx))}`;
      } catch {
        return line;
      }
    }
    return line;
  };
  return new TransformStream({
    transform(chunk, controller) {
      buffer += dec.decode(chunk, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop();
      if (lines.length) controller.enqueue(enc.encode(lines.map(rewriteLine).join("\n") + "\n"));
    },
    flush(controller) {
      buffer += dec.decode();
      if (buffer) controller.enqueue(enc.encode(rewriteLine(buffer)));
    },
  });
}

function oauthError(status, error, description) {
  return Response.json({ error, error_description: description }, { status, headers: { "cache-control": "no-store" } });
}
