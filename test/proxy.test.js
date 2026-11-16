// End-to-end tests against a mock upstream shaped like Notion's hosted MCP
// (same discovery documents, DCR, PKCE authorize and token endpoints).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHandler, parseRoutes, splitPath } from "../src/proxy.js";

const UP = "https://mcp.notion.com";
const P = "https://proxy.test";
const SECRET = "x".repeat(40);
const CLIENT_CB = "https://claude.ai/api/mcp/auth_callback";

function mockUpstream() {
  const log = [];
  const clients = new Map();
  const codes = new Map();
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    const body = typeof init.body === "string" ? init.body : undefined;
    const headers = new Headers(init.headers);
    log.push({ url: u.toString(), method: init.method || "GET", body, headers });
    const json = (o, status = 200, extra = {}) =>
      new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json", ...extra } });

    if (u.pathname === "/.well-known/oauth-protected-resource/mcp") {
      return json({ resource: `${UP}/mcp`, authorization_servers: [UP], scopes_supported: ["default"], bearer_methods_supported: ["header"], resource_name: "Notion MCP (Beta)" });
    }
    if (u.pathname === "/.well-known/oauth-authorization-server") {
      return json({
        issuer: UP,
        authorization_endpoint: `${UP}/authorize`,
        token_endpoint: `${UP}/token`,
        registration_endpoint: `${UP}/register`,
        revocation_endpoint: `${UP}/token`,
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"],
        authorization_response_iss_parameter_supported: true,
        client_id_metadata_document_supported: true,
      });
    }
    if (u.pathname === "/register") {
      const req = JSON.parse(body);
      const id = `notion-client-${clients.size + 1}`;
      clients.set(id, req.redirect_uris);
      return json({ client_id: id, redirect_uris: req.redirect_uris, token_endpoint_auth_method: "none" }, 201);
    }
    if (u.pathname === "/token") {
      const p = new URLSearchParams(body);
      const c = codes.get(p.get("code"));
      if (!c || c.client !== p.get("client_id") || c.redirect !== p.get("redirect_uri") || c.resource !== p.get("resource")) {
        return json({ error: "invalid_grant" }, 400);
      }
      return json({ access_token: `tok-for-${c.client}`, token_type: "Bearer", refresh_token: "r1" });
    }
    if (u.pathname === "/mcp") {
      if (!headers.get("authorization")) {
        return new Response("unauthorized", {
          status: 401,
          headers: { "www-authenticate": `Bearer resource_metadata="${UP}/.well-known/oauth-protected-resource/mcp"` },
        });
      }
      const msg = JSON.parse(body);
      const result = { jsonrpc: "2.0", id: msg.id, result: msg.method === "initialize" ? { protocolVersion: "2025-06-18", serverInfo: { name: "Notion", version: "1.0" }, capabilities: {} } : { tools: [] } };
      if ((headers.get("accept") || "").includes("text/event-stream") && headers.get("x-test-sse")) {
        return new Response(`event: message\ndata: ${JSON.stringify(result)}\n\n`, { headers: { "content-type": "text/event-stream", "mcp-session-id": "s1" } });
      }
      return json(result, 200, { "mcp-session-id": "s1" });
    }
    if (u.pathname === "/sse") {
      return new Response("event: endpoint\ndata: /message?sessionId=abc\n\n", { headers: { "content-type": "text/event-stream" } });
    }
    return new Response("nope", { status: 404 });
  };
  // What the upstream's own authorize page does after the user consents.
  const consent = (authorizeUrl) => {
    const u = new URL(authorizeUrl);
    assert.equal(u.origin + u.pathname, `${UP}/authorize`);
    const client = u.searchParams.get("client_id");
    const redirect = u.searchParams.get("redirect_uri");
    assert.ok(clients.get(client).includes(redirect), "upstream sees a registered redirect_uri");
    const code = `code-${codes.size + 1}`;
    codes.set(code, { client, redirect, resource: u.searchParams.get("resource") });
    const back = new URL(redirect);
    back.searchParams.set("code", code);
    back.searchParams.set("state", u.searchParams.get("state"));
    back.searchParams.set("iss", UP);
    return back.toString();
  };
  return { fetchImpl, log, consent };
}

function setup() {
  const up = mockUpstream();
  const routes = parseRoutes({
    "notion-work": { upstream: `${UP}/mcp`, name: "Notion (work)" },
    "notion-personal": { upstream: `${UP}/mcp`, name: "Notion (personal)" },
  });
  const handle = createHandler({ routes, secret: SECRET, fetchImpl: up.fetchImpl });
  const call = (path, init) => handle(new Request(P + path, init));
  return { up, call };
}

// Runs the whole sign-in a client like claude.ai does, through one route.
async function signIn(call, up, route) {
  const mcpUrl = `${P}/${route}/mcp`;
  const r401 = await call(`/${route}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  assert.equal(r401.status, 401);
  const prmUrl = r401.headers.get("www-authenticate").match(/resource_metadata="([^"]+)"/)[1];
  assert.equal(prmUrl, `${P}/${route}/.well-known/oauth-protected-resource/mcp`);

  // Clients usually try the RFC 9728 path-inserted form first.
  const prm = await (await call(`/.well-known/oauth-protected-resource/${route}/mcp`)).json();
  assert.equal(prm.resource, mcpUrl);
  assert.deepEqual(prm.authorization_servers, [`${P}/${route}`]);

  const asm = await (await call(`/.well-known/oauth-authorization-server/${route}`)).json();
  assert.equal(asm.issuer, `${P}/${route}`);
  assert.equal(asm.authorization_endpoint, `${P}/${route}/authorize`);
  assert.equal(asm.registration_endpoint, `${P}/${route}/register`);
  assert.equal(asm.client_id_metadata_document_supported, undefined);

  const reg = await call(`/${route}/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "Claude", redirect_uris: [CLIENT_CB], token_endpoint_auth_method: "none" }),
  });
  assert.equal(reg.status, 201);
  const client = await reg.json();
  assert.ok(client.client_id.startsWith("mcpp1."));
  assert.deepEqual(client.redirect_uris, [CLIENT_CB]);

  const authQ = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: CLIENT_CB, state: "client-state", code_challenge: "abc", code_challenge_method: "S256", resource: mcpUrl });
  const authRes = await call(`/${route}/authorize?${authQ}`);
  assert.equal(authRes.status, 302);
  const upstreamAuth = new URL(authRes.headers.get("location"));
  assert.equal(upstreamAuth.searchParams.get("resource"), `${UP}/mcp`);
  assert.equal(upstreamAuth.searchParams.get("redirect_uri"), `${P}/${route}/__mcp_proxy/callback`);

  const cb = new URL(up.consent(upstreamAuth.toString()));
  const cbRes = await call(cb.pathname + cb.search);
  assert.equal(cbRes.status, 302);
  const back = new URL(cbRes.headers.get("location"));
  assert.equal(back.origin + back.pathname, CLIENT_CB);
  assert.equal(back.searchParams.get("state"), "client-state");
  assert.equal(back.searchParams.get("iss"), `${P}/${route}`);

  const tokRes = await call(`/${route}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code: back.searchParams.get("code"), client_id: client.client_id, redirect_uri: CLIENT_CB, code_verifier: "v", resource: mcpUrl }).toString(),
  });
  assert.equal(tokRes.status, 200, await tokRes.clone().text());
  return { token: (await tokRes.json()).access_token, client };
}

test("full sign-in, then initialize is renamed per route", async () => {
  const { up, call } = setup();
  const { token } = await signIn(call, up, "notion-work");
  const init = await call("/notion-work/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}`, accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
  });
  const body = await init.json();
  assert.equal(body.result.serverInfo.name, "Notion (work)");
  assert.equal(init.headers.get("mcp-session-id"), "s1");
  assert.equal(up.log.at(-1).headers.get("authorization"), `Bearer ${token}`);
});

test("two routes to the same upstream get separate clients and tokens", async () => {
  const { up, call } = setup();
  const a = await signIn(call, up, "notion-work");
  const b = await signIn(call, up, "notion-personal");
  assert.notEqual(a.token, b.token);
  assert.notEqual(a.client.client_id, b.client.client_id);
});

test("initialize over SSE is renamed; other calls pass through", async () => {
  const { call } = setup();
  const res = await call("/notion-personal/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer t", accept: "text/event-stream", "x-test-sse": "1" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "a", method: "initialize", params: {} }),
  });
  const text = await res.text();
  assert.match(text, /"name":"Notion \(personal\)"/);
  const list = await call("/notion-personal/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer t" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
  });
  assert.deepEqual((await list.json()).result, { tools: [] });
});

test("legacy SSE endpoint event is mapped onto the route", async () => {
  const { call } = setup();
  const text = await (await call("/notion-work/sse", { headers: { authorization: "Bearer t" } })).text();
  assert.match(text, /data: \/notion-work\/message\?sessionId=abc/);
});

test("a client_id from one route is refused on another", async () => {
  const { up, call } = setup();
  const { client } = await signIn(call, up, "notion-work");
  const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: CLIENT_CB, state: "s" });
  const res = await call(`/notion-personal/authorize?${q}`);
  assert.equal(res.status, 400);
});

test("an unregistered redirect_uri is refused (no open redirect)", async () => {
  const { up, call } = setup();
  const { client } = await signIn(call, up, "notion-work");
  const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: "https://evil.example/cb", state: "s" });
  assert.equal((await call(`/notion-work/authorize?${q}`)).status, 400);
});

test("forged client_id and state are refused", async () => {
  const { call } = setup();
  const q = new URLSearchParams({ response_type: "code", client_id: "mcpp1.eyJjIjoiYSJ9.AAAA", redirect_uri: CLIENT_CB });
  assert.equal((await call(`/notion-work/authorize?${q}`)).status, 400);
  assert.equal((await call(`/notion-work/__mcp_proxy/callback?code=x&state=mcpps1.e30.AAAA`)).status, 400);
});

test("unknown routes and hosts are not proxied", async () => {
  const { call } = setup();
  assert.equal((await call("/other/mcp")).status, 404);
  assert.equal((await call("/notion-work/~evil.example/x")).status, 403);
});

test("splitPath handles the path-inserted well-known forms", () => {
  const routes = parseRoutes({ r: "https://a.example/mcp" });
  assert.deepEqual(splitPath("/.well-known/oauth-authorization-server/r", routes).rest, "/.well-known/oauth-authorization-server");
  assert.deepEqual(splitPath("/.well-known/oauth-protected-resource/r/mcp", routes).rest, "/.well-known/oauth-protected-resource/mcp");
  assert.equal(splitPath("/.well-known/oauth-protected-resource/nope/mcp", routes), null);
});

test("short secrets are rejected", () => {
  assert.throws(() => createHandler({ routes: new Map(), secret: "short" }));
});
