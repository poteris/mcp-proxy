# mcp-proxy

A small pass-through reverse proxy for remote MCP servers, so the same MCP service can be added to an AI client more than once, each with its own sign-in.

## Why this exists

Hosted MCP servers such as Notion's (`https://mcp.notion.com/mcp`) use one URL for everyone and decide whose data you see from the OAuth token. Some MCP clients, claude.ai among them, only allow one connector per URL, and some also merge connectors that report the same server name. If you have a work Notion and a personal Notion, or two client workspaces, you can only connect one of them at a time.

mcp-proxy gives each account its own URL:

```
https://your-proxy.example/notion-work/mcp      -> https://mcp.notion.com/mcp
https://your-proxy.example/notion-personal/mcp  -> https://mcp.notion.com/mcp
```

Add each URL as a separate custom connector. Each one runs Notion's own OAuth sign-in, so you pick a different account or workspace for each, and the client keeps the tokens apart.

The same approach works for any remote MCP server that follows the MCP authorization spec (OAuth 2.1 with discovery and dynamic client registration): Linear, Sentry, and so on. Add a route per account.

## How it works

The proxy forwards MCP traffic (Streamable HTTP and the older SSE transport) unchanged, apart from these rewrites:

- **Discovery documents.** Upstream URLs in the protected-resource metadata (RFC 9728) and authorization-server metadata (RFC 8414) are rewritten to point back through the route. To the client, each route looks like its own server with its own issuer. Both the path-inserted form (`/.well-known/oauth-protected-resource/notion-work/mcp`) and the route-prefixed form are served.
- **The `resource` parameter** (RFC 8707) is mapped back to the upstream URL on authorization and token requests. The upstream therefore issues tokens for itself, and those tokens work unchanged.
- **Client registration and the redirect.** The proxy registers its own callback with the upstream. It gives the client a signed `client_id` that carries the upstream client ID and the client's redirect URIs. After sign-in, the upstream redirects to the proxy. The proxy checks the signed state, swaps in the proxy's issuer (`iss`, RFC 9207) and redirects to the client's registered callback. This keeps the issuer consistent for clients that check it, and an unregistered redirect URI is refused, so the proxy cannot be used as an open redirect.
- **Server name.** The `serverInfo.name` in the `initialize` result is replaced with the route's `name`, so clients that merge connectors by name keep them apart.
- **`WWW-Authenticate`, `Location` and the legacy SSE `endpoint` event** are rewritten to stay on the route.

The proxy stores nothing: there is no database and no token storage. Upstream access and refresh tokens pass straight through to the client, as they would without the proxy. Its only secret is `PROXY_SECRET`, used to sign the client IDs and OAuth state.

It only forwards to hosts configured for a route, so it is not an open proxy. Cookies are not forwarded.

## Deploy (Cloudflare Workers)

```bash
git clone https://github.com/poteris/mcp-proxy && cd mcp-proxy
npm install
cp wrangler.example.toml wrangler.toml   # edit ROUTES
openssl rand -base64 48 | npx wrangler secret put PROXY_SECRET
npx wrangler deploy
```

`wrangler.toml` is gitignored, so your routes and account settings stay out of the repo.

Routes are set in `ROUTES`:

```json
{
  "notion-work":     { "upstream": "https://mcp.notion.com/mcp", "name": "Notion (work)" },
  "notion-personal": { "upstream": "https://mcp.notion.com/mcp", "name": "Notion (personal)" }
}
```

| Field | Meaning |
| --- | --- |
| key | Route name: lower-case letters, digits, `-` and `_`. It becomes the first path segment. |
| `upstream` | The upstream MCP endpoint. The connector URL is `https://<proxy>/<route><upstream path>`. |
| `name` | Optional. Replaces the server name reported to the client. Set it when two routes share an upstream. |
| `authHosts` | Optional. Extra hosts to allow when the upstream's authorization server is on a different host from the MCP server. They are proxied as `/<route>/~<host>/...`. |

Then, in Claude: **Settings → Connectors → Add custom connector**, paste `https://<proxy>/notion-work/mcp`, and sign in. Repeat for each route.

The handler (`src/proxy.js`) is plain Web-standard `fetch` code with no Cloudflare bindings. It should also run on other runtimes that support the Fetch API, such as Deno, Bun or Vercel Edge, with a few lines of glue.

## Things to know

- **It depends on the upstream's OAuth flow.** If a provider changes how discovery or registration works, a route can break until the proxy is updated. Providers that don't support dynamic client registration, or that pin redirect URIs to their own allow-list, won't work without changes.
- **The upstream sees the proxy's callback URL** (for example `https://your-proxy.example/notion-work/__mcp_proxy/callback`) as the redirect URI, and the client name the AI client registered with.
- **Your proxy is in the path of your MCP traffic and tokens.** Run your own instance, keep `PROXY_SECRET` secret, and don't add logging that records request bodies or headers.
- **Rotating `PROXY_SECRET`** invalidates every registered client ID. Each connector then has to be removed and added again.
- This is not affiliated with Notion, Anthropic or any MCP provider.

## Development

```bash
npm test        # node --test, against a mock upstream shaped like Notion's
npx wrangler dev
```

## Licence

MIT. See [LICENSE](./LICENSE).
