# gsc-mcp

Google Search Console audit server for MCP (FastMCP; stdio by default, optional
bearer-protected HTTP for hosting; no frontend).
Read-only by default, hard daily API caps, SSRF-safe fetches.

## Setup
```
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```
Auth (one of):
- Service account: share the property with its email, set `GSC_CREDENTIALS_PATH`.
- OAuth desktop: set `GSC_OAUTH_CLIENT_SECRETS`, run `python server.py --login`
  (token saved to `~/.gsc-mcp/token.json`, mode 0600).

PageSpeed: set `PSI_API_KEY`. All variables are listed in `.env.example`.

MCP client config (secrets stay in env or key files, never in this repo):
```
{"mcpServers": {"gsc": {"command": "/abs/path/.venv/bin/python",
  "args": ["/abs/path/server.py"], "env": {"GSC_CREDENTIALS_PATH": "/abs/path/key-file"}}}}
```

## Tools
Raw: `list_sites`, `search_analytics`, `inspect_url`, `list_sitemaps`, `get_sitemap`,
`submit_sitemap` and `delete_sitemap` (write; need `GSC_ENABLE_WRITE=1`).
Audit: `bulk_inspect_urls`, `sitemap_urls`, `compare_periods`, `striking_distance`,
`low_ctr_pages`, `cannibalization`, `traffic_by_segment`, `page_query_map`,
`export_all`, `pagespeed`, `robots_check`, `usage_status`.

## Daily caps
Counted in `~/.gsc-mcp/usage.db` (SQLite, atomic, shared by all instances) before every
outbound call; failed calls count. Every call also counts against `total`.
- `analytics` (1000): all non-inspect Search Console calls
- `inspect` (1500), `psi` (200), `fetch` (200, sitemap/robots), `write` (20)
- `total` (1500), plus `GSC_RATE_PER_MIN` (60) tool calls per minute per process.

At a cap the tool returns "Daily cap reached (X/Y), resets 00:00 UTC". Multi-call tools
return partial results with a note. Check `usage_status`.

## Security notes
- One wrapper validates inputs (allowlists), catches errors, caps output at 200 KB.
  Errors are one generic line; details go to stderr, scrubbed of keys/paths/tokens.
- Fetches: https only, host must belong to the property, public IPs only (DNS result
  is pinned for the connection), max 3 same-host redirects, 10 s, 10 MB.
  PageSpeed uses 60 s because Lighthouse runs take longer than 10 s.
- Sitemaps parsed with `defusedxml` (DTD/entities rejected).
- Key files with permissions wider than 0600 trigger a warning.
- `oauth.py`: OAuth 2.1 with PKCE, redirects limited to claude.ai/claude.com/localhost.
- `GSC_ALLOWED_SITES` limits which properties the server will touch.

## Deploy on Render (free)
1. Push this folder to GitHub, then Render > New > Blueprint > pick the repo
   (`render.yaml`, `plan: free`). `MCP_AUTH_TOKEN` is generated for you.
2. Service > Environment > Secret Files: add `gsc-key.json` (service-account key).
   Optional env: `PSI_API_KEY`, `GSC_ALLOWED_SITES`, `GSC_ENABLE_WRITE`, caps.
3. Claude web/desktop: Settings > Connectors > Add custom connector, URL
   `https://<service>.onrender.com/mcp`, then "Sign in now" and "Use your own OAuth
   client". Enter `OAUTH_CLIENT_ID` (`gsc-mcp-claude`) and the generated
   `OAUTH_CLIENT_SECRET` from Render's Environment tab. It connects with no prompt.
   Second option: "Register automatically"; the sign-in page then asks for
   `MCP_AUTH_TOKEN` as the password. Header-capable clients can also send
   `Authorization: Bearer <MCP_AUTH_TOKEN>`. `/health` is open (returns `ok`).
4. Keep-alive: GitHub repo > Settings > Variables > `RENDER_URL` (service URL).
   `.github/workflows/keepalive.yml` pings `/health` every 5 min (free services
   sleep after 15 min idle). Best-effort: GitHub may delay crons and pauses them
   after 60 days without repo activity.
Free tier has no persistent disk: daily caps reset on every redeploy/restart.
OAuth state is signed with `MCP_AUTH_TOKEN`, so redeploys keep connections; rotating
the token signs out every client. Five wrong passwords lock the login for 10 minutes.
The preset client is only as safe as its secret: keep it private, rotate in Render.
Local HTTP test: `MCP_AUTH_TOKEN=<24+ chars> python server.py --http`.

## Development
```
pip install pytest ruff vulture bandit pip-audit
pytest -q && ruff check --select F,E,B,S,C90 . && vulture server.py && bandit -r . -x ./.venv
```
