"""GSC audit MCP server (stdio). Read-only unless GSC_ENABLE_WRITE=1."""

import functools
import hmac
import inspect
import ipaddress
import json
import os
import re
import socket
import sqlite3
import statistics
import sys
import time
from collections import deque
from contextlib import closing
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import google_auth_httplib2
import httplib2
import httpx
import uvicorn
from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

__all__ = [  # the registered tools (also tells vulture they are used)
    "list_sites", "search_analytics", "inspect_url", "list_sitemaps", "get_sitemap",
    "submit_sitemap", "delete_sitemap", "bulk_inspect_urls", "sitemap_urls",
    "compare_periods", "striking_distance", "low_ctr_pages", "cannibalization",
    "traffic_by_segment", "page_query_map", "export_all", "pagespeed",
    "robots_check", "usage_status",
]
_HOST = os.environ.get("RENDER_EXTERNAL_HOSTNAME", "localhost")  # HTTP Host allowlist
mcp = FastMCP(
    "gsc-audit",
    stateless_http=True,
    transport_security=TransportSecuritySettings(allowed_hosts=[_HOST, _HOST + ":*"]),
)
CAPS = dict(total=1500, analytics=1000, inspect=1500, psi=200, fetch=200, write=20)
SITE_RE = r"(sc-domain:[a-z0-9.-]+|https?://[^\s/]+/.*)"
DIMS = {"query", "page", "country", "device", "date", "searchAppearance"}
OPS = {"equals", "notEquals", "contains", "notContains", "includingRegex",
       "excludingRegex"}
ALLOWED = {
    "search_type": {"web", "image", "video", "news", "googleNews", "discover"},
    "data_state": {"final", "all"},
    "strategy": {"mobile", "desktop"},
    "by": {"page", "query"},
}
LIMITS = {"row_limit": (1, 5000), "start_row": (0, 10**6), "max_rows": (1, 50000),
          "limit": (1, 200), "min_impressions": (0, 10**9)}
PAIRS = (("start_date", "end_date"), ("a_start", "a_end"), ("b_start", "b_end"))
OWNED = ("inspection_url", "sitemap_url", "url", "page", "urls")
REASONS = {400: "bad request", 401: "authentication failed",
           403: "permission denied for property", 404: "not found",
           429: "quota exceeded"}
SECRET_ENV = ("GSC_CREDENTIALS_PATH", "GSC_OAUTH_CLIENT_SECRETS", "PSI_API_KEY")
FIELD = {"lcp_ms": "LARGEST_CONTENTFUL_PAINT_MS", "inp_ms": "INTERACTION_TO_NEXT_PAINT",
         "cls_x100": "CUMULATIVE_LAYOUT_SHIFT_SCORE"}
IX = {"verdict": "verdict", "coverage": "coverageState", "indexing": "indexingState",
      "robots": "robotsTxtState", "last_crawl": "lastCrawlTime",
      "google_canonical": "googleCanonical", "user_canonical": "userCanonical"}
API_MAX, MAX_BODY, MAX_OUT, MAX_URLS = 25000, 10 * 2**20, 200_000, 50000
PSI_URL = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
Opt = str | None
_hits = deque()


class Err(Exception):
    """Safe, user-facing error message."""


class Cap(Err):
    """Daily cap reached."""


def _scrub(s):
    for k in SECRET_ENV:
        s = s.replace(os.environ[k], "[redacted]") if os.environ.get(k) else s
    s = re.sub(r"(?i)\b(key|token|api_key)=[^&\s'\"]+", r"\1=[redacted]", s)
    s = re.sub(r"ya29\.[\w.-]+|Bearer\s+\S+", "[redacted]", s)
    return re.sub(r"~?(?:/[\w.-]+){2,}", "[path]", s.replace(str(Path.home()), "~"))


def _log(msg):
    print(_scrub(msg), file=sys.stderr)


def _msg(e):
    if isinstance(e, HttpError):
        why = REASONS.get(e.resp.status, "request failed")
        return f"Google API error {e.resp.status}: {why}"
    if isinstance(e, httpx.HTTPError):
        return "Fetch failed: network error"
    return str(e) if isinstance(e, Err) else "Internal error"


def _today():
    return datetime.now(timezone.utc).date()


def _d(s):
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", s or "")
    try:
        return date(*map(int, m.groups()))
    except (AttributeError, ValueError):
        raise Err("Invalid date, use YYYY-MM-DD") from None


def _owns(site, url):
    u = urlsplit(url)
    h = u.hostname or ""
    if u.scheme not in ("http", "https"):
        return False
    if site.startswith("sc-domain:"):
        return h == site[10:] or h.endswith("." + site[10:])
    return h == urlsplit(site).hostname


def _allowed():
    return [s for s in os.environ.get("GSC_ALLOWED_SITES", "").split(",") if s]


def _dates(a):
    today = _today()
    if "start_date" in a:
        a["end_date"] = a["end_date"] or str(today - timedelta(3))
        a["start_date"] = a["start_date"] or str(_d(a["end_date"]) - timedelta(27))
    for s, e in PAIRS:
        if s in a and not today - timedelta(487) <= _d(a[s]) <= _d(a[e]):
            raise Err("Invalid date range (start <= end, max 16 months back)")


def _check(a):
    """Validate arguments by name against allowlists; fill default dates."""
    site = a.get("site_url")
    allow = _allowed()
    bad = [k for k, ok in ALLOWED.items() if k in a and a[k] not in ok]
    bad += [k for k, (lo, hi) in LIMITS.items() if k in a and not lo <= a[k] <= hi]
    if site is not None and not re.fullmatch(SITE_RE, site):
        bad.append("site_url")
    if site is not None and allow and site not in allow:
        bad.append("site_url")
    if not set(a.get("dimensions") or ()) <= DIMS:
        bad.append("dimensions")
    for f in a.get("filters") or ():
        if not (f.get("dimension") in DIMS and f.get("operator") in OPS
                and isinstance(f.get("expression"), str)):
            bad.append("filters")
    if len(a.get("urls") or ()) > 200:
        bad.append("urls (max 200)")
    if bad:
        raise Err("Invalid or out-of-range: " + ", ".join(bad))
    for k in OWNED:
        v = a.get(k)
        if not all(_owns(site, u) for u in ([v] if isinstance(v, str) else v or ())):
            raise Err(f"{k} must belong to site_url")
    _dates(a)


def _out(x):
    s = x if isinstance(x, str) else json.dumps(x, separators=(",", ":"), default=str)
    b = s.encode()
    if len(b) > MAX_OUT:
        s = b[:MAX_OUT].decode(errors="ignore") + "\n[truncated at 200 KB]"
    return s


def _rate():
    now, limit = time.monotonic(), int(os.environ.get("GSC_RATE_PER_MIN", 60))
    while _hits and now - _hits[0] > 60:
        _hits.popleft()
    if len(_hits) >= limit:
        raise Err(f"Rate limit reached ({limit}/min), retry shortly")
    _hits.append(now)


def tool(fn):
    """Register fn as a tool behind rate limit, validation, error and size guards."""
    sig = inspect.signature(fn)

    @functools.wraps(fn)
    def run(*args, **kw):
        try:
            _rate()
            b = sig.bind(*args, **kw)
            b.apply_defaults()
            _check(b.arguments)
            return _out(fn(**b.arguments))
        except Exception as e:  # every failure leaves here as a one-line message
            _log(f"{fn.__name__}: {type(e).__name__}: {e}")
            return _msg(e)

    return mcp.tool()(run)


def _dir():
    d = Path.home() / ".gsc-mcp"
    d.mkdir(mode=0o700, exist_ok=True)
    d.chmod(0o700)
    return d


def _cap(b):
    return int(os.environ.get(f"GSC_DAILY_CAP_{b.upper()}", CAPS[b]))


def _db():
    p = _dir() / "usage.db"
    p.touch(mode=0o600)
    p.chmod(0o600)
    c = sqlite3.connect(p, timeout=10, isolation_level="IMMEDIATE")
    c.execute("CREATE TABLE IF NOT EXISTS usage "
              "(day TEXT, bucket TEXT, n INTEGER NOT NULL, PRIMARY KEY (day, bucket))")
    return c


def _take(bucket):
    """Atomically count one call against the total and bucket caps, before the call."""
    day = str(_today())
    with closing(_db()) as c:
        for b in ("total", bucket):
            c.execute("INSERT OR IGNORE INTO usage VALUES (?, ?, 0)", (day, b))
            up = "UPDATE usage SET n = n + 1 WHERE day = ? AND bucket = ? AND n < ?"
            if c.execute(up, (day, b, _cap(b))).rowcount == 0:
                sel = "SELECT n FROM usage WHERE day=? AND bucket=?"
                used = c.execute(sel, (day, b)).fetchone()[0]
                c.rollback()
                raise Cap(f"Daily cap reached ({used}/{_cap(b)}), resets 00:00 UTC")
        c.commit()


def _call(bucket, fn):
    """The only path to an outbound request: count first, then call (failures count)."""
    _take(bucket)
    return fn()


def _scope():
    base = "https://www.googleapis.com/auth/webmasters"
    return base if os.environ.get("GSC_ENABLE_WRITE") == "1" else base + ".readonly"


@functools.cache
def _svc():
    path, token = os.environ.get("GSC_CREDENTIALS_PATH"), _dir() / "token.json"
    try:
        if Path(path or token).stat().st_mode & 0o077:
            _log("warning: key file permissions wider than 0600")
        if path:
            creds = service_account.Credentials.from_service_account_file(
                path, scopes=[_scope()])
        else:
            creds = Credentials.from_authorized_user_file(str(token), [_scope()])
    except FileNotFoundError:
        raise Err("No credentials: set GSC_CREDENTIALS_PATH or run --login") from None
    http = google_auth_httplib2.AuthorizedHttp(creds, http=httplib2.Http(timeout=30))
    return build("searchconsole", "v1", http=http, cache_discovery=False)


def _login():
    secrets = os.environ.get("GSC_OAUTH_CLIENT_SECRETS")
    if not secrets:
        sys.exit("Set GSC_OAUTH_CLIENT_SECRETS to the OAuth desktop client file")
    flow = InstalledAppFlow.from_client_secrets_file(secrets, [_scope()])
    creds, token = flow.run_local_server(port=0), _dir() / "token.json"
    fd = os.open(token, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(creds.to_json())
    token.chmod(0o600)


def _api(bucket, resource, method, **kw):
    res = getattr(_svc(), resource)
    return _call(bucket, lambda: getattr(res(), method)(**kw).execute())


def _public(host):
    """Resolve host; return one IP, refusing any non-public address."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        raise Err("Fetch blocked: DNS failure") from None
    ips = {i[4][0].split("%")[0] for i in infos}
    for s in ips:
        ip = ipaddress.ip_address(s)
        ip = getattr(ip, "ipv4_mapped", None) or ip
        if not ip.is_global or ip.is_multicast:
            raise Err("Fetch blocked: non-public address")
    return sorted(ips)[0]


def _get(c, url, host, params, types):
    hdr, ext = {"Host": host, "User-Agent": "gsc-mcp"}, {"sni_hostname": host}
    with c.stream("GET", url, params=params, headers=hdr, extensions=ext) as r:
        if r.is_redirect:
            return r.headers["location"], b""
        if r.status_code != 200:
            raise Err(f"Fetch failed: HTTP {r.status_code}")
        if not any(t in r.headers.get("content-type", "") for t in types):
            raise Err("Fetch blocked: unexpected content type")
        buf = bytearray()
        for chunk in r.iter_bytes():
            buf += chunk
            if len(buf) > MAX_BODY:
                raise Err("Fetch blocked: response over 10 MB")
        return None, bytes(buf)


def _fetch(url, site, types, bucket="fetch", params=None, timeout=10):
    """SSRF-safe GET: same-host https, pinned public IP, <=3 redirects, 10 MB cap."""
    host = urlsplit(url).hostname
    with httpx.Client(timeout=timeout, follow_redirects=False) as c:
        for _ in range(4):
            u = urlsplit(url)
            robots = u.path == "/robots.txt" and (site or "").startswith("http://")
            if not (u.scheme == "https" or u.scheme == "http" and robots):
                raise Err("Fetch blocked: https only")
            if u.username or u.port or u.hostname != host:
                raise Err("Fetch blocked: URL not allowed")
            if site and not _owns(site, url):
                raise Err("Fetch blocked: host not in property")
            ip = _public(host)
            pinned = u._replace(netloc=f"[{ip}]" if ":" in ip else ip).geturl()
            go = functools.partial(_get, c, pinned, host, params, types)
            nxt, body = _call(bucket, go)
            if nxt is None:
                return body
            url = urljoin(url, nxt)
    raise Err("Fetch blocked: too many redirects")


def _query(site, dims, start, end, *, search_type="web", filters=None,
           limit=API_MAX, start_row=0, data_state="final"):
    """The one Search Analytics helper every analytics-based tool shares."""
    body = {"startDate": start, "endDate": end, "dimensions": dims, "type": search_type,
            "rowLimit": limit, "startRow": start_row, "dataState": data_state}
    if filters:
        keys = ("dimension", "operator", "expression")
        keep = [{k: f[k] for k in keys} for f in filters]
        body["dimensionFilterGroups"] = [{"groupType": "and", "filters": keep}]
    res = _api("analytics", "searchanalytics", "query", siteUrl=site, body=body)
    return [dict(zip(dims, r["keys"], strict=True), clicks=r["clicks"],
                 impressions=r["impressions"], ctr=round(r["ctr"], 4),
                 position=round(r["position"], 1)) for r in res.get("rows", [])]


def _export(site, dims, start, end, max_rows, **kw):
    """Page through _query (one counted call per page); stop at the cap."""
    rows, note = [], None
    while len(rows) < max_rows:
        n = min(API_MAX, max_rows - len(rows))
        try:
            page = _query(site, dims, start, end, limit=n, start_row=len(rows), **kw)
        except Cap as e:
            note = f"stopped at cap: {e}"
            break
        rows += page
        if len(page) < n:
            break
    return rows, note


def _inspect(site, url):
    body = {"inspectionUrl": url, "siteUrl": site}
    idx = _svc().urlInspection().index()
    res = _call("inspect", lambda: idx.inspect(body=body).execute())
    r = res.get("inspectionResult") or {}
    ix, mob, rich = (r.get(k) or {} for k in ("indexStatusResult",
                     "mobileUsabilityResult", "richResultsResult"))
    out = {"url": url, **{k: ix.get(v) for k, v in IX.items()}}
    g, u = out["google_canonical"], out["user_canonical"]
    return {**out, "canonical_mismatch": bool(g and u and g != u),
            "sitemaps": (ix.get("sitemap") or [])[:10], "mobile": mob.get("verdict"),
            "rich_results": rich.get("verdict"),
            "rich_types": [d.get("richResultType")
                           for d in rich.get("detectedItems") or ()]}


def _tag(e):
    return e.tag.rsplit("}", 1)[-1]


def _locs(body):
    try:
        root = fromstring(body, forbid_dtd=True)
    except (ParseError, DefusedXmlException):
        raise Err("Sitemap XML rejected") from None
    locs = [(c.text or "").strip() for e in root for c in e if _tag(c) == "loc"]
    return _tag(root) == "sitemapindex", locs


def _sitemap_urls(site, root):
    """Walk sitemap indexes (depth <= 2, <= 50k URLs); returns (urls, notes)."""
    urls, notes, queue = {}, [], [(root, 0)]
    while queue and len(urls) < MAX_URLS:
        loc, depth = queue.pop(0)
        try:
            is_index, locs = _locs(_fetch(loc, site, ("xml", "text/plain")))
        except Err as e:
            notes.append(str(e))
            if isinstance(e, Cap):
                break
            continue
        if not is_index:
            urls.update(dict.fromkeys(u for u in locs if _owns(site, u)))
        elif depth < 2:
            queue += [(x, depth + 1) for x in locs]
    return list(urls)[:MAX_URLS], notes


def _robots(text, path):
    """Parse robots.txt with Google semantics (longest match wins, allow on tie)."""
    groups, sitemaps, agents, in_rules = {}, [], [], False
    for line in text.splitlines():
        k, _, v = line.split("#")[0].partition(":")
        k, v = k.strip().lower(), v.strip()
        if k == "user-agent":
            agents, in_rules = ([] if in_rules else agents) + [v.lower()], False
        elif k in ("allow", "disallow"):
            in_rules = True
            for a in agents:
                groups.setdefault(a, []).append((k == "allow", v))
        elif k == "sitemap":
            sitemaps.append(v[:500])
    best = (-1, True)
    for allow, pat in groups.get("googlebot") or groups.get("*") or []:
        rx = re.escape(pat).replace(r"\*", ".*").replace(r"\$", "$")
        if pat and re.match(rx, path) and (len(pat), allow) > best:
            best = (len(pat), allow)
    return best[1], sitemaps[:20]


def _sm(e):
    keys = ("path", "type", "lastSubmitted", "lastDownloaded", "isPending",
            "warnings", "errors", "contents")
    return {k: e.get(k) for k in keys}


def _sitemap_write(method, site_url, sitemap_url):
    if os.environ.get("GSC_ENABLE_WRITE") != "1":
        raise Err("Write tools disabled; set GSC_ENABLE_WRITE=1")
    _api("write", "sitemaps", method, siteUrl=site_url, feedpath=sitemap_url)
    return {"ok": True}


@tool
def list_sites():
    """List Search Console properties this account can access."""
    allow = _allowed()
    rows = _api("analytics", "sites", "list").get("siteEntry", [])
    return [{"site": e["siteUrl"], "level": e["permissionLevel"]}
            for e in rows if not allow or e["siteUrl"] in allow]


@tool
def search_analytics(site_url: str, dimensions: list[str] | None = None,
                     search_type: str = "web", filters: list[dict] | None = None,
                     start_date: Opt = None, end_date: Opt = None,
                     row_limit: int = 1000, start_row: int = 0,
                     data_state: str = "final"):
    """Search Analytics rows (max 5000/call); filters: dimension/operator/expression."""
    return _query(site_url, dimensions or ["query"], start_date, end_date,
                  search_type=search_type, filters=filters, limit=row_limit,
                  start_row=start_row, data_state=data_state)


@tool
def inspect_url(site_url: str, inspection_url: str):
    """URL Inspection: index verdict, canonicals, crawl, robots, mobile, rich."""
    return _inspect(site_url, inspection_url)


@tool
def list_sitemaps(site_url: str):
    """List submitted sitemaps with status, warnings and errors."""
    res = _api("analytics", "sitemaps", "list", siteUrl=site_url)
    return [_sm(e) for e in res.get("sitemap", [])]


@tool
def get_sitemap(site_url: str, sitemap_url: str):
    """Status of one submitted sitemap."""
    kw = {"siteUrl": site_url, "feedpath": sitemap_url}
    return _sm(_api("analytics", "sitemaps", "get", **kw))


@tool
def submit_sitemap(site_url: str, sitemap_url: str):
    """Submit a sitemap. Write tool: needs GSC_ENABLE_WRITE=1."""
    return _sitemap_write("submit", site_url, sitemap_url)


@tool
def delete_sitemap(site_url: str, sitemap_url: str):
    """Delete a sitemap. Write tool: needs GSC_ENABLE_WRITE=1."""
    return _sitemap_write("delete", site_url, sitemap_url)


@tool
def bulk_inspect_urls(site_url: str, urls: list[str] | None = None,
                      sitemap_url: Opt = None):
    """Inspect <=200 URLs (list or sitemap), one row each; stops at the inspect cap."""
    if bool(urls) == bool(sitemap_url):
        raise Err("Provide exactly one of urls or sitemap_url")
    todo, notes = (urls, []) if urls else _sitemap_urls(site_url, sitemap_url)
    keys = ("url", "verdict", "coverage", "canonical_mismatch", "last_crawl",
            "robots", "mobile")
    rows = []
    for u in todo[:200]:
        try:
            r = _inspect(site_url, u)
        except (Err, HttpError) as e:
            notes.append(f"stopped: {_msg(e)}")
            break
        rows.append({"indexed": r["verdict"] == "PASS", **{k: r[k] for k in keys}})
    return {"done": len(rows), "total": min(len(todo), 200), "notes": notes,
            "rows": rows}


@tool
def sitemap_urls(site_url: str, sitemap_url: str, flag_zero_impressions: bool = False):
    """Parse a sitemap (depth 2, 50k URLs); optionally flag 0-impression URLs (90d)."""
    urls, notes = _sitemap_urls(site_url, sitemap_url)
    if not flag_zero_impressions:
        return {"count": len(urls), "notes": notes, "urls": urls}
    end = _today() - timedelta(3)
    rows, note = _export(site_url, ["page"], str(end - timedelta(89)), str(end), 50000)
    seen = {r["page"] for r in rows if r["impressions"] > 0}
    zero = [u for u in urls if u not in seen]
    return {"count": len(urls), "zero_count": len(zero), "zero_impression_urls": zero,
            "notes": notes + ([note] if note else [])}


@tool
def compare_periods(site_url: str, a_start: str, a_end: str, b_start: str, b_end: str,
                    by: str = "page", limit: int = 20):
    """Compare period A (baseline) vs B by page/query: top gainers and losers."""
    a, b = ({r[by]: r for r in _query(site_url, [by], s, e)}
            for s, e in ((a_start, a_end), (b_start, b_end)))
    rows = []
    for k in a.keys() | b.keys():
        x, y, row = a.get(k, {}), b.get(k, {}), {by: k}
        for m in ("clicks", "impressions"):
            d = y.get(m, 0) - x.get(m, 0)
            pct = round(100 * d / x[m], 1) if x.get(m) else None
            row[m] = {"a": x.get(m, 0), "b": y.get(m, 0), "change": d, "pct": pct}
        row["position_delta"] = x and y and round(y["position"] - x["position"], 1)
        rows.append(row)
    rows.sort(key=lambda r: r["clicks"]["change"])
    return {"losers": [r for r in rows[:limit] if r["clicks"]["change"] < 0],
            "gainers": [r for r in rows[::-1][:limit] if r["clicks"]["change"] > 0]}


@tool
def striking_distance(site_url: str, min_impressions: int = 100, limit: int = 50,
                      start_date: Opt = None, end_date: Opt = None):
    """Queries at average position 8-20 with at least min_impressions."""
    rows = _query(site_url, ["query"], start_date, end_date)
    hits = [r for r in rows
            if 8 <= r["position"] <= 20 and r["impressions"] >= min_impressions]
    return sorted(hits, key=lambda r: -r["impressions"])[:limit]


@tool
def low_ctr_pages(site_url: str, min_impressions: int = 100, limit: int = 50,
                  start_date: Opt = None, end_date: Opt = None):
    """Pages at position <= 10 with CTR below the median of their position bucket."""
    rows = _query(site_url, ["page"], start_date, end_date)
    rows = [r for r in rows
            if r["position"] <= 10 and r["impressions"] >= min_impressions]
    for r in rows:
        r["bucket"] = max(1, int(r["position"]))
    med = {k: statistics.median(r["ctr"] for r in rows if r["bucket"] == k)
           for k in {r["bucket"] for r in rows}}
    out = [{**r, "median_ctr": med[r["bucket"]],
            "missed_clicks": round((med[r["bucket"]] - r["ctr"]) * r["impressions"])}
           for r in rows if r["ctr"] < med[r["bucket"]]]
    return sorted(out, key=lambda r: -r["missed_clicks"])[:limit]


@tool
def cannibalization(site_url: str, min_impressions: int = 50, limit: int = 25,
                    start_date: Opt = None, end_date: Opt = None):
    """Queries where 2+ pages each reach min_impressions, with each page's share."""
    by_q, out = {}, []
    for r in _query(site_url, ["query", "page"], start_date, end_date):
        if r["impressions"] >= min_impressions:
            by_q.setdefault(r["query"], []).append(r)
    for q, pages in by_q.items():
        total = sum(p["impressions"] for p in pages)
        pages.sort(key=lambda p: -p["impressions"])
        if len(pages) > 1:
            top = [{**{k: p[k] for k in ("page", "clicks", "impressions", "position")},
                    "share": round(p["impressions"] / total, 2)} for p in pages[:5]]
            out.append({"query": q, "impressions": total, "pages": top})
    return sorted(out, key=lambda o: -o["impressions"])[:limit]


@tool
def traffic_by_segment(site_url: str, start_date: Opt = None, end_date: Opt = None):
    """Breakdown by device, country and searchAppearance, plus the daily trend."""
    return {d: _query(site_url, [d], start_date, end_date, limit=250)
            for d in ("device", "country", "searchAppearance", "date")}


@tool
def page_query_map(site_url: str, page: Opt = None, query: Opt = None, limit: int = 50,
                   start_date: Opt = None, end_date: Opt = None):
    """Top queries for one page, or top pages for one query (give exactly one)."""
    if bool(page) == bool(query):
        raise Err("Provide exactly one of page or query")
    dim, fdim = ("query", "page") if page else ("page", "query")
    flt = [{"dimension": fdim, "operator": "equals", "expression": page or query}]
    return _query(site_url, [dim], start_date, end_date, filters=flt, limit=limit)


@tool
def export_all(site_url: str, dimensions: list[str] | None = None,
               search_type: str = "web", filters: list[dict] | None = None,
               start_date: Opt = None, end_date: Opt = None, max_rows: int = 50000,
               data_state: str = "final"):
    """Paginate Search Analytics past 25k rows (<= 50k); each page counts as a call."""
    dims = dimensions or ["query"]
    rows, note = _export(site_url, dims, start_date, end_date, max_rows,
                         search_type=search_type, filters=filters,
                         data_state=data_state)
    cols = dims + ["clicks", "impressions", "ctr", "position"]
    return {"count": len(rows), "note": note, "columns": cols,
            "rows": [[r[c] for c in cols] for r in rows]}


@tool
def pagespeed(site_url: str, url: str, strategy: str = "mobile"):
    """PageSpeed Insights: score, LCP/INP/CLS (lab and CrUX), top 5 opportunities."""
    p = {"url": url, "strategy": strategy, "category": "performance"}
    if os.environ.get("PSI_API_KEY"):
        p["key"] = os.environ["PSI_API_KEY"]
    d = json.loads(_fetch(PSI_URL, None, ("json",), "psi", p, 60))
    lh, fe = d.get("lighthouseResult") or {}, d.get("loadingExperience") or {}
    au, m = lh.get("audits") or {}, fe.get("metrics") or {}
    opp = [a for a in au.values()
           if (a.get("details") or {}).get("type") == "opportunity"]
    opp.sort(key=lambda a: -a["details"].get("overallSavingsMs", 0))
    score = ((lh.get("categories") or {}).get("performance") or {}).get("score")
    lab = {"lcp_ms": "largest-contentful-paint", "cls": "cumulative-layout-shift"}
    return {
        "url": url, "strategy": strategy,
        "performance_score": score and round(score * 100),
        "lab": {k: (au.get(v) or {}).get("numericValue") for k, v in lab.items()},
        "field": {n: {x: (m.get(k) or {}).get(x) for x in ("percentile", "category")}
                  for n, k in FIELD.items()},
        "field_category": fe.get("overall_category"),
        "opportunities": [{"title": a.get("title"),
                           "savings_ms": a["details"].get("overallSavingsMs")}
                          for a in opp[:5]]}


@tool
def robots_check(site_url: str, path: str = "/"):
    """Fetch robots.txt: is path allowed for Googlebot, plus its Sitemap lines."""
    if not path.startswith("/") or re.search(r"\s", path):
        raise Err("path must start with / and contain no whitespace")
    u = urlsplit(site_url)
    origin = f"{u.scheme}://{u.netloc}"
    if site_url.startswith("sc-domain:"):
        origin = "https://" + site_url[10:]
    body = _fetch(origin + "/robots.txt", site_url, ("text/plain",))
    text = body.decode("utf-8", "replace")
    allowed, sitemaps = _robots(text, path)
    return {"path": path, "allowed": allowed, "sitemaps": sitemaps}


@tool
def usage_status():
    """Today's API calls used and remaining per cap bucket, plus the cap values."""
    with closing(_db()) as c:
        rows = c.execute("SELECT bucket, n FROM usage WHERE day = ?", (str(_today()),))
        used = dict(rows.fetchall())
    return {"date_utc": str(_today()),
            "per_minute_cap": int(os.environ.get("GSC_RATE_PER_MIN", 60)),
            "buckets": {b: {"used": used.get(b, 0), "cap": _cap(b),
                            "remaining": max(0, _cap(b) - used.get(b, 0))}
                        for b in CAPS}}


def _asgi(inner, token):
    """Wrap the MCP app: open /health, bearer token elsewhere, strict headers."""
    hdr = [(b"content-security-policy", b"default-src 'none'"),
           (b"x-content-type-options", b"nosniff")]
    want = b"Bearer " + token.encode()

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return await inner(scope, receive, send)
        got = dict(scope["headers"]).get(b"authorization", b"")
        health = scope["path"] == "/health" and scope["method"] in ("GET", "HEAD")
        if health or not hmac.compare_digest(got, want):
            status = 200 if health else 401
            start = {"type": "http.response.start", "status": status, "headers": hdr}
            await send(start)
            return await send({"type": "http.response.body", "body": b"ok" * health})

        async def send_safe(m):
            if m["type"] == "http.response.start":
                m = {**m, "headers": [*m.get("headers", []), *hdr]}
            await send(m)

        await inner(scope, receive, send_safe)

    return app


def _serve_http():
    """Remote hosting mode: streamable HTTP, bearer auth, Host-checked, no CORS."""
    token = os.environ.get("MCP_AUTH_TOKEN", "")
    if len(token) < 24:
        sys.exit("Set MCP_AUTH_TOKEN (at least 24 characters) for --http")
    uvicorn.run(_asgi(mcp.streamable_http_app(), token),
                host=os.environ.get("HOST", "127.0.0.1"),
                port=int(os.environ.get("PORT", 8000)),
                access_log=False, log_level="warning")


if __name__ == "__main__":
    if "--login" in sys.argv:
        _login()
    elif "--http" in sys.argv:
        _serve_http()
    else:
        mcp.run()
