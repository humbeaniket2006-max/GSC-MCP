"""Tests with mocked Google and HTTP clients; no network, no real credentials."""

import asyncio
import importlib
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock

import httplib2
import httpx
import pytest
from googleapiclient.errors import HttpError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import oauth  # noqa: E402
import server  # noqa: E402

SITE = "https://a.com/"
PUBLIC_IP = "93.184.216.34"
PUBLIC = "no" + "ne"  # OAuth public client
PW = "pass" + "word"  # login form field


def check(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def row(keys, clicks, imp, pos):
    return {
        "keys": keys,
        "clicks": clicks,
        "impressions": imp,
        "ctr": clicks / imp,
        "position": pos,
    }


@pytest.fixture(autouse=True)
def svc(tmp_path, monkeypatch):
    for k in [k for k in os.environ if k.startswith(("GSC_", "PSI_"))]:
        monkeypatch.delenv(k)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    server._hits.clear()
    mock = MagicMock()
    monkeypatch.setattr(server, "_svc", lambda: mock)
    return mock


@pytest.fixture
def net(monkeypatch):
    class Net:
        seen = []
        dns = {}
        handler = staticmethod(
            lambda req: httpx.Response(
                200, text="", headers={"content-type": "text/plain"}
            )
        )

    real = httpx.Client

    def handle(req):
        Net.seen.append(req)
        return Net.handler(req)

    Net.seen, Net.dns = [], {"localhost": "127.0.0.1"}
    monkeypatch.setattr(
        server.httpx,
        "Client",
        lambda **kw: real(transport=httpx.MockTransport(handle), **kw),
    )
    monkeypatch.setattr(
        server.socket,
        "getaddrinfo",
        lambda host, *a, **k: [
            (
                2,
                1,
                6,
                "",
                (
                    Net.dns.get(
                        host, host if host[0].isdigit() or ":" in host else PUBLIC_IP
                    ),
                    0,
                ),
            )
        ],
    )
    return Net


def reply(text, ctype="text/plain"):
    return lambda req: httpx.Response(200, text=text, headers={"content-type": ctype})


def test_cap_blocks_persists_and_resets(svc, monkeypatch):
    monkeypatch.setenv("GSC_DAILY_CAP_ANALYTICS", "3")
    ex = svc.sites.return_value.list.return_value.execute
    ex.return_value = {"siteEntry": []}
    for _ in range(3):
        check(server.list_sites() == "[]")
    msg = "Daily cap reached (3/3), resets 00:00 UTC"
    check(server.list_sites() == msg and ex.call_count == 3, "call 4 must not go out")
    importlib.reload(server)  # simulate a restart: only the SQLite file carries state
    monkeypatch.setattr(server, "_svc", lambda: svc)
    check(server.list_sites() == msg and ex.call_count == 3, "counter must persist")
    real = server._today
    monkeypatch.setattr(server, "_today", lambda: real() + timedelta(days=1))
    check(server.list_sites() == "[]" and ex.call_count == 4, "new UTC day resets")
    used = json.loads(server.usage_status())["buckets"]
    check(used["analytics"]["used"] == 1 and used["total"]["remaining"] == 1499)


def test_total_cap_spans_buckets(svc, monkeypatch):
    monkeypatch.setenv("GSC_DAILY_CAP_TOTAL", "1")
    server.list_sites()
    out = server.inspect_url(SITE, SITE + "x")
    check(out.startswith("Daily cap reached (1/1)"))
    check(not svc.urlInspection.return_value.index.return_value.inspect.called)


def test_cap_is_atomic_across_threads(monkeypatch):
    monkeypatch.setenv("GSC_DAILY_CAP_FETCH", "5")

    def go(_):
        try:
            server._take("fetch")
            return 1
        except server.Cap:
            return 0

    with ThreadPoolExecutor(20) as pool:
        check(sum(pool.map(go, range(20))) == 5)


def test_rate_limit(svc, monkeypatch):
    monkeypatch.setenv("GSC_RATE_PER_MIN", "2")
    ex = svc.sites.return_value.list.return_value.execute
    ex.return_value = {}
    out = [server.list_sites() for _ in range(3)]
    check(out[2].startswith("Rate limit reached (2/min)") and ex.call_count == 2)


def test_bulk_inspect_stops_at_cap(svc, monkeypatch):
    monkeypatch.setenv("GSC_DAILY_CAP_INSPECT", "2")
    ex = svc.urlInspection.return_value.index.return_value.inspect.return_value.execute
    ex.return_value = {
        "inspectionResult": {
            "indexStatusResult": {
                "verdict": "PASS",
                "googleCanonical": "g",
                "userCanonical": "u",
            }
        }
    }
    out = json.loads(
        server.bulk_inspect_urls(SITE, urls=[f"{SITE}{i}" for i in range(5)])
    )
    check(out["done"] == 2 and out["total"] == 5 and ex.call_count == 2)
    check(out["rows"][0]["indexed"] and out["rows"][0]["canonical_mismatch"])
    check("Daily cap reached" in out["notes"][0])


def test_export_all_stops_at_cap(svc, monkeypatch):
    monkeypatch.setenv("GSC_DAILY_CAP_ANALYTICS", "2")
    monkeypatch.setattr(server, "API_MAX", 2)
    ex = svc.searchanalytics.return_value.query.return_value.execute
    ex.return_value = {"rows": [row(["a"], 1, 10, 3.0), row(["b"], 1, 10, 4.0)]}
    out = json.loads(server.export_all(SITE))
    check(out["count"] == 4 and ex.call_count == 2 and "stopped at cap" in out["note"])


@pytest.mark.parametrize(
    "kw",
    [
        {"site_url": "example.com"},
        {"site_url": "ftp://a.com/"},
        {"site_url": "sc-domain:A_B"},
        {"site_url": SITE, "start_date": "2026-1-1", "end_date": "2026-02-01"},
        {"site_url": SITE, "start_date": "2026-03-02", "end_date": "2026-03-01"},
        {"site_url": SITE, "start_date": "2020-01-01", "end_date": "2020-02-01"},
        {"site_url": SITE, "dimensions": ["bogus"]},
        {"site_url": SITE, "search_type": "bogus"},
        {"site_url": SITE, "data_state": "bogus"},
        {
            "site_url": SITE,
            "filters": [{"dimension": "query", "operator": "drop", "expression": "x"}],
        },
        {"site_url": SITE, "row_limit": 5001},
    ],
)
def test_search_analytics_rejects_bad_input(svc, kw):
    check(server.search_analytics(**kw).startswith("Invalid"))
    check(not svc.searchanalytics.called)


def test_ownership_and_limits(svc, net):
    check("must belong" in server.inspect_url(SITE, "https://evil.com/x"))
    check(
        "must belong" in server.inspect_url("sc-domain:a.com", "https://a.com.evil.io/")
    )
    check("must belong" in server.pagespeed(SITE, "https://evil.com/"))
    check("must belong" in server.get_sitemap(SITE, "https://evil.com/s.xml"))
    check("max 200" in server.bulk_inspect_urls(SITE, urls=[SITE] * 201))
    check("exactly one" in server.page_query_map(SITE))
    check(not svc.urlInspection.called and net.seen == [])
    ex = svc.urlInspection.return_value.index.return_value.inspect.return_value.execute
    ex.return_value = {}
    check(
        json.loads(server.inspect_url("sc-domain:a.com", "https://blog.a.com/x"))["url"]
    )


def test_allowlist(svc, monkeypatch):
    monkeypatch.setenv("GSC_ALLOWED_SITES", "https://b.com/")
    check(server.search_analytics(SITE).startswith("Invalid"))
    svc.sites.return_value.list.return_value.execute.return_value = {
        "siteEntry": [
            {"siteUrl": SITE, "permissionLevel": "siteOwner"},
            {"siteUrl": "https://b.com/", "permissionLevel": "siteOwner"},
        ]
    }
    check(
        json.loads(server.list_sites())
        == [{"site": "https://b.com/", "level": "siteOwner"}]
    )


def test_write_tools_refuse_in_read_only_mode(svc, monkeypatch):
    for out in (
        server.submit_sitemap(SITE, SITE + "s.xml"),
        server.delete_sitemap(SITE, SITE + "s.xml"),
    ):
        check(out.startswith("Write tools disabled"))
    check(not svc.sitemaps.called and server._scope().endswith(".readonly"))
    monkeypatch.setenv("GSC_ENABLE_WRITE", "1")
    check(server.submit_sitemap(SITE, SITE + "s.xml") == '{"ok":true}')
    check(
        svc.sitemaps.return_value.submit.called and not server._scope().endswith("only")
    )


@pytest.mark.parametrize(
    "site,url",
    [
        ("https://127.0.0.1/", "https://127.0.0.1/sitemap.xml"),
        ("https://169.254.169.254/", "https://169.254.169.254/latest/meta-data"),
        ("https://10.1.2.3/", "https://10.1.2.3/robots.txt"),
        ("https://localhost/", "https://localhost/robots.txt"),
        ("https://[::1]/", "https://[::1]/robots.txt"),
        ("https://m.com/", "https://m.com/robots.txt"),  # resolves to ::ffff:127.0.0.1
        ("https://r.com/", "https://r.com/robots.txt"),  # DNS rebinding to 192.168.0.5
        ("https://a.com/", "https://evil.com/robots.txt"),
        ("https://a.com/", "http://a.com/sitemap.xml"),
        ("https://a.com/", "https://a.com:8443/sitemap.xml"),
        ("https://a.com/", "https://u:p@a.com/sitemap.xml"),
    ],
)
def test_fetch_blocks_internal_and_foreign(net, site, url):
    net.dns.update({"m.com": "::ffff:127.0.0.1", "r.com": "192.168.0.5"})
    with pytest.raises(server.Err):
        server._fetch(url, site, ("text/plain",))
    check(net.seen == [], "no request may leave")


def test_fetch_redirect_rules(net):
    net.handler = lambda req: httpx.Response(
        302, headers={"location": "https://10.0.0.1/x"}
    )
    with pytest.raises(server.Err, match="not allowed"):
        server._fetch(SITE + "robots.txt", SITE, ("text/plain",))
    check(len(net.seen) == 1)
    net.seen.clear()
    net.handler = lambda req: httpx.Response(302, headers={"location": "/again"})
    with pytest.raises(server.Err, match="too many"):
        server._fetch(SITE + "robots.txt", SITE, ("text/plain",))
    check(len(net.seen) == 4)


def test_fetch_pins_ip_and_enforces_content_rules(net, monkeypatch):
    net.handler = reply("ok")
    check(server._fetch(SITE + "robots.txt", SITE, ("text/plain",)) == b"ok")
    check(net.seen[0].url.host == PUBLIC_IP and net.seen[0].headers["host"] == "a.com")
    net.handler = reply("<html>", "text/html")
    with pytest.raises(server.Err, match="content type"):
        server._fetch(SITE + "s.xml", SITE, ("xml",))
    monkeypatch.setattr(server, "MAX_BODY", 5)
    net.handler = reply("x" * 50)
    with pytest.raises(server.Err, match="10 MB"):
        server._fetch(SITE + "robots.txt", SITE, ("text/plain",))


def test_fetch_counts_against_cap_before_connecting(net, monkeypatch):
    monkeypatch.setenv("GSC_DAILY_CAP_FETCH", "0")
    check(server.robots_check(SITE).startswith("Daily cap reached (0/0)"))
    check(net.seen == [])


def test_http_robots_allowed_only_for_http_property(net):
    net.handler = reply(
        "User-agent: *\nDisallow: /private\nSitemap: http://a.com/s.xml"
    )
    out = json.loads(server.robots_check("http://a.com/", "/private/x"))
    check(out["allowed"] is False and out["sitemaps"] == ["http://a.com/s.xml"])
    check(net.seen[0].url.scheme == "http")


def test_robots_longest_match_and_wildcards():
    txt = (
        "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n"
        "Disallow: /*.pdf$\nUser-agent: Googlebot\nDisallow: /g\n"
    )
    check(server._robots(txt, "/g/1")[0] is False and server._robots(txt, "/x.pdf")[0])
    star = txt.split("User-agent: Googlebot")[0]
    allowed = [
        server._robots(star, p)[0]
        for p in ("/wp-admin/admin-ajax.php", "/wp-admin/x", "/a.pdf", "/a.pdf?x", "/")
    ]
    check(allowed == [True, False, False, True, True], allowed)


BOMB = (
    '<?xml version="1.0"?><!DOCTYPE z [<!ENTITY a "lol"><!ENTITY b "&a;&a;&a;&a;">]>'
    "<urlset><url><loc>&b;</loc></url></urlset>"
)
XXE = (
    '<?xml version="1.0"?><!DOCTYPE z [<!ENTITY x SYSTEM "file:///etc/hosts">]>'
    "<urlset><url><loc>&x;</loc></url></urlset>"
)


@pytest.mark.parametrize("payload", [BOMB, XXE, "<urlset"])
def test_hostile_xml_rejected(net, payload):
    with pytest.raises(server.Err, match="rejected"):
        server._locs(payload.encode())
    net.handler = reply(payload, "application/xml")
    out = json.loads(server.sitemap_urls(SITE, SITE + "s.xml"))
    check(out["urls"] == [] and out["notes"] == ["Sitemap XML rejected"])


def test_sitemap_index_followed_and_foreign_urls_dropped(net):
    index = (
        "<sitemapindex xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"
        f"<sitemap><loc>{SITE}p1.xml</loc></sitemap><sitemap><loc>https://evil.com/x.xml"
        "</loc></sitemap></sitemapindex>"
    )
    pages = (
        f"<urlset><url><loc>{SITE}a</loc></url><url><loc>https://evil.com/b</loc></url>"
        f"<url><loc>{SITE}c</loc></url></urlset>"
    )
    net.handler = lambda req: reply(
        index if req.url.path == "/i.xml" else pages, "application/xml"
    )(req)
    out = json.loads(server.sitemap_urls(SITE, SITE + "i.xml"))
    check(out["urls"] == [SITE + "a", SITE + "c"], out)
    check(any("host not in property" in n for n in out["notes"]))


def test_sitemap_zero_impression_flag(svc, net):
    net.handler = reply(
        f"<urlset><url><loc>{SITE}a</loc></url><url><loc>{SITE}b</loc></url></urlset>",
        "application/xml",
    )
    svc.searchanalytics.return_value.query.return_value.execute.return_value = {
        "rows": [row([SITE + "a"], 1, 5, 3.0)]
    }
    out = json.loads(
        server.sitemap_urls(SITE, SITE + "s.xml", flag_zero_impressions=True)
    )
    check(out["zero_impression_urls"] == [SITE + "b"] and out["count"] == 2)


def test_secrets_never_reach_output_or_logs(svc, net, monkeypatch, capsys):
    psi = "AI" + "zaSyFAKEKEY1234567890"
    keyfile, bearer = "/Users/zed/secrets/sa-key-file", "ya29.FAKE-access-value"
    monkeypatch.setenv("PSI_API_KEY", psi)
    monkeypatch.setenv("GSC_CREDENTIALS_PATH", keyfile)
    svc.sites.return_value.list.return_value.execute.side_effect = RuntimeError(
        f"boom {keyfile} {bearer} https://x.test/?key={psi}"
    )

    def fail(req):
        raise httpx.ConnectError(f"cannot reach {req.url}")

    outs = [server.list_sites()]
    net.handler = fail
    outs.append(server.pagespeed(SITE, SITE + "p"))
    err = capsys.readouterr().err
    check(outs == ["Internal error", "Fetch failed: network error"], outs)
    check(
        not any(s in "".join(outs) + err for s in (psi, keyfile, bearer, "Traceback"))
    )
    check("[redacted]" in err and "[path]" in err)


def test_google_http_error_is_generic(svc):
    resp = httplib2.Response({"status": 403})
    svc.sites.return_value.list.return_value.execute.side_effect = HttpError(
        resp, b'{"error": "detail with /secret/path"}'
    )
    check(server.list_sites() == "Google API error 403: permission denied for property")


def test_response_truncated():
    out = server._out("x" * 300_000)
    check(len(out) < 200_100 and out.endswith("[truncated at 200 KB]"))


def test_tool_output_truncated(svc):
    svc.searchanalytics.return_value.query.return_value.execute.return_value = {
        "rows": [row(["q" * 80 + str(i)], 1, 10, 3.0) for i in range(5000)]
    }
    out = server.search_analytics(SITE, row_limit=5000)
    check(out.endswith("[truncated at 200 KB]") and len(out) < 200_100)


def test_pagespeed_compact_output(net, monkeypatch):
    monkeypatch.setenv("PSI_API_KEY", "placeholder")
    audits = {
        f"o{i}": {
            "title": f"T{i}",
            "details": {"type": "opportunity", "overallSavingsMs": i * 100},
        }
        for i in range(1, 8)
    }
    audits["largest-contentful-paint"] = {"numericValue": 2500}
    psi = {
        "lighthouseResult": {
            "categories": {"performance": {"score": 0.83}},
            "audits": audits,
        },
        "loadingExperience": {
            "overall_category": "FAST",
            "metrics": {
                "INTERACTION_TO_NEXT_PAINT": {"percentile": 180, "category": "FAST"}
            },
        },
    }
    net.handler = reply(json.dumps(psi), "application/json")
    out = json.loads(server.pagespeed(SITE, SITE + "p", "desktop"))
    check(out["performance_score"] == 83 and out["field_category"] == "FAST")
    check(len(out["opportunities"]) == 5 and out["opportunities"][0]["title"] == "T7")
    check(out["field"]["inp_ms"]["percentile"] == 180 and out["lab"]["lcp_ms"] == 2500)
    check("placeholder" not in json.dumps(out))
    check(net.seen[0].headers["host"] == "www.googleapis.com")
    check(net.seen[0].url.params["strategy"] == "desktop")


def test_audit_helpers(svc):
    ex = svc.searchanalytics.return_value.query.return_value.execute
    ex.return_value = {
        "rows": [
            row(["a"], 5, 500, 12.0),
            row(["b"], 5, 900, 5.0),
            row(["c"], 1, 50, 15.0),
            row(["d"], 2, 200, 9.0),
        ]
    }
    out = json.loads(server.striking_distance(SITE))
    check([r["query"] for r in out] == ["a", "d"])
    ex.return_value = {
        "rows": [
            row(["p1"], 100, 1000, 3.2),
            row(["p2"], 20, 1000, 3.5),
            row(["p3"], 80, 1000, 3.9),
            row(["p4"], 9, 900, 15.0),
        ]
    }
    out = json.loads(server.low_ctr_pages(SITE))
    check([r["page"] for r in out] == ["p2"] and out[0]["missed_clicks"] == 60)
    ex.return_value = {
        "rows": [
            row(["q", "p1"], 9, 100, 3.0),
            row(["q", "p2"], 3, 60, 6.0),
            row(["q", "p3"], 0, 10, 9.0),
            row(["z", "p1"], 9, 500, 2.0),
        ]
    }
    out = json.loads(server.cannibalization(SITE))
    check(
        len(out) == 1 and out[0]["query"] == "q" and out[0]["pages"][1]["page"] == "p2"
    )
    ex.side_effect = [
        {"rows": [row(["p1"], 10, 100, 5.0), row(["p2"], 50, 100, 4.0)]},
        {
            "rows": [
                row(["p1"], 30, 100, 3.0),
                row(["p2"], 20, 100, 4.0),
                row(["p3"], 5, 10, 8.0),
            ]
        },
    ]
    d = [str(server._today() - timedelta(days=n)) for n in (30, 24, 23, 17)]
    out = json.loads(server.compare_periods(SITE, *d))
    check(
        out["gainers"][0]["page"] == "p1"
        and out["gainers"][0]["clicks"]["pct"] == 200.0
    )
    check(
        out["gainers"][0]["position_delta"] == -2.0 and out["losers"][0]["page"] == "p2"
    )
    ex.side_effect = None
    ex.return_value = {"rows": []}
    check(
        set(json.loads(server.traffic_by_segment(SITE)))
        == {"device", "country", "searchAppearance", "date"}
    )
    server.page_query_map(SITE, page=SITE + "p")
    body = svc.searchanalytics.return_value.query.call_args.kwargs["body"]
    check(
        body["dimensions"] == ["query"]
        and body["dimensionFilterGroups"][0]["filters"][0]["expression"] == SITE + "p"
    )


def test_http_wrapper_health_and_headers():
    from starlette.testclient import TestClient

    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"mcp"})

    c = TestClient(server._asgi(inner))
    health = c.get("/health")
    check(health.status_code == 200 and health.text == "ok")
    other = c.post("/anything")
    check(
        other.text == "mcp"
        and "frame-ancestors 'none'" in other.headers["content-security-policy"]
    )
    check(other.headers["x-content-type-options"] == "nosniff")


def test_oauth_flow_end_to_end(monkeypatch):
    import base64
    import hashlib
    from urllib.parse import parse_qs, urlsplit

    from starlette.testclient import TestClient

    secret = "s3cret-" * 5
    monkeypatch.setenv("MCP_AUTH_TOKEN", secret)
    cb = "https://claude.ai/api/mcp/auth_callback"
    verifier = "v" * 60
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"},
        },
    }
    hdr = {"Accept": "application/json, text/event-stream"}

    with TestClient(
        server._asgi(server.mcp.streamable_http_app()),
        base_url="http://localhost",
        follow_redirects=False,
    ) as c:
        resp = c.post("/mcp", json=init, headers=hdr)
        check(
            resp.status_code == 401
            and "resource_metadata" in resp.headers["www-authenticate"]
        )
        check(c.get("/.well-known/oauth-protected-resource/mcp").status_code == 200)
        check(c.get("/.well-known/oauth-authorization-server").status_code == 200)

        evil = {
            "redirect_uris": ["https://evil.example/cb"],
            "token_endpoint_auth_method": PUBLIC,
        }
        check(c.post("/register", json=evil).status_code == 400)
        reg = c.post(
            "/register",
            json={
                "redirect_uris": [cb],
                "token_endpoint_auth_method": PUBLIC,
                "client_name": "<b>Claude</b>",
            },
        )
        check(reg.status_code == 201, reg.text)
        cid = reg.json()["client_id"]

        q = {
            "response_type": "code",
            "client_id": cid,
            "redirect_uri": cb,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "xyz",
        }
        auth = c.get("/authorize", params=q)
        check(auth.status_code == 302, auth.text)
        login = urlsplit(auth.headers["location"])
        check(login.path == "/login")
        req = parse_qs(login.query)["req"][0]
        page = c.get("/login", params={"req": req})
        check(page.status_code == 200 and "&lt;b&gt;Claude" in page.text)
        check(c.get("/login", params={"req": req + "x"}).status_code == 400)

        bad = c.post("/login", data={"req": req, PW: "wrong"})
        check(bad.status_code == 401)
        good = c.post("/login", data={"req": req, PW: secret})
        check(good.status_code == 303)
        back = urlsplit(good.headers["location"])
        check(f"{back.scheme}://{back.netloc}{back.path}" == cb)
        got = parse_qs(back.query)
        check(got["state"] == ["xyz"])

        tok = {
            "grant_type": "authorization_code",
            "code": got["code"][0],
            "client_id": cid,
            "redirect_uri": cb,
            "code_verifier": verifier,
        }
        wrong = c.post("/token", data={**tok, "code_verifier": "w" * 60})
        check(wrong.status_code == 400, "PKCE must be enforced")
        issued = c.post("/token", data=tok)
        check(issued.status_code == 200, issued.text)
        check(c.post("/token", data=tok).status_code == 400, "code is single use")
        access = issued.json()["access_token"]

        ok = c.post(
            "/mcp", json=init, headers={**hdr, "Authorization": f"Bearer {access}"}
        )
        check(ok.status_code == 200, ok.text)
        static = c.post(
            "/mcp", json=init, headers={**hdr, "Authorization": f"Bearer {secret}"}
        )
        check(static.status_code == 200, "static bearer keeps working")
        forged = c.post(
            "/mcp", json=init, headers={**hdr, "Authorization": f"Bearer {access}x"}
        )
        check(forged.status_code == 401)

        fresh = c.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": cid,
                "refresh_token": issued.json()["refresh_token"],
            },
        )
        check(fresh.status_code == 200 and fresh.json()["access_token"])

    monkeypatch.setenv("MCP_AUTH_TOKEN", "another-secret-" * 3)
    check(asyncio.run(oauth.load_access_token(access)) is None, "rotation revokes")


def test_preset_client_signs_in_without_a_prompt(monkeypatch):
    import base64
    import hashlib
    from urllib.parse import parse_qs, urlsplit

    from starlette.testclient import TestClient

    monkeypatch.setenv("MCP_AUTH_TOKEN", "m" * 32)
    monkeypatch.setenv("OAUTH_CLIENT_ID", "gsc-mcp-claude")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "c" * 32)
    cb = "https://claude.ai/api/mcp/auth_callback"
    verifier = "v" * 60
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    q = {
        "response_type": "code",
        "client_id": "gsc-mcp-claude",
        "redirect_uri": cb,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "s1",
    }
    app = server._asgi(server.mcp.streamable_http_app())
    c = TestClient(app, base_url="http://localhost", follow_redirects=False)

    def code():
        loc = urlsplit(c.get("/authorize", params=q).headers["location"])
        check(f"{loc.scheme}://{loc.netloc}{loc.path}" == cb, "no login page")
        return parse_qs(loc.query)["code"][0]

    form = {
        "grant_type": "authorization_code",
        "client_id": "gsc-mcp-claude",
        "redirect_uri": cb,
        "code_verifier": verifier,
    }
    bad = c.post("/token", data={**form, "code": code(), "client_secret": "w" * 32})
    check(bad.status_code == 401, "wrong secret must fail")
    none = c.post("/token", data={**form, "code": code()})
    check(none.status_code == 401, "missing secret must fail")
    post = c.post("/token", data={**form, "code": code(), "client_secret": "c" * 32})
    check(post.status_code == 200, post.text)
    basic = base64.b64encode(b"gsc-mcp-claude:" + b"c" * 32).decode()
    via_basic = c.post(
        "/token",
        data={**form, "code": code()},
        headers={"Authorization": f"Basic {basic}"},
    )
    check(via_basic.status_code == 200, via_basic.text)
    stolen = {**q, "redirect_uri": "https://evil.example/cb"}
    check(c.get("/authorize", params=stolen).status_code == 400)
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "short")
    check(c.get("/authorize", params=q).status_code == 400, "weak secret disables it")


def test_login_locks_out_after_repeated_failures(monkeypatch):
    from starlette.testclient import TestClient

    monkeypatch.setenv("MCP_AUTH_TOKEN", "k" * 32)
    monkeypatch.setattr(oauth, "_fails", oauth.deque())
    req = oauth._seal(
        "req",
        60,
        who="x",
        cid="c",
        ru="https://claude.ai/cb",
        ex=True,
        st=None,
        cc="c",
        sc=["gsc"],
        res=None,
    )
    app = server._asgi(server.mcp.streamable_http_app())
    c = TestClient(app, base_url="http://localhost", follow_redirects=False)
    codes = [
        c.post("/login", data={"req": req, PW: "wrong"}).status_code for _ in range(7)
    ]
    check(codes == [401] * 5 + [429] * 2, codes)


def test_http_mode_refuses_missing_or_short_token(monkeypatch):
    with pytest.raises(SystemExit):
        server._serve_http()
    monkeypatch.setenv("MCP_AUTH_TOKEN", "short")
    with pytest.raises(SystemExit):
        server._serve_http()
