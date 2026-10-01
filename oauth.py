"""Single-user OAuth 2.1 server for the hosted endpoint.

Preferred: a pre-registered client (OAUTH_CLIENT_ID + OAUTH_CLIENT_SECRET) that signs in
without a prompt. Fallback: any registered client plus the MCP_AUTH_TOKEN password page.

Clients, codes and tokens are HMAC-signed strings keyed by MCP_AUTH_TOKEN, so nothing
is stored and a redeploy keeps sessions alive. Rotating MCP_AUTH_TOKEN revokes all.
"""

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
from collections import deque
from contextvars import ContextVar
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    RefreshToken,
    RegistrationError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.responses import HTMLResponse, RedirectResponse, Response

ISSUER = os.environ.get("RENDER_EXTERNAL_URL", "http://localhost:8000").rstrip("/")
SCOPES = ["gsc"]
ACCESS_TTL, REFRESH_TTL, CODE_TTL, REQ_TTL = 3600, 30 * 86400, 300, 600
REDIRECT_HOSTS = {"claude.ai", "claude.com"}
PAGE = (
    "<!doctype html><meta name=viewport content='width=device-width'>"
    "<title>Sign in</title><h1>GSC MCP</h1><p>{who} wants access to Search Console "
    "tools.</p><p>{note}</p><form method=post action=/login>"
    "<input type=hidden name=req value='{req}'>"
    "<label>Password (MCP_AUTH_TOKEN) <input type=password name=password autofocus>"
    "</label> <button>Allow</button></form>"
)
DEFAULT_REDIRECTS = (
    "https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback"
)
basic = ContextVar("basic", default=False)  # set per /token request by the ASGI wrapper
_used, _fails = {}, deque()


def _key():
    key = os.environ.get("MCP_AUTH_TOKEN", "")
    if len(key) < 24:
        raise ValueError("MCP_AUTH_TOKEN must be at least 24 characters")
    return key.encode()


def _b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _mac(msg):
    return _b64(hmac.new(_key(), msg.encode(), hashlib.sha256).digest())


def _seal(kind, ttl=None, **data):
    body = {"k": kind, **data}
    if ttl:
        body["exp"] = int(time.time()) + ttl
    payload = _b64(json.dumps(body, separators=(",", ":")).encode())
    return f"{payload}.{_mac(payload)}"


def _open(kind, token):
    payload, _, sig = (token or "").partition(".")
    if not hmac.compare_digest(_mac(payload).encode(), sig.encode()):
        return None
    body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    live = body.get("exp", time.time() + 1) > time.time()
    return body if body.get("k") == kind and live else None


def _tokens(cid, scopes):
    return OAuthToken(
        access_token=_seal("at", ACCESS_TTL, cid=cid, sc=scopes),
        expires_in=ACCESS_TTL,
        scope=" ".join(scopes),
        refresh_token=_seal("rt", REFRESH_TTL, cid=cid, sc=scopes),
    )


def _preset():
    cid = os.environ.get("OAUTH_CLIENT_ID", "")
    secret = os.environ.get("OAUTH_CLIENT_SECRET", "")
    return (cid, secret) if cid and len(secret) >= 24 else None


async def get_client(client_id):
    preset = _preset()
    if preset and client_id == preset[0]:
        uris = os.environ.get("OAUTH_REDIRECT_URIS", DEFAULT_REDIRECTS).split(",")
        return OAuthClientInformationFull(
            client_id=client_id,
            client_secret=preset[1],
            client_name="Claude",
            redirect_uris=[u.strip() for u in uris if u.strip()],
            token_endpoint_auth_method="client_secret_basic"
            if basic.get()
            else "client_secret_post",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope=" ".join(SCOPES),
        )
    d = _open("client", client_id)
    if not d:
        return None
    secret = None if d["m"] == "none" else _mac("secret" + client_id)
    return OAuthClientInformationFull(
        client_id=client_id,
        client_secret=secret,
        redirect_uris=d["r"],
        token_endpoint_auth_method=d["m"],
        client_name=d["n"] or None,
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope=" ".join(SCOPES),
    )


async def register_client(info):
    for u in info.redirect_uris or []:
        s = urlsplit(str(u))
        ok = s.scheme == "https" and s.hostname in REDIRECT_HOSTS
        if not ok and not (
            s.scheme == "http" and s.hostname in ("localhost", "127.0.0.1")
        ):
            raise RegistrationError("invalid_redirect_uri", "redirect host not allowed")
    method = info.token_endpoint_auth_method
    cid = _seal(
        "client",
        r=[str(u) for u in info.redirect_uris],
        m=method,
        n=(info.client_name or "")[:100],
    )
    secret = None if method == "none" else _mac("secret" + cid)
    for field, value in (("client_id", cid), ("client_secret", secret)):
        setattr(info, field, value)


def _redirect(d):
    """Client redirect carrying a fresh single-use authorization code."""
    code = _seal(
        "code",
        CODE_TTL,
        jti=secrets.token_urlsafe(16),
        **{k: d[k] for k in ("cid", "ru", "ex", "cc", "sc", "res")},
    )
    return construct_redirect_uri(d["ru"], code=code, state=d["st"])


async def authorize(client, params):
    d = {
        "cid": client.client_id,
        "ru": str(params.redirect_uri),
        "ex": params.redirect_uri_provided_explicitly,
        "st": params.state,
        "cc": params.code_challenge,
        "sc": params.scopes or SCOPES,
        "res": params.resource,
    }
    preset = _preset()
    if preset and client.client_id == preset[0]:
        return _redirect(d)  # the secret is enforced at /token, so no prompt here
    who = client.client_name or "An application"
    return f"{ISSUER}/login?req={_seal('req', REQ_TTL, who=who, **d)}"


async def login(request):
    """Password gate between /authorize and the redirect back to the client."""
    form = {}
    if request.method == "POST":
        form = parse_qs((await request.body())[:4096].decode(errors="ignore"))
    req = form.get("req", [request.query_params.get("req", "")])[0]
    d = _open("req", req)
    if not d:
        return Response("Authorization request expired or invalid.", 400)

    def page(note="", status=200):
        return HTMLResponse(
            PAGE.format(who=html.escape(d["who"]), note=note, req=html.escape(req)),
            status,
        )

    if "password" not in form:
        return page()
    now = time.time()
    while _fails and now - _fails[0] > 600:
        _fails.popleft()
    if len(_fails) >= 5:
        return Response("Too many attempts, try again later.", 429)
    if not hmac.compare_digest(form["password"][0].encode(), _key()):
        _fails.append(now)
        return page("Wrong password.", 401)
    return RedirectResponse(_redirect(d), 303)


async def load_authorization_code(client, code):
    d = _open("code", code)
    if not d or d["cid"] != client.client_id or d["jti"] in _used:
        return None
    return AuthorizationCode(
        code=code,
        scopes=d["sc"],
        expires_at=d["exp"],
        client_id=d["cid"],
        code_challenge=d["cc"],
        redirect_uri=d["ru"],
        redirect_uri_provided_explicitly=d["ex"],
        resource=d["res"],
    )


async def exchange_authorization_code(client, code):
    now = time.time()
    _used.update({k: v for k, v in _used.items() if v > now})
    _used[_open("code", code.code)["jti"]] = now + CODE_TTL
    return _tokens(client.client_id, code.scopes)


async def load_refresh_token(client, token):
    d = _open("rt", token)
    if not d or d["cid"] != client.client_id:
        return None
    return RefreshToken(
        token=token, client_id=d["cid"], scopes=d["sc"], expires_at=d["exp"]
    )


async def exchange_refresh_token(client, refresh_token, scopes):
    return _tokens(client.client_id, scopes or refresh_token.scopes)


async def load_access_token(token):
    if hmac.compare_digest(token.encode(), _key()):
        return AccessToken(token=token, client_id="static", scopes=SCOPES)
    d = _open("at", token)
    if not d:
        return None
    return AccessToken(
        token=token, client_id=d["cid"], scopes=d["sc"], expires_at=d["exp"]
    )


provider = SimpleNamespace(
    get_client=get_client,
    register_client=register_client,
    authorize=authorize,
    load_authorization_code=load_authorization_code,
    exchange_authorization_code=exchange_authorization_code,
    load_refresh_token=load_refresh_token,
    exchange_refresh_token=exchange_refresh_token,
    load_access_token=load_access_token,
)
settings = AuthSettings(
    issuer_url=ISSUER,
    resource_server_url=f"{ISSUER}/mcp",
    validate_token_resource=False,
    client_registration_options=ClientRegistrationOptions(
        enabled=True, valid_scopes=SCOPES, default_scopes=SCOPES
    ),
)
