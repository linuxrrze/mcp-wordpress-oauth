"""AUTH_MODE=wordpress: this server as OAuth authorization server, with the
WordPress side (authorize-application.php, Application Passwords) faked.

The full flow below is what a browser does: DCR → /authorize → consent →
WordPress approval → /wp/callback → code → /token → MCP with that token."""

import base64
import hashlib
import re
import secrets
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from cryptography.fernet import Fernet

from mcp_wordpress import auth as auth_module
from mcp_wordpress.config import load
from mcp_wordpress.server import create_server, http_middleware

from .conftest import BASE_URL, call, rpc, tool_names
from .fake_wp import SITE

REDIRECT = "http://localhost:3000/callback"
STORAGE_KEY = Fernet.generate_key().decode()


def wp_env(tmp_path, **extra):
    return {"AUTH_MODE": "wordpress", "BASE_URL": BASE_URL, "WORDPRESS_URL": SITE,
            "OAUTH_JWT_SIGNING_KEY": "s" * 40, "OAUTH_STORAGE_KEY": STORAGE_KEY,
            "OAUTH_STATE_DIR": str(tmp_path / "oauth"), "OAUTH_DCR_ENABLED": "on", **extra}


def make_app(settings, wp_client):
    auth, resolver = auth_module.build_auth(settings, wp_client)
    mcp = create_server(settings, auth=auth, wp=wp_client, resolver=resolver)
    app = mcp.http_app(path="/mcp", stateless_http=True, json_response=True, middleware=http_middleware(settings))
    return app, auth


@pytest.fixture
def wp_settings(tmp_path):
    return load(wp_env(tmp_path))


@pytest.fixture
async def server(serve, wp_settings, wp_client):
    app, auth = make_app(wp_settings, wp_client)
    async with serve(app) as c:
        yield c, auth


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


async def register(c, redirect=REDIRECT):
    resp = await c.post("/register", json={"redirect_uris": [redirect], "client_name": "Test client",
                                           "token_endpoint_auth_method": "none",
                                           "grant_types": ["authorization_code", "refresh_token"],
                                           "response_types": ["code"]})
    assert resp.status_code == 201, resp.text
    return resp.json()["client_id"]


async def to_wordpress(c, client_id, redirect=REDIRECT):
    """/authorize and the consent screen; returns (WordPress URL, PKCE verifier)."""
    verifier, challenge = _pkce()
    resp = await c.get("/authorize", params={"response_type": "code", "client_id": client_id, "redirect_uri": redirect,
                                             "state": "client-state", "code_challenge": challenge,
                                             "code_challenge_method": "S256"})
    assert resp.status_code == 302, resp.text
    page = await c.get(resp.headers["location"])
    assert page.status_code == 200, page.text
    txn = re.search(r'name="txn_id" value="([^"]+)"', page.text).group(1)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    resp = await c.post("/consent", data={"txn_id": txn, "csrf_token": csrf, "action": "approve", "submit": "true"})
    assert resp.status_code == 302, resp.text
    return resp.headers["location"], verifier


def approve_in_wordpress(fake_wp, wp_url, login="alice", site=SITE):
    """What WordPress does when the user clicks "Yes, I approve of this connection"."""
    parts = urlsplit(wp_url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{SITE}/wp-admin/authorize-application.php"
    q = {k: v[0] for k, v in parse_qs(parts.query).items()}
    password, _ = fake_wp.create_app_password(login, app_id=q["app_id"], name=q["app_name"])
    return q["success_url"] + "&" + urlencode({"site_url": site, "user_login": login, "password": password}), password


async def connect(c, fake_wp, login="alice"):
    """The whole flow; returns the token response."""
    client_id = await register(c)
    wp_url, verifier = await to_wordpress(c, client_id)
    callback, _ = approve_in_wordpress(fake_wp, wp_url, login)
    resp = await c.get(callback)
    assert resp.status_code == 302, resp.text
    back = urlsplit(resp.headers["location"])
    assert f"{back.scheme}://{back.netloc}{back.path}" == REDIRECT
    q = {k: v[0] for k, v in parse_qs(back.query).items()}
    assert q["state"] == "client-state"
    resp = await c.post("/token", data={"grant_type": "authorization_code", "code": q["code"], "redirect_uri": REDIRECT,
                                        "client_id": client_id, "code_verifier": verifier})
    assert resp.status_code == 200, resp.text
    return {**resp.json(), "client_id": client_id}


# ── Metadata and client admission ─────────────────────────────────────────────

async def test_metadata_with_dcr(server):
    c, _ = server
    meta = (await c.get("/.well-known/oauth-authorization-server")).json()
    assert meta["issuer"].rstrip("/") == BASE_URL
    assert meta["registration_endpoint"] == BASE_URL + "/register"
    assert meta["revocation_endpoint"] == BASE_URL + "/revoke"
    assert meta["client_id_metadata_document_supported"] is True
    prm = (await c.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert prm["authorization_servers"][0].rstrip("/") == BASE_URL


async def test_dcr_is_off_by_default(serve, tmp_path, wp_client):
    env = wp_env(tmp_path)
    del env["OAUTH_DCR_ENABLED"]
    app, _ = make_app(load(env), wp_client)
    async with serve(app) as c:
        meta = (await c.get("/.well-known/oauth-authorization-server")).json()
        assert "registration_endpoint" not in meta
        assert meta["revocation_endpoint"] == BASE_URL + "/revoke"
        assert (await c.post("/register", json={"redirect_uris": [REDIRECT]})).status_code in (404, 405)


@pytest.mark.parametrize("redirect, ok", [
    ("http://localhost:3000/callback", True),
    ("http://127.0.0.1:61234/cb", True),
    ("https://chatgpt.com/connector_platform_oauth_redirect", True),
    ("https://chatgpt.com/connector/oauth/abc123", True),
    ("https://claude.ai/api/mcp/auth_callback", True),
    ("https://evil.example/callback", False),
    ("https://chatgpt.com.evil.example/connector_platform_oauth_redirect", False),
])
async def test_registration_redirect_allowlist(server, redirect, ok):
    c, _ = server
    resp = await c.post("/register", json={"redirect_uris": [redirect], "token_endpoint_auth_method": "none"})
    assert (resp.status_code == 201) is ok, resp.text


async def test_cimd_allowlist_and_upstream_id(server):
    _, auth = server
    assert await auth.get_client("https://evil.example/oauth/client-metadata") is None
    # The app_id WordPress sees is public; OAuthProxy would otherwise accept it
    # as a client id with any redirect URI.
    assert await auth.get_client(auth.app_id) is None


# ── Full flow ─────────────────────────────────────────────────────────────────

async def test_full_flow_acts_as_the_wordpress_user(server, fake_wp):
    c, _ = server
    tokens = await connect(c, fake_wp, "bob")
    assert tokens["refresh_token"]
    assert await tool_names(c, tokens["access_token"]) == {"whoami", "core-get-site-info", "ewpa-create-post"}
    result = await call(c, tokens["access_token"], "ewpa-create-post", {"title": "Via MCP"})
    assert result["structuredContent"]["author"] == "bob"
    who = (await call(c, tokens["access_token"], "whoami"))["structuredContent"]
    assert who["username"] == "bob" and who["auth_mode"] == "wordpress"
    assert {call.auth for call in fake_wp.calls if call.route.startswith("/wp-abilities")} == {"basic:bob"}
    # WordPress lists the connection under this server's app id and name.
    [pw] = fake_wp.passwords_of("bob")
    assert pw["app_id"] == server[1].app_id and pw["name"] == "MCP (mcp-wp.example.com)"


async def test_wordpress_authorize_url(server):
    c, auth = server
    wp_url, _ = await to_wordpress(c, await register(c))
    q = {k: v[0] for k, v in parse_qs(urlsplit(wp_url).query).items()}
    assert q["reject_url"] == q["success_url"] + "&success=false"
    assert q["success_url"].startswith(BASE_URL + "/wp/callback?state=")
    assert "redirect_uri" not in q and "client_id" not in q


async def test_callback_without_consent_cookie_is_refused(server, serve, wp_settings, wp_client, fake_wp):
    c, _ = server
    wp_url, _ = await to_wordpress(c, await register(c))
    callback, _ = approve_in_wordpress(fake_wp, wp_url)
    c.cookies.clear()  # another browser: e.g. a victim following an attacker's link
    resp = await c.get(callback)
    assert resp.status_code == 403
    assert fake_wp.passwords_of("alice") == []  # the new Application Password was deleted again


async def test_callback_for_another_site_is_refused(server, fake_wp):
    c, _ = server
    wp_url, _ = await to_wordpress(c, await register(c))
    callback, _ = approve_in_wordpress(fake_wp, wp_url, site="https://other.example.com")
    resp = await c.get(callback)
    assert resp.status_code == 400
    assert fake_wp.passwords_of("alice") == []


async def test_rejection_in_wordpress_is_passed_to_the_client(server):
    c, _ = server
    wp_url, _ = await to_wordpress(c, await register(c))
    reject = {k: v[0] for k, v in parse_qs(urlsplit(wp_url).query).items()}["reject_url"]
    resp = await c.get(reject)  # WordPress uses reject_url as given
    assert resp.status_code == 302
    q = parse_qs(urlsplit(resp.headers["location"]).query)
    assert q["error"] == ["access_denied"] and q["state"] == ["client-state"]


async def test_allowed_roles(serve, tmp_path, wp_client, fake_wp):
    app, _ = make_app(load(wp_env(tmp_path, WP_ALLOWED_ROLES="administrator,editor")), wp_client)
    async with serve(app) as c:
        wp_url, _ = await to_wordpress(c, await register(c))
        callback, _ = approve_in_wordpress(fake_wp, wp_url, "bob")  # an author
        resp = await c.get(callback)
        assert resp.status_code == 302
        assert parse_qs(urlsplit(resp.headers["location"]).query)["error"] == ["access_denied"]
        assert fake_wp.passwords_of("bob") == []


# ── Lifecycle ─────────────────────────────────────────────────────────────────

async def test_password_revoked_in_wordpress_ends_the_session(server, fake_wp):
    c, _ = server
    tokens = await connect(c, fake_wp)
    assert (await rpc(c, tokens["access_token"], "tools/list")).status_code == 200  # checked, valid for 60s
    fake_wp.app_passwords.clear()  # the user revokes it in their WordPress profile
    result = await call(c, tokens["access_token"], "whoami")
    assert result["isError"] and "Application Password" in result["content"][0]["text"]
    assert (await rpc(c, tokens["access_token"], "tools/list")).status_code == 401
    resp = await c.post("/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
                                        "client_id": tokens["client_id"]})
    # 401, not 400: FastMCP follows the MCP spec for invalid grants.
    assert resp.status_code == 401 and resp.json()["error"] == "invalid_grant"


async def test_password_revoked_is_noticed_by_the_recheck(serve, tmp_path, wp_client, fake_wp):
    app, _ = make_app(load(wp_env(tmp_path, WP_CREDENTIAL_RECHECK="0")), wp_client)
    async with serve(app) as c:
        tokens = await connect(c, fake_wp)
        assert (await rpc(c, tokens["access_token"], "tools/list")).status_code == 200
        fake_wp.app_passwords.clear()
        assert (await rpc(c, tokens["access_token"], "tools/list")).status_code == 401


async def test_wordpress_down_does_not_sign_anyone_out(serve, tmp_path, wp_client, fake_wp):
    app, _ = make_app(load(wp_env(tmp_path, WP_CREDENTIAL_RECHECK="0")), wp_client)
    async with serve(app) as c:
        tokens = await connect(c, fake_wp)
        fake_wp.down = True
        assert (await rpc(c, tokens["access_token"], "tools/list")).status_code == 200
        fake_wp.down = False
        assert (await call(c, tokens["access_token"], "whoami"))["structuredContent"]["username"] == "alice"


async def test_refresh(server, fake_wp):
    c, _ = server
    tokens = await connect(c, fake_wp)
    resp = await c.post("/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
                                        "client_id": tokens["client_id"]})
    assert resp.status_code == 200, resp.text
    assert await tool_names(c, resp.json()["access_token"]) >= {"whoami", "ewpa-delete-post"}


@pytest.mark.parametrize("kind", ["refresh_token", "access_token"])
async def test_revoke_deletes_the_application_password(server, fake_wp, kind):
    c, _ = server
    tokens = await connect(c, fake_wp)
    assert len(fake_wp.passwords_of("alice")) == 1
    # client_secret="" for a public client: the MCP SDK's RevocationRequest
    # declares the field without a default, so it must be present.
    resp = await c.post("/revoke", data={"token": tokens[kind], "client_id": tokens["client_id"],
                                         "client_secret": ""})
    assert resp.status_code == 200, resp.text
    assert fake_wp.passwords_of("alice") == []
    assert (await rpc(c, tokens["access_token"], "tools/list")).status_code == 401


async def test_no_plaintext_secrets_on_disk(server, fake_wp, tmp_path):
    c, _ = server
    tokens = await connect(c, fake_wp)
    [password] = [p for p, e in fake_wp.app_passwords.items() if e["login"] == "alice"]
    files = [p for p in (tmp_path / "oauth").rglob("*") if p.is_file()]
    assert files
    for path in files:
        data = path.read_bytes()
        assert password.encode() not in data
        assert b"alice" not in data
        assert tokens["access_token"].encode() not in data


async def test_callback_with_unknown_state_never_calls_wordpress(server, fake_wp):
    c, _ = server
    resp = await c.get("/wp/callback", params={"state": "made-up", "site_url": SITE, "user_login": "alice",
                                               "password": "guess guess guess"})
    assert resp.status_code == 400
    assert fake_wp.calls == []  # no password tries through this server
