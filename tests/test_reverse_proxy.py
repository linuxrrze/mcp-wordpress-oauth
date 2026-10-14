"""Sub-directory deployment behind a prefix-stripping reverse proxy. These pin
down the URLs FastMCP generates from a BASE_URL with a path."""

from unittest import mock

import httpx2
import pytest

from mcp_wordpress import auth as auth_module
from mcp_wordpress.config import load
from mcp_wordpress.server import create_server, http_middleware

from .conftest import BASE_ENV, HEADERS, ISSUER
from .test_wp_oauth import wp_env

PUBLIC = "https://ai.example.com/mcp/wordpress"
INTERNAL = "http://mcp-wordpress:8000"


def _app(settings, wp_client, auth, resolver):
    return create_server(settings, auth=auth, wp=wp_client, resolver=resolver).http_app(
        path="/mcp", stateless_http=True, json_response=True, middleware=http_middleware(settings))


async def test_resource_mode_under_prefix(serve, keypair, make_token, wp_client):
    settings = load({**BASE_ENV, "BASE_URL": PUBLIC})
    verifier = auth_module.build_token_verifier(settings, public_key=keypair.public_key)
    app = _app(settings, wp_client, *auth_module.build_auth(settings, wp_client, verifier))
    async with serve(app, base_url=INTERNAL) as c:
        anonymous = await c.post("/mcp", headers=HEADERS, json={})
        metadata = await c.get("/.well-known/oauth-protected-resource/mcp/wordpress/mcp")
        slash = await c.post("/mcp/", headers={**HEADERS, "Authorization": f"Bearer {make_token()}"},
                             json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        root = await c.post("/", headers=HEADERS, json={})
    assert ('resource_metadata="https://ai.example.com/.well-known/oauth-protected-resource/mcp/wordpress/mcp"'
            in anonymous.headers["www-authenticate"])
    assert metadata.json()["resource"] == PUBLIC + "/mcp"
    assert slash.status_code == 200, slash.text
    assert root.status_code == 404 and PUBLIC + "/mcp" in root.text


DISCOVERY = {
    "issuer": ISSUER,
    "authorization_endpoint": ISSUER + "/protocol/openid-connect/auth",
    "token_endpoint": ISSUER + "/protocol/openid-connect/token",
    "jwks_uri": ISSUER + "/protocol/openid-connect/certs",
    "userinfo_endpoint": ISSUER + "/protocol/openid-connect/userinfo",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}


async def test_proxy_mode_under_prefix(serve, keypair, tmp_path, monkeypatch, wp_client):
    monkeypatch.setattr("fastmcp.settings.home", tmp_path)  # OIDCProxy's encrypted store
    settings = load({**BASE_ENV, "BASE_URL": PUBLIC, "AUTH_MODE": "proxy", "OIDC_CLIENT_ID": "mcp-wordpress",
                     "OIDC_CLIENT_SECRET": "secret", "JWT_SIGNING_KEY": "k" * 32})
    verifier = auth_module.build_token_verifier(settings, public_key=keypair.public_key)
    discovery = httpx2.Response(200, json=DISCOVERY, request=httpx2.Request("GET", ISSUER))
    with mock.patch("httpx2.get", return_value=discovery):
        provider, resolver = auth_module.build_auth(settings, wp_client, verifier)
    async with serve(_app(settings, wp_client, provider, resolver), base_url=INTERNAL) as c:
        metadata = (await c.get("/.well-known/oauth-authorization-server")).json()
    assert metadata["issuer"].rstrip("/") == PUBLIC
    for key, path in [("authorization_endpoint", "/authorize"), ("token_endpoint", "/token"),
                      ("registration_endpoint", "/register")]:
        assert metadata[key] == PUBLIC + path
    assert str(provider.base_url).rstrip("/") + provider._redirect_path == PUBLIC + "/auth/callback"


async def test_wordpress_mode_under_prefix(serve, tmp_path, wp_client):
    settings = load({**wp_env(tmp_path), "BASE_URL": PUBLIC})
    provider, resolver = auth_module.build_auth(settings, wp_client)
    async with serve(_app(settings, wp_client, provider, resolver), base_url=INTERNAL) as c:
        metadata = (await c.get("/.well-known/oauth-authorization-server")).json()
    assert metadata["authorization_endpoint"] == PUBLIC + "/authorize"
    # WordPress sends the browser back here (success_url / reject_url).
    assert provider._callback_url("t") == PUBLIC + "/wp/callback?state=t"


@pytest.mark.parametrize("path", ["/wp/callback", "/authorize", "/token", "/register", "/consent", "/revoke"])
def test_wordpress_mode_routes_exist_without_prefix(tmp_path, wp_client, path):
    settings = load({**wp_env(tmp_path), "BASE_URL": PUBLIC})
    app = _app(settings, wp_client, *auth_module.build_auth(settings, wp_client))
    assert path in {getattr(route, "path", None) for route in app.routes}
