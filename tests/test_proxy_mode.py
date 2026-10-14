"""AUTH_MODE=proxy: FastMCP's OIDCProxy against Keycloak, also accepting
directly forwarded Keycloak tokens (ported from mcp-mail-oauth)."""

from mcp_wordpress import auth as auth_module
from mcp_wordpress.config import load
from mcp_wordpress.credentials import BearerResolver

from .conftest import BASE_ENV


async def test_proxy_falls_back_to_direct_verification(monkeypatch):
    class Verifier:
        async def verify_token(self, token):
            return f"direct:{token}"

    async def proxy_rejects(self, token):
        return None

    monkeypatch.setattr(auth_module.OIDCProxy, "load_access_token", proxy_rejects)
    proxy = object.__new__(auth_module.ProxyAcceptingDirectTokens)  # skip discovery in __init__
    proxy._direct_verifier = Verifier()
    assert await proxy.load_access_token("kc-token") == "direct:kc-token"


async def test_proxy_prefers_its_own_tokens(monkeypatch):
    async def proxy_accepts(self, token):
        return "proxy"

    monkeypatch.setattr(auth_module.OIDCProxy, "load_access_token", proxy_accepts)
    proxy = object.__new__(auth_module.ProxyAcceptingDirectTokens)
    proxy._direct_verifier = None
    assert await proxy.load_access_token("fastmcp-token") == "proxy"


def test_proxy_keeps_consent_screen_and_explicit_signing_key(monkeypatch, wp_client):
    captured = {}
    monkeypatch.setattr(auth_module.OIDCProxy, "__init__", lambda self, **kw: captured.update(kw))
    monkeypatch.setattr(auth_module.OIDCProxy, "update_default_scopes",
                        lambda self, scopes: captured.update(default_scopes=scopes))

    settings = load({**BASE_ENV, "AUTH_MODE": "proxy", "OIDC_CLIENT_ID": "mcp-wordpress",
                     "OIDC_CLIENT_SECRET": "s", "JWT_SIGNING_KEY": "k" * 32})
    provider, resolver = auth_module.build_auth(settings, wp_client, verifier=object())
    assert isinstance(provider, auth_module.ProxyAcceptingDirectTokens)
    assert isinstance(resolver, BearerResolver)  # tools forward the upstream Keycloak token
    assert captured["require_authorization_consent"] is True
    assert captured["jwt_signing_key"] == "k" * 32
    assert captured["config_url"] == settings.oidc_issuer + "/.well-known/openid-configuration"
