import pytest
from cryptography.fernet import Fernet

from mcp_wordpress.config import DEFAULT_REDIRECT_ALLOWLIST, ConfigError, load

from .conftest import BASE_ENV

WP_ENV = {"AUTH_MODE": "wordpress", "BASE_URL": "https://mcp.example.com", "WORDPRESS_URL": "https://wp.example.com",
          "OAUTH_JWT_SIGNING_KEY": "x" * 32, "OAUTH_STORAGE_KEY": Fernet.generate_key().decode()}


def test_defaults():
    s = load(dict(BASE_ENV))
    assert s.auth_mode == "resource"
    assert s.mcp_audience == "mcp-wordpress"
    assert s.wordpress.rest_prefix == "/wp-json"
    assert s.wordpress.ability_allow == ("*",) and s.wordpress.mcp_public_only
    assert s.oauth is None


@pytest.mark.parametrize("missing", ["OIDC_ISSUER", "BASE_URL", "WORDPRESS_URL"])
def test_required_in_resource_mode(missing):
    env = dict(BASE_ENV)
    del env[missing]
    with pytest.raises(ConfigError, match=missing):
        load(env)


def test_proxy_needs_client_credentials():
    with pytest.raises(ConfigError, match="OIDC_CLIENT_ID"):
        load({**BASE_ENV, "AUTH_MODE": "proxy"})


def test_wordpress_mode():
    s = load(dict(WP_ENV))
    assert s.oidc_issuer is None
    assert s.oauth.dcr_enabled is False
    assert s.oauth.redirect_allowlist == DEFAULT_REDIRECT_ALLOWLIST
    assert s.oauth.app_name == "MCP (mcp.example.com)"
    assert s.oauth.state_dir == "/data/oauth"


@pytest.mark.parametrize("key", ["OAUTH_JWT_SIGNING_KEY", "OAUTH_STORAGE_KEY"])
def test_wordpress_mode_requires_keys(key):
    env = dict(WP_ENV)
    del env[key]
    with pytest.raises(ConfigError, match=key):
        load(env)


@pytest.mark.parametrize("override, match", [
    ({"OAUTH_STORAGE_KEY": "not-a-fernet-key"}, "Fernet"),
    ({"OAUTH_JWT_SIGNING_KEY": "short"}, "32 characters"),
    ({"OAUTH_REDIRECT_ALLOWLIST": "https://*.chatgpt.com/cb"}, "wildcard in the host"),
    ({"OAUTH_REDIRECT_ALLOWLIST": "http://example.com/cb"}, "loopback"),
    ({"OAUTH_REDIRECT_ALLOWLIST": "https://user:pw@example.com/cb"}, "credentials"),
    ({"OAUTH_REDIRECT_ALLOWLIST": "myapp://cb"}, "http"),
    ({"OAUTH_REFRESH_TOKEN_TTL": "10"}, "at least"),
])
def test_wordpress_mode_validation(override, match):
    with pytest.raises(ConfigError, match=match):
        load({**WP_ENV, **override})


def test_empty_allowlist_means_none():
    assert load({**WP_ENV, "OAUTH_CIMD_ALLOWLIST": ""}).oauth.cimd_allowlist == ()


@pytest.mark.parametrize("url, ok", [
    ("https://wp.example.com", True),
    ("http://localhost:8080", True),
    ("http://wp.example.com", False),
    ("https://wp.example.com/?x=1", False),
    ("ftp://wp.example.com", False),
])
def test_wordpress_url(url, ok):
    env = {**BASE_ENV, "WORDPRESS_URL": url}
    if ok:
        assert load(env).wordpress.url == url.rstrip("/")
    else:
        with pytest.raises(ConfigError):
            load(env)


def test_http_wordpress_allowed_explicitly():
    assert load({**BASE_ENV, "WORDPRESS_URL": "http://wordpress", "WORDPRESS_ALLOW_HTTP": "on"}).wordpress.url == \
        "http://wordpress"



def test_http_base_url_allowed_explicitly_in_resource_mode():
    assert load({**BASE_ENV, "BASE_URL": "http://mcp:8000", "BASE_URL_ALLOW_HTTP": "on"}).base_url == \
        "http://mcp:8000"


@pytest.mark.parametrize("env", [
    {**WP_ENV},
    {**BASE_ENV, "AUTH_MODE": "proxy", "OIDC_CLIENT_ID": "mcp", "OIDC_CLIENT_SECRET": "s"},
], ids=["wordpress", "proxy"])
def test_oauth_server_modes_need_https_base_url(env):
    # The MCP SDK rejects a plain-http OAuth issuer on anything but loopback.
    with pytest.raises(ConfigError, match="requires an https BASE_URL"):
        load({**env, "BASE_URL": "http://mcp:8000", "BASE_URL_ALLOW_HTTP": "on"})
    assert load({**env, "BASE_URL": "http://localhost:8000"}).base_url == "http://localhost:8000"


@pytest.mark.parametrize("prefix, expected", [("/wp-json", "/wp-json"), ("wp-json/", "/wp-json"),
                                              ("/blog/wp-json", "/blog/wp-json"), ("", "")])
def test_rest_prefix(prefix, expected):
    assert load({**BASE_ENV, "WP_REST_PREFIX": prefix}).wordpress.rest_prefix == expected


def test_lists():
    s = load({**BASE_ENV, "ABILITY_ALLOW": "core/*, ewpa/*", "ABILITY_DENY": "ewpa/delete-*"})
    assert s.wordpress.ability_allow == ("core/*", "ewpa/*")
    assert s.wordpress.ability_deny == ("ewpa/delete-*",)


def test_invalid_auth_mode():
    with pytest.raises(ConfigError, match="AUTH_MODE"):
        load({**BASE_ENV, "AUTH_MODE": "magic"})
