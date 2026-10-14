"""AUTH_MODE=resource end to end through the real HTTP stack: FastMCP's auth
middleware, the JWT verifier, the per-user ability provider and the tools.
Only WordPress is faked (tests/fake_wp.py)."""

import json

import pytest
from fastmcp.server.auth.providers.jwt import RSAKeyPair

from mcp_wordpress import auth as auth_module
from mcp_wordpress.abilities import AbilityCache
from mcp_wordpress.config import load
from mcp_wordpress.server import create_server, http_middleware

from .conftest import BASE_ENV, HEADERS, ISSUER, call, rpc, tool_names

ALICE_TOOLS = {"whoami", "core-get-site-info", "ewpa-create-post", "ewpa-delete-post"}


def make_app(settings, keypair, wp_client, cache=None):
    verifier = auth_module.build_token_verifier(settings, public_key=keypair.public_key)
    auth, resolver = auth_module.build_auth(settings, wp_client, verifier)
    mcp = create_server(settings, auth=auth, wp=wp_client, resolver=resolver, cache=cache)
    return mcp.http_app(path="/mcp", stateless_http=True, json_response=True, middleware=http_middleware(settings))


@pytest.fixture
def app(settings, keypair, wp_client):
    return make_app(settings, keypair, wp_client)


@pytest.fixture
async def client(serve, app):
    async with serve(app) as c:
        yield c


# ── Who gets in ───────────────────────────────────────────────────────────────

async def test_no_token_is_401_with_resource_metadata(client):
    resp = await rpc(client, None, "tools/list")
    assert resp.status_code == 401
    assert "resource_metadata" in resp.headers["www-authenticate"]


async def test_protected_resource_metadata_names_keycloak(client):
    body = (await client.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert body["resource"] == "https://mcp-wp.example.com/mcp"
    assert body["authorization_servers"] == [ISSUER]


@pytest.mark.parametrize("override", [
    {"audience": ["account"]},                               # not meant for this server
    {"issuer": "https://evil.example/realms/wp"},            # other issuer
    {"expires_in": -120},                                    # expired
])
async def test_rejected_tokens(client, make_token, override, fake_wp):
    assert (await rpc(client, make_token(**override), "tools/list")).status_code == 401
    assert fake_wp.calls == []  # never forwarded to WordPress


async def test_token_signed_by_another_key_is_rejected(client):
    foreign = RSAKeyPair.generate().create_token(subject="kc-alice", issuer=ISSUER, audience=["mcp-wordpress"])
    assert (await rpc(client, foreign, "tools/list")).status_code == 401


async def test_healthz_needs_no_token(client):
    assert (await client.get("/healthz")).text == "ok"


async def test_endpoint_paths(client, make_token):
    slash = await client.post("/mcp/", headers={**HEADERS, "Authorization": f"Bearer {make_token()}"},
                              content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
    assert slash.status_code == 200
    root = await client.get("/")
    assert root.status_code == 404 and "https://mcp-wp.example.com/mcp" in root.text


@pytest.mark.parametrize("version", ["2025-03-26", "2025-06-18", "2025-11-25"])
async def test_handshake_era_clients(client, make_token, version):
    token = make_token()
    init = await rpc(client, token, "initialize", {
        "protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "open-webui", "version": "0"}})
    assert init.status_code == 200, init.text
    assert init.json()["result"]["protocolVersion"] == version
    result = (await rpc(client, token, "tools/call", {"name": "whoami", "arguments": {}},
                        headers={"MCP-Protocol-Version": version})).json()["result"]
    assert result["structuredContent"]["username"] == "alice"


# ── Tools per user ────────────────────────────────────────────────────────────

async def test_alice_and_bob_see_different_tools(client, make_token):
    assert await tool_names(client, make_token("kc-alice")) == ALICE_TOOLS
    # bob is an author: WordPress doesn't show him the delete ability.
    assert await tool_names(client, make_token("kc-bob")) == ALICE_TOOLS - {"ewpa-delete-post"}


async def test_each_call_forwards_the_callers_own_token(client, make_token, fake_wp):
    alice, bob = make_token("kc-alice"), make_token("kc-bob")
    a = await call(client, alice, "ewpa-create-post", {"title": "Hi"})
    b = await call(client, bob, "ewpa-create-post", {"title": "Yo"})
    assert a["structuredContent"]["author"] == "alice"
    assert b["structuredContent"]["author"] == "bob"
    runs = fake_wp.runs("ewpa/create-post")
    assert [r.auth for r in runs] == ["bearer:alice", "bearer:bob"]
    assert [r.body for r in runs] == [{"input": {"title": "Hi"}}, {"input": {"title": "Yo"}}]


async def test_tool_definition_from_ability(client, make_token):
    tools = {t["name"]: t for t in (await rpc(client, make_token(), "tools/list")).json()["result"]["tools"]}
    info = tools["core-get-site-info"]
    assert info["annotations"]["readOnlyHint"] is True
    assert info["annotations"]["title"] == "Get site info"
    assert "core/get-site-info" in info["description"]
    assert info["outputSchema"]["properties"]["name"] == {"type": "string"}
    delete = tools["ewpa-delete-post"]
    assert delete["annotations"]["destructiveHint"] is True
    assert delete["inputSchema"]["properties"]["input"] == {"type": "integer"}


async def test_methods_follow_annotations(client, make_token, fake_wp):
    token = make_token()
    info = await call(client, token, "core-get-site-info", {"fields": ["name", "url"]})
    assert not info.get("isError"), info
    assert info["structuredContent"] == {"name": "Example", "fields": {"fields": ["name", "url"]}}
    deleted = await call(client, token, "ewpa-delete-post", {"input": 7})
    assert not deleted.get("isError"), deleted
    assert deleted["structuredContent"] == {"result": True}
    assert fake_wp.runs("core/get-site-info")[0].method == "GET"
    assert fake_wp.runs("core/get-site-info")[0].query == [("input[fields][]", "name"), ("input[fields][]", "url")]
    assert fake_wp.runs("ewpa/delete-post")[0].method == "DELETE"
    assert fake_wp.runs("ewpa/delete-post")[0].query == [("input", "7")]


async def test_wordpress_403_is_a_tool_error(client, make_token, fake_wp):
    # bob doesn't see the tool; even when called by name it isn't there.
    result = (await rpc(client, make_token("kc-bob"), "tools/call",
                        {"name": "ewpa-delete-post", "arguments": {"input": 1}})).json()
    assert "error" in result or result["result"]["isError"]
    assert fake_wp.runs("ewpa/delete-post") == []


async def test_unlinked_user_gets_a_hint(client, make_token):
    assert await tool_names(client, make_token("kc-nobody")) == {"whoami"}
    result = await call(client, make_token("kc-nobody"), "whoami")
    assert result["isError"]
    text = result["content"][0]["text"]
    assert "No WordPress account is linked" in text and "mcp-wordpress" in text


async def test_bearer_feature_off_is_explained(client, make_token, fake_wp):
    fake_wp.bearer_enabled = False
    result = await call(client, make_token(), "whoami")
    assert result["isError"]
    assert "bearer token authentication" in result["content"][0]["text"]


async def test_wordpress_down_is_a_tool_error(client, make_token, fake_wp):
    fake_wp.down = True
    assert await tool_names(client, make_token()) == {"whoami"}
    result = await call(client, make_token(), "whoami")
    assert result["isError"] and "not reachable" in result["content"][0]["text"]


async def test_whoami(client, make_token):
    result = await call(client, make_token(), "whoami")
    data = result["structuredContent"]
    assert data["username"] == "alice" and data["roles"] == ["administrator"]
    assert data["ability_tools"] == 3
    assert "token" not in json.dumps(data).lower().replace("_tools", "")


# ── Configuration ─────────────────────────────────────────────────────────────

async def test_ability_filters(serve, keypair, wp_client, make_token):
    settings = load({**BASE_ENV, "ABILITY_DENY": "ewpa/delete-*", "ABILITY_MCP_PUBLIC_ONLY": "off"})
    async with serve(make_app(settings, keypair, wp_client)) as c:
        assert await tool_names(c, make_token()) == {"whoami", "core-get-site-info", "ewpa-create-post",
                                                     "core-internal"}


async def test_ability_list_is_cached_per_user(serve, settings, keypair, wp_client, make_token, fake_wp):
    async with serve(make_app(settings, keypair, wp_client, cache=AbilityCache(ttl=60))) as c:
        for _ in range(3):
            await tool_names(c, make_token("kc-alice"))
        await tool_names(c, make_token("kc-bob"))
    lists = [x.auth for x in fake_wp.calls if x.route == "/wp-abilities/v1/abilities"]
    assert lists == ["bearer:alice", "bearer:bob"]
