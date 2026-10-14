"""Shared fixtures. No Keycloak or WordPress needed: tokens are signed with a
local RSA key and WordPress is tests/fake_wp.py behind httpx2.MockTransport."""

import asyncio
import json

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import RSAKeyPair

from mcp_wordpress.config import load
from mcp_wordpress.wordpress import WordPressClient

from .fake_wp import SITE, FakeAbility, FakeWordPress

ISSUER = "https://sso.example.com/realms/wp"
BASE_URL = "https://mcp-wp.example.com"
BASE_ENV = {
    "OIDC_ISSUER": ISSUER,
    "BASE_URL": BASE_URL,
    "WORDPRESS_URL": SITE,
}
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@pytest.fixture
def settings():
    return load(dict(BASE_ENV))


@pytest.fixture(scope="session")
def keypair():
    return RSAKeyPair.generate()


@pytest.fixture
def make_token(keypair):
    """Keycloak-shaped access token for a subject."""

    def _make(subject="kc-alice", audience=("mcp-wordpress",), issuer=ISSUER, expires_in=300, scopes=("openid",)):
        return keypair.create_token(subject=subject, issuer=issuer, audience=list(audience), scopes=list(scopes),
                                    expires_in_seconds=expires_in, additional_claims={"azp": "openwebui"})

    return _make


@pytest.fixture
def fake_wp():
    """alice (administrator) and bob (author) match SSO subjects;
    carol exists in WordPress only."""
    wp = FakeWordPress()
    wp.add_user("alice", roles=["administrator"], sub="kc-alice")
    wp.add_user("bob", roles=["author"], sub="kc-bob")
    wp.add_user("carol", roles=["editor"])
    wp.add_ability(FakeAbility("core/get-site-info", label="Get site info", readonly=True, idempotent=True,
                               input_schema={"type": "object", "properties": {"fields": {"type": "array"}}},
                               output_schema={"type": "object", "properties": {"name": {"type": "string"}}},
                               handler=lambda input, user: {"name": "Example", "fields": input}))
    wp.add_ability(FakeAbility("ewpa/create-post", label="Create post", input_schema={
        "type": "object", "properties": {"title": {"type": "string"}}, "required": ["title"]},
        handler=lambda input, user: {"id": 42, "title": input["title"], "author": user.login}))
    wp.add_ability(FakeAbility("ewpa/delete-post", label="Delete post", destructive=True, idempotent=True,
                               input_schema={"type": "integer"}, roles=("administrator", "editor"),
                               handler=lambda input, user: True))
    wp.add_ability(FakeAbility("core/internal", label="Not for MCP", public=False, readonly=True))
    return wp


@pytest.fixture
def wp_client(fake_wp):
    return WordPressClient(SITE, transport=fake_wp.transport())


async def _lifespan(app, ready, stop):
    async with app.router.lifespan_context(app):
        ready.set()
        await stop.wait()


@pytest.fixture
def serve():
    """`async with serve(app) as client`: runs the app's lifespan (it starts the
    MCP session manager's task group) in a task of its own, since it must be
    entered and exited in one task."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _serve(app, base_url=BASE_URL):
        ready, stop = asyncio.Event(), asyncio.Event()
        task = asyncio.create_task(_lifespan(app, ready, stop))
        await ready.wait()
        try:
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=base_url) as c:
                yield c
        finally:
            stop.set()
            await task

    return _serve


async def rpc(client, token, method, params=None, headers=None):
    h = dict(HEADERS)
    if token:
        h["Authorization"] = f"Bearer {token}"
    h.update(headers or {})
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    return await client.post("/mcp", headers=h, content=json.dumps(body))


async def tool_names(client, token):
    resp = await rpc(client, token, "tools/list")
    assert resp.status_code == 200, resp.text
    return {t["name"] for t in resp.json()["result"]["tools"]}


async def call(client, token, name, arguments=None):
    resp = await rpc(client, token, "tools/call", {"name": name, "arguments": arguments or {}})
    assert resp.status_code == 200, resp.text
    return resp.json()["result"]
