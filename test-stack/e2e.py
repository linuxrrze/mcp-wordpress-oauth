"""End-to-end checks against the disposable test stack (test-stack/README.md).

Runs inside the mcp-wordpress-oauth image, on the stack's network, and plays
every client: Open WebUI (Keycloak password grant, token forwarded to the
MCP server), and in AUTH_MODE=wordpress a browser (wp-login.php, the
consent screen, WordPress' authorize-application.php) plus the MCP client
behind it. Each check names the link in the chain it proves; the first
failure stops the run.

E2E_MODE=resource | wordpress | all selects the checks (default: all).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
import sys
import time
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlsplit

import httpx2
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

MODE = os.environ.get("E2E_MODE", "all")
KEYCLOAK = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
OIDC = f"{KEYCLOAK}/realms/wp/protocol/openid-connect"
WORDPRESS = os.environ.get("WORDPRESS_URL", "http://wordpress")
REST = f"{WORDPRESS}/wp-json"
MCP_RESOURCE = os.environ.get("MCP_RESOURCE_URL", "http://mcp-resource:8000")
MCP_WP = os.environ.get("MCP_WP_URL", "http://mcp-wp:8000")
OPENWEBUI = {"client_id": "openwebui", "client_secret": "openwebui-test-secret"}
OTHER = {"client_id": "other", "client_secret": "other-test-secret"}
# The MCP client's redirect URI in the wordpress-mode flow. Nothing listens
# there: the runner reads the code from the Location header (loopback is in
# the default OAUTH_REDIRECT_ALLOWLIST, any port).
REDIRECT = "http://127.0.0.1:9999/callback"
E2E_TOOLS = {"whoami", "e2e-get-info", "e2e-update-note", "e2e-delete-note", "e2e-echo-text", "e2e-editor-only"}
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}

passed = 0


def check(description: str, condition: bool, detail: object = "") -> None:
    global passed
    if not condition:
        print(f"FAIL  {description}\n      {detail}", flush=True)
        sys.exit(1)
    passed += 1
    print(f"ok    {description}", flush=True)


def claims(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def keycloak_token(username: str, client: dict = OPENWEBUI) -> str:
    resp = httpx2.post(f"{OIDC}/token", data={**client, "grant_type": "password", "username": username,
                                              "password": username, "scope": "openid email"})
    check(f"Keycloak issues a token for {username} (client {client['client_id']})", resp.status_code == 200, resp.text)
    return resp.json()["access_token"]


def mcp(base: str, token: str) -> Client:
    return Client(StreamableHttpTransport(f"{base}/mcp", headers={"Authorization": f"Bearer {token}"}))


async def tool_names(base: str, token: str) -> set[str]:
    async with mcp(base, token) as client:
        return {t.name for t in await client.list_tools()}


async def tool(base: str, token: str, name: str, **arguments):
    """The tool result (structured_content, is_error, text)."""
    async with mcp(base, token) as client:
        result = await client.call_tool(name, arguments, raise_on_error=False)
    text = " ".join(getattr(c, "text", "") for c in result.content)
    return result.structured_content, result.is_error, text


def mcp_status(base: str, token: str | None) -> httpx2.Response:
    headers = dict(MCP_HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx2.post(f"{base}/mcp", headers=headers,
                       json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})


# ── AUTH_MODE=resource ────────────────────────────────────────────────────────

async def resource_mode() -> None:
    print("\n== AUTH_MODE=resource", flush=True)
    alice, bob, carol = keycloak_token("alice"), keycloak_token("bob"), keycloak_token("carol")
    aud = claims(alice)["aud"]
    check("alice's token names mcp-wordpress in aud (audience mapper)",
          "mcp-wordpress" in (aud if isinstance(aud, list) else [aud]), aud)

    # WordPress on its own: sso-login-oidc's bearer feature.
    me = httpx2.get(f"{REST}/wp/v2/users/me", headers={"Authorization": f"Bearer {alice}"})
    check("WordPress accepts the token on /wp/v2/users/me as alice (Authorization reaches PHP)",
          me.status_code == 200 and me.json().get("slug") == "alice", me.text[:300])
    settings = httpx2.get(f"{REST}/wp/v2/settings", headers={"Authorization": f"Bearer {alice}"})
    check("WordPress ignores the token on a route not allowlisted for bearer auth (/wp/v2/settings)",
          settings.status_code == 401, (settings.status_code, settings.text[:300]))
    other = keycloak_token("alice", OTHER)
    me = httpx2.get(f"{REST}/wp/v2/users/me", headers={"Authorization": f"Bearer {other}"})
    check("WordPress refuses a token without the mcp-wordpress audience", me.status_code == 401, me.text[:300])

    # The MCP server.
    resp = mcp_status(MCP_RESOURCE, None)
    check("MCP without a token: 401 with resource metadata",
          resp.status_code == 401 and "resource_metadata" in resp.headers.get("www-authenticate", ""),
          resp.status_code)
    check("MCP refuses a token without the mcp-wordpress audience", mcp_status(MCP_RESOURCE, other).status_code == 401)

    alice_tools = await tool_names(MCP_RESOURCE, alice)
    bob_tools = await tool_names(MCP_RESOURCE, bob)
    check("alice (administrator) gets one tool per e2e ability, incl. the editor-only listing",
          E2E_TOOLS | {"e2e-editor-tools"} <= alice_tools, sorted(alice_tools))
    check("bob (author) gets a different list: no e2e-editor-tools",
          E2E_TOOLS <= bob_tools and "e2e-editor-tools" not in bob_tools, sorted(bob_tools))
    check("abilities without meta.mcp.public are not tools (ABILITY_MCP_PUBLIC_ONLY)",
          "e2e-not-public" not in alice_tools, sorted(alice_tools))
    print(f"      (alice: {len(alice_tools)} tools, {len(alice_tools - E2E_TOOLS - {'e2e-editor-tools'})} "
          "besides the e2e ones)", flush=True)

    who, error, text = await tool(MCP_RESOURCE, alice, "whoami")
    check("whoami: alice, administrator", not error and who["username"] == "alice"
          and "administrator" in (who["roles"] or []), text or who)

    # WordPress' run controller: method per annotations, input encoding.
    data, error, text = await tool(MCP_RESOURCE, alice, "e2e-get-info",
                                   fields=["title", "url"], filter={"status": "publish", "sticky": True})
    check("readonly ability runs with GET; nested input survives the PHP bracket query encoding",
          not error and data["method"] == "GET" and data["user"] == "alice"
          and data["input"]["fields"] == ["title", "url"] and data["input"]["filter"]["status"] == "publish"
          and data["input"]["filter"]["sticky"] in ("1", 1, True),
          text or data)
    data, error, text = await tool(MCP_RESOURCE, bob, "e2e-update-note", title="Hi", count=3, draft=False)
    check("write ability runs with POST and a JSON body, as the calling user (bob)",
          not error and data["method"] == "POST" and data["user"] == "bob"
          and data["input"] == {"title": "Hi", "count": 3, "draft": False}, text or data)
    data, error, text = await tool(MCP_RESOURCE, alice, "e2e-delete-note", input=7)
    check("destructive+idempotent ability runs with DELETE, scalar input as ?input=7",
          not error and data["method"] == "DELETE" and str(data["input"]) == "7", text or data)
    data, error, text = await tool(MCP_RESOURCE, alice, "e2e-echo-text", input="a b&c=d")
    check("scalar-input ability: the MCP {input: ...} wrapper is unwrapped for WordPress",
          not error and data["method"] == "POST" and data["input"] == "a b&c=d", text or data)

    _, error, text = await tool(MCP_RESOURCE, bob, "e2e-editor-only")
    check("bob runs an editor-only ability: a tool error with WordPress' reason, not a crash",
          error and "rest_ability_cannot_execute" in text, text)
    _, error, text = await tool(MCP_RESOURCE, alice, "e2e-editor-only")
    check("alice may run it", not error, text)

    carol_tools = await tool_names(MCP_RESOURCE, carol)
    check("carol (no linked WordPress account) gets no ability tools", carol_tools == {"whoami"}, carol_tools)
    _, error, text = await tool(MCP_RESOURCE, carol, "whoami")
    check("carol's whoami explains it: unlinked account, how to fix",
          error and "No WordPress account is linked" in text and "linked to your SSO account" in text, text)


# ── AUTH_MODE=wordpress ───────────────────────────────────────────────────────

class Forms(HTMLParser):
    """Every <form> with its action and input values (hidden and text; the
    submit buttons are added by the caller)."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.forms.append({"action": a.get("action") or "", "fields": {}})
        elif tag == "input" and self.forms and a.get("name") and a.get("type") not in ("submit", "button"):
            if a.get("type") in ("checkbox", "radio") and "checked" not in a:
                return
            self.forms[-1]["fields"][a["name"]] = a.get("value") or ""


def form(html: str, key: str) -> dict:
    """The first form whose action contains `key` or that has a field named `key`."""
    parser = Forms()
    parser.feed(html)
    for f in parser.forms:
        if key in f["action"] or key in f["fields"]:
            return f
    raise AssertionError(f"no form for {key!r} in:\n{html[:2000]}")


def location(resp: httpx2.Response) -> str:
    return urljoin(str(resp.url), resp.headers["location"])


def query(url: str) -> dict:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


class Browser:
    """A cookie jar and manual redirects: every hop is checked."""

    def __init__(self) -> None:
        self.http = httpx2.Client(follow_redirects=False, timeout=30)

    def wp_login(self, username: str) -> None:
        self.http.get(f"{WORDPRESS}/wp-login.php")  # sets wordpress_test_cookie
        resp = self.http.post(f"{WORDPRESS}/wp-login.php", data={
            "log": username, "pwd": username, "wp-submit": "Log In", "testcookie": "1",
            "redirect_to": f"{WORDPRESS}/wp-admin/"})
        check(f"WordPress login as {username}", resp.status_code == 302
              and any(c.startswith("wordpress_logged_in") for c in self.http.cookies.keys()),
              (resp.status_code, resp.text[:500]))

    def consent(self, client_id: str) -> tuple[str, str]:
        """/authorize -> consent screen -> approve. Returns (WordPress URL, PKCE verifier)."""
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        resp = self.http.get(f"{MCP_WP}/authorize", params={
            "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT, "state": "e2e-state",
            "code_challenge": challenge, "code_challenge_method": "S256"})
        check("/authorize sends the browser to the consent screen", resp.status_code == 302
              and "/consent" in resp.headers.get("location", ""), (resp.status_code, resp.text[:300]))
        page = self.http.get(location(resp))
        f = form(page.text, "txn_id")  # FastMCP's consent form posts to its own URL (action="")
        resp = self.http.post(urljoin(str(page.url), f["action"]),
                              data={**f["fields"], "action": "approve"})
        wp_url = location(resp) if resp.status_code == 302 else ""
        check("approving consent sends the browser to WordPress' authorize-application.php",
              wp_url.startswith(f"{WORDPRESS}/wp-admin/authorize-application.php"), (resp.status_code, wp_url))
        return wp_url, verifier

    def wordpress_answer(self, wp_url: str, button: str) -> str:
        """Click approve/reject in WordPress; returns where WordPress sends the browser."""
        page = self.http.get(wp_url)
        check("authorize-application.php shows the approval form (app name, our callback)",
              page.status_code == 200 and "MCP e2e" in page.text and "/wp/callback" in page.text,
              (page.status_code, page.text[:800]))
        f = form(page.text, "authorize-application.php")
        resp = self.http.post(urljoin(str(page.url), f["action"]), data={**f["fields"], button: "1"})
        check(f"WordPress redirects after '{button}'", resp.status_code in (302, 303),
              (resp.status_code, resp.text[:800]))
        return location(resp)


async def wordpress_mode() -> None:
    print("\n== AUTH_MODE=wordpress", flush=True)
    meta = httpx2.get(f"{MCP_WP}/.well-known/oauth-authorization-server").json()
    check("authorization server metadata: DCR on (as configured), revocation, CIMD",
          meta.get("registration_endpoint") == f"{MCP_WP}/register" and meta.get("revocation_endpoint")
          and meta.get("client_id_metadata_document_supported") is True, meta)
    check("MCP without a token: 401 with resource metadata",
          mcp_status(MCP_WP, None).status_code == 401)
    check("a Keycloak token means nothing here", mcp_status(MCP_WP, keycloak_token("alice")).status_code == 401)

    resp = httpx2.post(f"{MCP_WP}/register", json={"redirect_uris": ["https://evil.example/cb"],
                                                   "token_endpoint_auth_method": "none"})
    check("DCR refuses a redirect URI outside OAUTH_REDIRECT_ALLOWLIST", resp.status_code == 400, resp.text)
    resp = httpx2.post(f"{MCP_WP}/register", json={
        "redirect_uris": [REDIRECT], "client_name": "e2e", "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]})
    check("DCR registers a loopback client", resp.status_code == 201, resp.text)
    client_id = resp.json()["client_id"]

    # Rejecting in WordPress reaches the MCP client as access_denied.
    browser = Browser()
    browser.wp_login("bob")
    wp_url, _ = browser.consent(client_id)
    callback = browser.wordpress_answer(wp_url, "reject")
    check("WordPress sends a rejection to our reject_url (success=false)",
          callback.startswith(f"{MCP_WP}/wp/callback") and query(callback).get("success") == "false", callback)
    resp = browser.http.get(callback)
    back = location(resp) if resp.status_code == 302 else ""
    check("... which the MCP client receives as error=access_denied with its state",
          back.startswith(REDIRECT) and query(back).get("error") == "access_denied"
          and query(back).get("state") == "e2e-state", (resp.status_code, back or resp.text[:300]))

    # The real thing: alice approves.
    browser = Browser()
    browser.wp_login("alice")
    wp_url, verifier = browser.consent(client_id)
    callback = browser.wordpress_answer(wp_url, "approve")
    q = query(callback)
    check("WordPress creates an Application Password and hands it to our callback",
          callback.startswith(f"{MCP_WP}/wp/callback") and q.get("user_login") == "alice" and q.get("password")
          and urlsplit(q.get("site_url", "")).hostname == "wordpress", {k: v for k, v in q.items() if k != "password"})
    app_password = q["password"]
    resp = browser.http.get(callback)
    back = location(resp) if resp.status_code == 302 else ""
    check("the callback checks it and redirects to the MCP client with a code",
          back.startswith(REDIRECT) and "code" in query(back) and query(back).get("state") == "e2e-state",
          (resp.status_code, back or resp.text[:500]))
    resp = httpx2.post(f"{MCP_WP}/token", data={"grant_type": "authorization_code", "code": query(back)["code"],
                                                "redirect_uri": REDIRECT, "client_id": client_id,
                                                "code_verifier": verifier})
    check("/token: access and refresh token", resp.status_code == 200 and resp.json().get("refresh_token"),
          resp.text)
    tokens = resp.json()

    names = await tool_names(MCP_WP, tokens["access_token"])
    check("MCP with this server's token: the e2e abilities as tools", E2E_TOOLS | {"e2e-editor-tools"} <= names,
          sorted(names))
    who, error, text = await tool(MCP_WP, tokens["access_token"], "whoami")
    check("whoami: alice, via the Application Password", not error and who["username"] == "alice"
          and who["auth_mode"] == "wordpress", text or who)
    data, error, text = await tool(MCP_WP, tokens["access_token"], "e2e-update-note", title="via app password")
    check("a write ability runs as alice (Basic auth with the Application Password)",
          not error and data["user"] == "alice" and data["method"] == "POST", text or data)
    data, error, text = await tool(MCP_WP, tokens["access_token"], "e2e-delete-note", input=3)
    check("... and a DELETE one", not error and data["method"] == "DELETE", text or data)

    resp = httpx2.post(f"{MCP_WP}/token", data={"grant_type": "refresh_token", "client_id": client_id,
                                                "refresh_token": tokens["refresh_token"]})
    check("refresh works", resp.status_code == 200, resp.text)
    tokens = resp.json()

    # Disconnect: /revoke deletes the Application Password in WordPress.
    me = httpx2.get(f"{REST}/wp/v2/users/me", auth=("alice", app_password))
    check("the Application Password works against WordPress directly", me.status_code == 200, me.text[:300])
    # client_secret="" for a public client: the MCP SDK's RevocationRequest
    # declares the field without a default.
    resp = httpx2.post(f"{MCP_WP}/revoke", data={"token": tokens["refresh_token"], "client_id": client_id,
                                                 "client_secret": ""})
    check("/revoke", resp.status_code == 200, resp.text)
    me = httpx2.get(f"{REST}/wp/v2/users/me", auth=("alice", app_password))
    check("... deleted the Application Password in WordPress", me.status_code == 401, me.text[:300])
    check("... and the access token no longer works", mcp_status(MCP_WP, tokens["access_token"]).status_code == 401)
    resp = httpx2.post(f"{MCP_WP}/token", data={"grant_type": "refresh_token", "client_id": client_id,
                                                "refresh_token": tokens["refresh_token"]})
    check("... nor the refresh token (invalid_grant)", resp.status_code in (400, 401)
          and resp.json().get("error") == "invalid_grant", resp.text)


async def main() -> None:
    print(f"E2E_MODE={MODE}", flush=True)
    if MODE in ("resource", "all"):
        await resource_mode()
    if MODE in ("wordpress", "all"):
        await wordpress_mode()
    print(f"\nall {passed} checks passed", flush=True)


if __name__ == "__main__":
    started = time.monotonic()
    asyncio.run(main())
    print(f"({time.monotonic() - started:.1f}s)")
