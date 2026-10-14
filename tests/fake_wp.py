"""An in-memory WordPress for tests, behind httpx2.MockTransport.

It models what this server relies on: the Abilities API (paged list,
per-user visibility, run with the method rule of WP 6.9's run controller),
users/me, Application Passwords (Basic auth, introspect, delete) and
sso-login-oidc's bearer feature (a JWT whose `sub` is linked to a user; the
signature was already checked by this server, so it isn't re-checked here).
Extend it rather than mocking calls one by one.
"""

from __future__ import annotations

import base64
import json
import math
import re
import uuid
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import parse_qsl, unquote, urlsplit

import httpx2

SITE = "https://wp.example.com"


@dataclass
class User:
    id: int
    login: str
    name: str
    roles: list[str]
    sub: str | None = None  # linked SSO subject (sso-login-oidc)


@dataclass
class FakeAbility:
    name: str
    label: str = ""
    description: str = ""
    input_schema: Any = None
    output_schema: Any = None
    readonly: bool = False
    destructive: bool = False
    idempotent: bool = False
    public: bool = True
    roles: tuple[str, ...] | None = None  # None = everyone may see and run it
    handler: Callable[[Any, User], Any] = lambda input, user: {"ok": True, "input": input}

    def method(self) -> str:
        if self.readonly:
            return "GET"
        if self.destructive and self.idempotent:
            return "DELETE"
        return "POST"

    def rest(self) -> dict:
        return {
            "name": self.name, "label": self.label or self.name, "description": self.description,
            "category": self.name.split("/")[0],
            "input_schema": self.input_schema if self.input_schema is not None else [],
            "output_schema": self.output_schema if self.output_schema is not None else [],
            "meta": {"annotations": {"readonly": self.readonly, "destructive": self.destructive,
                                     "idempotent": self.idempotent},
                     "show_in_rest": True, "mcp": {"public": self.public}},
        }


@dataclass
class Call:
    method: str
    route: str
    auth: str  # "bearer:<login>" | "basic:<login>" | "anonymous"
    query: list[tuple[str, str]]
    body: Any


def _error(status: int, code: str, message: str) -> httpx2.Response:
    return httpx2.Response(status, json={"code": code, "message": message, "data": {"status": status}})


def _parse_php_query(pairs: list[tuple[str, str]], key: str) -> Any:
    """Enough of PHP's parse_str for input[a][b]=…, input[]=…."""
    root: dict = {}
    found = False
    for k, v in pairs:
        if k != key and not k.startswith(key + "["):
            continue
        found = True
        parts = [key] + re.findall(r"\[([^\]]*)\]", k[len(key):])
        node: Any = root
        for i, part in enumerate(parts):
            last = i == len(parts) - 1
            if isinstance(node, list):
                if last:
                    node.append(v)
                else:
                    node.append({} if parts[i + 1] else [])
                    node = node[-1]
                continue
            if last:
                node[part] = v
            else:
                node = node.setdefault(part, [] if parts[i + 1] == "" else {})
    return root.get(key) if found else None


class FakeWordPress:
    def __init__(self, site: str = SITE) -> None:
        self.site = site
        self.users: dict[str, User] = {}
        self.app_passwords: dict[str, dict] = {}  # password -> {login, uuid, app_id, name}
        self.abilities: dict[str, FakeAbility] = {}
        self.calls: list[Call] = []
        self.bearer_enabled = True
        self.per_page_max = 100
        self.down = False

    # ── setup helpers ─────────────────────────────────────────────────────────

    def add_user(self, login: str, roles=("administrator",), sub: str | None = None, name: str | None = None) -> User:
        user = User(id=len(self.users) + 1, login=login, name=name or login.title(), roles=list(roles), sub=sub)
        self.users[login] = user
        return user

    def add_ability(self, ability: FakeAbility) -> FakeAbility:
        self.abilities[ability.name] = ability
        return ability

    def create_app_password(self, login: str, app_id: str = "", name: str = "MCP") -> tuple[str, str]:
        password = " ".join(uuid.uuid4().hex[i:i + 4] for i in range(0, 24, 4))
        pw_uuid = str(uuid.uuid4())
        self.app_passwords[password] = {"login": login, "uuid": pw_uuid, "app_id": app_id, "name": name}
        return password, pw_uuid

    def passwords_of(self, login: str) -> list[dict]:
        return [p for p in self.app_passwords.values() if p["login"] == login]

    def transport(self) -> httpx2.MockTransport:
        return httpx2.MockTransport(self.handle)

    def runs(self, name: str) -> list[Call]:
        return [c for c in self.calls if c.route == f"/wp-abilities/v1/abilities/{name}/run"]

    # ── request handling ──────────────────────────────────────────────────────

    def _authenticate(self, request: httpx2.Request) -> tuple[User | None, dict | None, str, httpx2.Response | None]:
        header = request.headers.get("authorization", "")
        if header.startswith("Basic "):
            login, _, password = base64.b64decode(header[6:]).decode().partition(":")
            entry = self.app_passwords.get(password)
            if entry is None or entry["login"] != login or login not in self.users:
                return None, None, "basic:?", _error(401, "incorrect_password",
                                                      "The provided password is an invalid application password.")
            return self.users[login], entry, f"basic:{login}", None
        if header.startswith("Bearer "):
            if not self.bearer_enabled:
                return None, None, "bearer:?", None  # plugin feature off: request stays anonymous
            try:
                payload = header[7:].split(".")[1]
                claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            except (IndexError, ValueError):
                return None, None, "bearer:?", _error(401, "sso_oidc_bearer_invalid", "Invalid bearer token.")
            user = next((u for u in self.users.values() if u.sub and u.sub == claims.get("sub")), None)
            if user is None:
                return None, None, "bearer:?", _error(401, "sso_oidc_bearer_unlinked",
                                                      "No WordPress account is linked to this SSO account.")
            return user, None, f"bearer:{user.login}", None
        return None, None, "anonymous", None

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        if self.down:
            raise httpx2.ConnectError("connection refused", request=request)
        url = urlsplit(str(request.url))
        query = parse_qsl(url.query, keep_blank_values=True)
        prefix = "/wp-json"
        route = unquote(url.path[len(prefix):]) if url.path.startswith(prefix) else url.path
        body = json.loads(request.content) if request.content else None
        user, app_pw, auth, failure = self._authenticate(request)
        self.calls.append(Call(request.method, route, auth, query, body))
        if failure is not None:
            return failure
        if user is None:
            return _error(401, "rest_not_logged_in", "You are not currently logged in.")

        if route == "/wp/v2/users/me" and request.method == "GET":
            data = {"id": user.id, "name": user.name, "slug": user.login}
            if ("context", "edit") in query:
                data |= {"username": user.login, "roles": user.roles}
            return httpx2.Response(200, json=data)
        if route == "/wp/v2/users/me/application-passwords/introspect":
            if app_pw is None:
                return _error(404, "application_password_not_found", "The current request is not authenticated "
                                                                     "with an application password.")
            return httpx2.Response(200, json={"uuid": app_pw["uuid"], "app_id": app_pw["app_id"],
                                              "name": app_pw["name"]})
        m = re.fullmatch(r"/wp/v2/users/me/application-passwords/([0-9a-f-]+)", route)
        if m and request.method == "DELETE":
            for password, entry in list(self.app_passwords.items()):
                if entry["uuid"] == m.group(1) and entry["login"] == user.login:
                    del self.app_passwords[password]
                    return httpx2.Response(200, json={"deleted": True})
            return _error(404, "application_password_not_found", "Application password not found.")

        if route == "/wp-abilities/v1/abilities" and request.method == "GET":
            visible = [a for a in sorted(self.abilities.values(), key=lambda a: a.name)
                       if a.roles is None or set(a.roles) & set(user.roles)]
            per_page = min(int(dict(query).get("per_page", 50)), self.per_page_max)
            page = int(dict(query).get("page", 1))
            total_pages = max(1, math.ceil(len(visible) / per_page))
            chunk = visible[(page - 1) * per_page:page * per_page]
            return httpx2.Response(200, json=[a.rest() for a in chunk],
                                   headers={"X-WP-Total": str(len(visible)), "X-WP-TotalPages": str(total_pages)})

        m = re.fullmatch(r"/wp-abilities/v1/abilities/([a-zA-Z0-9\-/]+?)/run", route)
        if m:
            ability = self.abilities.get(m.group(1))
            if ability is None:
                return _error(404, "rest_ability_not_found", "Ability not found.")
            if request.method != ability.method():
                return _error(405, "rest_ability_invalid_method",
                              f"Ability must be executed with {ability.method()} method.")
            if ability.roles is not None and not set(ability.roles) & set(user.roles):
                return _error(403, "rest_ability_cannot_execute", "Ability \"%s\" cannot be executed." % ability.name)
            if request.method == "POST":
                input = (body or {}).get("input")
            else:
                input = _parse_php_query(query, "input")
            return httpx2.Response(200, json=ability.handler(input, user))

        return _error(404, "rest_no_route", "No route was found matching the URL and request method.")
