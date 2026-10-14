"""The WordPress side: REST calls made on behalf of one user.

Every call takes a `WPCredential`: the caller's Keycloak bearer token
(AUTH_MODE resource/proxy, accepted by sso-login-oidc's bearer feature) or
their Application Password (AUTH_MODE wordpress). There is no service
account: WordPress itself decides what the user may do (D5).

Abilities API (WordPress 6.9 core, /wp-abilities/v1):
- GET  abilities?page=&per_page=          list (only `show_in_rest` abilities;
                                          not filtered by permission)
- GET|POST|DELETE abilities/{name}/run    execute; the method must match the
                                          ability's annotations (run_method)
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx2

logger = logging.getLogger(__name__)

Method = Literal["GET", "POST", "DELETE"]
ABILITY_NAME = re.compile(r"^[a-zA-Z0-9\-/]+$")  # WP's own route pattern
PER_PAGE = 100


@dataclass(frozen=True)
class WPCredential:
    kind: Literal["bearer", "basic"]
    secret: str = field(repr=False)
    user_login: str | None = None

    def auth_header(self) -> str:
        if self.kind == "bearer":
            return f"Bearer {self.secret}"
        raw = f"{self.user_login}:{self.secret}".encode()
        return "Basic " + base64.b64encode(raw).decode()


@dataclass(frozen=True)
class Ability:
    name: str
    label: str
    description: str
    category: str | None
    input_schema: dict | None
    output_schema: dict | None
    readonly: bool
    destructive: bool
    idempotent: bool
    mcp_public: bool

    @property
    def method(self) -> Method:
        """The HTTP method WordPress' run controller insists on
        (WP_REST_Abilities_V1_Run_Controller::validate_request_method)."""
        if self.readonly:
            return "GET"
        if self.destructive and self.idempotent:
            return "DELETE"
        return "POST"

    @classmethod
    def from_rest(cls, item: dict) -> Ability:
        meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
        annotations = meta.get("annotations") if isinstance(meta.get("annotations"), dict) else {}
        mcp = meta.get("mcp") if isinstance(meta.get("mcp"), dict) else {}

        def schema(value: Any) -> dict | None:
            # PHP serialises an empty array as [], not {}.
            return value if isinstance(value, dict) and value else None

        return cls(
            name=str(item["name"]),
            label=str(item.get("label") or item["name"]),
            description=str(item.get("description") or ""),
            category=item.get("category") or None,
            input_schema=schema(item.get("input_schema")),
            output_schema=schema(item.get("output_schema")),
            readonly=bool(annotations.get("readonly")),
            destructive=bool(annotations.get("destructive")),
            idempotent=bool(annotations.get("idempotent")),
            mcp_public=bool(mcp.get("public") or meta.get("public")),
        )


class WordPressError(Exception):
    """A failed WordPress call, carrying WP_Error's code and message.

    The message is WordPress' own (safe to show the user); request headers,
    and with them the credential, never end up in it.
    """

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{message} ({code}, HTTP {status})")
        self.status = status
        self.code = code
        self.message = message


class WPUnauthorized(WordPressError):
    """401: WordPress didn't accept the credential."""


class WPForbidden(WordPressError):
    """403: authenticated, but not allowed."""


class WPNotFound(WordPressError):
    """404: no such route or ability (or one not shown in REST)."""


_ERRORS = {401: WPUnauthorized, 403: WPForbidden, 404: WPNotFound}


def _raise_for_wp(resp: httpx2.Response) -> None:
    if resp.status_code < 400:
        return
    code, message = "http_error", resp.reason_phrase or "error"
    try:
        body = resp.json()
        if isinstance(body, dict):
            code = str(body.get("code") or code)
            message = str(body.get("message") or message)
    except ValueError:
        pass
    raise _ERRORS.get(resp.status_code, WordPressError)(resp.status_code, code, message)


def encode_php_query(key: str, value: Any) -> list[tuple[str, str]]:
    """Encode a value as PHP-style query parameters (input[a][b]=1, input[l][]=x).

    GET and DELETE runs take their input from the query string, which PHP
    parses into nested arrays. Booleans become "1"/"0" (PHP's "false" string
    is truthy); None is left out; an empty list or object can't be expressed
    and is left out too. WordPress sees strings: the ability's input schema
    validation accepts numeric and boolean strings (rest_validate_value_from_schema).
    """
    if value is None:
        return []
    if isinstance(value, bool):
        return [(key, "1" if value else "0")]
    if isinstance(value, dict):
        return [pair for k, v in value.items() for pair in encode_php_query(f"{key}[{k}]", v)]
    if isinstance(value, (list, tuple)):
        if any(isinstance(v, (dict, list, tuple)) for v in value):
            return [pair for i, v in enumerate(value) for pair in encode_php_query(f"{key}[{i}]", v)]
        return [pair for v in value for pair in encode_php_query(f"{key}[]", v)]
    return [(key, str(value))]


class WordPressClient:
    def __init__(self, base_url: str, *, rest_prefix: str = "/wp-json", timeout: float = 30,
                 verify: str | bool = True, transport: httpx2.AsyncBaseTransport | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.rest_prefix = rest_prefix
        self._http = httpx2.AsyncClient(timeout=timeout, verify=verify, transport=transport,
                                        follow_redirects=False,
                                        headers={"Accept": "application/json"})

    async def aclose(self) -> None:
        await self._http.aclose()

    def _url(self, route: str) -> tuple[str, list[tuple[str, str]]]:
        route = "/" + route.lstrip("/")
        if self.rest_prefix:
            return f"{self.base_url}{self.rest_prefix}{route}", []
        return f"{self.base_url}/", [("rest_route", route)]

    async def request(self, cred: WPCredential, method: str, route: str, *,
                      params: list[tuple[str, str]] | None = None, json: Any = None) -> httpx2.Response:
        url, base_params = self._url(route)
        kwargs: dict[str, Any] = {"params": base_params + list(params or []),
                                  "headers": {"Authorization": cred.auth_header()}}
        if json is not None:
            kwargs["json"] = json
        try:
            resp = await self._http.request(method, url, **kwargs)
        except httpx2.TimeoutException:
            raise WordPressError(504, "wp_timeout", "WordPress did not answer in time") from None
        except httpx2.HTTPError as exc:
            raise WordPressError(502, "wp_unreachable", f"WordPress is not reachable ({type(exc).__name__})") from None
        if 300 <= resp.status_code < 400:
            # Usually http->https or a changed site URL; following it could
            # send the credential somewhere unintended.
            raise WordPressError(resp.status_code, "wp_redirect",
                                 f"WordPress redirected to {resp.headers.get('location')!r}; "
                                 "check WORDPRESS_URL and WP_REST_PREFIX")
        _raise_for_wp(resp)
        return resp

    @staticmethod
    def _json(resp: httpx2.Response) -> Any:
        try:
            return resp.json()
        except ValueError:
            raise WordPressError(resp.status_code, "wp_invalid_json",
                                 "WordPress returned something other than JSON "
                                 "(a security plugin or caching layer in the way?)") from None

    async def list_abilities(self, cred: WPCredential, *, max_items: int = 1000) -> list[Ability]:
        abilities: list[Ability] = []
        page = 1
        while True:
            resp = await self.request(cred, "GET", "/wp-abilities/v1/abilities",
                                      params=[("page", str(page)), ("per_page", str(PER_PAGE))])
            items = self._json(resp)
            if not isinstance(items, list):
                raise WordPressError(resp.status_code, "wp_invalid_response", "Unexpected abilities list")
            for item in items:
                if isinstance(item, dict) and isinstance(item.get("name"), str):
                    abilities.append(Ability.from_rest(item))
            try:
                total_pages = int(resp.headers.get("X-WP-TotalPages", "1"))
            except ValueError:
                total_pages = 1
            if page >= total_pages or not items or len(abilities) >= max_items:
                break
            page += 1
        if len(abilities) > max_items:
            logger.warning("WordPress lists more than ABILITY_MAX=%d abilities; the rest are ignored", max_items)
        return abilities[:max_items]

    async def run_ability(self, cred: WPCredential, name: str, input: Any, method: Method) -> Any:
        if not ABILITY_NAME.match(name):
            raise WordPressError(400, "invalid_ability_name", f"Invalid ability name {name!r}")
        route = f"/wp-abilities/v1/abilities/{name}/run"
        if method == "POST":
            resp = await self.request(cred, "POST", route, json={"input": input} if input is not None else {})
        else:
            resp = await self.request(cred, method, route, params=encode_php_query("input", input))
        return self._json(resp)

    async def whoami(self, cred: WPCredential) -> dict:
        """The user WordPress authenticates this credential as (roles with
        context=edit, which every user may use on themselves)."""
        try:
            resp = await self.request(cred, "GET", "/wp/v2/users/me", params=[("context", "edit")])
        except WPForbidden:
            resp = await self.request(cred, "GET", "/wp/v2/users/me")
        return self._json(resp)

    async def introspect_app_password(self, cred: WPCredential) -> dict:
        resp = await self.request(cred, "GET", "/wp/v2/users/me/application-passwords/introspect")
        return self._json(resp)

    async def delete_app_password(self, cred: WPCredential, uuid: str) -> None:
        await self.request(cred, "DELETE", f"/wp/v2/users/me/application-passwords/{uuid}")
