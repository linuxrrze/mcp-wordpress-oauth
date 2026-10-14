"""WordPress abilities as MCP tools, one tool per ability, per user (D2).

The tool list is built per request by a FastMCP `Provider`: FastMCP calls
`_list_tools()` / `_get_tool()` on every tools/list and tools/call, and the
caller's access token is available there. The list WordPress returns is
cached per user for ABILITY_CACHE_TTL seconds.
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import re
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.providers import Provider
from fastmcp.utilities.tasks import TaskConfig
from fastmcp.tools import Tool, ToolResult
from mcp.types import ToolAnnotations

from .credentials import CredentialResolver
from .wordpress import Ability, WordPressClient, WordPressError, WPUnauthorized

logger = logging.getLogger(__name__)

_INVALID_TOOL_CHARS = re.compile(r"[^A-Za-z0-9._-]")
EMPTY_OBJECT = {"type": "object", "properties": {}}


def tool_name(ability_name: str) -> str:
    """MCP tool names allow [A-Za-z0-9._-]{1,128}; ability names are
    namespace/name, so "core/get-site-info" becomes "core-get-site-info"."""
    return _INVALID_TOOL_CHARS.sub("-", ability_name.replace("/", "-"))[:128]


def _is_object_schema(schema: dict | None) -> bool:
    if not schema:
        return False
    kind = schema.get("type")
    return kind == "object" or (isinstance(kind, list) and "object" in kind) or (
        kind is None and "properties" in schema)


def input_schema_for(ability: Ability) -> tuple[dict, bool]:
    """(MCP inputSchema, wrapped). MCP tool arguments are always an object,
    an ability's input can be anything: non-object inputs become {"input": ...}."""
    schema = ability.input_schema
    if schema is None:
        return dict(EMPTY_OBJECT), False
    if _is_object_schema(schema):
        return schema, False
    return {"type": "object", "properties": {"input": schema}, "required": ["input"]}, True


def output_schema_for(ability: Ability) -> dict | None:
    schema = ability.output_schema
    if schema is None:
        return None
    if _is_object_schema(schema):
        return schema
    return {"type": "object", "properties": {"result": schema}, "required": ["result"],
            "x-fastmcp-wrap-result": True}


def annotations_for(ability: Ability) -> ToolAnnotations:
    return ToolAnnotations(
        title=ability.label,
        read_only_hint=ability.readonly,
        destructive_hint=ability.destructive,
        idempotent_hint=ability.idempotent,
        open_world_hint=False,
    )


class AbilityFilter:
    """ABILITY_ALLOW / ABILITY_DENY: comma-separated globs on ability names
    (e.g. "core/*,ewpa/*"); deny wins. ABILITY_MCP_PUBLIC_ONLY additionally
    requires meta.mcp.public, the MCP Adapter's own exposure flag."""

    def __init__(self, allow: Sequence[str] = ("*",), deny: Sequence[str] = (), mcp_public_only: bool = True) -> None:
        self.allow = tuple(allow)
        self.deny = tuple(deny)
        self.mcp_public_only = mcp_public_only

    def allows(self, ability: Ability) -> bool:
        if self.mcp_public_only and not ability.mcp_public:
            return False
        name = ability.name
        if any(fnmatch.fnmatchcase(name, pattern) for pattern in self.deny):
            return False
        return any(fnmatch.fnmatchcase(name, pattern) for pattern in self.allow)

    def describe(self) -> dict:
        return {"allow": list(self.allow), "deny": list(self.deny), "mcp_public_only": self.mcp_public_only}


class AbilityCache:
    """Per-user tool sets with a TTL, bounded LRU, one load at a time per user."""

    def __init__(self, ttl: float = 300, max_users: int = 1000) -> None:
        self.ttl = ttl
        self.max_users = max_users
        self._entries: OrderedDict[str, tuple[float, dict[str, AbilityTool]]] = OrderedDict()
        self._locks: dict[str, asyncio.Lock] = {}

    async def get(self, key: str, loader: Callable[[], Awaitable[dict[str, AbilityTool]]]) -> dict[str, AbilityTool]:
        entry = self._entries.get(key)
        if entry and entry[0] > time.monotonic():
            self._entries.move_to_end(key)
            return entry[1]
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            entry = self._entries.get(key)
            if entry and entry[0] > time.monotonic():
                return entry[1]
            tools = await loader()
            if self.ttl > 0:
                self._entries[key] = (time.monotonic() + self.ttl, tools)
                self._entries.move_to_end(key)
                while len(self._entries) > self.max_users:
                    old, _ = self._entries.popitem(last=False)
                    self._locks.pop(old, None)
            return tools

    def invalidate(self, key: str) -> None:
        self._entries.pop(key, None)


class AbilityRuntime:
    """What every AbilityTool needs at call time, shared."""

    def __init__(self, wp: WordPressClient, resolver: CredentialResolver, cache: AbilityCache) -> None:
        self.wp = wp
        self.resolver = resolver
        self.cache = cache

    def current_token(self) -> AccessToken:
        token = get_access_token()
        if token is None:
            raise ToolError("Not signed in.")
        return token

    async def tool_error(self, token: AccessToken, exc: WordPressError) -> ToolError:
        if isinstance(exc, WPUnauthorized):
            self.cache.invalidate(self.resolver.user_key(token))
            await self.resolver.on_unauthorized(token)
            return ToolError(f"{exc.message}. {self.resolver.unauthorized_hint()}")
        return ToolError(f"WordPress: {exc.message} ({exc.code})")


class AbilityTool(Tool):
    """One WordPress ability; `run` executes it as the calling user."""

    task_config: TaskConfig = TaskConfig(mode="forbidden")

    def __init__(self, ability: Ability, runtime: AbilityRuntime) -> None:
        parameters, wrapped = input_schema_for(ability)
        description = ability.description.strip() or ability.label
        super().__init__(
            name=tool_name(ability.name),
            description=f"{description}\n\n(WordPress ability `{ability.name}`)",
            parameters=parameters,
            output_schema=output_schema_for(ability),
            annotations=annotations_for(ability),
            tags={ability.category} if ability.category else set(),
        )
        self._ability = ability
        self._wrapped = wrapped
        self._runtime = runtime

    def __repr__(self) -> str:
        return f"AbilityTool(name={self.name!r}, ability={self._ability.name!r}, method={self._ability.method})"

    @property
    def ability(self) -> Ability:
        return self._ability

    def _input(self, arguments: dict[str, Any]) -> Any:
        if self._wrapped:
            return arguments.get("input")
        if self._ability.input_schema is None:
            return None
        return arguments

    async def run(self, arguments: dict[str, Any]) -> ToolResult:
        rt = self._runtime
        token = rt.current_token()
        cred = await rt.resolver.credential(token)
        try:
            result = await rt.wp.run_ability(cred, self._ability.name, self._input(arguments), self._ability.method)
        except WordPressError as exc:
            logger.info("Ability %s failed: %s", self._ability.name, exc)
            raise await rt.tool_error(token, exc) from None
        return self._result(result)

    def _result(self, result: Any) -> ToolResult:
        if self.output_schema is not None and not self.output_schema.get("x-fastmcp-wrap-result"):
            # An object result; PHP serialises an empty one as [].
            if result == []:
                result = {}
            structured = result if isinstance(result, dict) else {"result": result}
        elif self.output_schema is None and isinstance(result, dict) and result:
            structured = result
        else:
            structured = {"result": result}
        text = json.dumps(result, ensure_ascii=False)
        return ToolResult(content=text, structured_content=structured)


def build_tools(abilities: Sequence[Ability], filt: AbilityFilter, runtime: AbilityRuntime) -> dict[str, AbilityTool]:
    """Tool name -> tool. Two abilities whose names map to the same tool name
    ("a-b/c" and "a/b-c"): the first by ability name wins, the other is
    logged and skipped."""
    tools: dict[str, AbilityTool] = {}
    for ability in sorted(abilities, key=lambda a: a.name):
        if not filt.allows(ability):
            continue
        name = tool_name(ability.name)
        if name in tools:
            logger.warning("Abilities %s and %s both map to tool name %s; skipping the second",
                           tools[name].ability.name, ability.name, name)
            continue
        tools[name] = AbilityTool(ability, runtime)
    return tools


class AbilityProvider(Provider):
    def __init__(self, runtime: AbilityRuntime, filt: AbilityFilter, *, max_items: int = 1000,
                 reserved: Sequence[str] = ()) -> None:
        super().__init__()
        self.runtime = runtime
        self.filt = filt
        self.max_items = max_items
        self.reserved = set(reserved)

    async def tools_for(self, token: AccessToken) -> dict[str, AbilityTool]:
        rt = self.runtime
        cred = await rt.resolver.credential(token)

        async def load() -> dict[str, AbilityTool]:
            abilities = await rt.wp.list_abilities(cred, max_items=self.max_items)
            tools = build_tools(abilities, self.filt, rt)
            for name in self.reserved & tools.keys():
                logger.warning("Ability tool %s is shadowed by this server's own tool of that name", name)
                del tools[name]
            return tools

        return await rt.cache.get(rt.resolver.user_key(token), load)

    async def _current_tools(self) -> dict[str, AbilityTool]:
        token = get_access_token()
        if token is None:
            return {}
        try:
            return await self.tools_for(token)
        except ToolError as exc:
            logger.info("No abilities for this user: %s", exc)
        except WordPressError as exc:
            logger.warning("Listing abilities failed: %s", exc)
            if isinstance(exc, WPUnauthorized):
                await self.runtime.tool_error(token, exc)
        return {}

    async def _list_tools(self) -> Sequence[Tool]:
        return list((await self._current_tools()).values())

    async def _get_tool(self, name: str, version=None) -> Tool | None:
        return (await self._current_tools()).get(name)
