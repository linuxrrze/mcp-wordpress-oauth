import pytest

from mcp_wordpress.abilities import (
    AbilityCache,
    AbilityFilter,
    AbilityTool,
    build_tools,
    input_schema_for,
    output_schema_for,
    tool_name,
)
from mcp_wordpress.wordpress import Ability

from .fake_wp import FakeAbility


def ability(name="a/b", **kw) -> Ability:
    return Ability.from_rest(FakeAbility(name, **kw).rest())


@pytest.mark.parametrize("name, expected", [
    ("core/get-site-info", "core-get-site-info"),
    ("ewpa/posts/list", "ewpa-posts-list"),
    ("a/" + "x" * 200, ("a-" + "x" * 200)[:128]),
])
def test_tool_name(name, expected):
    assert tool_name(name) == expected


def test_input_schema_mapping():
    assert input_schema_for(ability()) == ({"type": "object", "properties": {}}, False)
    obj = {"type": "object", "properties": {"x": {"type": "string"}}}
    assert input_schema_for(ability(input_schema=obj)) == (obj, False)
    wrapped, is_wrapped = input_schema_for(ability(input_schema={"type": "integer"}))
    assert is_wrapped and wrapped["properties"]["input"] == {"type": "integer"} and wrapped["required"] == ["input"]


def test_output_schema_mapping():
    assert output_schema_for(ability()) is None
    obj = {"type": "object", "properties": {"x": {"type": "string"}}}
    assert output_schema_for(ability(output_schema=obj)) == obj
    wrapped = output_schema_for(ability(output_schema={"type": "array"}))
    assert wrapped["properties"]["result"] == {"type": "array"}


@pytest.mark.parametrize("schema, arguments, expected", [
    (None, {}, None),
    ({"type": "object", "properties": {"t": {"type": "string"}}}, {"t": "x"}, {"t": "x"}),
    ({"type": "integer"}, {"input": 3}, 3),
])
def test_tool_input(schema, arguments, expected):
    tool = AbilityTool(ability(input_schema=schema), runtime=None)
    assert tool._input(arguments) == expected


@pytest.mark.parametrize("output_schema, result, structured", [
    ({"type": "object", "properties": {}}, [], {}),            # PHP's empty object
    ({"type": "object", "properties": {}}, {"a": 1}, {"a": 1}),
    ({"type": "array"}, [1, 2], {"result": [1, 2]}),
    (None, {"a": 1}, {"a": 1}),
    (None, "text", {"result": "text"}),
    (None, [], {"result": []}),
])
def test_tool_result(output_schema, result, structured):
    tool = AbilityTool(ability(output_schema=output_schema), runtime=None)
    assert tool._result(result).structured_content == structured


def test_annotations():
    tool = AbilityTool(ability(label="Delete", destructive=True, idempotent=True), runtime=None)
    assert tool.annotations.title == "Delete"
    assert tool.annotations.destructive_hint and tool.annotations.idempotent_hint
    assert tool.annotations.read_only_hint is False and tool.annotations.open_world_hint is False


def test_filter():
    f = AbilityFilter(allow=("core/*", "ewpa/*"), deny=("ewpa/delete-*",))
    assert f.allows(ability("core/x"))
    assert not f.allows(ability("ewpa/delete-post"))
    assert not f.allows(ability("other/x"))
    assert not f.allows(ability("core/hidden", public=False))
    assert AbilityFilter(mcp_public_only=False).allows(ability("core/hidden", public=False))


def test_name_collisions_keep_the_first(caplog):
    tools = build_tools([ability("a/b-c"), ability("a-b/c")], AbilityFilter(), runtime=None)
    assert list(tools) == ["a-b-c"] and tools["a-b-c"].ability.name == "a-b/c"
    assert "both map to tool name" in caplog.text


async def test_cache_ttl_and_keys(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("mcp_wordpress.abilities.time.monotonic", lambda: now[0])
    cache = AbilityCache(ttl=10, max_users=2)
    loads = []

    def loader(key):
        async def load():
            loads.append(key)
            return {key: None}
        return load

    assert await cache.get("alice", loader("alice")) == {"alice": None}
    await cache.get("alice", loader("alice"))
    await cache.get("bob", loader("bob"))
    assert loads == ["alice", "bob"]
    now[0] += 11
    await cache.get("alice", loader("alice"))
    assert loads == ["alice", "bob", "alice"]
    cache.invalidate("alice")
    await cache.get("alice", loader("alice"))
    await cache.get("carol", loader("carol"))  # evicts the least recently used (bob)
    await cache.get("bob", loader("bob"))
    assert loads[-3:] == ["alice", "carol", "bob"]


async def test_cache_ttl_zero_never_stores():
    cache = AbilityCache(ttl=0)
    calls = []

    async def load():
        calls.append(1)
        return {}

    await cache.get("a", load)
    await cache.get("a", load)
    assert len(calls) == 2
