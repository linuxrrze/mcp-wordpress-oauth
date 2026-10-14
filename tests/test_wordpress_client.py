import pytest

from mcp_wordpress.wordpress import (
    Ability,
    WordPressClient,
    WordPressError,
    WPCredential,
    WPNotFound,
    WPUnauthorized,
    encode_php_query,
)

from .fake_wp import SITE, FakeAbility, FakeWordPress

ALICE = WPCredential("bearer", "header.eyJzdWIiOiJrYy1hbGljZSJ9.sig")  # {"sub":"kc-alice"}


@pytest.mark.parametrize("readonly, destructive, idempotent, method", [
    (True, False, True, "GET"),
    (True, True, True, "GET"),        # readonly wins
    (False, True, True, "DELETE"),
    (False, True, False, "POST"),
    (False, False, True, "POST"),
    (False, False, False, "POST"),
])
def test_method_rule(readonly, destructive, idempotent, method):
    ability = Ability.from_rest(FakeAbility("a/b", readonly=readonly, destructive=destructive,
                                            idempotent=idempotent).rest())
    assert ability.method == method


def test_from_rest_tolerates_php_empty_arrays():
    ability = Ability.from_rest({"name": "a/b", "input_schema": [], "output_schema": [], "meta": []})
    assert ability.input_schema is None and ability.output_schema is None
    assert ability.label == "a/b" and not ability.mcp_public


@pytest.mark.parametrize("value, expected", [
    ({"a": 1, "b": "x"}, [("input[a]", "1"), ("input[b]", "x")]),
    ({"flag": True, "off": False}, [("input[flag]", "1"), ("input[off]", "0")]),
    ({"ids": [1, 2]}, [("input[ids][]", "1"), ("input[ids][]", "2")]),
    ({"q": {"x": {"y": "z"}}}, [("input[q][x][y]", "z")]),
    ({"l": [{"a": 1}]}, [("input[l][0][a]", "1")]),
    ({"skip": None}, []),
    (5, [("input", "5")]),
    (None, []),
])
def test_php_query_encoding(value, expected):
    assert encode_php_query("input", value) == expected


def test_basic_auth_header_and_repr():
    cred = WPCredential("basic", "abcd efgh", "alice")
    assert cred.auth_header() == "Basic YWxpY2U6YWJjZCBlZmdo"
    assert "abcd" not in repr(cred)


async def test_listing_is_paged_and_capped():
    wp = FakeWordPress()
    wp.add_user("alice", sub="kc-alice")
    wp.per_page_max = 3
    for i in range(8):
        wp.add_ability(FakeAbility(f"x/a{i}"))
    client = WordPressClient(SITE, transport=wp.transport())
    assert len(await client.list_abilities(ALICE)) == 8
    assert [dict(c.query)["page"] for c in wp.calls] == ["1", "2", "3"]
    wp.calls.clear()
    assert len(await client.list_abilities(ALICE, max_items=4)) == 4
    assert len(wp.calls) == 2


async def test_errors_carry_wordpress_code_and_message(fake_wp, wp_client):
    with pytest.raises(WPNotFound) as exc:
        await wp_client.run_ability(ALICE, "nope/nope", None, "POST")
    assert exc.value.code == "rest_ability_not_found"
    with pytest.raises(WordPressError) as exc:  # wrong method
        await wp_client.run_ability(ALICE, "ewpa/create-post", {"title": "x"}, "GET")
    assert exc.value.status == 405 and exc.value.code == "rest_ability_invalid_method"


async def test_secrets_never_appear_in_errors(fake_wp, wp_client):
    cred = WPCredential("basic", "super secret pw", "alice")
    with pytest.raises(WPUnauthorized) as exc:
        await wp_client.whoami(cred)
    assert "super secret" not in str(exc.value) and "super secret" not in repr(exc.value)


async def test_invalid_ability_name_never_reaches_wordpress(fake_wp, wp_client):
    with pytest.raises(WordPressError):
        await wp_client.run_ability(ALICE, "../../wp/v2/users", None, "POST")
    assert fake_wp.calls == []


async def test_redirects_are_not_followed():
    import httpx2

    transport = httpx2.MockTransport(lambda r: httpx2.Response(301, headers={"location": "https://elsewhere/"}))
    client = WordPressClient(SITE, transport=transport)
    with pytest.raises(WordPressError, match="redirected"):
        await client.whoami(ALICE)


async def test_non_json_answer():
    import httpx2

    transport = httpx2.MockTransport(lambda r: httpx2.Response(200, text="<html>cached</html>"))
    with pytest.raises(WordPressError, match="other than JSON"):
        await WordPressClient(SITE, transport=transport).whoami(ALICE)


async def test_plain_permalinks_use_rest_route(fake_wp):
    import httpx2

    seen = []

    def handler(request):
        seen.append(request.url)
        return httpx2.Response(200, json={"id": 1})

    client = WordPressClient(SITE, rest_prefix="", transport=httpx2.MockTransport(handler))
    await client.whoami(ALICE)
    assert seen[0].path == "/" and seen[0].params["rest_route"] == "/wp/v2/users/me"
