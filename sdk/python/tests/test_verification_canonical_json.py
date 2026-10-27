"""Tests for qodiqa._verification._canonical_json.stable_stringify."""

from __future__ import annotations

import pytest

from qodiqa import CanonicalizationError, stable_stringify


def test_sorts_object_keys_lexicographically_at_every_depth() -> None:
    assert stable_stringify({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    assert stable_stringify({"z": {"b": 1, "a": 2}, "a": 1}) == '{"a":1,"z":{"a":2,"b":1}}'


def test_sorts_keys_in_utf16_code_unit_order_not_codepoint_order() -> None:
    # U+E000 (BMP, private-use area) vs an astral character U+1F600 (an
    # emoji). In UTF-16, U+1F600 is a surrogate pair starting with 0xD83D
    # (in the 0xD800-0xDBFF range), which sorts BELOW 0xE000 — the opposite
    # of Python's default codepoint order, where 0x1F600 > 0xE000. This must
    # match the JS SDK's ordering exactly for cross-language hash parity.
    bmp = "\uE000"
    astral = "\U0001F600"
    result = stable_stringify({astral: 1, bmp: 2})
    assert result.index(f'"{astral}"') < result.index(f'"{bmp}"')


def test_produces_zero_whitespace() -> None:
    assert stable_stringify({"a": [1, 2, 3], "b": "x"}) == '{"a":[1,2,3],"b":"x"}'


def test_none_serializes_as_null() -> None:
    assert stable_stringify({"a": None}) == '{"a":null}'


def test_preserves_array_order() -> None:
    assert stable_stringify([3, 1, 2]) == "[3,1,2]"


def test_escapes_control_characters_like_json_stringify() -> None:
    assert stable_stringify('a\nb\tc"d\\e') == '"a\\nb\\tc\\"d\\\\e"'
    assert stable_stringify("\x01\x02") == '"\\u0001\\u0002"'


def test_does_not_escape_non_ascii_characters() -> None:
    assert stable_stringify("héllo") == '"héllo"'


@pytest.mark.parametrize("n", [float("nan"), float("inf"), float("-inf")])
def test_rejects_non_finite_number(n: float) -> None:
    with pytest.raises(CanonicalizationError) as exc_info:
        stable_stringify({"x": n})
    assert exc_info.value.code == "NON_FINITE_NUMBER"


def test_rejects_non_integer_float() -> None:
    with pytest.raises(CanonicalizationError) as exc_info:
        stable_stringify({"x": 3.14})
    assert exc_info.value.code == "NON_INTEGER_FLOAT"


def test_whole_number_float_formats_as_integer_matching_js() -> None:
    # JS numbers are always float64; JSON.stringify(5.0) === "5", never "5.0".
    assert stable_stringify({"x": 5.0}) == stable_stringify({"x": 5})


@pytest.mark.parametrize("key", ["__proto__", "constructor", "prototype"])
def test_rejects_forbidden_key(key: str) -> None:
    with pytest.raises(CanonicalizationError) as exc_info:
        stable_stringify({key: 1})
    assert exc_info.value.code == "FORBIDDEN_KEY"


def test_rejects_non_string_keys() -> None:
    with pytest.raises(CanonicalizationError):
        stable_stringify({1: "x"})


def test_rejects_unsupported_types() -> None:
    class Custom:
        pass

    with pytest.raises(CanonicalizationError):
        stable_stringify({"o": Custom()})
    with pytest.raises(CanonicalizationError):
        stable_stringify({"o": object()})


def test_rejects_circular_references() -> None:
    obj: dict = {"a": 1}
    obj["self"] = obj
    with pytest.raises(CanonicalizationError) as exc_info:
        stable_stringify(obj)
    assert exc_info.value.code == "CIRCULAR_REFERENCE"


def test_rejects_pathologically_deep_nesting() -> None:
    deep: object = 1
    for _ in range(1005):
        deep = {"n": deep}
    with pytest.raises(CanonicalizationError) as exc_info:
        stable_stringify(deep)
    assert exc_info.value.code == "MAX_DEPTH_EXCEEDED"


def test_accepts_nesting_within_the_depth_guard() -> None:
    deep: object = 1
    for _ in range(500):
        deep = {"n": deep}
    stable_stringify(deep)  # must not raise


def test_byte_identical_for_a_realistic_artifact_payload() -> None:
    payload = {
        "tenantId": "dev-local",
        "requestId": "e5d4b3de-dddb-43c6-b424-2f2f871d69d2",
        "requestHash": "5c31ef9f6cc851294dd030131f482b052811e477b78a78c2dc77680cee419e7",
        "policyHash": "0cd6ec4385a972e9dec9ca3582778d5f59c86b7eada72c2a34421e9c71120fe4",
    }
    assert stable_stringify(payload) == (
        '{"policyHash":"0cd6ec4385a972e9dec9ca3582778d5f59c86b7eada72c2a34421e9c71120fe4",'
        '"requestHash":"5c31ef9f6cc851294dd030131f482b052811e477b78a78c2dc77680cee419e7",'
        '"requestId":"e5d4b3de-dddb-43c6-b424-2f2f871d69d2","tenantId":"dev-local"}'
    )
