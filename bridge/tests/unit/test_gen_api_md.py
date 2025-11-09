"""Tests for scripts.gen_api_md utilities."""

from scripts.gen_api_md import example_from_schema


def test_example_from_schema_optional_string() -> None:
    schema = {"type": ["string", "null"]}
    assert example_from_schema(schema) == "string"


def test_example_from_schema_optional_integer() -> None:
    schema = {"type": ["integer", "null"]}
    assert example_from_schema(schema) == 0
