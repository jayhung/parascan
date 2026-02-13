"""GraphQL introspection-based endpoint generation."""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("parascan.discovery.graphql")

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args {
          name
          type {
            name
            kind
            ofType { name kind }
          }
          defaultValue
        }
        type {
          name
          kind
          ofType { name kind }
        }
      }
    }
  }
}
"""


async def discover_graphql_endpoints(
    client: httpx.AsyncClient,
    url: str,
) -> list[dict[str, Any]]:
    """
    Use introspection to discover GraphQL queries and mutations.

    Returns endpoint dicts with url, method, and params containing the query string.
    """
    endpoints: list[dict[str, Any]] = []

    try:
        resp = await client.post(
            url,
            json={"query": INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code != 200:
            return endpoints

        data = resp.json()
    except Exception:
        return endpoints

    schema = data.get("data", {}).get("__schema", {})
    if not schema:
        return endpoints

    query_type_name = (schema.get("queryType") or {}).get("name", "Query")
    mutation_type_name = (schema.get("mutationType") or {}).get("name", "Mutation")

    types = {t["name"]: t for t in schema.get("types", []) if t.get("name")}

    # generate test queries
    for type_name, target_label in [
        (query_type_name, "query"),
        (mutation_type_name, "mutation"),
    ]:
        type_def = types.get(type_name)
        if not type_def or not type_def.get("fields"):
            continue

        for field in type_def["fields"]:
            if field["name"].startswith("__"):
                continue

            query = _build_test_query(target_label, field)
            endpoints.append({
                "url": url,
                "method": "POST",
                "params": {"query": query, "_graphql": True},
            })

    return endpoints


def _build_test_query(operation: str, field: dict) -> str:
    """build a minimal test query for a field."""
    name = field["name"]
    args = field.get("args", [])

    args_str = ""
    if args:
        arg_parts = []
        for arg in args:
            arg_type = arg.get("type", {})
            default = _get_default_value(arg_type)
            arg_parts.append(f'{arg["name"]}: {default}')
        args_str = f"({', '.join(arg_parts)})"

    # determine if the return type has sub-fields
    return_type = field.get("type", {})
    sub_selection = _get_sub_selection(return_type)

    return f"{operation} {{ {name}{args_str}{sub_selection} }}"


def _get_default_value(type_info: dict) -> str:
    """generate a default test value for a GraphQL type."""
    name = type_info.get("name") or ""
    of_type = type_info.get("ofType") or {}
    inner_name = of_type.get("name") or name

    if inner_name in ("String", "ID"):
        return '"test"'
    if inner_name in ("Int", "Float"):
        return "1"
    if inner_name == "Boolean":
        return "true"
    return '"test"'


def _get_sub_selection(type_info: dict) -> str:
    """return a sub-selection placeholder if the type is an object."""
    kind = type_info.get("kind", "")
    of_type = type_info.get("ofType") or {}
    inner_kind = of_type.get("kind") or kind

    if inner_kind in ("OBJECT", "LIST"):
        return " { __typename }"
    return ""
