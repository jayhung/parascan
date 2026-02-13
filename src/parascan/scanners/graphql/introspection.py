"""GraphQL introspection leak scanner."""

from __future__ import annotations

from typing import Any

import httpx

from parascan.scanners.base import BaseScanner, ScanResult

INTROSPECTION_QUERY = '{"query": "{ __schema { types { name } } }"}'


class GraphQLIntrospectionScanner(BaseScanner):
    module_name = "graphql-introspection"
    description = "Checks if GraphQL introspection is enabled"

    async def scan(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any]
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        url = endpoint["url"]

        # try common GraphQL endpoint paths
        paths_to_try = [url]
        if not url.endswith("/graphql"):
            paths_to_try.append(url.rstrip("/") + "/graphql")

        for target_url in paths_to_try:
            resp = await self._request(
                client, "POST", target_url,
                content=INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
            )

            if resp is None:
                continue

            try:
                data = resp.json()
            except Exception:
                continue

            # check if introspection returned schema data
            schema = data.get("data", {}).get("__schema")
            if schema and schema.get("types"):
                type_count = len(schema["types"])
                type_names = [t["name"] for t in schema["types"][:10]]
                results.append(ScanResult(
                    module=self.module_name,
                    severity="medium",
                    title=f"GraphQL introspection enabled at {target_url}",
                    description=(
                        f"The GraphQL endpoint exposes its full schema via introspection. "
                        f"Found {type_count} types. An attacker can enumerate all queries, "
                        f"mutations, and data types."
                    ),
                    evidence=f"Types found: {', '.join(type_names)}...",
                    request_data=self._format_request(
                        "POST", target_url,
                        headers={"Content-Type": "application/json"},
                    ),
                    response_data=self._format_response(resp),
                ))
                break  # found it, no need to check more paths

        return results
