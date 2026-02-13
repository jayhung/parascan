"""GraphQL batch/DoS scanner — tests for batched and deeply nested queries."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from parascan.scanners.base import BaseScanner, ScanResult


class GraphQLBatchScanner(BaseScanner):
    module_name = "graphql-batch"
    description = "GraphQL batch query and nested query DoS detection"

    async def scan(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any]
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        url = endpoint["url"]
        params = endpoint.get("params", {})

        if not params.get("_graphql") and not url.endswith("/graphql"):
            return results

        # test batch queries
        batch_result = await self._test_batch(client, url)
        if batch_result:
            results.append(batch_result)

        # test deeply nested queries
        nested_result = await self._test_nested(client, url)
        if nested_result:
            results.append(nested_result)

        return results

    async def _test_batch(
        self, client: httpx.AsyncClient, url: str
    ) -> ScanResult | None:
        """test if the endpoint accepts batched queries (array of operations)."""
        batch = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]

        resp = await self._request(
            client, "POST", url,
            content=json.dumps(batch),
            headers={"Content-Type": "application/json"},
        )

        if resp is None:
            return None

        try:
            data = resp.json()
        except Exception:
            return None

        # if the response is a list with results, batching is enabled
        if isinstance(data, list) and len(data) >= 5:
            return ScanResult(
                module=self.module_name,
                severity="low",
                title=f"GraphQL query batching enabled at {url}",
                description=(
                    "The GraphQL endpoint accepts batched queries. An attacker could "
                    "use this to bypass rate limiting or amplify brute-force attacks "
                    "by sending many operations in a single request."
                ),
                evidence=f"Batch of 5 queries returned {len(data)} results",
                request_data=json.dumps(batch)[:500],
                response_data=self._format_response(resp),
            )

        return None

    async def _test_nested(
        self, client: httpx.AsyncClient, url: str
    ) -> ScanResult | None:
        """test if the endpoint is vulnerable to deeply nested query DoS."""
        # build a deeply nested introspection query
        depth = 10
        inner = "{ name kind ofType " * depth + "{ name }" + " }" * depth
        query = f"{{ __schema {{ types {{ name fields {{ name type {inner} }} }} }} }}"

        start = time.monotonic()
        resp = await self._request(
            client, "POST", url,
            content=json.dumps({"query": query}),
            headers={"Content-Type": "application/json"},
        )
        elapsed = time.monotonic() - start

        if resp is None:
            return None

        # if a deeply nested query takes significantly longer, the server
        # lacks query depth limiting
        if elapsed > 3.0 and resp.status_code == 200:
            return ScanResult(
                module=self.module_name,
                severity="medium",
                title=f"GraphQL nested query DoS at {url}",
                description=(
                    f"A deeply nested query (depth {depth}) took {elapsed:.1f}s to process. "
                    f"The server may lack query depth or complexity limits, making it "
                    f"vulnerable to denial-of-service attacks."
                ),
                evidence=f"Nested query response time: {elapsed:.1f}s",
                request_data=f"Query depth: {depth}",
                response_data=self._format_response(resp),
            )

        # also check if the server rejected the query (good behavior)
        try:
            data = resp.json()
            errors = data.get("errors", [])
            if errors:
                # server has depth protection — not vulnerable
                return None
        except Exception:
            pass

        return None
