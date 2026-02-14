"""GraphQL injection scanner — tests for query injection and variable manipulation."""

from __future__ import annotations

import json
from typing import Any

import httpx

from parascan.scanners.base import BaseScanner, ScanResult


REMEDIATION = (
    "Validate and sanitize all GraphQL variables server-side. Use parameterized "
    "resolvers that never concatenate user input into database queries. Apply "
    "input validation on variable types. Use an ORM or query builder for all "
    "database access within resolvers."
)

SOC2 = "CC6.8"


class GraphQLInjectionScanner(BaseScanner):
    module_name = "graphql-injection"
    description = "GraphQL query injection and variable manipulation"

    INJECTION_PAYLOADS = [
        # field injection
        '{ __typename }',
        # union injection
        '{ __typename ... on Query { __schema { types { name } } } }',
        # sql injection via variables
        {"query": "query($id: String!) { user(id: $id) { name } }",
         "variables": {"id": "' OR '1'='1"}},
        # nosql injection via variables
        {"query": "query($id: String!) { user(id: $id) { name } }",
         "variables": {"id": '{"$ne": null}'}},
    ]

    ERROR_SIGNATURES = [
        "SQL syntax",
        "mysql",
        "postgresql",
        "ORA-",
        "sqlite",
        "SQLSTATE",
        "MongoError",
        "Cannot query field",
    ]

    async def scan(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any]
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        url = endpoint["url"]
        params = endpoint.get("params", {})

        # only test GraphQL endpoints
        if not params.get("_graphql") and not url.endswith("/graphql"):
            return results

        target_url = url

        for payload in self.INJECTION_PAYLOADS:
            if isinstance(payload, str):
                body = json.dumps({"query": payload})
            else:
                body = json.dumps(payload)

            resp = await self._request(
                client, "POST", target_url,
                content=body,
                headers={"Content-Type": "application/json"},
            )

            if resp is None:
                continue

            response_text = resp.text.lower()

            # check for error signatures indicating injection
            for sig in self.ERROR_SIGNATURES:
                if sig.lower() in response_text:
                    severity = "high" if "SQL" in sig or "ORA" in sig else "medium"
                    results.append(ScanResult(
                        module=self.module_name,
                        severity=severity,
                        title=f"GraphQL injection at {target_url}",
                        description=(
                            f"The GraphQL endpoint may be vulnerable to injection. "
                            f"A test payload triggered an error containing '{sig}'."
                        ),
                        evidence=f"Error signature: {sig}",
                        request_data=body[:500],
                        response_data=self._format_response(resp),
                        remediation=REMEDIATION,
                        soc2_criteria=SOC2,
                    ))
                    return results  # one finding is enough

        return results
