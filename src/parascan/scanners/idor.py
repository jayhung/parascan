"""IDOR scanner — detects insecure direct object reference vulnerabilities."""

from __future__ import annotations

from typing import Any

import httpx

from parascan.scanners.base import BaseScanner, ScanResult


REMEDIATION = (
    "Implement server-side authorization checks on every request. Verify that "
    "the authenticated user has permission to access the requested resource. "
    "Use indirect references (e.g., UUIDs or mapped IDs) instead of sequential "
    "database IDs. Apply the principle of least privilege to API endpoints."
)

SOC2 = "CC6.1"


class IDORScanner(BaseScanner):
    module_name = "idor"
    description = "Insecure direct object reference detection"

    # parameter names that commonly hold object identifiers
    ID_PARAMS = {
        "id", "user_id", "userId", "uid", "account_id", "accountId",
        "order_id", "orderId", "doc_id", "docId", "file_id", "fileId",
        "record_id", "recordId", "item_id", "itemId", "pid", "profile_id",
    }

    async def scan(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any]
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        url = endpoint["url"]
        method = endpoint.get("method", "GET")
        params = endpoint.get("params", {})

        if not params:
            return results

        # find parameters that look like object IDs
        id_params = [
            (name, value)
            for name, value in params.items()
            if name.lower() in self.ID_PARAMS or self._looks_like_id(str(value))
        ]

        if not id_params:
            return results

        # get the original response
        if method == "GET":
            original_resp = await self._request(client, method, url, params=params)
        else:
            original_resp = await self._request(client, method, url, data=params)

        if original_resp is None:
            return results

        # try adjacent IDs
        for param_name, original_value in id_params:
            test_values = self._generate_test_ids(str(original_value))

            for test_value in test_values:
                injected = {**params, param_name: test_value}

                if method == "GET":
                    resp = await self._request(client, method, url, params=injected)
                else:
                    resp = await self._request(client, method, url, data=injected)

                if resp is None:
                    continue

                # if we get a 200 with different content, possible IDOR
                if resp.status_code == 200 and original_resp.status_code == 200:
                    if (
                        resp.text != original_resp.text
                        and len(resp.text) > 50  # not an empty/error page
                        and abs(len(resp.text) - len(original_resp.text)) < len(original_resp.text)
                    ):
                        results.append(ScanResult(
                            module=self.module_name,
                            severity="high",
                            title=f"Potential IDOR in parameter '{param_name}'",
                            description=(
                                f"Changing '{param_name}' from '{original_value}' to "
                                f"'{test_value}' returned different content with HTTP 200. "
                                f"This may indicate access to another user's data."
                            ),
                            evidence=(
                                f"Original ID: {original_value} ({len(original_resp.text)}B), "
                                f"Test ID: {test_value} ({len(resp.text)}B)"
                            ),
                            request_data=self._format_request(method, url, params=injected),
                            response_data=self._format_response(resp),
                            remediation=REMEDIATION,
                            soc2_criteria=SOC2,
                        ))
                        break  # one finding per parameter

        return results

    def _looks_like_id(self, value: str) -> bool:
        """check if a value looks like a numeric or UUID-style identifier."""
        if value.isdigit():
            return True
        # UUID pattern
        if len(value) == 36 and value.count("-") == 4:
            return True
        return False

    def _generate_test_ids(self, original: str) -> list[str]:
        """generate test IDs adjacent to the original."""
        if original.isdigit():
            num = int(original)
            return [str(num + 1), str(num - 1), str(num + 100), "0", "1"]
        # for non-numeric, try common test values
        return ["1", "2", "0", "admin", "test"]
