"""directory traversal scanner — detects path traversal vulnerabilities."""

from __future__ import annotations

from typing import Any

import httpx
import yaml

from parascan.scanners.base import BaseScanner, ScanResult


REMEDIATION = (
    "Never use user input directly in file system paths. Validate file names against "
    "an allowlist of permitted files. Use os.path.realpath() or Path.resolve() to "
    "canonicalize paths and verify they remain within the expected directory. "
    "Remove or reject inputs containing '../', '..\\', or null bytes."
)

SOC2 = "CC6.8"


class DirectoryTraversalScanner(BaseScanner):
    module_name = "traversal"
    description = "Directory/path traversal detection"

    # parameter names that commonly handle file paths
    FILE_PARAMS = {
        "file", "path", "filepath", "filename", "page", "template",
        "include", "doc", "document", "folder", "dir", "img",
        "image", "load", "read", "download", "attachment",
    }

    def __init__(self) -> None:
        super().__init__()
        self._payloads_data = self._load_payloads()

    def _load_payloads(self) -> dict:
        import pathlib

        path = pathlib.Path(__file__).parent.parent / "payloads" / "traversal.yaml"
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    async def scan(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any]
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        url = endpoint["url"]
        method = endpoint.get("method", "GET")
        params = endpoint.get("params", {})

        if not params:
            return results

        success_sigs = self._payloads_data.get("success_signatures", [])
        unix_payloads = self._payloads_data.get("unix", [])[:6]
        windows_payloads = self._payloads_data.get("windows", [])[:3]
        all_payloads = unix_payloads + windows_payloads

        for param_name in params:
            # prioritize file-related params
            is_file_param = param_name.lower() in self.FILE_PARAMS

            payloads = all_payloads if is_file_param else unix_payloads[:3]

            for payload in payloads:
                injected = {**params, param_name: payload}

                if method == "GET":
                    resp = await self._request(client, method, url, params=injected)
                else:
                    resp = await self._request(client, method, url, data=injected)

                if resp is None:
                    continue

                body = resp.text
                for sig in success_sigs:
                    if sig in body:
                        results.append(ScanResult(
                            module=self.module_name,
                            severity="high",
                            title=f"Directory traversal in parameter '{param_name}'",
                            description=(
                                f"The parameter '{param_name}' is vulnerable to path "
                                f"traversal. The payload '{payload}' returned file contents."
                            ),
                            evidence=f"File content signature: {sig}",
                            request_data=self._format_request(method, url, params=injected),
                            response_data=self._format_response(resp),
                            remediation=REMEDIATION,
                            soc2_criteria=SOC2,
                        ))
                        return results  # critical, stop immediately

        return results
