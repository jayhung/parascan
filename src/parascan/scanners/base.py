"""base scanner class — all vulnerability scanners inherit from this."""

from __future__ import annotations

import pathlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx
import yaml


@dataclass
class ScanResult:
    """a single vulnerability finding from a scanner."""

    module: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    evidence: str | None = None
    request_data: str | None = None
    response_data: str | None = None


class BaseScanner(ABC):
    """abstract base class for all vulnerability scanners."""

    # subclasses must set these
    module_name: str = ""
    description: str = ""

    def __init__(self) -> None:
        self._payloads: list[str] = []

    def load_payloads(self, filename: str) -> list[str]:
        """load payloads from a YAML file in the payloads directory."""
        payload_dir = pathlib.Path(__file__).parent.parent / "payloads"
        path = payload_dir / filename
        if not path.exists():
            return []
        with open(path) as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            # flatten all values from the yaml
            payloads = []
            for v in data.values():
                if isinstance(v, list):
                    payloads.extend(str(p) for p in v)
                else:
                    payloads.append(str(v))
            return payloads
        if isinstance(data, list):
            return [str(p) for p in data]
        return []

    @abstractmethod
    async def scan(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any]
    ) -> list[ScanResult]:
        """
        Run the scanner against a single endpoint.

        Args:
            client: configured httpx async client with auth/proxy applied
            endpoint: dict with 'url', 'method', and 'params' keys

        Returns:
            list of ScanResult findings (empty if no vulnerabilities found)
        """
        ...

    async def _request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response | None:
        """make an HTTP request with error handling."""
        try:
            resp = await client.request(method, url, **kwargs)
            return resp
        except Exception:
            return None

    def _format_request(self, method: str, url: str, **kwargs: Any) -> str:
        """format a request as a string for evidence."""
        lines = [f"{method} {url}"]
        if "headers" in kwargs:
            for k, v in kwargs["headers"].items():
                lines.append(f"{k}: {v}")
        if "params" in kwargs:
            lines.append(f"Params: {kwargs['params']}")
        if "data" in kwargs:
            lines.append(f"Body: {kwargs['data']}")
        if "json" in kwargs:
            lines.append(f"JSON: {kwargs['json']}")
        return "\n".join(lines)

    def _format_response(self, resp: httpx.Response, max_body: int = 1000) -> str:
        """format a response as a string for evidence."""
        lines = [f"HTTP {resp.status_code}"]
        for k, v in resp.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        body = resp.text[:max_body]
        if len(resp.text) > max_body:
            body += f"\n... (truncated, {len(resp.text)} bytes total)"
        lines.append(body)
        return "\n".join(lines)
