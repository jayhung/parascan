"""OpenAPI/Swagger spec parser for endpoint discovery."""

from __future__ import annotations

import json
import pathlib
from typing import Any
from urllib.parse import urljoin

import yaml


def parse_openapi_spec(spec_path: str, base_url: str) -> list[dict[str, Any]]:
    """
    Parse an OpenAPI spec file and return a list of endpoint dicts.

    Supports both JSON and YAML spec files.
    """
    path = pathlib.Path(spec_path)
    if not path.exists():
        return []

    with open(path) as f:
        if path.suffix in (".yaml", ".yml"):
            spec = yaml.safe_load(f)
        else:
            spec = json.load(f)

    if not spec:
        return []

    endpoints: list[dict[str, Any]] = []

    # determine base path from spec
    spec_base = _get_base_path(spec, base_url)

    paths = spec.get("paths", {})
    for path_str, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method, operation in methods.items():
            method = method.upper()
            if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                continue

            url = urljoin(spec_base, path_str.lstrip("/"))

            # extract parameters
            params: dict[str, str] = {}
            parameters = operation.get("parameters", [])
            if isinstance(methods.get("parameters"), list):
                parameters = methods["parameters"] + parameters

            for param in parameters:
                if not isinstance(param, dict):
                    continue
                name = param.get("name", "")
                location = param.get("in", "query")
                if location == "query" and name:
                    params[name] = param.get("schema", {}).get("example", "test")
                elif location == "path" and name:
                    # replace path parameter placeholder
                    example = str(param.get("schema", {}).get("example", "1"))
                    url = url.replace(f"{{{name}}}", example)

            # extract request body params for POST/PUT/PATCH
            if method in ("POST", "PUT", "PATCH"):
                body_params = _extract_body_params(operation)
                params.update(body_params)

            endpoints.append({
                "url": url,
                "method": method,
                "params": params,
            })

    return endpoints


def _get_base_path(spec: dict, base_url: str) -> str:
    """determine the base URL from the spec or fall back to provided base_url."""
    # openapi 3.x
    servers = spec.get("servers", [])
    if servers and isinstance(servers[0], dict):
        server_url = servers[0].get("url", "")
        if server_url.startswith("http"):
            return server_url.rstrip("/") + "/"
        return urljoin(base_url, server_url.lstrip("/")).rstrip("/") + "/"

    # swagger 2.x
    host = spec.get("host", "")
    base_path = spec.get("basePath", "/")
    if host:
        scheme = "https"
        schemes = spec.get("schemes", [])
        if schemes:
            scheme = schemes[0]
        return f"{scheme}://{host}{base_path}".rstrip("/") + "/"

    return base_url.rstrip("/") + "/"


def _extract_body_params(operation: dict) -> dict[str, str]:
    """extract request body parameters from an operation."""
    params: dict[str, str] = {}

    # openapi 3.x request body
    request_body = operation.get("requestBody", {})
    content = request_body.get("content", {})
    for media_type, media_data in content.items():
        schema = media_data.get("schema", {})
        props = schema.get("properties", {})
        for name, prop in props.items():
            params[name] = str(prop.get("example", "test"))

    # swagger 2.x body parameter
    for param in operation.get("parameters", []):
        if isinstance(param, dict) and param.get("in") == "body":
            schema = param.get("schema", {})
            props = schema.get("properties", {})
            for name, prop in props.items():
                params[name] = str(prop.get("example", "test"))

    return params
