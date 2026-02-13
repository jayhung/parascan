"""target config loading from YAML files and CLI flags."""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field
from typing import Any

import yaml


@dataclass
class AuthConfig:
    bearer: str | None = None
    cookie: str | None = None
    api_key_header: str | None = None
    api_key_value: str | None = None
    basic_username: str | None = None
    basic_password: str | None = None


@dataclass
class ScopeConfig:
    allowed_domains: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=lambda: ["/logout"])


@dataclass
class ScanConfig:
    modules: list[str] = field(default_factory=list)
    exclude_modules: list[str] = field(default_factory=list)
    concurrency: int = 10
    rate_limit: int = 10


@dataclass
class ProxyConfig:
    url: str | None = None


@dataclass
class OutputConfig:
    format: str = "json"
    directory: str | None = None


@dataclass
class TargetConfig:
    """complete configuration for a scan target."""

    url: str
    openapi: str | None = None
    auth: AuthConfig = field(default_factory=AuthConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    output: OutputConfig = field(default_factory=OutputConfig)

    def __post_init__(self) -> None:
        # auto-add target domain to scope
        from urllib.parse import urlparse

        parsed = urlparse(self.url)
        if parsed.hostname and parsed.hostname not in self.scope.allowed_domains:
            self.scope.allowed_domains.append(parsed.hostname)


def load_config(path: str | pathlib.Path) -> TargetConfig:
    """load a target config from a YAML file."""
    with open(path) as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}

    target_data = raw.get("target", {})
    url = target_data.get("url", "")
    openapi = target_data.get("openapi")

    auth_data = raw.get("auth", {})
    auth = AuthConfig(
        bearer=auth_data.get("bearer"),
        cookie=auth_data.get("cookie"),
        api_key_header=auth_data.get("api_key", {}).get("header") if auth_data.get("api_key") else None,
        api_key_value=auth_data.get("api_key", {}).get("value") if auth_data.get("api_key") else None,
        basic_username=auth_data.get("basic", {}).get("username") if auth_data.get("basic") else None,
        basic_password=auth_data.get("basic", {}).get("password") if auth_data.get("basic") else None,
    )

    scope_data = raw.get("scope", {})
    scope = ScopeConfig(
        allowed_domains=scope_data.get("allowed_domains", []),
        allowed_paths=scope_data.get("allowed_paths", []),
        excluded_paths=scope_data.get("excluded_paths", ["/logout"]),
    )

    scan_data = raw.get("scan", {})
    scan = ScanConfig(
        modules=scan_data.get("modules", []),
        exclude_modules=scan_data.get("exclude_modules", []),
        concurrency=scan_data.get("concurrency", 10),
        rate_limit=scan_data.get("rate_limit", 10),
    )

    proxy_data = raw.get("proxy", {})
    proxy = ProxyConfig(url=proxy_data.get("url"))

    output_data = raw.get("output", {})
    output = OutputConfig(
        format=output_data.get("format", "json"),
        directory=output_data.get("directory"),
    )

    return TargetConfig(
        url=url,
        openapi=openapi,
        auth=auth,
        scope=scope,
        scan=scan,
        proxy=proxy,
        output=output,
    )


def build_config_from_cli(
    url: str,
    bearer: str | None = None,
    cookie: str | None = None,
    api_key: str | None = None,
    basic_auth: str | None = None,
    modules: str | None = None,
    exclude_modules: str | None = None,
    concurrency: int = 10,
    rate_limit: int = 10,
    proxy: str | None = None,
    openapi: str | None = None,
) -> TargetConfig:
    """build a TargetConfig from CLI flags with sensible defaults."""
    api_key_header = None
    api_key_value = None
    if api_key:
        parts = api_key.split(":", 1)
        if len(parts) == 2:
            api_key_header = parts[0].strip()
            api_key_value = parts[1].strip()

    basic_username = None
    basic_password = None
    if basic_auth:
        parts = basic_auth.split(":", 1)
        if len(parts) == 2:
            basic_username = parts[0]
            basic_password = parts[1]

    auth = AuthConfig(
        bearer=bearer,
        cookie=cookie,
        api_key_header=api_key_header,
        api_key_value=api_key_value,
        basic_username=basic_username,
        basic_password=basic_password,
    )

    module_list = [m.strip() for m in modules.split(",")] if modules else []
    exclude_list = [m.strip() for m in exclude_modules.split(",")] if exclude_modules else []

    return TargetConfig(
        url=url,
        openapi=openapi,
        auth=auth,
        scope=ScopeConfig(),
        scan=ScanConfig(
            modules=module_list,
            exclude_modules=exclude_list,
            concurrency=concurrency,
            rate_limit=rate_limit,
        ),
        proxy=ProxyConfig(url=proxy),
        output=OutputConfig(),
    )
