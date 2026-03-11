"""soft-404 detection via baseline calibration.

SPAs and custom error pages often return 200 OK for every route. This module
detects those "soft-404" responses by requesting a few random non-existent
paths before scanning and building a fingerprint of the catch-all response.
"""

from __future__ import annotations

import hashlib
import logging
import uuid

import httpx

logger = logging.getLogger("parascan.soft404")

_NUM_PROBES = 3
_LENGTH_TOLERANCE = 0.05


def _body_hash(text: str) -> str:
    """sha-256 of whitespace-stripped body for stable comparison."""
    return hashlib.sha256(text.strip().encode()).hexdigest()


class Soft404Detector:
    """detects soft-404 / SPA catch-all responses via baseline calibration."""

    def __init__(self) -> None:
        self._calibrated = False
        self._baselines: list[tuple[int, int, str]] = []  # (status, length, hash)
        self.filtered_count = 0

    async def calibrate(self, client: httpx.AsyncClient, base_url: str) -> None:
        """request random non-existent paths and record the response profile."""
        base = base_url.rstrip("/")
        responses: list[httpx.Response] = []

        for _ in range(_NUM_PROBES):
            probe_path = f"{base}/{uuid.uuid4().hex}-parascan-probe"
            try:
                resp = await client.get(probe_path, follow_redirects=True)
                responses.append(resp)
            except Exception as exc:
                logger.debug("soft-404 probe failed: %s", exc)

        if not responses:
            logger.warning("soft-404 calibration failed — no successful probes")
            return

        for resp in responses:
            body = resp.text
            self._baselines.append((resp.status_code, len(body), _body_hash(body)))

        self._calibrated = True
        statuses = {b[0] for b in self._baselines}
        lengths = [b[1] for b in self._baselines]
        logger.info(
            "soft-404 calibrated: status=%s, body lengths=%s",
            statuses, lengths,
        )

    @property
    def summary(self) -> str:
        """human-readable description of the calibration result."""
        if not self._calibrated:
            return ""
        statuses = sorted({b[0] for b in self._baselines})
        avg_len = int(sum(b[1] for b in self._baselines) / len(self._baselines))
        return (
            f"Target returns HTTP {'/'.join(str(s) for s in statuses)} "
            f"with ~{avg_len} bytes for non-existent paths (SPA or custom error page detected). "
            f"Response fingerprinting was used to filter false positives."
        )

    def is_soft_404(self, resp: httpx.Response) -> bool:
        """return True if the response looks like a soft-404 catch-all page."""
        if not self._calibrated:
            return False

        body = resp.text
        resp_hash = _body_hash(body)
        resp_len = len(body)

        for status, base_len, base_hash in self._baselines:
            if resp.status_code != status:
                continue

            # exact content match — definite soft-404
            if resp_hash == base_hash:
                self.filtered_count += 1
                return True

            # length within tolerance — likely the same SPA shell with minor variance
            if base_len > 0:
                ratio = abs(resp_len - base_len) / base_len
                if ratio <= _LENGTH_TOLERANCE:
                    self.filtered_count += 1
                    return True

        return False
