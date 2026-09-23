"""Authentication-ready API key check and a small in-memory rate limiter."""

import hmac
import time
from collections import defaultdict

from fastapi import Header, HTTPException, Request, status

from app.core.config import get_settings


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    expected = get_settings().api_key
    if expected is None or not expected.get_secret_value():
        return  # auth disabled (local development default)
    if not x_api_key or not hmac.compare_digest(x_api_key, expected.get_secret_value()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing X-API-Key")


class RateLimiter:
    """Fixed one-minute window per client IP.

    ponytail: in-process only; behind multiple workers use a shared store (Redis) or the reverse proxy.
    """

    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._hits: dict[tuple[str, int], int] = defaultdict(int)

    def check(self, request: Request) -> None:
        if self.per_minute <= 0:
            return
        window = int(time.time() // 60)
        key = (request.client.host if request.client else "unknown", window)
        self._hits[key] += 1
        if len(self._hits) > 10000:  # drop old windows
            for k in [k for k in self._hits if k[1] < window]:
                del self._hits[k]
        if self._hits[key] > self.per_minute:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limit exceeded")
