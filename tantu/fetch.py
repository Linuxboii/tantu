"""Minimal HTTP fetching with rate limiting, built on urllib."""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from . import __version__

USER_AGENT = f"tantu/{__version__} (self-audit)"


@dataclass
class Response:
    url: str
    status: int | None
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def is_html(self) -> bool:
        if self.content_type in ("text/html", "application/xhtml+xml"):
            return True
        if not self.content_type:
            head = self.body[:512].lstrip().lower()
            return head.startswith(b"<!doctype html") or head.startswith(b"<html")
        return False

    def text(self) -> str:
        charset = "utf-8"
        ctype = self.headers.get("content-type", "")
        if "charset=" in ctype:
            charset = ctype.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


class RateLimiter:
    """Enforces a minimum delay between consecutive requests."""

    def __init__(self, delay: float):
        self.delay = max(0.0, delay)
        self._last = 0.0

    def wait(self) -> None:
        if self.delay > 0:
            gap = self._last + self.delay - time.monotonic()
            if gap > 0:
                time.sleep(gap)
        self._last = time.monotonic()


class Fetcher:
    def __init__(self, delay: float = 0.5, timeout: float = 10.0,
                 max_bytes: int = 2_000_000, user_agent: str = USER_AGENT):
        self.limiter = RateLimiter(delay)
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.user_agent = user_agent
        self.requests = 0

    def get(self, url: str) -> Response:
        self.limiter.wait()
        self.requests += 1
        req = urllib.request.Request(url, headers={
            "User-Agent": self.user_agent,
            "Accept": "*/*",
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(self.max_bytes)
                headers = {k.lower(): v for k, v in r.headers.items()}
                return Response(r.geturl(), r.status, headers, body)
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in (e.headers or {}).items()}
            try:
                body = e.read(self.max_bytes)
            except Exception:
                body = b""
            return Response(url, e.code, headers, body)
        except urllib.error.URLError as e:
            return Response(url, None, error=str(e.reason))
        except (OSError, ValueError) as e:
            return Response(url, None, error=str(e) or e.__class__.__name__)
