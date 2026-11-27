"""Same-origin crawler: broken links, mixed content, robots.txt awareness."""

from __future__ import annotations

import urllib.parse
import urllib.robotparser
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser

from .fetch import Fetcher, Response

# (tag, attribute) pairs that reference other URLs.
LINK_ATTRS = {
    ("a", "href"), ("area", "href"), ("link", "href"), ("img", "src"),
    ("script", "src"), ("iframe", "src"), ("frame", "src"), ("source", "src"),
    ("video", "src"), ("audio", "src"), ("track", "src"), ("embed", "src"),
    ("object", "data"), ("form", "action"), ("img", "srcset"), ("source", "srcset"),
    ("video", "poster"),
}

# Which references count as active mixed content (browser blocks them).
ACTIVE_TAGS = {"script", "iframe", "frame", "object", "embed", "link"}
PASSIVE_TAGS = {"img", "video", "audio", "source", "track"}
NAVIGATION_TAGS = {"a", "area"}


@dataclass
class Link:
    tag: str
    attr: str
    url: str          # absolute, fragment stripped
    rel: str = ""


class LinkParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: list[Link] = []

    def handle_starttag(self, tag, attrs):
        attrs_d = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and attrs_d.get("href"):
            self.base_url = urllib.parse.urljoin(self.base_url, attrs_d["href"].strip())
            return
        for attr, value in attrs_d.items():
            if (tag, attr) not in LINK_ATTRS or not value.strip():
                continue
            candidates = [value]
            if attr == "srcset":
                candidates = [part.strip().split()[0] for part in value.split(",") if part.strip()]
            for raw in candidates:
                absolute = resolve(self.base_url, raw)
                if absolute:
                    self.links.append(Link(tag, attr, absolute, attrs_d.get("rel", "").lower()))

    handle_startendtag = handle_starttag


def resolve(base: str, raw: str) -> str | None:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    try:
        absolute = urllib.parse.urljoin(base, raw)
    except ValueError:
        return None
    absolute, _ = urllib.parse.urldefrag(absolute)
    scheme = urllib.parse.urlsplit(absolute).scheme.lower()
    if scheme not in ("http", "https"):
        return None
    return normalize(absolute)


def normalize(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    path = parts.path or "/"
    return urllib.parse.urlunsplit((scheme, netloc, path, parts.query, ""))


def origin(url: str) -> tuple[str, str, int]:
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return scheme, (parts.hostname or "").lower(), port


def same_origin(a: str, b: str) -> bool:
    return origin(a) == origin(b)


def extract_links(page_url: str, html: str) -> list[Link]:
    parser = LinkParser(page_url)
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass
    return parser.links


def find_mixed_content(page_url: str, links: list[Link]) -> list[dict]:
    """Insecure http:// references on an https:// page."""
    if urllib.parse.urlsplit(page_url).scheme.lower() != "https":
        return []
    found = []
    seen = set()
    for link in links:
        if urllib.parse.urlsplit(link.url).scheme != "http":
            continue
        if link.tag in NAVIGATION_TAGS:
            continue
        if link.tag == "link" and "stylesheet" not in link.rel and "preload" not in link.rel \
                and "icon" not in link.rel and "manifest" not in link.rel:
            continue
        if link.tag == "form":
            kind = "insecure-form"
        elif link.tag in ACTIVE_TAGS:
            kind = "active"
        else:
            kind = "passive"
        key = (link.tag, link.url)
        if key in seen:
            continue
        seen.add(key)
        found.append({"page": page_url, "resource": link.url, "tag": link.tag, "kind": kind})
    return found


@dataclass
class CrawlResult:
    start_url: str
    pages: list[dict] = field(default_factory=list)
    broken: list[dict] = field(default_factory=list)
    mixed: list[dict] = field(default_factory=list)
    robots_skipped: list[str] = field(default_factory=list)
    external_checked: int = 0


class Crawler:
    def __init__(self, start_url: str, fetcher: Fetcher, max_depth: int = 2,
                 max_pages: int = 200, respect_robots: bool = True,
                 check_external: bool = False):
        self.start_url = normalize(start_url)
        self.fetcher = fetcher
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        self.check_external = check_external
        self.robots: urllib.robotparser.RobotFileParser | None = None

    def load_robots(self) -> None:
        scheme, host, _ = origin(self.start_url)
        netloc = urllib.parse.urlsplit(self.start_url).netloc
        robots_url = f"{scheme}://{netloc}/robots.txt"
        rp = urllib.robotparser.RobotFileParser(robots_url)
        resp = self.fetcher.get(robots_url)
        if resp.status in (401, 403):
            rp.disallow_all = True
        elif resp.ok:
            rp.parse(resp.text().splitlines())
            delay = rp.crawl_delay(self.fetcher.user_agent)
            if delay and float(delay) > self.fetcher.limiter.delay:
                self.fetcher.limiter.delay = float(delay)
        else:
            rp.allow_all = True
        self.robots = rp

    def allowed(self, url: str) -> bool:
        if not self.respect_robots or self.robots is None:
            return True
        return self.robots.can_fetch(self.fetcher.user_agent, url)

    def run(self) -> CrawlResult:
        result = CrawlResult(self.start_url)
        if self.respect_robots:
            self.load_robots()

        referrers: dict[str, set[str]] = {}
        queue: deque[tuple[str, int, bool]] = deque([(self.start_url, 0, True)])
        queued = {self.start_url}
        external: set[str] = set()
        fetched = 0

        while queue and fetched < self.max_pages:
            url, depth, navigable = queue.popleft()
            if not self.allowed(url):
                result.robots_skipped.append(url)
                continue
            resp = self.fetcher.get(url)
            fetched += 1
            result.pages.append({"url": url, "status": resp.status, "depth": depth,
                                 "error": resp.error})
            if not resp.ok:
                self._record_broken(result, url, resp, referrers.get(url, set()))
                continue
            if not (navigable and resp.is_html):
                continue
            final_url = normalize(resp.url)
            if not same_origin(final_url, self.start_url):
                continue
            links = extract_links(final_url, resp.text())
            result.mixed.extend(find_mixed_content(final_url, links))
            for link in links:
                if same_origin(link.url, self.start_url):
                    referrers.setdefault(link.url, set()).add(final_url)
                    if link.url in queued:
                        continue
                    is_nav = link.tag in NAVIGATION_TAGS or link.tag in ("iframe", "frame")
                    if is_nav and depth + 1 > self.max_depth:
                        continue
                    queued.add(link.url)
                    queue.append((link.url, depth + 1, is_nav))
                elif self.check_external and link.tag != "form":
                    referrers.setdefault(link.url, set()).add(final_url)
                    external.add(link.url)

        if self.check_external:
            for url in sorted(external):
                resp = self.fetcher.get(url)
                result.external_checked += 1
                if not resp.ok:
                    self._record_broken(result, url, resp, referrers.get(url, set()), external=True)
        return result

    @staticmethod
    def _record_broken(result: CrawlResult, url: str, resp: Response,
                       refs: set[str], external: bool = False) -> None:
        result.broken.append({
            "url": url,
            "status": resp.status,
            "error": resp.error,
            "external": external,
            "referrers": sorted(refs),
        })
