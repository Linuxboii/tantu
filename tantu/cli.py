"""Command line interface for tantu."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse

from . import __version__
from .crawler import Crawler, CrawlResult
from .fetch import Fetcher
from .probes import PROBES, ProbeFinding, run_probes

NOTICE = "Use only on sites you own or are explicitly authorized to test."


class Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def red(self, t): return self._wrap("31", t)
    def yellow(self, t): return self._wrap("33", t)
    def green(self, t): return self._wrap("32", t)
    def dim(self, t): return self._wrap("2", t)
    def bold(self, t): return self._wrap("1", t)

    def severity(self, sev: str) -> str:
        label = sev.upper().ljust(6)
        return {"high": self.red, "medium": self.yellow}.get(sev, self.dim)(label)


def table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(strip_ansi(cell)))
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip(),
             "  ".join("-" * w for w in widths)]
    for row in rows:
        lines.append("  ".join(cell + " " * (widths[i] - len(strip_ansi(cell)))
                               for i, cell in enumerate(row)).rstrip())
    return "\n".join(lines)


def strip_ansi(s: str) -> str:
    import re
    return re.sub(r"\033\[[0-9;]*m", "", s)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tantu",
        description="Audit your own website for broken links, mixed content and "
                    "exposed sensitive files. " + NOTICE)
    p.add_argument("url", help="start URL, e.g. https://example.com/")
    p.add_argument("--depth", type=int, default=2, help="link depth to crawl (default 2)")
    p.add_argument("--max-pages", type=int, default=200, help="max requests during crawl (default 200)")
    p.add_argument("--delay", type=float, default=0.5,
                   help="seconds between requests (default 0.5; robots Crawl-delay wins if larger)")
    p.add_argument("--timeout", type=float, default=10.0, help="request timeout seconds")
    p.add_argument("--ignore-robots", action="store_true", help="do not honour robots.txt while crawling")
    p.add_argument("--check-external", action="store_true", help="also check off-site links for errors")
    p.add_argument("--no-crawl", action="store_true", help="skip the crawl, only run probes")
    p.add_argument("--no-probes", action="store_true", help="skip sensitive-path probes")
    p.add_argument("--json", action="store_true", help="emit JSON report")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    p.add_argument("--version", action="version", version=f"tantu {__version__}")
    return p


def render_text(args, crawl: CrawlResult | None, findings: list[ProbeFinding],
                soft404: bool, requests: int, style: Style) -> str:
    out = [style.bold(f"tantu {__version__}") + f"  target: {args.url}",
           style.dim(NOTICE), ""]
    if crawl is not None:
        out.append(style.bold("Crawl"))
        out.append(f"  pages fetched: {len(crawl.pages)}   robots-skipped: "
                   f"{len(crawl.robots_skipped)}   external checked: {crawl.external_checked}")
        out.append("")
        out.append(style.bold(f"Broken links ({len(crawl.broken)})"))
        if crawl.broken:
            rows = []
            for b in crawl.broken:
                status = str(b["status"]) if b["status"] else "ERR"
                ref = b["referrers"][0] if b["referrers"] else "-"
                if len(b["referrers"]) > 1:
                    ref += f" (+{len(b['referrers']) - 1})"
                rows.append([style.red(status), b["url"], ref])
            out.append(indent(table(rows, ["STATUS", "URL", "FOUND ON"])))
        else:
            out.append("  " + style.green("none"))
        out.append("")
        out.append(style.bold(f"Mixed content ({len(crawl.mixed)})"))
        if crawl.mixed:
            rows = [[style.red(m["kind"]) if m["kind"] == "active" else style.yellow(m["kind"]),
                     m["tag"], m["resource"], m["page"]] for m in crawl.mixed]
            out.append(indent(table(rows, ["KIND", "TAG", "RESOURCE", "PAGE"])))
        else:
            out.append("  " + style.green("none"))
        if crawl.robots_skipped:
            out.append("")
            out.append(style.dim("Skipped by robots.txt: " + ", ".join(crawl.robots_skipped[:10])
                                 + (" ..." if len(crawl.robots_skipped) > 10 else "")))
        out.append("")
    if not args.no_probes:
        title = f"Exposed paths ({len(findings)} of {len(PROBES)} probes hit)"
        out.append(style.bold(title))
        if soft404:
            out.append(style.dim("  server answers 200 for unknown paths; content checks applied"))
        if findings:
            rows = [[style.severity(f.severity), f.path, f.name, str(f.size)] for f in findings]
            out.append(indent(table(rows, ["SEV", "PATH", "WHAT", "BYTES"])))
            out.append("")
            out.append(style.bold("Remediation"))
            for f in findings:
                out.append(f"  {f.path}: {f.remediation}")
        else:
            out.append("  " + style.green("none"))
        out.append("")
    out.append(style.dim(f"{requests} requests made"))
    return "\n".join(out)


def indent(text: str, n: int = 2) -> str:
    return "\n".join(" " * n + line for line in text.splitlines())


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    parts = urllib.parse.urlsplit(args.url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        print("error: URL must start with http:// or https://", file=sys.stderr)
        return 2
    if not parts.path:
        args.url = args.url + "/"
    use_color = (not args.no_color and not args.json and sys.stdout.isatty()
                 and os.environ.get("NO_COLOR") is None)
    style = Style(use_color)
    fetcher = Fetcher(delay=args.delay, timeout=args.timeout)

    crawl = None
    if not args.no_crawl:
        crawler = Crawler(args.url, fetcher, max_depth=args.depth, max_pages=args.max_pages,
                          respect_robots=not args.ignore_robots,
                          check_external=args.check_external)
        crawl = crawler.run()
        if crawl.pages and crawl.pages[0]["status"] is None:
            print(f"error: could not reach {args.url}: {crawl.pages[0]['error']}", file=sys.stderr)
            return 2

    findings, soft404 = ([], False)
    if not args.no_probes:
        findings, soft404 = run_probes(args.url, fetcher)

    if args.json:
        report = {
            "target": args.url,
            "version": __version__,
            "requests": fetcher.requests,
            "crawl": None if crawl is None else {
                "pages": crawl.pages,
                "broken": crawl.broken,
                "mixed_content": crawl.mixed,
                "robots_skipped": crawl.robots_skipped,
                "external_checked": crawl.external_checked,
            },
            "probes": None if args.no_probes else {
                "soft404": soft404,
                "findings": [f.to_dict() for f in findings],
            },
        }
        print(json.dumps(report, indent=2))
    else:
        print(render_text(args, crawl, findings, soft404, fetcher.requests, style))

    issues = len(findings) + (len(crawl.broken) + len(crawl.mixed) if crawl else 0)
    return 1 if issues else 0
