"""Probes for commonly exposed sensitive files, with content verification.

A probe only reports a finding when the response is 2xx AND the body looks
like the real artifact. This keeps soft-404 pages (servers that answer 200
with an HTML "not found" page) from producing false positives.
"""

from __future__ import annotations

import re
import secrets
import urllib.parse
from dataclasses import dataclass
from typing import Callable

from .fetch import Fetcher, Response


def looks_html(body: bytes) -> bool:
    head = body[:1024].lstrip().lower()
    return head.startswith((b"<!doctype", b"<html", b"<head", b"<body")) or b"<html" in head


def _not_html(check: Callable[[bytes], bool]) -> Callable[[bytes], bool]:
    return lambda body: bool(body) and not looks_html(body) and check(body)


def _count_lines(pattern: bytes, minimum: int) -> Callable[[bytes], bool]:
    rx = re.compile(pattern, re.MULTILINE)
    return lambda body: len(rx.findall(body[:65536])) >= minimum


_git_head = re.compile(rb"\A(ref: refs/[\w./-]+|[0-9a-f]{40})\s*\Z")


@dataclass(frozen=True)
class Probe:
    path: str
    name: str
    severity: str  # high | medium | low
    check: Callable[[bytes], bool]
    remediation: str


PROBES: list[Probe] = [
    Probe("/.git/HEAD", "Git repository HEAD", "high",
          _not_html(lambda b: bool(_git_head.match(b.strip() + b"\n"))),
          "Block /.git/ at the web server and remove the repository from the web root."),
    Probe("/.git/config", "Git repository config", "high",
          _not_html(lambda b: b"[core]" in b and b"repositoryformatversion" in b),
          "Block /.git/ at the web server; the config may reveal remote URLs and credentials."),
    Probe("/.svn/entries", "Subversion metadata", "high",
          _not_html(lambda b: bool(re.match(rb"\A\d+\s*\n", b)) or b"wc-entries" in b),
          "Remove .svn directories from the deployed tree."),
    Probe("/.svn/wc.db", "Subversion working copy DB", "high",
          lambda b: b.startswith(b"SQLite format 3\x00"),
          "Remove .svn directories from the deployed tree."),
    Probe("/.hg/requires", "Mercurial repository", "high",
          _not_html(lambda b: b"revlogv1" in b or b"store" in b and b"fncache" in b),
          "Remove .hg directories from the deployed tree."),
    Probe("/.env", "Environment file", "high",
          _not_html(_count_lines(rb"^\s*(?:export\s+)?[A-Z][A-Z0-9_]*\s*=", 2)),
          "Move .env outside the web root and rotate any secrets it contained."),
    Probe("/.env.production", "Environment file (production)", "high",
          _not_html(_count_lines(rb"^\s*(?:export\s+)?[A-Z][A-Z0-9_]*\s*=", 2)),
          "Move .env files outside the web root and rotate any secrets they contained."),
    Probe("/.DS_Store", "macOS .DS_Store directory index", "medium",
          lambda b: b[:8] == b"\x00\x00\x00\x01Bud1",
          "Delete .DS_Store files and deny dotfiles at the web server."),
    Probe("/backup.zip", "Backup archive (zip)", "high",
          lambda b: b.startswith(b"PK\x03\x04"),
          "Remove backup archives from the web root."),
    Probe("/site.zip", "Site archive (zip)", "high",
          lambda b: b.startswith(b"PK\x03\x04"),
          "Remove backup archives from the web root."),
    Probe("/backup.tar.gz", "Backup archive (tar.gz)", "high",
          lambda b: b.startswith(b"\x1f\x8b"),
          "Remove backup archives from the web root."),
    Probe("/backup.sql", "SQL dump", "high",
          _not_html(lambda b: any(m in b[:65536] for m in
                                  (b"CREATE TABLE", b"INSERT INTO", b"-- MySQL dump",
                                   b"PostgreSQL database dump"))),
          "Remove database dumps from the web root and rotate stored credentials."),
    Probe("/dump.sql", "SQL dump", "high",
          _not_html(lambda b: any(m in b[:65536] for m in
                                  (b"CREATE TABLE", b"INSERT INTO", b"-- MySQL dump",
                                   b"PostgreSQL database dump"))),
          "Remove database dumps from the web root and rotate stored credentials."),
    Probe("/wp-config.php.bak", "WordPress config backup", "high",
          lambda b: b"DB_PASSWORD" in b,
          "Delete editor/backup copies of wp-config.php and rotate the DB password."),
    Probe("/config.php.bak", "PHP config backup", "high",
          lambda b: b"<?php" in b and (b"password" in b.lower() or b"define(" in b),
          "Delete backup copies of PHP source files; they are served as plain text."),
    Probe("/.htpasswd", "htpasswd credential file", "high",
          _not_html(_count_lines(
              rb"^[^:\s#]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|\$[156]\$|[./0-9A-Za-z]{13}\s*$)", 1)),
          "Store htpasswd files outside the web root."),
    Probe("/.aws/credentials", "AWS credentials", "high",
          _not_html(lambda b: b"aws_access_key_id" in b.lower()),
          "Remove the file and rotate the AWS keys immediately."),
    Probe("/id_rsa", "SSH private key", "high",
          lambda b: b"-----BEGIN" in b and b"PRIVATE KEY-----" in b,
          "Remove the key and revoke it everywhere it is authorized."),
    Probe("/.npmrc", "npm config with auth token", "high",
          _not_html(lambda b: b"_authToken" in b or b"_auth=" in b),
          "Remove .npmrc from the web root and revoke the token."),
    Probe("/.vscode/sftp.json", "Editor SFTP config", "high",
          _not_html(lambda b: b'"host"' in b and (b'"password"' in b or b'"privateKeyPath"' in b)),
          "Remove editor config folders from deployments."),
    Probe("/phpinfo.php", "phpinfo() page", "medium",
          lambda b: b"phpinfo()" in b and b"PHP Version" in b,
          "Delete phpinfo pages; they disclose versions, paths and environment."),
    Probe("/info.php", "phpinfo() page", "medium",
          lambda b: b"phpinfo()" in b and b"PHP Version" in b,
          "Delete phpinfo pages; they disclose versions, paths and environment."),
    Probe("/server-status", "Apache mod_status", "medium",
          lambda b: b"Apache Server Status" in b,
          "Restrict mod_status to localhost (Require local)."),
    Probe("/server-info", "Apache mod_info", "medium",
          lambda b: b"Apache Server Information" in b,
          "Disable mod_info or restrict it to localhost."),
    Probe("/nginx_status", "nginx stub_status", "low",
          _not_html(lambda b: b"Active connections:" in b),
          "Restrict stub_status with allow/deny rules."),
    Probe("/web.config", "IIS web.config", "medium",
          lambda b: b"<configuration" in b,
          "Ensure web.config is never served as static content."),
    Probe("/docker-compose.yml", "docker-compose file", "low",
          _not_html(lambda b: b"services:" in b),
          "Keep deployment manifests out of the web root."),
    Probe("/crossdomain.xml", "Permissive Flash cross-domain policy", "low",
          lambda b: b"<cross-domain-policy" in b and b'domain="*"' in b,
          "Remove crossdomain.xml or restrict allowed domains."),
]


@dataclass
class ProbeFinding:
    url: str
    path: str
    name: str
    severity: str
    status: int
    size: int
    remediation: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _join(base_url: str, path: str) -> str:
    parts = urllib.parse.urlsplit(base_url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def run_probes(base_url: str, fetcher: Fetcher,
               probes: list[Probe] | None = None) -> tuple[list[ProbeFinding], bool]:
    """Return (findings, soft404_detected)."""
    probes = PROBES if probes is None else probes
    baseline = fetcher.get(_join(base_url, f"/tantu-{secrets.token_hex(8)}"))
    soft404 = baseline.ok
    findings = []
    for probe in probes:
        resp: Response = fetcher.get(_join(base_url, probe.path))
        if not resp.ok or not resp.body:
            continue
        if soft404 and resp.body == baseline.body:
            continue
        if probe.check(resp.body):
            findings.append(ProbeFinding(_join(base_url, probe.path), probe.path, probe.name,
                                         probe.severity, resp.status, len(resp.body),
                                         probe.remediation))
    return findings, soft404
