# tantu

A small, polite auditor that crawls your own website and reports broken links, mixed content and sensitive files that should never have been deployed.

## The name

*Tantu* (तन्तु) is Sanskrit for a thread, the single strand from which a web or a cloth is woven. A crawler follows one thread of links after another until it has traced the whole web of your site.

## Features

- Same-origin crawler built on `html.parser`, with a configurable depth limit and page cap
- Honours `robots.txt` (including `Crawl-delay`) unless you pass `--ignore-robots`
- Rate limited: a fixed delay between every request (default 0.5 s)
- Broken link report (4xx, 5xx and connection errors) with the page each link was found on
- Optional checking of off-site links (`--check-external`)
- Mixed content detection on HTTPS pages, classified as `active` (scripts, iframes, stylesheets), `passive` (images, media) or `insecure-form`
- 28 probes for commonly exposed paths: `/.git/HEAD`, `/.git/config`, `/.env`, `/.DS_Store`, `/backup.zip`, `/backup.sql`, `/phpinfo.php`, `/server-status`, `/.htpasswd`, `/.aws/credentials`, `/id_rsa`, `/.svn/entries`, `/wp-config.php.bak` and more
- Every probe verifies the response content (magic bytes, file structure, signature strings), and soft-404 servers that answer 200 for everything are detected, so an HTML "not found" page is never reported as an exposed `.env`
- Remediation hint for every finding
- Text tables or `--json`; exit code 1 when anything is found

Standard library only. Python 3.10+.

> Use only on sites you own or are explicitly authorized to test.

## Install

```sh
git clone https://github.com/Linuxboii/tantu.git
cd tantu
pip install .
```

Or run without installing: `python -m tantu ...`

## Usage

```sh
tantu https://example.com/
tantu https://example.com/ --depth 3 --max-pages 500 --delay 1
tantu https://example.com/ --no-crawl          # probes only
tantu https://example.com/ --no-probes --check-external
tantu https://example.com/ --json > report.json
```

Sample run against a local test site:

```
$ tantu http://127.0.0.1:8765/ --delay 0.05
tantu 1.0.0  target: http://127.0.0.1:8765/
Use only on sites you own or are explicitly authorized to test.

Crawl
  pages fetched: 7   robots-skipped: 1   external checked: 0

Broken links (3)
  STATUS  URL                             FOUND ON
  ------  ------------------------------  ---------------------------
  404     http://127.0.0.1:8765/missing   http://127.0.0.1:8765/
  404     http://127.0.0.1:8765/logo.png  http://127.0.0.1:8765/
  500     http://127.0.0.1:8765/err       http://127.0.0.1:8765/about

Mixed content (0)
  none

Skipped by robots.txt: http://127.0.0.1:8765/private/area

Exposed paths (3 of 28 probes hit)
  server answers 200 for unknown paths; content checks applied
  SEV     PATH          WHAT                             BYTES
  ------  ------------  -------------------------------  -----
  HIGH    /.git/HEAD    Git repository HEAD              21
  MEDIUM  /.DS_Store    macOS .DS_Store directory index  40
  MEDIUM  /phpinfo.php  phpinfo() page                   54

Remediation
  /.git/HEAD: Block /.git/ at the web server and remove the repository from the web root.
  /.DS_Store: Delete .DS_Store files and deny dotfiles at the web server.
  /phpinfo.php: Delete phpinfo pages; they disclose versions, paths and environment.

37 requests made
```

That test site answers 200 for every unknown path and also serves an HTML page at `/.env`. Neither one shows up as a finding.

JSON output (`--no-crawl --json`, trimmed):

```json
{
  "target": "http://127.0.0.1:8765/",
  "version": "1.0.0",
  "requests": 29,
  "crawl": null,
  "probes": {
    "soft404": true,
    "findings": [
      {
        "url": "http://127.0.0.1:8765/.git/HEAD",
        "path": "/.git/HEAD",
        "name": "Git repository HEAD",
        "severity": "high",
        "status": 200,
        "size": 21,
        "remediation": "Block /.git/ at the web server and remove the repository from the web root."
      }
    ]
  }
}
```

### Exit codes

| code | meaning |
|------|---------|
| 0 | nothing found |
| 1 | broken links, mixed content or exposed paths found |
| 2 | bad arguments or start URL unreachable |

## Tests

```sh
python -m unittest -v
```

The tests start a throwaway HTTP server on localhost, so they need no network access.

## License

MIT, see [LICENSE](LICENSE).
