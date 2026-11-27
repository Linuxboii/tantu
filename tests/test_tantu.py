import contextlib
import io
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tantu.cli import main
from tantu.crawler import Crawler, extract_links, find_mixed_content, normalize, same_origin
from tantu.fetch import Fetcher
from tantu.probes import looks_html, run_probes

SOFT_404 = b"<!doctype html><html><body>Page not found</body></html>"

SITE = {
    "/": (200, "text/html", b"""<!doctype html><html><head>
        <link rel="stylesheet" href="/style.css"></head><body>
        <a href="/about">About</a> <a href="/missing">Gone</a>
        <a href="/private/area">Private</a> <a href="mailto:me@example.com">mail</a>
        <a href="#top">top</a> <img src="/logo.png"></body></html>"""),
    "/about": (200, "text/html", b"""<html><body><a href="/">home</a>
        <a href="/deep">deeper</a> <a href="/err">err</a></body></html>"""),
    "/deep": (200, "text/html", b"<html><body><a href='/deeper-still'>x</a></body></html>"),
    "/deeper-still": (200, "text/html", b"<html><body>end</body></html>"),
    "/err": (500, "text/html", b"<html>boom</html>"),
    "/style.css": (200, "text/css", b"body{}"),
    "/robots.txt": (200, "text/plain", b"User-agent: *\nDisallow: /private\n"),
    "/.git/HEAD": (200, "text/plain", b"ref: refs/heads/main\n"),
    "/.env": (200, "text/html", SOFT_404),             # soft 404 must not be flagged
    "/phpinfo.php": (200, "text/html", b"<html><title>phpinfo()</title>PHP Version 8.2.1</html>"),
    "/.DS_Store": (200, "application/octet-stream", b"\x00\x00\x00\x01Bud1" + b"\x00" * 32),
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]
        if path in SITE:
            status, ctype, body = SITE[path]
        elif path == "/logo.png":
            status, ctype, body = 404, "text/html", b"nope"
        elif path == "/missing":
            status, ctype, body = 404, "text/html", b"not here"
        else:
            status, ctype, body = 200, "text/html", SOFT_404
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class ServerCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}/"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()


class CrawlTests(ServerCase):
    def crawl(self, depth=2, robots=True):
        return Crawler(self.base, Fetcher(delay=0), max_depth=depth, respect_robots=robots).run()

    def test_broken_links_found_with_referrers(self):
        result = self.crawl()
        broken = {b["url"].rsplit("/", 1)[1]: b for b in result.broken}
        self.assertEqual(broken["missing"]["status"], 404)
        self.assertEqual(broken["err"]["status"], 500)
        self.assertEqual(broken["logo.png"]["status"], 404)
        self.assertTrue(broken["err"]["referrers"][0].endswith("/about"))

    def test_robots_respected(self):
        result = self.crawl()
        self.assertTrue(any(u.endswith("/private/area") for u in result.robots_skipped))
        fetched = [p["url"] for p in result.pages]
        self.assertFalse(any("/private" in u for u in fetched))

    def test_ignore_robots(self):
        result = self.crawl(robots=False)
        self.assertEqual(result.robots_skipped, [])
        self.assertTrue(any(p["url"].endswith("/private/area") for p in result.pages))

    def test_depth_limit(self):
        urls = [p["url"] for p in self.crawl(depth=1).pages]
        self.assertTrue(any(u.endswith("/about") for u in urls))
        self.assertFalse(any(u.endswith("/deep") for u in urls))
        urls = [p["url"] for p in self.crawl(depth=3).pages]
        self.assertTrue(any(u.endswith("/deeper-still") for u in urls))


class ProbeTests(ServerCase):
    def test_probes_use_content_checks(self):
        findings, soft404 = run_probes(self.base, Fetcher(delay=0))
        self.assertTrue(soft404)
        paths = {f.path for f in findings}
        self.assertEqual(paths, {"/.git/HEAD", "/phpinfo.php", "/.DS_Store"})

    def test_cli_json_and_exit_code(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main([self.base, "--delay", "0", "--json"])
        self.assertEqual(code, 1)
        report = json.loads(buf.getvalue())
        self.assertEqual(len(report["probes"]["findings"]), 3)
        self.assertEqual(len(report["crawl"]["broken"]), 3)

    def test_cli_text(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main([self.base, "--delay", "0", "--no-color"])
        out = buf.getvalue()
        self.assertIn("Broken links (3)", out)
        self.assertIn("/.git/HEAD", out)
        self.assertNotIn("\033[", out)


class UnitTests(unittest.TestCase):
    def test_mixed_content(self):
        html = """<html><body>
            <script src="http://cdn.example.com/a.js"></script>
            <img src="http://img.example.com/b.png">
            <img srcset="http://img.example.com/c.png 1x, https://ok.example.com/d.png 2x">
            <link rel="stylesheet" href="http://cdn.example.com/s.css">
            <link rel="canonical" href="http://example.com/">
            <a href="http://example.com/plain">plain link is fine</a>
            <form action="http://example.com/login"></form>
            <iframe src="https://safe.example.com/"></iframe></body></html>"""
        links = extract_links("https://example.com/", html)
        mixed = find_mixed_content("https://example.com/", links)
        kinds = {(m["tag"], m["kind"]) for m in mixed}
        self.assertEqual(kinds, {("script", "active"), ("img", "passive"),
                                 ("link", "active"), ("form", "insecure-form")})
        self.assertEqual(len(mixed), 5)
        self.assertEqual(find_mixed_content("http://example.com/", links), [])

    def test_normalize_and_origin(self):
        self.assertEqual(normalize("HTTP://Example.COM:80"), "http://example.com/")
        self.assertEqual(normalize("https://a.com:443/x?y=1"), "https://a.com/x?y=1")
        self.assertTrue(same_origin("https://a.com/x", "https://a.com:443/y"))
        self.assertFalse(same_origin("https://a.com/", "http://a.com/"))
        self.assertFalse(same_origin("https://a.com/", "https://b.a.com/"))

    def test_base_href(self):
        links = extract_links("https://a.com/x/", '<base href="/root/"><a href="p">p</a>')
        self.assertEqual(links[0].url, "https://a.com/root/p")

    def test_looks_html(self):
        self.assertTrue(looks_html(b"  <!DOCTYPE html><html>"))
        self.assertFalse(looks_html(b"DB_HOST=localhost\nDB_PASS=x\n"))


if __name__ == "__main__":
    unittest.main()
