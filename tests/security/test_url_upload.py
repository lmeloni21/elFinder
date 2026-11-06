"""URL-upload regression tests using only local HTTP/TLS fixtures.

Run: rtk python3 tests/security/test_url_upload.py
Requires Python 3, PHP CLI with cURL, and the openssl command.
"""

import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit


PROBE = Path(__file__).with_name("url_upload_probe.php")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        parsed = urlsplit(self.path)
        if parsed.path in ("/allowed-start", "/redirect"):
            query = parse_qs(parsed.query)
            self.send_response(int(query.get("code", ["302"])[0]))
            self.send_header("Location", query.get("to", ["/blocked"])[0])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Disposition", 'attachment; filename="fixture.txt"')
        body = self.headers.get("Authorization", "fixture content").encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class UrlUploadSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="elfinder-url-tests-")
        cls.addClassCleanup(cls.temp.cleanup)
        folder = Path(cls.temp.name)
        cls.cert = folder / "cert.pem"
        key = folder / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cls.cert), "-days", "1",
             "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        cls.http = cls.start_server()
        cls.https = cls.start_server(tls=True, key=key)
        cls.base = "http://127.0.0.1:%s" % cls.http.server_port
        cls.secure_base = "https://127.0.0.1:%s" % cls.https.server_port

    @classmethod
    def start_server(cls, tls=False, key=None):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.requests = []
        cls.addClassCleanup(server.server_close)
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cls.cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        cls.addClassCleanup(thread.join)
        cls.addClassCleanup(server.shutdown)
        return server

    def probe(self, url, mode="fetch", ca=None, **options):
        arguments = [os.environ.get("PHP_BINARY", "php"), "-d", "xdebug.mode=off", "-d", "display_errors=stderr"]
        if ca:
            arguments.extend(["-d", "curl.cainfo=" + str(ca)])
        arguments.extend([str(PROBE), json.dumps(dict(url=url, mode=mode, **options))])
        # Fixtures must not be routed through a machine's optional HTTP proxy.
        env = {key: value for key, value in os.environ.items() if not key.lower().endswith("_proxy")}
        result = subprocess.run(arguments, capture_output=True, text=True, env=env, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout)

    def test_malformed_urls_are_rejected_without_php_warnings(self):
        for url in ("", "http://", "http:///broken", "http://8.8.8.8:99999/", "/relative"):
            with self.subTest(url=url):
                self.assertIs(self.probe(url, mode="validate"), False)

    def test_only_documented_upload_protocols_are_accepted(self):
        for scheme in ("file", "gopher", "dict", "sftp", "httpx"):
            with self.subTest(scheme=scheme):
                self.assertIs(self.probe(scheme + "://8.8.8.8/file", mode="validate"), False)
        for scheme, port in (("http", 80), ("https", 443), ("ftp", 21), ("ftps", 990)):
            with self.subTest(scheme=scheme):
                info = self.probe(scheme.upper() + "://8.8.8.8/file", mode="validate")
                self.assertEqual(info["scheme"], scheme)
                self.assertEqual(info["port"], port)
                self.assertEqual(info["ip"], "8.8.8.8")

    def test_private_and_loopback_addresses_are_denied_by_default(self):
        for host in ("127.0.0.1", "127.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.169.254", "[::1]"):
            with self.subTest(host=host):
                self.assertIs(self.probe("http://" + host + "/", mode="validate"), False)

    def test_explicit_lan_exception_remains_supported(self):
        self.assertEqual(self.probe(self.base, mode="validate", lan=["local"])["ip"], "127.0.0.1")

    def test_direct_upload_returns_content_and_supports_streams(self):
        for stream in (False, True):
            with self.subTest(stream=stream):
                self.assertEqual(self.probe(self.base + "/file", lan=["local"], stream=stream), "fixture content")

    def test_redirect_cannot_bypass_the_url_filter(self):
        before = len(self.http.requests)
        result = self.probe(self.base + "/allowed-start", lan=["local"], prefix=self.base + "/allowed")
        self.assertIs(result, False)
        self.assertEqual(self.http.requests[before:], ["/allowed-start"])

    def test_allowed_redirects_work_for_strings_and_streams(self):
        for code in (301, 302):
            for stream in (False, True):
                with self.subTest(code=code, stream=stream):
                    url = self.base + "/allowed-start?to=/allowed-file&code=" + str(code)
                    self.assertEqual(self.probe(url, lan=["local"], prefix=self.base + "/allowed", stream=stream), "fixture content")

    def test_redirect_does_not_forward_embedded_credentials(self):
        destination = self.base.replace("://", "://user:secret@") + "/file"
        self.assertEqual(self.probe(self.base + "/redirect?to=" + destination, lan=["local"]), "fixture content")

    def test_redirects_still_validate_the_destination_address(self):
        self.assertIs(self.probe(self.base + "/redirect?to=http://169.254.169.254/latest/meta-data", lan=["local"]), False)

    def test_redirect_loops_are_bounded(self):
        before = len(self.http.requests)
        self.assertIs(self.probe(self.base + "/loop", lan=["local"]), False)
        self.assertEqual(len(self.http.requests) - before, 5)

    def test_untrusted_tls_certificate_is_rejected(self):
        before = len(self.https.requests)
        self.assertIs(self.probe(self.secure_base + "/file", lan=["local"]), False)
        self.assertEqual(len(self.https.requests), before)

    def test_trusted_tls_certificate_is_accepted(self):
        self.assertEqual(self.probe(self.secure_base + "/file", lan=["local"], ca=self.cert), "fixture content")


if __name__ == "__main__":
    unittest.main(verbosity=2)
