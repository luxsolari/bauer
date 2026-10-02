"""Offline fixtures exercise real parsing and provenance; no network needed."""
import hashlib
import http.client
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / "skills/bauer/scripts/sources.py"


def load_sources():
    assert MODULE.exists(), "OWASP source helper is not implemented"
    spec = importlib.util.spec_from_file_location("bauer_sources", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Response(io.BytesIO):
    def __init__(self, body, url, content_type="text/html"):
        super().__init__(body)
        self.url = url
        self.headers = {"Content-Type": content_type}

    def geturl(self):
        return self.url


class SourcesTests(unittest.TestCase):
    def test_web_rejects_discovery_exhaustion_and_newer_redirect_to_stale(self):
        sources = load_sources()
        def page(year, newer):
            return ('<h1>OWASP Top 10:%s</h1>' % year +
                    ''.join('<a href="A%02d_%s-Risk/">A%02d:%s Risk %d</a>' %
                            (n, year, n, year, n) for n in range(1, 11)) +
                    '<a href="/%s/">OWASP Top 10 %s</a>' % (newer, newer)).encode()
        for stale_redirect in (False, True):
            def opener(request, timeout):
                year = 2025 if request.full_url == 'https://owasp.org/Top10/' else int(request.full_url.split('/')[-2])
                if stale_redirect:
                    year = 2025
                return Response(page(year, year + 1), 'https://top10.owasp.org/%s/' % year)
            with self.subTest(stale_redirect=stale_redirect), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    sources.discover_web(directory, opener=opener)

    def test_fetch_rejects_unofficial_urls_redirects_and_oversized_bodies(self):
        sources = load_sources()
        with tempfile.TemporaryDirectory() as directory:
            for url in ("http://owasp.org/", "https://evil.example/", "https://owasp.org.evil.example/", "https://user@owasp.org/", "https://owasp.org:444/"):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    sources.fetch_source(url, directory, opener=lambda *a, **k: self.fail("network called"))
            with self.assertRaises(ValueError):
                sources.fetch_source("https://owasp.org/", directory,
                    opener=lambda *a, **k: Response(b"x", "https://evil.example/"))
            with self.assertRaises(ValueError):
                sources.fetch_source("https://owasp.org/", directory,
                    opener=lambda *a, **k: Response(b"x" * (8 * 1024 * 1024 + 1), "https://owasp.org/"))
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_redirect_is_rejected_before_following_external_location(self):
        sources = load_sources()
        handler_type = getattr(sources, "OfficialRedirectHandler", None)
        self.assertIsNotNone(handler_type, "redirect guard missing")
        handler = handler_type()
        request = sources.urllib.request.Request("https://owasp.org/")
        for destination in ("https://evil.example/", "http://owasp.org/"):
            with self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, "Found", {}, destination)
        redirected = handler.redirect_request(request, None, 302, "Found", {}, "https://top10.owasp.org/2025/")
        self.assertEqual(redirected.full_url, "https://top10.owasp.org/2025/")

    def test_web_discovery_validates_ten_categories_from_current_landing(self):
        sources = load_sources()
        discover = getattr(sources, "discover_web", None)
        self.assertIsNotNone(discover, "Web discovery missing")
        html = '<h1>OWASP Top 10:2025</h1>' + ''.join(
            '<a href="A%02d_2025-Risk_%d/">A%02d:2025 Risk %d</a>' % (n, n, n, n)
            for n in range(1, 11))
        with tempfile.TemporaryDirectory() as directory:
            result = discover(Path(directory), opener=lambda *a, **k: Response(html.encode(), "https://top10.owasp.org/2025/"))
            self.assertEqual(result["edition"], "2025")
            self.assertEqual(result["status"], "verified")
            self.assertEqual([c["id"] for c in result["categories"]], ['A%02d:2025' % n for n in range(1, 11)])
            self.assertEqual(result["categories"][0]["name"], "Risk 1")
            self.assertEqual(result["categories"][0]["url"], "https://top10.owasp.org/2025/A01_2025-Risk_1/")
            self.assertEqual(len(result["sources"]), 1)

    def test_web_inspects_newer_release_from_stale_year_landing(self):
        sources = load_sources()
        def categories(year):
            return ''.join('<a href="A%02d_%s-Risk_%d/">A%02d:%s Risk %d</a>' %
                           (n, year, n, n, year, n) for n in range(1, 11))
        fixtures = {
            "https://owasp.org/Top10/": (categories("2025") +
                '<a href="/2026/">OWASP Top 10 2026</a>' +
                '<a href="/2027/">OWASP Top 10 2027 Draft</a>', "https://top10.owasp.org/2025/"),
            "https://top10.owasp.org/2026/": ('<h1>OWASP Top 10 2026</h1>' + categories("2026"), "https://top10.owasp.org/2026/")}
        called = []
        def opener(request, **kwargs):
            called.append(request.full_url)
            body, final = fixtures[request.full_url]
            return Response(body.encode(), final)
        with tempfile.TemporaryDirectory() as directory:
            result = sources.discover_web(directory, opener=opener)
            self.assertEqual(result["edition"], "2026")
            self.assertEqual(len(result["sources"]), 2)
            self.assertEqual([c["id"] for c in result["categories"]],
                             ['A%02d:2026' % n for n in range(1, 11)])
            self.assertNotIn("https://top10.owasp.org/2027/", called)

    def test_web_newer_candidate_draft_fails_closed_without_stale_fallback(self):
        sources = load_sources()
        stale = ''.join('<a href="A%02d_2025-Risk_%d/">A%02d:2025 Risk %d</a>' %
                        (n, n, n, n) for n in range(1, 11)).encode()
        called = []
        def opener(request, **kwargs):
            called.append(request.full_url)
            if request.full_url == "https://owasp.org/Top10/":
                return Response(stale + b'<a href="/2026/">OWASP Top 10 2026</a>', "https://top10.owasp.org/2025/")
            return Response(b'<h1>OWASP Top 10 2026 Draft</h1>', request.full_url)
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            sources.discover_web(directory, opener=opener)
        self.assertEqual(called, ["https://owasp.org/Top10/", "https://top10.owasp.org/2026/"])

    def test_web_rejects_missing_mixed_and_conflicting_categories(self):
        sources = load_sources()
        valid = ''.join('<a href="A%02d_2025-Risk_%d/">A%02d:2025 Risk %d</a>' % (n, n, n, n) for n in range(1, 11))
        cases = [valid.replace('A10_2025', 'A10_2024'), valid + '<a href="A11_2025-Extra/">A11:2025 Extra</a>', valid + '<a href="A01_2025-Other/">A01:2025 Other</a>', valid.replace('A01:2025 Risk 1', 'A01:2025')]
        with tempfile.TemporaryDirectory() as directory:
            for html in cases:
                with self.subTest(html=html), self.assertRaises(ValueError):
                    sources.discover_web(directory, opener=lambda *a, **k: Response(html.encode(), "https://top10.owasp.org/2025/"))

    def test_llm_discovers_newer_publication_instead_of_stale_landing(self):
        sources = load_sources()
        discover = getattr(sources, "discover_llm", None)
        self.assertIsNotNone(discover, "LLM discovery missing")
        homepage = b'<a href="/resource/owasp-genai-llm-top-10-2026/">OWASP GenAI LLM Top 10 2026</a><a href="/resource/llm-top-10-2027-draft/">LLM Top 10 2027 Draft</a>'
        publication = b'<h1>OWASP GenAI LLM Top 10 2026</h1><a href="/download/56857/">Download PDF</a>'
        fixtures = {
            "https://genai.owasp.org/": homepage,
            "https://genai.owasp.org/llm-top-10/": b'<h1>LLM Top 10 2025</h1>',
            "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/": publication,
            "https://genai.owasp.org/download/56857/": b'%PDF-1.7\nfixture',
        }
        called = []
        def opener(request, timeout):
            called.append(request.full_url)
            return Response(fixtures[request.full_url], request.full_url)
        with tempfile.TemporaryDirectory() as directory:
            result = discover(directory, opener=opener)
            self.assertEqual(result["edition"], "2026")
            self.assertEqual(result["status"], "needs_extraction")
            self.assertEqual(result["categories"], [])
            self.assertEqual(result["publication_url"], "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/")
            self.assertEqual(result["download_url"], "https://genai.owasp.org/download/56857/")
            self.assertEqual(len(result["sources"]), 4)
            self.assertNotIn("https://genai.owasp.org/resource/llm-top-10-2027-draft/", called)

    def test_llm_selects_publication_associated_download_not_first_url(self):
        sources = load_sources()
        publication_url = "https://genai.owasp.org/resource/llm-top-10-2026/"
        document_url = "https://genai.owasp.org/download/9/"
        fixtures = {
            "https://genai.owasp.org/": b'<a href="/resource/llm-top-10-2026/">LLM Top 10 2026</a>',
            "https://genai.owasp.org/llm-top-10/": b'<h1>LLM Top 10 2025</h1>',
            publication_url: b'<h1>OWASP LLM Top 10 2026</h1><a href="/download/1/">Sponsor brochure PDF</a><a href="/download/9/">Download OWASP LLM Top 10 2026 PDF</a>',
            "https://genai.owasp.org/download/1/": b'%PDF-1.7\nwrong document',
            document_url: b'%PDF-1.7\npublication'}
        called = []
        def opener(request, **kwargs):
            called.append(request.full_url)
            return Response(fixtures[request.full_url], request.full_url)
        with tempfile.TemporaryDirectory() as directory:
            result = sources.discover_llm(directory, opener=opener)
            self.assertEqual(result["download_url"], document_url)
            self.assertNotIn("https://genai.owasp.org/download/1/", called)

    def test_llm_ambiguous_downloads_fail_before_document_request(self):
        sources = load_sources()
        resource = "https://genai.owasp.org/resource/llm-top-10-2026/"
        for labels in (("Download PDF", "Download PDF"),
                       ("LLM Top 10 2026 PDF", "LLM Top 10 2026 PDF"),
                       ("LLM Top 10 2025 PDF", "LLM Top 10 2027 Draft PDF")):
            publication = ('<h1>LLM Top 10 2026</h1><a href="/download/1/">%s</a><a href="/download/2/">%s</a>' % labels).encode()
            fixtures = {"https://genai.owasp.org/": b'<a href="/resource/llm-top-10-2026/">LLM Top 10 2026</a>',
                        "https://genai.owasp.org/llm-top-10/": b'<h1>LLM Top 10 2025</h1>',
                        resource: publication}
            called = []
            def opener(request, **kwargs):
                called.append(request.full_url)
                return Response(fixtures.get(request.full_url, b'%PDF-1.7\nwrong guess'), request.full_url)
            with self.subTest(labels=labels), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    sources.discover_llm(directory, opener=opener)
                self.assertEqual(called, list(fixtures))

    def test_llm_fails_closed_for_unpublished_mismatched_or_non_pdf_resource(self):
        sources = load_sources()
        homepage = b'<a href="/resource/llm-top-10-2026/">LLM Top 10 2026</a>'
        resource_url = "https://genai.owasp.org/resource/llm-top-10-2026/"
        for title, pdf in (("LLM Top 10 2026 Draft", b"%PDF-1.7"), ("LLM Top 10 2025", b"%PDF-1.7"), ("LLM Top 10 2026", b"<html>blocked</html>")):
            fixtures = {"https://genai.owasp.org/": homepage,
                "https://genai.owasp.org/llm-top-10/": b'<h1>LLM Top 10 2025</h1>',
                resource_url: ('<h1>' + title + '</h1><a href="/download/1/">PDF</a>').encode(),
                "https://genai.owasp.org/download/1/": pdf}
            with self.subTest(title=title, pdf=pdf), tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                sources.discover_llm(directory, opener=lambda request, **k: Response(fixtures[request.full_url], request.full_url))
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            sources.discover_llm(directory, opener=lambda request, **k: Response(b'<h1>LLM Top 10 2025</h1>', request.full_url))

    def test_cli_writes_partial_manifest_and_returns_nonzero_on_failed_source(self):
        sources = load_sources()
        main = getattr(sources, "main", None)
        self.assertIsNotNone(main, "CLI missing")
        html = ''.join('<a href="A%02d_2025-Risk_%d/">A%02d:2025 Risk %d</a>' % (n, n, n, n) for n in range(1, 11)).encode()
        def opener(request, timeout):
            if request.full_url == "https://owasp.org/Top10/":
                return Response(html, "https://top10.owasp.org/2025/")
            raise OSError("network unavailable")
        with tempfile.TemporaryDirectory() as directory, patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(main(["--output-dir", directory], opener=opener), 1)
            manifest = json.loads(Path(directory, "sources.json").read_text(encoding='utf-8'))
            self.assertEqual(manifest["web"]["status"], "verified")
            self.assertEqual(manifest["llm"]["status"], "error")
            self.assertEqual(manifest["llm"]["error"], "transport_error")
            self.assertEqual(len(manifest["sources"]), 1)
        with patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit):
            main([])

    def test_permanent_308_redirect_works_on_python39_with_same_guard(self):
        sources = load_sources()
        handler = sources.OfficialRedirectHandler()
        redirect = getattr(handler, "http_error_308", None)
        self.assertIsNotNone(redirect, "Python 3.9 needs explicit 308 support")
        request = sources.urllib.request.Request("https://owasp.org/Top10/")
        request.timeout = 20
        with self.assertRaises(ValueError):
            redirect(request, io.BytesIO(b""), 308, "Permanent Redirect", {"location": "https://evil.example/"})
        parent = sources.urllib.request.build_opener(handler)
        with patch.object(parent, "open", return_value="followed") as opened:
            self.assertEqual(redirect(request, io.BytesIO(b""), 308, "Permanent Redirect", {"location": "https://top10.owasp.org/2025/"}), "followed")
            self.assertEqual(opened.call_args[0][0].full_url, "https://top10.owasp.org/2025/")

    def test_web_follows_official_year_link_from_redirect_splash(self):
        sources = load_sources()
        html = ''.join('<a href="A%02d_2025-Risk_%d/">A%02d:2025 Risk %d</a>' % (n, n, n, n) for n in range(1, 11)).encode()
        def opener(request, timeout):
            if request.full_url == "https://owasp.org/Top10/":
                return Response(b'<title>OWASP Top 10</title><a href="./2025/en/">click here</a>', "https://top10.owasp.org/")
            self.assertEqual(request.full_url, "https://top10.owasp.org/2025/en/")
            return Response(html, request.full_url)
        with tempfile.TemporaryDirectory() as directory:
            result = sources.discover_web(directory, opener=opener)
            self.assertEqual(result["edition"], "2025")
            self.assertEqual(len(result["sources"]), 2)

    def test_web_follows_bounded_html_redirect_chain(self):
        sources = load_sources()
        html = ''.join('<a href="A%02d_2025-Risk_%d/">A%02d:2025 Risk %d</a>' % (n, n, n, n) for n in range(1, 11)).encode()
        fixtures = {"https://owasp.org/Top10/": (b'<a href="/2025/en/">click here</a>', "https://top10.owasp.org/"),
            "https://top10.owasp.org/2025/en/": (b'<title>Redirecting...</title><a href="/2025/">OWASP Top 10:2025</a>', "https://top10.owasp.org/2025/en/"),
            "https://top10.owasp.org/2025/": (html, "https://top10.owasp.org/2025/")}
        with tempfile.TemporaryDirectory() as directory:
            result = sources.discover_web(directory, opener=lambda request, **k: Response(*fixtures[request.full_url]))
            self.assertEqual(len(result["sources"]), 3)
            self.assertEqual(len(result["categories"]), 10)

    def test_web_deduplicates_short_navigation_labels_against_full_identifiers(self):
        sources = load_sources()
        html = ''.join('<a href="A%02d_2025-Risk_%d/">A%02d Risk %d</a><a href="A%02d_2025-Risk_%d/">A%02d:2025 - Risk %d</a>' % (n, n, n, n, n, n, n, n) for n in range(1, 11)).encode()
        with tempfile.TemporaryDirectory() as directory:
            result = sources.discover_web(directory, opener=lambda *a, **k: Response(html, "https://top10.owasp.org/2025/"))
            self.assertEqual(len(result["categories"]), 10)
            self.assertEqual(result["categories"][0]["name"], "Risk 1")

    def test_cli_catches_http_protocol_failures_with_partial_provenance(self):
        sources = load_sources()
        class BrokenResponse(Response):
            def read(self, *args):
                raise http.client.IncompleteRead(b"partial", 100)
        for failure in ("incomplete", "bad_status"):
            def opener(request, **kwargs):
                if request.full_url == "https://genai.owasp.org/":
                    return Response(b'<h1>OWASP</h1>', request.full_url)
                if request.full_url == "https://owasp.org/Top10/":
                    raise OSError("offline")
                if failure == "incomplete":
                    return BrokenResponse(b"", request.full_url)
                raise http.client.BadStatusLine("broken server response")
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, patch("sys.stdout", new_callable=io.StringIO) as stdout:
                self.assertEqual(sources.main(["--output-dir", directory], opener=opener), 1)
                manifest = json.loads(Path(directory, "sources.json").read_text(encoding='utf-8'))
                self.assertEqual(manifest["llm"]["status"], "error")
                self.assertEqual(len(manifest["sources"]), 1)
                self.assertEqual(manifest["llm"]["sources"], manifest["sources"])
                self.assertEqual(manifest["sources"][0]["url"], "https://genai.owasp.org/")
                self.assertEqual(json.loads(stdout.getvalue()), manifest)

    def test_cli_errors_are_static_codes_without_exception_or_url_details(self):
        sources = load_sources()
        secret = "https://user:password@owasp.org/private?token=secret"
        failures = ((OSError(secret * 1000), "transport_error"),
                    (ValueError(secret), "invalid_source"),
                    (http.client.BadStatusLine(secret), "protocol_error"),
                    (http.client.IncompleteRead(secret.encode(), 1), "protocol_error"))
        for failure, code in failures:
            def opener(request, **kwargs):
                raise failure
            with self.subTest(code=code, kind=type(failure).__name__), tempfile.TemporaryDirectory() as directory, patch("sys.stdout", new_callable=io.StringIO) as stdout:
                self.assertEqual(sources.main(["--output-dir", directory], opener=opener), 1)
                persisted = Path(directory, "sources.json").read_text(encoding='utf-8')
                self.assertEqual(persisted, stdout.getvalue())
                manifest = json.loads(persisted)
                for framework in ("web", "llm"):
                    self.assertEqual(manifest[framework]["error"], code)
                self.assertNotIn("password", persisted)
                self.assertNotIn("secret", persisted)
                self.assertLess(len(persisted), 500)

    def test_cli_preserves_provenance_for_downloads_before_partial_failure(self):
        sources = load_sources()
        def opener(request, timeout):
            if request.full_url == "https://genai.owasp.org/":
                return Response(b'<h1>OWASP</h1>', request.full_url)
            raise OSError("offline")
        with tempfile.TemporaryDirectory() as directory, patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(sources.main(["--output-dir", directory], opener=opener), 1)
            manifest = json.loads(Path(directory, "sources.json").read_text(encoding='utf-8'))
            self.assertEqual(len(manifest["sources"]), 1)
            self.assertEqual(manifest["sources"][0]["url"], "https://genai.owasp.org/")
            self.assertEqual(manifest["llm"]["sources"], manifest["sources"])

    def test_web_refuses_draft_page_or_mismatched_category_label(self):
        sources = load_sources()
        html = ''.join('<a href="A%02d_2025-Risk_%d/">A%02d:2025 Risk %d</a>' % (n, n, n, n) for n in range(1, 11))
        for invalid in ('<h1>OWASP Top 10 2025 Draft</h1>' + html, html.replace('A01:2025 Risk 1', 'A02:2024 Risk 1')):
            with self.subTest(html=invalid), tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                sources.discover_web(directory, opener=lambda *a, **k: Response(invalid.encode(), "https://top10.owasp.org/2025/"))

    def test_raw_snapshot_records_exact_bytes_and_provenance(self):
        sources = load_sources()
        body = b"<h1>OWASP</h1>\n"
        url = "https://owasp.org/Top10/"
        final = "https://top10.owasp.org/2025/"
        calls = []
        def opener(request, timeout):
            calls.append((request.full_url, timeout))
            return Response(body, final)
        with tempfile.TemporaryDirectory() as directory:
            record = sources.fetch_source(url, Path(directory), opener=opener)
            self.assertEqual(Path(directory, record["path"]).read_bytes(), body)
            self.assertEqual(record["sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(record["bytes"], len(body))
            self.assertEqual(record["url"], url)
            self.assertEqual(record["final_url"], final)
            self.assertRegex(record["retrieved_at"], r"^\d{4}-\d\d-\d\dT.*Z$")
            self.assertEqual(calls, [(url, 20)])


if __name__ == "__main__":
    unittest.main()
