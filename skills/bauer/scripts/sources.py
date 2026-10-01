#!/usr/bin/env python3
"""Discover official OWASP guidance and freeze raw source provenance.

Standard library only, Python 3.9+. Downloaded content is never executed.
"""
import argparse
import datetime
import json
import hashlib
import http.client
from html.parser import HTMLParser
import re
from pathlib import Path
import urllib.request
from urllib.parse import urljoin, urlsplit

ALLOWED_HOSTS = frozenset(("owasp.org", "top10.owasp.org", "genai.owasp.org"))
MAX_BYTES = 8 * 1024 * 1024


def validate_url(url):
    """Permit only HTTPS on the explicit official host allowlist."""
    parts = urlsplit(url)
    if (parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS
            or parts.username is not None or parts.password is not None
            or parts.port not in (None, 443) or any(ord(c) <= 32 for c in url)):
        raise ValueError("not an allowed official HTTPS URL: " + url)
    return url


class OfficialRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Validate each Location before urllib sends the next request."""
    http_error_308 = urllib.request.HTTPRedirectHandler.http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        # Python 3.9 lacks 308 support; this helper only sends GET requests.
        return super().redirect_request(req, fp, 301 if code == 308 else code, msg, headers, newurl)


def fetch_source(url, output_dir, opener=None, provenance=None):
    """Save exact response bytes under a generated, content-addressed name."""
    validate_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "Bauer-OWASP-sources/1.0"})
    open_url = opener or urllib.request.build_opener(OfficialRedirectHandler()).open
    with open_url(request, timeout=20) as response:
        final_url = validate_url(response.geturl())
        body = response.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise ValueError("source exceeds 8 MiB limit")
        content_type = response.headers.get("Content-Type", "")
    digest = hashlib.sha256(body).hexdigest()
    name = digest + ".raw"
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(body)
    record = {"url": url, "final_url": final_url,
            "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "sha256": digest, "bytes": len(body), "path": name,
            "content_type": content_type}
    if provenance is not None:
        provenance.append(record)
    return record


class Page(HTMLParser):
    """Extract link text and headings without executing page content."""
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.headings = []
        self.active = None
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.active = (tag, attrs["href"], [])
        elif tag in ("h1", "h2", "h3", "title"):
            self.active = (tag, None, [])

    def handle_data(self, data):
        if self.active:
            self.active[2].append(data)

    def handle_endtag(self, tag):
        if self.active and self.active[0] == tag:
            text = " ".join("".join(self.active[2]).split())
            if tag == "a":
                self.links.append((self.active[1], text))
            else:
                self.headings.append(text)
            self.active = None


def read_page(record, output_dir):
    return Page((Path(output_dir) / record["path"]).read_bytes().decode("utf-8", errors="replace"))


def discover_web(output_dir, opener=None, provenance=None):
    """Read the official current Web landing and its category links."""
    record = fetch_source("https://owasp.org/Top10/", output_dir, opener, provenance)
    page = read_page(record, output_dir)
    records = [record]
    edition = re.search(r"/(20\d{2})/", urlsplit(record["final_url"]).path)
    visited = set()
    for _ in range(4):
        if record['final_url'] in visited:
            raise ValueError('repeated Web discovery state')
        visited.add(record['final_url'])
        settled = edition and not any("Redirecting" in title for title in page.headings)
        links = []
        for href, text in page.links:
            url = urljoin(record["final_url"], href)
            match = re.fullmatch(r"/(20\d{2})/(?:en/)?", urlsplit(url).path)
            if (match and not UNPUBLISHED.search(text + " " + url)
                    and (not settled or (edition is not None and match.group(1) > edition.group(1)))):
                validate_url(url)
                links.append((match.group(1), url))
        if settled and not links:
            break
        if not links:
            raise ValueError("current Web landing has no verifiable edition")
        selected_year, url = max(links)
        record = fetch_source(url, output_dir, opener, provenance)
        records.append(record)
        page = read_page(record, output_dir)
        edition = re.search(r"/(20\d{2})/", urlsplit(record["final_url"]).path)
        if not edition:
            raise ValueError("Web edition link redirected to an unverified edition")
        if edition.group(1) != selected_year:
            raise ValueError('Web edition link redirected to a different edition')
    else:
        raise ValueError('Web release discovery budget exhausted')
    assert edition is not None
    year = edition.group(1)
    if any(re.search(r"top\s*10", title, re.I) and UNPUBLISHED.search(title) for title in page.headings):
        raise ValueError("Web landing is an unpublished edition")
    categories = {}
    for href, text in page.links:
        url = urljoin(record["final_url"], href)
        match = re.search(r"/A(\d{2})_(20\d{2})[-_/]", urlsplit(url).path)
        if match and match.group(2) == year:
            validate_url(url)
            identifier = "A" + match.group(1) + ":" + year
            label = re.match(r"^A(\d{2})(?:[:_ ](20\d{2}))?(?:\s|$)", text)
            if label and (label.group(1) != match.group(1) or label.group(2) not in (None, year)):
                raise ValueError("Web category label disagrees with official link")
            name = re.sub(r"^A\d{2}(?:[:_ ]20\d{2})?\s*[-:–]?\s*", "", text).strip()
            category = {"id": identifier, "name": name, "url": url}
            if not name or (identifier in categories and categories[identifier] != category):
                raise ValueError("empty or conflicting Web category: " + identifier)
            categories[identifier] = category
    if set(categories) != {"A%02d:%s" % (n, year) for n in range(1, 11)}:
        raise ValueError("Web categories must contain exactly A01 through A10 for " + year)
    return {"edition": year, "status": "verified", "categories": [categories[k] for k in sorted(categories)], "sources": records}


UNPUBLISHED = re.compile(r"\b(draft|preview|beta|proposed|upcoming|coming soon|release candidate)\b", re.I)


def publication_candidates(page, base):
    candidates = []
    for href, title in page.links:
        url = urljoin(base, href)
        description = title + " " + urlsplit(url).path.replace("-", " ")
        if ("/resource/" not in urlsplit(url).path
                or not re.search(r"\bllm\b", description, re.I)
                or not re.search(r"top\s*10", description, re.I)
                or UNPUBLISHED.search(description)):
            continue
        years = re.findall(r"\b(20\d{2})\b", description)
        if years:
            validate_url(url)
            candidates.append((max(years), url))
    return candidates


def discover_llm(output_dir, opener=None, provenance=None):
    """Discover publication links; save PDF but do not guess its categories."""
    records = []
    candidates = []
    for url in ("https://genai.owasp.org/", "https://genai.owasp.org/llm-top-10/"):
        record = fetch_source(url, output_dir, opener, provenance)
        records.append(record)
        candidates.extend(publication_candidates(read_page(record, output_dir), record["final_url"]))
    if not candidates:
        raise ValueError("no published LLM Top 10 resource discovered; refusing stale fallback")
    year, url = max(set(candidates))
    publication = fetch_source(url, output_dir, opener, provenance)
    records.append(publication)
    page = read_page(publication, output_dir)
    titles = [title for title in page.headings
              if re.search(r"\bllm\b", title, re.I) and re.search(r"top\s*10", title, re.I)]
    if (not titles or any(UNPUBLISHED.search(title) for title in titles)
            or not any(re.search(r"\b" + year + r"\b", title) for title in titles)):
        raise ValueError("LLM resource publication status or edition is unverified")
    downloads = []
    associated = set()
    for href, title in page.links:
        download = urljoin(publication["final_url"], href)
        if re.search(r"/download/\d+/?$", urlsplit(download).path) or urlsplit(download).path.lower().endswith(".pdf"):
            validate_url(download)
            downloads.append(download)
            description = title + " " + urlsplit(download).path.replace("-", " ").replace("_", " ")
            if (re.search(r"\bllm\b", description, re.I)
                    and re.search(r"top\s*10", description, re.I)
                    and re.search(r"\b" + year + r"\b", description)
                    and not UNPUBLISHED.search(description)):
                associated.add(download)
    if not downloads:
        raise ValueError("LLM publication has no official document download")
    choices = associated or set(downloads)
    if len(choices) != 1:
        raise ValueError("LLM publication document download is ambiguous")
    download_url = next(iter(choices))
    document = fetch_source(download_url, output_dir, opener, provenance)
    records.append(document)
    if not (Path(output_dir) / document["path"]).read_bytes().startswith(b"%PDF-"):
        raise ValueError("LLM document response is not a PDF")
    return {"edition": year, "status": "needs_extraction", "categories": [],
            "publication_url": publication["final_url"], "download_url": download_url,
            "extraction_required": "Extract the saved official PDF, verify all ten LLMxx:" + year + " identifiers and titles, then freeze the catalog before auditing.",
            "sources": records}


def main(argv=None, opener=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True,
                        help="Explicit snapshot directory; outside the audited repository is recommended")
    args = parser.parse_args(argv)
    directory = Path(args.output_dir)
    manifest = {"schema_version": 1, "sources": []}
    failed = False
    for framework, discover in (("web", discover_web), ("llm", discover_llm)):
        records = []
        try:
            manifest[framework] = discover(directory, opener, records)
        except (ValueError, OSError, http.client.HTTPException) as exc:
            # Never serialize network/parser exception text: it may contain credentials.
            reason = ("protocol_error" if isinstance(exc, http.client.HTTPException)
                      else "transport_error" if isinstance(exc, OSError)
                      else "invalid_source")
            manifest[framework] = {"status": "error", "error": reason, "categories": [], "sources": records}
            failed = True
        manifest["sources"].extend(records)
    directory.mkdir(parents=True, exist_ok=True)
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    (directory / "sources.json").write_text(text, encoding="utf-8")
    print(text, end="")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
