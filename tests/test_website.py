"""Buildless website contracts: links, language coverage and local assets."""
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET

DOCS = Path(__file__).resolve().parents[1] / "docs"


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))

    handle_startendtag = handle_starttag


class WebsiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = Page()
        cls.page.feed((DOCS / "index.html").read_text(encoding="utf-8"))
        cls.script = (DOCS / "app.js").read_text(encoding="utf-8")

    def test_unique_ids_and_valid_internal_links(self):
        ids = [attrs["id"] for _, attrs in self.page.elements if "id" in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        for _, attrs in self.page.elements:
            href = attrs.get("href", "")
            if href.startswith("#") and href != "#":
                self.assertIn(href[1:], ids)

    def test_assets_are_local_and_resolve_under_pages_subpath(self):
        for tag, attrs in self.page.elements:
            for name in ("src", "href"):
                ref = attrs.get(name, "")
                if not ref or ref.startswith("#"):
                    continue
                url = urlsplit(ref)
                if url.scheme:
                    self.assertEqual(tag, "a", "Page assets must not depend on third-party hosts")
                    self.assertEqual(url.scheme, "https")
                    self.assertEqual(url.netloc, "github.com")
                    self.assertTrue(url.path.startswith("/Dargon777/AntiOS"))
                else:
                    self.assertFalse(ref.startswith("/"), "GitHub project Pages needs relative assets")
                    target = (DOCS / unquote(url.path)).resolve()
                    self.assertTrue(target.is_relative_to(DOCS.resolve()))
                    self.assertTrue(target.is_file(), ref)

    def test_english_covers_all_text_and_accessible_labels(self):
        for attr, start, end in [("data-i18n", "const english =", "const englishLabels"), ("data-label", "const englishLabels =", "const texts")]:
            block = self.script.split(start, 1)[1].split(end, 1)[0]
            keys = set(re.findall(r"^\s*(\w+):", block, re.M))
            expected = {attrs[attr] for _, attrs in self.page.elements if attr in attrs}
            self.assertEqual(expected, keys)

    def test_tabs_have_reciprocal_panel_relationships(self):
        by_id = {attrs["id"]: attrs for _, attrs in self.page.elements if "id" in attrs}
        tabs = [attrs for _, attrs in self.page.elements if attrs.get("role") == "tab"]
        self.assertEqual(3, len(tabs))
        self.assertEqual(1, sum(tab["aria-selected"] == "true" for tab in tabs))
        for tab in tabs:
            panel = by_id[tab["aria-controls"]]
            self.assertEqual("tabpanel", panel["role"])
            self.assertEqual(tab["id"], panel["aria-labelledby"])
            self.assertEqual(tab["aria-selected"] == "false", "hidden" in panel)

    def test_original_svg_fallback_is_valid_and_triangulated(self):
        for file in (DOCS / "assets").glob("*.svg"):
            root = ET.parse(file).getroot()
            self.assertEqual("{http://www.w3.org/2000/svg}svg", root.tag)
        root = ET.parse(DOCS / "assets/sphere.svg").getroot()
        triangles = root.findall("{http://www.w3.org/2000/svg}polygon")
        self.assertEqual(320, len(triangles))
        for triangle in triangles:
            self.assertEqual(3, len(triangle.attrib["points"].split()))

    def test_runtime_has_no_external_requests_and_stays_lightweight(self):
        files = [DOCS / name for name in ("index.html", "styles.css", "app.js", "sphere.js", "assets/mark.svg", "assets/sphere.svg")]
        self.assertLess(sum(file.stat().st_size for file in files), 250_000)
        for filename in ("app.js", "sphere.js"):
            source = (DOCS / filename).read_text(encoding="utf-8")
            self.assertNotRegex(source, r"\b(fetch|XMLHttpRequest|WebSocket|sendBeacon)\s*\(")
        downloads = [attrs for _, attrs in self.page.elements if attrs.get("id") == "downloadButton"]
        self.assertEqual("https://github.com/Dargon777/AntiOS/releases", downloads[0]["href"])


if __name__ == "__main__":
    unittest.main()
