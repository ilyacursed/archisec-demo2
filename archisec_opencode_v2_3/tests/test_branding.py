"""QA branding tests: pinned integrity constants, palette tokens, WCAG, logo.

Owned file of the QA agent. Sources: docs/branding.md, README.md and the
localization task brief.

- ``BrandingBaselineTests`` — QA-owned pinned constants below fix the sha256
  of every ``data/*.json`` file and of the untouched source logo
  ``static/img/archisec-logo.png`` (PNG 1254 × 1254), verified against the
  original pre-localization state. Localization must not change demo data
  or the provided logo; drift fails loudly. The suite is portable: no
  external baseline file is read, and nothing is regenerated at test time.
  A deliberate, reviewed data/logo change requires updating these constants
  consciously in this file — never silently absorbing drift.
- ``BrandDocsTests`` — README and docs/branding.md keep referencing the real
  asset, tokens and contrast rules (single source of truth for the style).
- ``ContrastMathTests`` — pure WCAG 2.x relative-luminance math. Brand green
  ``#6AAF9C`` and brand blue ``#4182AE`` cannot serve as small text on a
  white background (< 4.5:1); the documented contrast derivative (accent
  candidate ``#2f6285``) passes AA 4.5:1 for normal text/focus 3:1.
- ``CssBrandTokenTests`` (tag ``qa_html``) — both brand hexes exist exactly
  once, only inside their ``--archisec-*`` token definitions; rules use
  ``var(--archisec-*)``; focus styling exists; brand green is never used as
  a text color.
- ``LogoReferenceHtmlTests`` (tag ``qa_html``) — header/home/result pages
  reference the static logo; the favicon link targets an existing static
  PNG.

``qa_html`` classes read frontend-active files (``static/style.css``) or
render templates and run only in the final integration pass
(``manage.py test`` without ``--exclude-tag qa_html``). Browser-level
responsive/console audits at 320/768/1280 are owned by the orchestrator and
are not duplicated here.
"""

import hashlib
import re
import struct
from pathlib import Path

from django.contrib.staticfiles import finders
from django.test import SimpleTestCase, tag

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LOGO_RELATIVE = "img/archisec-logo.png"
LOGO_PATH = BASE_DIR / "static" / "img" / "archisec-logo.png"

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

BRAND_GREEN = "#6AAF9C"
BRAND_BLUE = "#4182AE"
ACCENT_CANDIDATE = "#2f6285"  # documented contrast derivative of brand blue

HTML_ANALYZE = "/profile/analyze/"

# ---------------------------------------------------------------------------
# QA-pinned integrity constants (original pre-localization state, verified
# byte-for-byte; portable — nothing external is read or regenerated).
# ---------------------------------------------------------------------------

EXPECTED_DATA_SHA256 = {
    "ai_threats.json": "bcf6088045426d3a7de6518fc5f4e0f6585b0d84da4012a8bc54658837a4895c",
    "levels.json": "1c054294c7bc8c8c5139d57f50d9e724e537065f1cfcf0253d78acdbf4ac69fc",
    "mappings.json": "a6b360ace33982c0738df4a89dd8f06175039488116af9a9fc06d17f48c08c7d",
    "measures.json": "1ffd7bb7a9ea79ce18dfd693acdd058008a81454e266806bb6d1dc1404898d10",
    "tactics.json": "fec3838779bc41bc9b50ff2a07f43f1ea50c21fb13ec9574040109a877ec153e",
    "techniques.json": "db2dfff4de99ab6ea3391050e406d4f95063bb334b4c1baa8fb0154696ad1c34",
    "threats.json": "13b5f4bb1901ec1113ccc27ce95ef562a0b8bbdf3d29634560e79e0490033002",
    "tools.json": "9b6457089c5e7d67cc792655726e62f89ff4e02da68e981045e5b983a7fb976f",
}

EXPECTED_LOGO = {
    "sha256": "f7fc408a0c9d1d7881ecfbfadfa248c3f8f8f70ba217540abe497c56d3c0d6df",
    "width": 1254,
    "height": 1254,
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def png_dimensions(raw):
    assert raw[:8] == PNG_SIGNATURE, "logo file is not a PNG"
    return struct.unpack(">II", raw[16:24])


# ---------------------------------------------------------------------------
# Pinned baseline: demo data and the source logo are immutable inputs
# ---------------------------------------------------------------------------


class BrandingBaselineTests(SimpleTestCase):
    """Hash-level guard: localization changes code, not data or the logo."""

    def test_seed_files_match_the_pinned_original_hashes(self):
        current = {
            path.name: sha256(path) for path in sorted(DATA_DIR.glob("*.json"))
        }
        self.assertEqual(
            set(current), set(EXPECTED_DATA_SHA256),
            "seed file set drifted from the QA-pinned baseline",
        )
        for name, digest in current.items():
            with self.subTest(file=name):
                self.assertEqual(digest, EXPECTED_DATA_SHA256[name])

    def test_source_logo_is_byte_identical_to_the_pinned_baseline(self):
        self.assertTrue(LOGO_PATH.exists(), "source logo PNG is missing")
        self.assertEqual(sha256(LOGO_PATH), EXPECTED_LOGO["sha256"])

    def test_source_logo_is_png_1254_square_per_branding_doc(self):
        width, height = png_dimensions(LOGO_PATH.read_bytes())
        self.assertEqual((width, height), (1254, 1254))
        self.assertEqual(width, EXPECTED_LOGO["width"])
        self.assertEqual(height, EXPECTED_LOGO["height"])

    def test_logo_resolves_through_staticfiles(self):
        resolved = finders.find(LOGO_RELATIVE)
        self.assertIsNotNone(resolved, "logo must live under a static source")
        self.assertTrue(
            Path(resolved).resolve() == LOGO_PATH.resolve(),
            "staticfiles must serve the original logo file",
        )


# ---------------------------------------------------------------------------
# Docs keep pointing at the real asset and rules
# ---------------------------------------------------------------------------


class BrandDocsTests(SimpleTestCase):
    """README and docs/branding.md reference the asset, tokens and AA rule."""

    def test_readme_references_logo_tokens_and_branding_doc(self):
        text = (BASE_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn("static/img/archisec-logo.png", text)
        self.assertIn(BRAND_GREEN, text)
        self.assertIn(BRAND_BLUE, text)
        self.assertIn("docs/branding.md", text)

    def test_branding_doc_declares_tokens_sizes_and_contrast_rule(self):
        text = (BASE_DIR / "docs" / "branding.md").read_text(encoding="utf-8")
        self.assertIn("--archisec-green", text)
        self.assertIn("--archisec-blue", text)
        self.assertIn(BRAND_GREEN, text)
        self.assertIn(BRAND_BLUE, text)
        self.assertIn("1254", text)
        self.assertIn("4.5", text)
        self.assertIn("favicon", text)


# ---------------------------------------------------------------------------
# Pure WCAG contrast math (no runtime dependencies)
# ---------------------------------------------------------------------------


def srgb_channel(value):
    scaled = value / 255.0
    if scaled <= 0.04045:
        return scaled / 12.92
    return ((scaled + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_color):
    digits = hex_color.lstrip("#")
    assert len(digits) == 6, hex_color
    r, g, b = (int(digits[i : i + 2], 16) for i in (0, 2, 4))
    return (
        0.2126 * srgb_channel(r)
        + 0.7152 * srgb_channel(g)
        + 0.0722 * srgb_channel(b)
    )


def contrast_ratio(first, second):
    one = relative_luminance(first)
    two = relative_luminance(second)
    lighter, darker = max(one, two), min(one, two)
    return (lighter + 0.05) / (darker + 0.05)


class ContrastMathTests(SimpleTestCase):
    """WCAG AA: 4.5:1 normal text, 3:1 focus — brand tokens need derivatives."""

    def test_math_self_checks_against_known_ratios(self):
        self.assertAlmostEqual(contrast_ratio("#000000", "#FFFFFF"), 21.0, delta=0.01)
        self.assertAlmostEqual(contrast_ratio("#FFFFFF", "#000000"), 21.0, delta=0.01)
        self.assertAlmostEqual(contrast_ratio("#FFFFFF", "#FFFFFF"), 1.0, delta=1e-9)

    def test_brand_green_fails_aa_for_normal_text_on_white(self):
        self.assertLess(contrast_ratio(BRAND_GREEN, "#FFFFFF"), 4.5)

    def test_brand_blue_fails_aa_for_normal_text_on_white(self):
        self.assertLess(contrast_ratio(BRAND_BLUE, "#FFFFFF"), 4.5)

    def test_documented_accent_derivative_passes_aa_text_and_focus(self):
        ratio = contrast_ratio(ACCENT_CANDIDATE, "#FFFFFF")
        self.assertGreaterEqual(ratio, 4.5)
        self.assertGreaterEqual(ratio, 3.0)

    def test_white_text_on_accent_derivative_passes_aa(self):
        self.assertGreaterEqual(contrast_ratio("#FFFFFF", ACCENT_CANDIDATE), 4.5)

    def test_brand_blue_passes_focus_threshold_but_green_does_not(self):
        # 3:1 suffices for significant borders/focus. Brand blue qualifies on
        # white; brand green (≈2.55:1) is decorative only — links, focus and
        # significant borders must use the contrast derivatives of the blue.
        self.assertGreaterEqual(contrast_ratio(BRAND_BLUE, "#FFFFFF"), 3.0)
        self.assertLess(contrast_ratio(BRAND_GREEN, "#FFFFFF"), 3.0)


# ---------------------------------------------------------------------------
# CSS token discipline — reads frontend-active style.css (final pass only)
# ---------------------------------------------------------------------------


@tag("qa_html")
class CssBrandTokenTests(SimpleTestCase):
    """Brand hexes live once in tokens; rules use variables, not literals."""

    @staticmethod
    def css():
        return (BASE_DIR / "static" / "style.css").read_text(encoding="utf-8")

    def test_brand_hexes_appear_exactly_once_each(self):
        css = self.css()
        for hex_token in (BRAND_GREEN, BRAND_BLUE):
            with self.subTest(token=hex_token):
                occurrences = re.findall(hex_token, css, flags=re.IGNORECASE)
                self.assertEqual(
                    len(occurrences), 1,
                    f"{hex_token} must occur exactly once (token definition)",
                )

    def test_brand_hexes_exist_only_inside_token_definitions(self):
        css = self.css()
        for hex_token, token_name in (
            (BRAND_GREEN, "archisec-green"),
            (BRAND_BLUE, "archisec-blue"),
        ):
            with self.subTest(token=token_name):
                definition = re.search(
                    rf"--{token_name}\s*:\s*[^;}}]*{hex_token}", css, re.IGNORECASE
                )
                self.assertIsNotNone(
                    definition,
                    f"{hex_token} must be defined in --{token_name}",
                )

    def test_rules_consume_tokens_through_var_references(self):
        css = self.css()
        self.assertGreaterEqual(
            len(re.findall(r"var\(--archisec-", css)), 2,
            "CSS rules must use the --archisec-* tokens",
        )
        self.assertIn("--archisec-green", css)
        self.assertIn("--archisec-blue", css)

    def test_focus_styling_exists(self):
        self.assertIn(":focus", self.css())

    def test_brand_green_is_never_used_as_text_color(self):
        css = self.css()
        self.assertIsNone(
            re.search(r"color\s*:\s*var\(--archisec-green\)", css, re.IGNORECASE),
            "brand green fails AA as text on light backgrounds",
        )


# ---------------------------------------------------------------------------
# Logo/favicon references in rendered pages — final pass only
# ---------------------------------------------------------------------------

LOGO_IMG_RE = re.compile(
    r'<img[^>]+src="([^"]*static/img/archisec-logo\.png[^"]*)"[^>]*>'
)
ICON_LINK_RE = re.compile(r'<link[^>]+rel="[^"]*icon[^"]*"[^>]*>')
HREF_RE = re.compile(r'href="([^"]+)"')


@tag("qa_html")
class LogoReferenceHtmlTests(SimpleTestCase):
    """Header, home and favicon use the static original PNG (no redesign)."""

    @staticmethod
    def page(client, url, form_data=None):
        if form_data is None:
            response = client.get(url)
        else:
            response = client.post(url, form_data)
        assert response.status_code == 200, response.status_code
        return response.content.decode()

    def test_home_profile_and_result_pages_reference_the_static_logo(self):
        home = self.page(self.client, "/")
        profile = self.page(self.client, "/profile/")
        result = self.page(
            self.client,
            HTML_ANALYZE,
            {
                "system_type": "web",
                "interfaces": ["web"],
                "internet_exposed": "on",
                "data_classes": ["confidentiality"],
            },
        )
        for name, html in (("home", home), ("profile", profile), ("result", result)):
            with self.subTest(page=name):
                self.assertRegex(html, LOGO_IMG_RE)

    def test_favicon_link_targets_existing_static_png(self):
        html = self.page(self.client, "/")
        icon_links = ICON_LINK_RE.findall(html)
        self.assertTrue(icon_links, "home page must declare a favicon link")
        png_targets = []
        for link in icon_links:
            href = HREF_RE.search(link)
            self.assertIsNotNone(href, f"icon link without href: {link}")
            png_targets.append(href.group(1))
        self.assertTrue(
            any(re.search(r"^/?static/.+\.png$", target) for target in png_targets),
            f"favicon must point at a static PNG, got {png_targets}",
        )
        for target in png_targets:
            relative = re.sub(r"^/?(?:static/)?", "", target)
            if relative:
                self.assertTrue(
                    (BASE_DIR / "static" / relative).exists(),
                    f"favicon target missing on disk: {target}",
                )

    def test_referenced_logo_marks_have_a_non_empty_alt_attribute(self):
        html = self.page(self.client, "/")
        match = LOGO_IMG_RE.search(html)
        self.assertIsNotNone(match)
        self.assertIn('alt="', match.group(0))
