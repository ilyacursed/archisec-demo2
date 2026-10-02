"""QA-owned tests: compact header + client-side light/dark theme stage.

Ownership: this file belongs to the QA agent and is the only new test module
of the header/theme stage. Existing suites are untouched; the full run must
stay green with this module added on top.

Verified sources: docs/branding.md («Компактный header и темы»), the stage
brief (header layout, inert login button, single logo, external-only theme
script, dark derived tokens, separated link/button colors, AA contrast).

Coverage split:
- ``HeaderDomTests`` / ``HeadScriptOrderTests`` (tag ``qa_html``) — real DOM
  (html.parser) checks of rendered pages: exactly one logo image per page,
  header control order (logo → Главная → Профиль системы → Войти → theme),
  inert native login button (``aria-disabled``, demo tooltip, no form/POST),
  hero without an image, single non-deferred external ``js/theme.js`` loaded
  before the stylesheet, no inline scripts/handlers.
- ``ThemeJsContractTests`` — static contract of ``static/js/theme.js``: exact
  ``archisec-theme`` localStorage key, dark only for the exact value
  ``dark``, try/catch-guarded read and write, ``DOMContentLoaded`` ``once``
  binding with immediate fallback, button unhidden only at bind, click
  persistence of exactly ``light``/``dark``, Russian labels and
  ``aria-pressed`` state, no other storage/network/user-data APIs.
- ``HeaderCssTests`` (tag ``qa_html``) — ``static/style.css`` rules: full
  width header with 16–28px side padding, 72px logo + 6px block padding
  (84px compact header), 44px theme/nav/login targets, single-column hero,
  moon/sun swap rules, ``:root[data-theme="dark"]`` derived token overrides
  with ``color-scheme: dark`` while the brand hex tokens stay untouched, and
  light link color separated from the primary button background.
- ``ThemeContrastTests`` — WCAG 2.x math over the token values parsed from
  style.css (light and dark): links, body/muted text, white-on-button
  (documented 6.55), skip link, focus ring and toggle icons.
- ``FrontendScopeTests`` — no frameworks/CDN resources, single JS asset,
  theme.js served through Django staticfiles.

Browser-level behaviour (real click, storage blocking, responsive 320/768/
1280, keyboard focus) is owned by the orchestrator's headless browser pass
and is intentionally not duplicated here.
"""

import re
from html.parser import HTMLParser
from pathlib import Path

from django.contrib.staticfiles import finders
from django.test import SimpleTestCase, tag

BASE_DIR = Path(__file__).resolve().parent.parent
CSS_PATH = BASE_DIR / "static" / "style.css"
JS_PATH = BASE_DIR / "static" / "js" / "theme.js"

HOME_PAGE = "/"
PROFILE_PAGE = "/profile/"
HTML_ANALYZE = "/profile/analyze/"

RESULT_FORM = {
    "system_type": "web",
    "interfaces": ["web"],
    "internet_exposed": "on",
    "data_classes": ["confidentiality"],
}

BRAND_GREEN = "#6AAF9C"
BRAND_BLUE = "#4182AE"
ACCENT_DARK = "#2F6285"
ACCENT_HOVER_DARK = "#254C68"


# ---------------------------------------------------------------------------
# Minimal DOM (html.parser) — document order, attributes, ancestors
# ---------------------------------------------------------------------------

VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
}


class Node:
    def __init__(self, tag, attrs, parent):
        self.tag = tag
        self.attrs = {}
        for key, value in attrs:
            # Boolean attributes arrive as None and mean "present".
            self.attrs[key] = "" if value is None else value
        self.parent = parent
        self.children = []
        self.text_parts = []

    @property
    def text(self):
        return "".join(self.text_parts).strip()

    def classes(self):
        return (self.attrs.get("class") or "").split()

    def iter(self):
        yield self
        for child in self.children:
            yield from child.iter()

    def ancestors(self):
        node = self.parent
        while node is not None and node.tag != "#root":
            yield node
            node = node.parent


class PageBuilder(HTMLParser):
    """Builds a light DOM preserving document order and parent links."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("#root", [], None)
        self.stack = [self.root]
        self.order = []

    def _append(self, tag, attrs):
        node = Node(tag, attrs, self.stack[-1])
        self.stack[-1].children.append(node)
        self.order.append(node)
        return node

    def handle_starttag(self, tag, attrs):
        node = self._append(tag, attrs)
        if tag not in VOID_TAGS:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self._append(tag, attrs)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == tag:
                del self.stack[index:]
                return

    def handle_data(self, data):
        self.stack[-1].text_parts.append(data)


def parse_page(html):
    builder = PageBuilder()
    builder.feed(html)
    builder.root.order = builder.order
    return builder.root


def find_all(root, tag=None, class_=None, attrs=None):
    matched = []
    for node in root.iter():
        if node.tag == "#root":
            continue
        if tag is not None and node.tag != tag:
            continue
        if class_ is not None and class_ not in node.classes():
            continue
        if attrs is not None:
            ok = True
            for key, expected in attrs.items():
                if expected is True:
                    if key not in node.attrs:
                        ok = False
                        break
                elif node.attrs.get(key) != expected:
                    ok = False
                    break
            if not ok:
                continue
        matched.append(node)
    return matched


def find_one(root, *args, **kwargs):
    matches = find_all(root, *args, **kwargs)
    assert matches, f"no element for {args} {kwargs}"
    return matches[0]


def position(root, node):
    return root.order.index(node)


def ancestor_tags(node):
    return {ancestor.tag for ancestor in node.ancestors()}


class RenderedPages:
    """Home, profile and result pages rendered once per test class."""

    @staticmethod
    def pages(client):
        pages = {}
        pages["home"] = client.get(HOME_PAGE).content.decode()
        pages["profile"] = client.get(PROFILE_PAGE).content.decode()
        response = client.post(HTML_ANALYZE, RESULT_FORM)
        assert response.status_code == 200, response.status_code
        pages["result"] = response.content.decode()
        return pages


# ---------------------------------------------------------------------------
# Rendered header DOM
# ---------------------------------------------------------------------------


@tag("qa_html")
class HeaderDomTests(SimpleTestCase):
    """Header structure on home, profile and result pages (real DOM)."""

    def setUp(self):
        self.pages = {}
        for name, html in RenderedPages.pages(self.client).items():
            self.pages[name] = parse_page(html)

    def test_every_page_renders_200_with_header_and_single_logo(self):
        for name, root in self.pages.items():
            with self.subTest(page=name):
                header = find_one(root, tag="header")
                self.assertIn("site-header", header.classes())
                images = find_all(root, tag="img")
                self.assertEqual(
                    len(images), 1,
                    "exactly one <img> per page: the header logo",
                )
                logo = images[0]
                self.assertIn("brand-logo", logo.classes())
                self.assertIn("archisec-logo.png", logo.attrs.get("src", ""))
                self.assertTrue(logo.attrs.get("alt", "").strip())
                self.assertGreater(
                    position(root, logo), position(root, header),
                    "the single logo lives inside the header",
                )

    def test_brand_block_is_logo_link_and_demo_badge_without_brand_name(self):
        for name, root in self.pages.items():
            with self.subTest(page=name):
                header = find_one(root, tag="header")
                brand = find_one(header, class_="brand")
                self.assertEqual(
                    find_all(root, class_="brand-name"), [],
                    "brand-name text was removed from the header",
                )
                logo_link = find_one(brand, tag="a")
                self.assertEqual(len(find_all(logo_link, tag="img")), 1)
                badges = find_all(brand, tag="span", class_="badge")
                self.assertEqual(len(badges), 1)
                self.assertEqual(badges[0].text, "Демонстрация")
                # No extra textual brand wordmark next to the logo.
                direct_text = [
                    part.strip()
                    for part in brand.text_parts
                    if part.strip()
                ]
                self.assertEqual(direct_text, [])
                brand_words = [
                    node.text
                    for node in brand.iter()
                    if node.tag in {"span", "strong", "em", "b"}
                    and node.text.strip() == "АрхиСек"
                ]
                self.assertEqual(brand_words, [])

    def test_header_navigation_order_matches_the_contract(self):
        for name, root in self.pages.items():
            with self.subTest(page=name):
                header = find_one(root, tag="header")
                nav = find_one(header, tag="nav")
                self.assertEqual(
                    nav.attrs.get("aria-label"), "Основная навигация"
                )
                links = [
                    node for node in nav.iter()
                    if node.tag == "a" and node.parent.tag == "li"
                ]
                self.assertEqual(
                    [link.text for link in links],
                    ["Главная", "Профиль системы"],
                )
                self.assertEqual(links[0].attrs.get("href"), "/")
                self.assertEqual(links[1].attrs.get("href"), "/profile/")

                login = find_one(header, class_="login-button")
                theme = find_one(header, attrs={"id": "theme-toggle"})
                logo_a = find_one(find_one(root, class_="brand"), tag="a")
                self.assertEqual(login.text, "Войти")
                order = [
                    position(root, logo_a),
                    position(root, links[0]),
                    position(root, links[1]),
                    position(root, login),
                    position(root, theme),
                ]
                self.assertEqual(
                    order, sorted(order),
                    "header order must be logo → nav → login → theme toggle",
                )

    def test_theme_toggle_is_rightmost_header_control(self):
        for name, root in self.pages.items():
            with self.subTest(page=name):
                header = find_one(root, tag="header")
                controls = [
                    node for node in header.iter()
                    if node.tag in {"a", "button", "input", "select"}
                    and node.attrs.get("type") not in {"hidden"}
                ]
                theme = find_one(header, attrs={"id": "theme-toggle"})
                self.assertIs(controls[-1], theme)
                self.assertEqual(theme.tag, "button")

    def test_theme_button_starts_hidden_unpressed_with_russian_labels(self):
        for name, root in self.pages.items():
            with self.subTest(page=name):
                theme = find_one(root, attrs={"id": "theme-toggle"})
                self.assertEqual(theme.attrs.get("type"), "button")
                self.assertIn("hidden", theme.attrs,
                              "progressive enhancement: hidden until JS binds")
                self.assertEqual(theme.attrs.get("aria-pressed"), "false")
                self.assertEqual(
                    theme.attrs.get("aria-label"), "Включить тёмную тему"
                )
                self.assertEqual(
                    theme.attrs.get("title"), "Включить тёмную тему"
                )
                icons = find_all(theme, tag="svg")
                self.assertEqual(len(icons), 2)
                for icon in icons:
                    self.assertEqual(icon.attrs.get("aria-hidden"), "true")
                    self.assertEqual(icon.attrs.get("focusable"), "false")
                moon = find_one(theme, class_="theme-icon-moon")
                sun = find_one(theme, class_="theme-icon-sun")
                self.assertEqual(moon.tag, sun.tag, "moon and sun SVG icons")
                text = find_one(theme, class_="theme-toggle-text")
                self.assertIn("visually-hidden", text.classes())
                self.assertEqual(text.text, "Тёмная тема")

    def test_login_button_is_inert_native_and_explicitly_demo(self):
        for name, root in self.pages.items():
            with self.subTest(page=name):
                login = find_one(root, class_="login-button")
                self.assertEqual(login.tag, "button",
                                  "native button, not a link pretending")
                self.assertEqual(login.attrs.get("type"), "button")
                self.assertEqual(login.attrs.get("aria-disabled"), "true")
                title = login.attrs.get("title", "")
                self.assertTrue(title)
                self.assertIn("демонстрац", title.lower())
                self.assertIn("недоступн", title.lower())
                # Inert: no submit, no navigation, no scripted behaviour.
                for forbidden in ("onclick", "formaction", "form", "href"):
                    self.assertNotIn(forbidden, login.attrs)
                self.assertNotIn("form", ancestor_tags(login))
                self.assertNotIn("a", ancestor_tags(login))

    def test_header_has_no_form_and_only_profile_form_posts_to_analyze(self):
        for name, root in self.pages.items():
            with self.subTest(page=name):
                header = find_one(root, tag="header")
                self.assertEqual(find_all(header, tag="form"), [])
                for form in find_all(root, tag="form"):
                    self.assertEqual(form.attrs.get("method"), "post")
                    self.assertEqual(
                        form.attrs.get("action"), HTML_ANALYZE
                    )

    def test_home_hero_contains_no_image(self):
        root = self.pages["home"]
        hero = find_one(root, class_="hero")
        self.assertEqual(hero.tag, "section")
        self.assertEqual(find_all(hero, tag="img"), [])
        self.assertEqual(
            len(find_all(root, tag="img")), 1,
            "single logo: no second image anywhere on the page",
        )

    def test_html_root_is_russian_without_server_side_data_theme(self):
        for name, root in self.pages.items():
            with self.subTest(page=name):
                html_tag = root.children[0]
                self.assertEqual(html_tag.tag, "html")
                self.assertEqual(html_tag.attrs.get("lang"), "ru")
                self.assertNotIn(
                    "data-theme", html_tag.attrs,
                    "data-theme is applied only by client script",
                )

    def test_skip_link_is_the_first_body_control(self):
        for name, root in self.pages.items():
            with self.subTest(page=name):
                skip = find_one(root, class_="skip-link")
                self.assertEqual(skip.tag, "a")
                self.assertEqual(skip.attrs.get("href"), "#content")
                header = find_one(root, tag="header")
                self.assertLess(position(root, skip), position(root, header))

    def test_favicon_targets_the_static_logo_png(self):
        root = self.pages["home"]
        icons = [
            link for link in find_all(root, tag="link")
            if "icon" in (link.attrs.get("rel") or "")
        ]
        self.assertTrue(icons, "favicon link is present")
        self.assertTrue(
            any(
                "archisec-logo.png" in link.attrs.get("href", "")
                and link.attrs.get("href", "").startswith("/static/")
                for link in icons
            ),
            [link.attrs.get("href") for link in icons],
        )


# ---------------------------------------------------------------------------
# Head resource order: one external script before the stylesheet
# ---------------------------------------------------------------------------


@tag("qa_html")
class HeadScriptOrderTests(SimpleTestCase):
    """Theme bootstrap loads early, externally, and without inline JS."""

    def setUp(self):
        self.pages = RenderedPages.pages(self.client)

    def test_single_external_theme_script_and_no_inline_javascript(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                root = parse_page(html)
                scripts = find_all(root, tag="script")
                self.assertEqual(
                    len(scripts), 1,
                    "exactly one script: the external theme bootstrap",
                )
                script = scripts[0]
                self.assertTrue(
                    script.attrs.get("src", "").endswith("/static/js/theme.js"),
                    script.attrs.get("src"),
                )
                self.assertEqual(
                    "".join(script.text_parts).strip(), "",
                    "the script element itself must stay empty",
                )
                self.assertIn("theme.js", html)

    def test_theme_script_is_not_deferred_or_async_or_modular(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                root = parse_page(html)
                script = find_one(root, tag="script")
                self.assertNotIn(
                    "defer", script.attrs,
                    "updated contract: blocking head script before CSS",
                )
                self.assertNotIn("async", script.attrs)
                self.assertNotIn("type", script.attrs)
                self.assertNotIn("crossorigin", script.attrs)
                self.assertNotIn("integrity", script.attrs)

    def test_theme_script_precedes_the_stylesheet_in_the_head(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                root = parse_page(html)
                script = find_one(root, tag="script")
                styles = [
                    link for link in find_all(root, tag="link")
                    if link.attrs.get("rel") == "stylesheet"
                ]
                self.assertEqual(len(styles), 1)
                stylesheet = styles[0]
                self.assertTrue(
                    stylesheet.attrs.get("href", "").endswith("/static/style.css")
                )
                self.assertLess(
                    position(root, script), position(root, stylesheet),
                    "script runs before the stylesheet link to avoid flashes",
                )

    def test_no_inline_event_handlers_anywhere(self):
        handler_re = re.compile(r'\son[a-z]+\s*=', re.IGNORECASE)
        for name, html in self.pages.items():
            with self.subTest(page=name):
                self.assertIsNone(
                    handler_re.search(html),
                    "no inline event handler attributes",
                )

    def test_head_references_only_local_static_resources(self):
        for name, html in self.pages.items():
            with self.subTest(page=name):
                root = parse_page(html)
                head = find_one(root, tag="head")
                for node in head.iter():
                    for attribute in ("src", "href"):
                        value = node.attrs.get(attribute, "")
                        if value:
                            self.assertTrue(
                                value.startswith("/") or value.startswith("#")
                                or value.startswith("{%"),
                                f"non-local head resource: {value}",
                            )
                self.assertNotIn("http://", html)
                self.assertNotIn("https://", html)


# ---------------------------------------------------------------------------
# static/js/theme.js contract
# ---------------------------------------------------------------------------


class ThemeJsContractTests(SimpleTestCase):
    """Static source contract of the client theme bootstrap."""

    @staticmethod
    def js():
        return JS_PATH.read_text(encoding="utf-8")

    def test_file_exists_as_strict_iife_without_frameworks(self):
        self.assertTrue(JS_PATH.exists(), "static/js/theme.js must exist")
        js = self.js()
        self.assertTrue(js.strip().startswith("(function"))
        self.assertIn('"use strict"', js)
        for framework in ("jQuery", "angular", "react", "vue", "DOMContentLoaded-lib"):
            self.assertNotIn(framework, js)

    def test_localstorage_only_with_the_single_archisec_theme_key(self):
        js = self.js()
        self.assertIn('var key = "archisec-theme"', js)
        calls = re.findall(r"localStorage\.(?:getItem|setItem)\(([^,)]+)", js)
        self.assertGreaterEqual(len(calls), 2)
        for argument in calls:
            self.assertEqual(
                argument.strip(), "key",
                "every storage call must use the single theme key",
            )
        for other_storage in (
            "sessionStorage", "document.cookie", "indexedDB", "caches.",
        ):
            self.assertNotIn(other_storage, js)

    def test_storage_read_and_write_are_individually_try_catch_guarded(self):
        js = self.js()
        self.assertRegex(
            js, r"try\s*\{[^{}]*localStorage\.getItem",
            "the read must tolerate blocked storage",
        )
        self.assertRegex(
            js, r"try\s*\{[^{}]*localStorage\.setItem",
            "the write must tolerate blocked storage",
        )
        self.assertGreaterEqual(js.count("catch"), 2)

    def test_dark_is_applied_only_for_the_exact_saved_dark_value(self):
        js = self.js()
        self.assertIn('localStorage.getItem(key) === "dark"', js)
        self.assertIn('dataset.theme = "dark"', js)
        self.assertNotIn('!== "dark"', js)

    def test_light_state_removes_the_data_theme_attribute(self):
        js = self.js()
        self.assertIn('removeAttribute("data-theme")', js)
        self.assertIn('dataset.theme === "dark" ? "dark" : "light"', js)

    def test_binding_uses_domcontentloaded_once_with_immediate_fallback(self):
        js = self.js()
        self.assertIn('document.readyState === "loading"', js)
        self.assertRegex(
            js,
            r'addEventListener\(\s*"DOMContentLoaded"\s*,\s*\w+\s*,'
            r'\s*\{\s*once\s*:\s*true\s*\}\s*\)',
        )
        self.assertIn("bindToggle()", js)

    def test_toggle_is_unhidden_only_when_bound_and_reacts_to_clicks(self):
        js = self.js()
        self.assertIn('getElementById("theme-toggle")', js)
        self.assertIn("button.hidden = false", js)
        self.assertIn('addEventListener("click"', js)
        self.assertIn("return", js)  # missing button stays hidden (no-JS safe)

    def test_click_persists_exactly_light_or_dark_strings(self):
        js = self.js()
        self.assertIn('"dark" : "light"', js)
        persisted = re.search(
            r'setItem\(\s*key\s*,\s*([^)]+)\)', js
        )
        self.assertIsNotNone(persisted)
        self.assertIn("dark", persisted.group(1))
        self.assertIn("light", persisted.group(1))
        for value in ('"true"', '"on"', '"1"'):
            self.assertNotIn(f"setItem(key, {value})", js)

    def test_state_updates_aria_pressed_and_russian_labels(self):
        js = self.js()
        self.assertIn('"aria-pressed"', js)
        self.assertIn("String(dark)", js)
        self.assertIn("Включить светлую тему", js)
        self.assertIn("Включить тёмную тему", js)
        self.assertIn("Светлая тема", js)
        self.assertIn("Тёмная тема", js)
        self.assertIn("aria-label", js)
        self.assertIn("title", js)

    def test_no_user_data_network_or_dynamic_code_apis(self):
        js = self.js()
        for forbidden in (
            "fetch(", "XMLHttpRequest", "navigator.sendBeacon", "matchMedia",
            "eval(", "Function(", "document.write", "userData", "require(",
            "import ", "localStorage.removeItem",
        ):
            self.assertNotIn(forbidden, js)

    def test_theme_js_contains_no_external_urls(self):
        js = self.js()
        for scheme in ("http://", "https://", "//cdn", "cdn.", "unpkg", "jsdelivr"):
            self.assertNotIn(scheme, js)


# ---------------------------------------------------------------------------
# CSS rule/token inspection
# ---------------------------------------------------------------------------


def css_source():
    return CSS_PATH.read_text(encoding="utf-8")


def parse_rules(css):
    """(selector, declarations) pairs; @media bodies are flattened."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    rules = []

    def scan(segment):
        position = 0
        while True:
            opening = segment.find("{", position)
            if opening == -1:
                return
            selector = segment[position:opening].strip()
            depth, index = 1, opening + 1
            while index < len(segment) and depth:
                if segment[index] == "{":
                    depth += 1
                elif segment[index] == "}":
                    depth -= 1
                index += 1
            body = segment[opening + 1:index - 1]
            if selector.startswith("@media") or selector.startswith("@supports"):
                scan(body)
            elif selector:
                for part in selector.split(","):
                    rules.append((part.strip(), body.strip()))
            position = index

    scan(css)
    return rules


def declaration(rules, selector):
    for candidate, body in rules:
        if candidate == selector:
            return body
    raise AssertionError(f"selector {selector!r} not found in style.css")


def property_value(body, name):
    match = re.search(rf"(?:^|[;{{\s]){re.escape(name)}\s*:\s*([^;]+);", body)
    return match.group(1).strip() if match else None


def token(body, name):
    return property_value(body, f"--{name}")


@tag("qa_html")
class HeaderCssTests(SimpleTestCase):
    """Header/theme rules of static/style.css."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.css = css_source()
        cls.rules = parse_rules(cls.css)
        cls.light = declaration(cls.rules, ":root")
        cls.dark = declaration(cls.rules, ':root[data-theme="dark"]')

    def test_header_inner_is_full_width_with_16_to_28_side_padding(self):
        body = declaration(self.rules, ".header-inner")
        self.assertEqual(property_value(body, "max-width"), "none")
        padding = property_value(body, "padding-inline")
        self.assertIsNotNone(padding)
        match = re.match(r"clamp\(\s*(\d+)px\s*,\s*[^,]+,\s*(\d+)px\s*\)", padding)
        self.assertIsNotNone(match, padding)
        low, high = int(match.group(1)), int(match.group(2))
        self.assertGreaterEqual(low, 16)
        self.assertLessEqual(high, 28)
        self.assertEqual(property_value(body, "padding-block"), "6px")

    def test_compact_header_logo_is_72px_with_84px_total_band(self):
        body = declaration(self.rules, ".brand-logo")
        self.assertEqual(property_value(body, "width"), "72px")
        self.assertEqual(property_value(body, "height"), "auto")
        header_body = declaration(self.rules, ".header-inner")
        block = int(property_value(header_body, "padding-block").rstrip("px"))
        self.assertEqual(72 + 2 * block, 84)
        self.assertNotIn("145", self.css,
                         "the old 145px desktop logo size is gone")

    def test_no_brand_name_selector_or_hero_media_leftovers(self):
        for selector in (".brand-name", ".hero-media", ".hero-image", ".hero-logo"):
            self.assertIsNone(
                next((body for name, body in self.rules if selector in name), None),
                f"{selector} must not survive the redesign",
            )

    def test_hero_is_a_single_column_grid(self):
        body = declaration(self.rules, ".hero")
        columns = property_value(body, "grid-template-columns")
        self.assertEqual(columns, "1fr",
                         "two-column hero layout was removed")

    def test_theme_toggle_is_a_44px_touch_target(self):
        body = declaration(self.rules, ".theme-toggle")
        self.assertEqual(property_value(body, "width"), "44px")
        self.assertEqual(property_value(body, "min-width"), "44px")
        self.assertEqual(property_value(body, "height"), "44px")

    def test_nav_and_login_controls_are_44px_minimum(self):
        body = declaration(self.rules, ".login-button")
        self.assertEqual(property_value(body, "min-height"), "44px")
        nav_body = declaration(self.rules, ".nav a")
        self.assertEqual(property_value(nav_body, "min-height"), "44px")

    def test_hidden_toggle_is_display_none_until_bound(self):
        body = declaration(self.rules, ".theme-toggle[hidden]")
        self.assertEqual(property_value(body, "display"), "none")

    def test_moon_sun_swap_rules_follow_the_dark_attribute(self):
        sun = declaration(self.rules, ".theme-icon-sun")
        self.assertEqual(property_value(sun, "display"), "none")
        moon_hidden = declaration(
            self.rules, ':root[data-theme="dark"] .theme-icon-moon'
        )
        sun_shown = declaration(
            self.rules, ':root[data-theme="dark"] .theme-icon-sun'
        )
        self.assertEqual(property_value(moon_hidden, "display"), "none")
        self.assertEqual(property_value(sun_shown, "display"), "block")

    def test_dark_block_overrides_derived_tokens_and_color_scheme(self):
        self.assertEqual(property_value(self.dark, "color-scheme"), "dark")
        self.assertEqual(property_value(self.light, "color-scheme"), "light")
        overridden = [
            "bg", "surface", "surface-2", "header-bg", "ink", "muted",
            "border", "border-strong", "accent", "accent-strong",
            "accent-soft", "accent-border", "input-bg", "notice-bg",
            "button-bg", "button-hover", "skip-ink",
            "demo-ink", "demo-bg", "demo-border",
        ]
        # --button-ink stays #ffffff in both themes (white on the blue
        # button); it is redefined for completeness, not changed.
        redefined_only = ["button-ink"]
        for name in overridden + redefined_only:
            with self.subTest(token=name):
                dark_value = token(self.dark, name)
                self.assertIsNotNone(dark_value, f"--{name} missing in dark")
                if name not in redefined_only:
                    self.assertNotEqual(
                        dark_value, token(self.light, name),
                        f"--{name} must be redefined for the dark theme",
                    )

    def test_dark_block_does_not_redefine_brand_hex_tokens(self):
        for name in ("archisec-green", "archisec-blue"):
            with self.subTest(token=name):
                self.assertIsNone(
                    token(self.dark, name),
                    "brand hexes stay defined once in :root",
                )
        self.assertEqual(token(self.light, "archisec-green"), BRAND_GREEN)
        self.assertEqual(token(self.light, "archisec-blue"), BRAND_BLUE)

    def test_light_links_are_separated_from_the_primary_button(self):
        self.assertEqual(token(self.light, "accent"), ACCENT_DARK)
        self.assertEqual(
            token(self.light, "button-bg"), "var(--accent)",
            "light button reuses the contrast accent",
        )
        self.assertEqual(token(self.light, "button-ink"), "#ffffff")
        self.assertEqual(token(self.light, "button-hover"), "var(--accent-strong)")
        self.assertEqual(token(self.light, "accent-strong"), ACCENT_HOVER_DARK)
        self.assertEqual(token(self.light, "archisec-blue"), BRAND_BLUE)

    def test_dark_button_tokens_are_the_pinned_brand_values(self):
        self.assertEqual(token(self.dark, "button-bg"), ACCENT_DARK)
        self.assertEqual(token(self.dark, "button-hover"), ACCENT_HOVER_DARK)
        self.assertEqual(token(self.dark, "button-ink"), "#ffffff")
        # Dark links use a bright accent distinct from the button background.
        self.assertEqual(token(self.dark, "accent"), "#8fc3e0")
        self.assertNotEqual(
            token(self.dark, "accent"), token(self.dark, "button-bg")
        )

    def test_skip_link_colors_come_from_theme_tokens(self):
        body = declaration(self.rules, ".skip-link")
        self.assertEqual(property_value(body, "background"), "var(--ink)")
        self.assertEqual(property_value(body, "color"), "var(--skip-ink)")

    def test_no_css_imports_or_external_resources(self):
        self.assertNotIn("@import", self.css)
        for external in ("http://", "https://", "url("):
            self.assertNotIn(external, self.css)

    def test_theme_ignores_system_color_preference(self):
        self.assertNotIn(
            "prefers-color-scheme", self.css,
            "absent/invalid stored choice means light, not system dark",
        )


# ---------------------------------------------------------------------------
# WCAG contrast over the parsed token values
# ---------------------------------------------------------------------------


def srgb_channel(value):
    scaled = value / 255.0
    if scaled <= 0.04045:
        return scaled / 12.92
    return ((scaled + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_color):
    digits = hex_color.lstrip("#")
    assert len(digits) == 6 and not digits.startswith("var"), hex_color
    red, green, blue = (int(digits[i:i + 2], 16) for i in (0, 2, 4))
    return (
        0.2126 * srgb_channel(red)
        + 0.7152 * srgb_channel(green)
        + 0.0722 * srgb_channel(blue)
    )


def contrast_ratio(first, second):
    one, two = relative_luminance(first), relative_luminance(second)
    lighter, darker = max(one, two), min(one, two)
    return (lighter + 0.05) / (darker + 0.05)


@tag("qa_html")
class ThemeContrastTests(SimpleTestCase):
    """AA (4.5:1 text, 3:1 focus/non-text) in both themes, from tokens."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        rules = parse_rules(css_source())
        cls.tokens = {}
        for selector in (":root", ':root[data-theme="dark"]'):
            body = declaration(rules, selector)
            for name, value in re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", body):
                cls.tokens.setdefault(selector, {})[name] = value.strip()
        cls.light = cls.tokens[":root"]
        cls.dark = cls.tokens[':root[data-theme="dark"]']

    def resolved(self, theme, name):
        value = theme[f"--{name}"]
        if value.startswith("var("):
            inner = value[4:-1].strip()
            return theme[inner]
        return value

    def test_self_check_of_the_math(self):
        self.assertAlmostEqual(
            contrast_ratio("#000000", "#FFFFFF"), 21.0, delta=0.01
        )

    def test_light_link_contrast_on_page_and_surface(self):
        accent = self.resolved(self.light, "accent")
        self.assertGreaterEqual(
            contrast_ratio(accent, self.resolved(self.light, "bg")), 4.5
        )
        self.assertGreaterEqual(
            contrast_ratio(accent, self.resolved(self.light, "surface")), 4.5
        )

    def test_dark_link_contrast_on_page_and_surface(self):
        accent = self.resolved(self.dark, "accent")
        self.assertGreaterEqual(
            contrast_ratio(accent, self.resolved(self.dark, "bg")), 4.5
        )
        self.assertGreaterEqual(
            contrast_ratio(accent, self.resolved(self.dark, "surface")), 4.5
        )

    def test_body_text_contrast_in_both_themes(self):
        for label, theme in (("light", self.light), ("dark", self.dark)):
            with self.subTest(theme=label):
                ink = self.resolved(theme, "ink")
                self.assertGreaterEqual(
                    contrast_ratio(ink, self.resolved(theme, "bg")), 4.5
                )
                self.assertGreaterEqual(
                    contrast_ratio(ink, self.resolved(theme, "surface")), 4.5
                )

    def test_muted_text_contrast_in_both_themes(self):
        for label, theme in (("light", self.light), ("dark", self.dark)):
            with self.subTest(theme=label):
                self.assertGreaterEqual(
                    contrast_ratio(
                        self.resolved(theme, "muted"),
                        self.resolved(theme, "bg"),
                    ),
                    4.5,
                )

    def test_primary_button_white_text_documented_ratios(self):
        for label, theme in (("light", self.light), ("dark", self.dark)):
            with self.subTest(theme=label):
                ink = self.resolved(theme, "button-ink")
                background = self.resolved(theme, "button-bg")
                hover = self.resolved(theme, "button-hover")
                self.assertGreaterEqual(
                    contrast_ratio(ink, background), 6.5,
                    f"{label}: white on #2F6285 is documented as 6.55",
                )
                self.assertGreaterEqual(contrast_ratio(ink, hover), 6.5)
        self.assertAlmostEqual(
            contrast_ratio("#ffffff", ACCENT_DARK), 6.55, delta=0.05
        )

    def test_skip_link_contrast_in_both_themes(self):
        for label, theme in (("light", self.light), ("dark", self.dark)):
            with self.subTest(theme=label):
                background = self.resolved(theme, "ink")
                ink = self.resolved(theme, "skip-ink")
                self.assertGreaterEqual(
                    contrast_ratio(ink, background), 4.5
                )

    def test_focus_ring_contrast_in_both_themes(self):
        for label, theme in (("light", self.light), ("dark", self.dark)):
            with self.subTest(theme=label):
                self.assertGreaterEqual(
                    contrast_ratio(
                        self.resolved(theme, "accent"),
                        self.resolved(theme, "bg"),
                    ),
                    3.0,
                )

    def test_toggle_icon_contrast_in_both_themes(self):
        for label, theme in (("light", self.light), ("dark", self.dark)):
            with self.subTest(theme=label):
                self.assertGreaterEqual(
                    contrast_ratio(
                        self.resolved(theme, "accent-strong"),
                        self.resolved(theme, "surface-2"),
                    ),
                    3.0,
                    "the visible moon/sun icon must stay perceivable",
                )


# ---------------------------------------------------------------------------
# Frontend-only scope: no new dependencies or assets
# ---------------------------------------------------------------------------


class FrontendScopeTests(SimpleTestCase):
    """The stage adds one JS asset and no external dependencies."""

    def test_static_js_directory_has_exactly_one_file_theme_js(self):
        files = sorted(
            path.relative_to(BASE_DIR / "static").as_posix()
            for path in (BASE_DIR / "static" / "js").rglob("*")
            if path.is_file()
        )
        self.assertEqual(files, ["js/theme.js"])

    def test_no_cdn_or_framework_references_in_frontend_sources(self):
        sources = {
            path: path.read_text(encoding="utf-8")
            for path in [
                BASE_DIR / "templates" / "base.html",
                BASE_DIR / "templates" / "home.html",
                BASE_DIR / "templates" / "profile.html",
                BASE_DIR / "templates" / "result.html",
                CSS_PATH,
                JS_PATH,
            ]
        }
        for path, text in sources.items():
            with self.subTest(file=path.name):
                for marker in (
                    "http://", "https://", "cdn", "googleapis",
                    "unpkg", "jsdelivr", "integrity=",
                ):
                    self.assertNotIn(marker, text.lower())

    def test_theme_js_resolves_through_staticfiles(self):
        resolved = finders.find("js/theme.js")
        self.assertIsNotNone(resolved)
        self.assertEqual(Path(resolved).resolve(), JS_PATH.resolve())

    def test_base_template_keeps_brand_logo_reference_without_inline_js(self):
        text = (BASE_DIR / "templates" / "base.html").read_text(encoding="utf-8")
        self.assertIn("img/archisec-logo.png", text)
        self.assertIn("js/theme.js", text)
        self.assertNotIn("<script>", text.replace('<script src=', ""),
                         "only the external script tag is allowed")
        self.assertNotIn("brand-name", text)
