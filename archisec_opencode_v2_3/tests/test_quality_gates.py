"""Comprehensive quality-gate tests for the ArchiSec demo MVP.

Covers the gates from docs/quality_gates.md and docs/mvp.md:

- API input robustness: malformed/empty/non-UTF-8 JSON, JSON parse-boundary
  failures (oversized integer literals, extremely deep nesting), JSON
  non-objects, nulls, wrong scalar/list/item types, string booleans. The API
  must answer 400 with a stable error code and must never answer 500.
- Valid analysis: documented defaults, ``AnalysisResult`` shape, equality with
  the shared ``analyze_profile()`` service, HTML/API consistency.
- CSRF: the HTML form enforces Django CSRF; the JSON analyze endpoint is
  explicitly ``csrf_exempt`` (documented demo limitation).
- Catalog APIs: every list endpoint returns ``{"source": "demo", "items": ...}``
  matching the seed JSON, detail returns 200/404, methods are restricted.
- Demo provenance: every seed entity lives in the ``DEMO-`` namespace, mapping
  references included; no real regulatory identifiers.
- Mappings: full integrity of the seed file plus canonical/reverse derivation,
  unknown references, reverse-only entries and duplicates verified against
  synthetic in-memory payloads (no repository files are modified).
- Scope: no ORM, ``Model.objects``, migrations, auth/session dependencies,
  database backend, Redis or Celery in production code/config.

Mapping tests import ``services.mappings`` and read ``data/mappings.json``
lazily; the remaining tests exercise only catalog data and view/service code.
"""

import json
import re
import sys
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.test import Client, SimpleTestCase

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

API_ANALYZE = "/api/profile/analyze/"
HTML_ANALYZE = "/profile/analyze/"
PROFILE_PAGE = "/profile/"
HOME_PAGE = "/"

# Entity catalogs that exist as seed files (mappings.json is handled separately).
CATALOG_FILES = {
    "threats": "threats.json",
    "measures": "measures.json",
    "tools": "tools.json",
    "tactics": "tactics.json",
    "ai_threats": "ai_threats.json",
    "levels": "levels.json",
    "techniques": "techniques.json",
}

# Catalogs exposed as JSON list endpoints per docs/mvp.md.
CATALOG_ENDPOINTS = {
    "threats": "/api/threats/",
    "measures": "/api/measures/",
    "tools": "/api/tools/",
    "tactics": "/api/tactics/",
    "ai_threats": "/api/ai-threats/",
    "levels": "/api/levels/",
}

PROFILE_FIELDS = ("system_type", "interfaces", "data_classes", "internet_exposed", "uses_ai")

# Canonical profile from docs/mvp.md.
MVP_PROFILE = {
    "system_type": "web",
    "interfaces": ["web", "api"],
    "internet_exposed": True,
    "data_classes": ["confidentiality"],
    "uses_ai": False,
}

CSRF_TOKEN_RE = re.compile(r'name="csrfmiddlewaretoken" value="([^"]+)"')


def read_seed(name):
    """Parse a seed catalog file independently of the repository layer."""
    with (DATA_DIR / CATALOG_FILES[name]).open(encoding="utf-8") as handle:
        return json.load(handle)


def walk_strings(node):
    """Yield every string value nested in JSON-like data."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for item in node:
            yield from walk_strings(item)
    elif isinstance(node, dict):
        for value in node.values():
            yield from walk_strings(value)


# ---------------------------------------------------------------------------
# Invalid API input: JSON transport and parse-boundary failures
# ---------------------------------------------------------------------------


class ApiInvalidInputTests(SimpleTestCase):
    """Malformed/empty/non-decodable bodies and JSON non-objects → 400, not 500."""

    def post_raw(self, body, content_type="application/json"):
        return self.client.post(API_ANALYZE, data=body, content_type=content_type)

    def assert_invalid_json(self, response):
        self.assertLess(response.status_code, 500)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response["Content-Type"].startswith("application/json"))
        self.assertEqual(response.json(), {"error": "invalid_json"})

    def assert_object_required(self, response):
        self.assertLess(response.status_code, 500)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response["Content-Type"].startswith("application/json"))
        payload = response.json()
        self.assertEqual(payload.get("error"), "object_required")
        self.assertIsInstance(payload.get("message"), str)
        self.assertTrue(payload["message"])

    def test_malformed_truncated_object(self):
        self.assert_invalid_json(self.post_raw(b'{"system_type": "web",'))

    def test_malformed_lone_brace(self):
        self.assert_invalid_json(self.post_raw(b"{"))

    def test_malformed_trailing_garbage(self):
        self.assert_invalid_json(self.post_raw(b"{} trailing"))

    def test_empty_body(self):
        self.assert_invalid_json(self.post_raw(b""))

    def test_whitespace_only_body(self):
        self.assert_invalid_json(self.post_raw(b"   \n\t "))

    def test_non_utf8_bytes_body(self):
        # Invalid UTF-8 bytes cannot be decoded by json.loads either.
        self.assert_invalid_json(self.post_raw(b"\x80\x81\x82\x83"))

    def test_json_array_is_not_an_object(self):
        self.assert_object_required(self.post_raw(b'[1, 2, 3]'))

    def test_json_scalars_and_literals_are_not_objects(self):
        for body in (b'"web"', b"42", b"3.14", b"null", b"true", b"false"):
            with self.subTest(body=body):
                self.assert_object_required(self.post_raw(body))


class JsonParseBoundaryTests(SimpleTestCase):
    """Regression: parser-level failures must map to 400 ``invalid_json``.

    ``json.loads`` can raise plain ``ValueError`` (e.g. oversized integer
    literals beyond ``sys.get_int_max_str_digits()``) and ``RecursionError``
    (extremely deep nesting). Neither is a ``json.JSONDecodeError``; the view
    must still answer 400 and never leak a 500 traceback.
    """

    def post_raw(self, body, content_type="application/json"):
        return self.client.post(API_ANALYZE, data=body, content_type=content_type)

    def assert_invalid_json(self, response):
        self.assertLess(response.status_code, 500)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_json"})

    def test_oversized_integer_literal(self):
        get_limit = getattr(sys, "get_int_max_str_digits", lambda: 0)
        limit = get_limit()
        if not limit:
            self.skipTest("integer digit limit is disabled in this interpreter")
        body = b'{"uses_ai": ' + b"1" * (limit + 100) + b"}"
        self.assert_invalid_json(self.post_raw(body))

    def test_oversized_integer_literal_at_boundary(self):
        get_limit = getattr(sys, "get_int_max_str_digits", lambda: 0)
        limit = get_limit()
        if not limit:
            self.skipTest("integer digit limit is disabled in this interpreter")
        body = b'{"internet_exposed": ' + b"9" * (limit + 1) + b"}"
        self.assert_invalid_json(self.post_raw(body))

    def test_extremely_deep_json_nesting(self):
        depth = 100_000
        body = b"[" * depth + b"]" * depth
        self.assert_invalid_json(self.post_raw(body))

    def test_deeply_nested_object_nesting(self):
        depth = 100_000
        body = b'{"interfaces": ' + b"[" * depth + b"]" * depth + b"}"
        self.assert_invalid_json(self.post_raw(body))

    def test_json_loads_value_error_is_invalid_json(self):
        with mock.patch("core.views.json") as fake_json:
            fake_json.loads.side_effect = ValueError("parser boundary")
            response = self.post_raw(b'{"uses_ai": false}')
        self.assert_invalid_json(response)

    def test_json_loads_recursion_error_is_invalid_json(self):
        with mock.patch("core.views.json") as fake_json:
            fake_json.loads.side_effect = RecursionError("parser boundary")
            response = self.post_raw(b'{"uses_ai": false}')
        self.assert_invalid_json(response)


# ---------------------------------------------------------------------------
# Invalid API input: wrong profile types
# ---------------------------------------------------------------------------


class ApiInvalidProfileTypesTests(SimpleTestCase):
    """Type-violating profiles → 400 ``invalid_profile`` naming the field."""

    def post_profile(self, payload):
        return self.client.post(
            API_ANALYZE, data=json.dumps(payload), content_type="application/json"
        )

    def assert_invalid_profile(self, response, field):
        self.assertLess(response.status_code, 500)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response["Content-Type"].startswith("application/json"))
        payload = response.json()
        self.assertEqual(payload.get("error"), "invalid_profile")
        self.assertEqual(payload.get("field"), field)
        self.assertIsInstance(payload.get("message"), str)
        self.assertTrue(payload["message"])

    def test_null_for_every_field(self):
        for field in PROFILE_FIELDS:
            with self.subTest(field=field):
                self.assert_invalid_profile(self.post_profile({field: None}), field)

    def test_system_type_wrong_scalar_types(self):
        for value in (7, 3.14, True, False, ["web"], {"web": 1}, [["web"]]):
            with self.subTest(value=value):
                self.assert_invalid_profile(
                    self.post_profile({"system_type": value}), "system_type"
                )

    def test_list_fields_wrong_container_types(self):
        for field in ("interfaces", "data_classes"):
            for value in ("web", 5, True, None, {"web": 1}, {"0": "web"}):
                with self.subTest(field=field, value=value):
                    self.assert_invalid_profile(
                        self.post_profile({field: value}), field
                    )

    def test_list_fields_wrong_item_types(self):
        for field in ("interfaces", "data_classes"):
            for items in (
                ["web", 1],
                [None],
                [True, False],
                [["nested"]],
                [{"key": "web"}],
                ["web", 3.14, "ok", 2],
            ):
                with self.subTest(field=field, items=items):
                    self.assert_invalid_profile(
                        self.post_profile({field: items}), field
                    )

    def test_string_booleans_are_rejected(self):
        for field in ("internet_exposed", "uses_ai"):
            for value in ("true", "false", "on", "off", "1", "0", "yes", "no", ""):
                with self.subTest(field=field, value=value):
                    self.assert_invalid_profile(
                        self.post_profile({field: value}), field
                    )

    def test_boolean_wrong_types(self):
        for field in ("internet_exposed", "uses_ai"):
            for value in (1, 0, 1.0, [True], {"value": True}):
                with self.subTest(field=field, value=value):
                    self.assert_invalid_profile(
                        self.post_profile({field: value}), field
                    )

    def test_several_invalid_fields_reports_one_of_them(self):
        response = self.post_profile(
            {
                "system_type": 42,
                "interfaces": "web",
                "data_classes": [1],
                "internet_exposed": "yes",
                "uses_ai": 2,
            }
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json().get("error"), "invalid_profile")
        self.assertIn(response.json().get("field"), PROFILE_FIELDS)


# ---------------------------------------------------------------------------
# Valid analysis: defaults, AnalysisResult shape, service equality
# ---------------------------------------------------------------------------


class ApiValidProfileTests(SimpleTestCase):
    """Valid JSON profiles → 200 with the documented AnalysisResult."""

    def post_profile(self, payload):
        return self.client.post(
            API_ANALYZE, data=json.dumps(payload), content_type="application/json"
        )

    def test_empty_object_applies_documented_defaults(self):
        response = self.post_profile({})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(
            payload["profile"],
            {
                "system_type": "web",
                "interfaces": [],
                "data_classes": [],
                "internet_exposed": False,
                "uses_ai": False,
            },
        )

    def test_partial_profile_applies_defaults_for_absent_keys(self):
        response = self.post_profile({"system_type": "internal"})
        self.assertEqual(response.status_code, 200)
        profile = response.json()["profile"]
        self.assertEqual(profile["system_type"], "internal")
        self.assertEqual(profile["interfaces"], [])
        self.assertEqual(profile["data_classes"], [])
        self.assertFalse(profile["internet_exposed"])
        self.assertFalse(profile["uses_ai"])

    def test_mvp_example_profile_analysis_result_shape(self):
        response = self.post_profile(MVP_PROFILE)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response["Content-Type"].startswith("application/json"))
        payload = response.json()
        self.assertEqual(
            set(payload),
            {"profile", "threats", "measures", "tools", "explanations", "statistics", "metadata"},
        )
        self.assertEqual(payload["metadata"], {"source": "demo", "version": "MVP-1"})
        self.assertEqual(
            payload["statistics"],
            {
                "threats": len(payload["threats"]),
                "measures": len(payload["measures"]),
                "tools": len(payload["tools"]),
            },
        )
        self.assertEqual(
            set(payload["profile"]),
            set(PROFILE_FIELDS),
        )
        for collection in ("threats", "measures", "tools"):
            self.assertIsInstance(payload[collection], list)
            for item in payload[collection]:
                self.assertIsInstance(item, dict)
                self.assertTrue(item["code"].startswith("DEMO-"))

    def test_unknown_keys_are_ignored(self):
        response = self.post_profile(
            {"system_type": "web", "extra": {"nested": 1}, "id": 5}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()["profile"]), set(PROFILE_FIELDS))

    def test_non_matching_categories_yield_empty_result(self):
        response = self.post_profile({"system_type": "does-not-exist"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["threats"], [])
        self.assertEqual(payload["measures"], [])
        self.assertEqual(payload["tools"], [])
        self.assertEqual(
            payload["statistics"], {"threats": 0, "measures": 0, "tools": 0}
        )
        self.assertEqual(payload["metadata"], {"source": "demo", "version": "MVP-1"})

    def test_uses_ai_selects_ai_category_threat(self):
        response = self.post_profile({"uses_ai": True})
        self.assertEqual(response.status_code, 200)
        codes = [threat["code"] for threat in response.json()["threats"]]
        self.assertIn("DEMO-T-005", codes)

    def test_response_equals_shared_service_call(self):
        from services.analyzer import analyze_profile

        response = self.post_profile(MVP_PROFILE)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), analyze_profile(MVP_PROFILE))


class HtmlAnalysisTests(SimpleTestCase):
    """Valid HTML form submissions render the shared analysis result."""

    def test_valid_form_renders_result(self):
        response = self.client.post(
            HTML_ANALYZE,
            {
                "system_type": "web",
                "interfaces": ["web"],
                "internet_exposed": "on",
                "data_classes": [],
                "uses_ai": "on",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Результат анализа")
        self.assertContains(response, "DEMO-T-001")

    def test_checkbox_semantics_map_to_categories(self):
        base = {"system_type": "web", "interfaces": [], "data_classes": []}

        exposed = self.client.post(HTML_ANALYZE, {**base, "internet_exposed": "on"})
        self.assertContains(exposed, "DEMO-T-003")

        ai = self.client.post(HTML_ANALYZE, {**base, "uses_ai": "on"})
        self.assertContains(ai, "DEMO-T-005")

        plain = self.client.post(HTML_ANALYZE, dict(base))
        self.assertNotContains(plain, "DEMO-T-003")

    def test_empty_selection_renders_demo_fallback(self):
        response = self.client.post(
            HTML_ANALYZE, {"system_type": "does-not-exist", "interfaces": []}
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Релевантных угроз не найдено")


class HtmlApiConsistencyTests(SimpleTestCase):
    """HTML form and JSON API run the same analyzer over the same profile."""

    def test_html_and_api_select_the_same_entities(self):
        from services.analyzer import analyze_profile

        canonical = {
            "system_type": "web",
            "interfaces": ["web", "api"],
            "internet_exposed": True,
            "data_classes": ["confidentiality"],
            "uses_ai": True,
        }
        form_data = {
            "system_type": "web",
            "interfaces": ["web", "api"],
            "internet_exposed": "on",
            "data_classes": ["confidentiality"],
            "uses_ai": "on",
        }
        expected = analyze_profile(canonical)
        self.assertGreater(expected["statistics"]["threats"], 0)

        api_response = self.client.post(
            API_ANALYZE, data=json.dumps(canonical), content_type="application/json"
        )
        self.assertEqual(api_response.status_code, 200)
        self.assertEqual(api_response.json(), expected)

        html_response = self.client.post(HTML_ANALYZE, form_data)
        self.assertEqual(html_response.status_code, 200)
        for collection in ("threats", "measures", "tools"):
            for item in expected[collection]:
                self.assertContains(html_response, item["code"])

    def test_html_and_api_agree_on_empty_result(self):
        html_response = self.client.post(
            HTML_ANALYZE, {"system_type": "does-not-exist", "interfaces": []}
        )
        self.assertContains(html_response, "Релевантных угроз не найдено")

        api_response = self.client.post(
            API_ANALYZE,
            data=json.dumps({"system_type": "does-not-exist"}),
            content_type="application/json",
        )
        self.assertEqual(api_response.status_code, 200)
        self.assertEqual(api_response.json()["statistics"]["threats"], 0)


# ---------------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------------


class CsrfEnforcementTests(SimpleTestCase):
    """Django CSRF is enforced for the HTML flow and skipped only for the demo API."""

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)

    def test_profile_form_contains_csrf_token_input(self):
        response = self.client.get(PROFILE_PAGE)
        self.assertEqual(response.status_code, 200)
        self.assertRegex(response.content.decode(), CSRF_TOKEN_RE.pattern)

    def test_html_analysis_without_csrf_token_is_rejected(self):
        response = self.client.post(
            HTML_ANALYZE, {"system_type": "web", "interfaces": ["web"]}
        )
        self.assertEqual(response.status_code, 403)
        self.assertNotContains(response, "Результат анализа", status_code=403)

    def test_html_analysis_with_wrong_csrf_token_is_rejected(self):
        response = self.client.post(
            HTML_ANALYZE,
            {"csrfmiddlewaretoken": "not-a-real-token", "system_type": "web"},
        )
        self.assertEqual(response.status_code, 403)

    def test_api_analysis_is_csrf_exempt_as_documented_demo_limitation(self):
        # csrf_exempt on the demo JSON endpoint: a request without any CSRF
        # token must reach the view (400 for malformed JSON, not 403).
        response = self.client.post(API_ANALYZE, data=b"{", content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_json"})

    def test_catalogs_are_readable_without_csrf_token(self):
        for url in CATALOG_ENDPOINTS.values():
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)


class CsrfTokenFlowTests(SimpleTestCase):
    """A real token obtained from the form allows the HTML analysis POST."""

    def test_html_analysis_with_real_token_succeeds(self):
        client = Client(enforce_csrf_checks=True)
        page = client.get(PROFILE_PAGE)
        self.assertEqual(page.status_code, 200)
        match = CSRF_TOKEN_RE.search(page.content.decode())
        self.assertIsNotNone(match)

        response = client.post(
            HTML_ANALYZE,
            {
                "csrfmiddlewaretoken": match.group(1),
                "system_type": "web",
                "interfaces": ["web"],
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Результат анализа")
        self.assertContains(response, "DEMO-T-001")


# ---------------------------------------------------------------------------
# Catalog endpoints
# ---------------------------------------------------------------------------


class CatalogListApiTests(SimpleTestCase):
    """Every catalog list endpoint serves demo provenance and the seed items."""

    def test_all_catalog_endpoints_return_demo_lists(self):
        for name, url in CATALOG_ENDPOINTS.items():
            with self.subTest(catalog=name):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response["Content-Type"].startswith("application/json"))
                payload = response.json()
                self.assertEqual(set(payload), {"source", "items"})
                self.assertEqual(payload["source"], "demo")
                items = payload["items"]
                self.assertIsInstance(items, list)
                self.assertGreater(len(items), 0)

                codes = []
                for item in items:
                    self.assertIsInstance(item, dict)
                    code = item.get("code")
                    self.assertIsInstance(code, str)
                    self.assertTrue(code.startswith("DEMO-"), code)
                    codes.append(code)
                self.assertEqual(len(codes), len(set(codes)), "duplicate codes")

                self.assertEqual(items, read_seed(name))

    def test_threat_catalog_contains_expected_demo_seed(self):
        payload = self.client.get("/api/threats/").json()
        codes = [item["code"] for item in payload["items"]]
        self.assertIn("DEMO-T-001", codes)


class CatalogDetailApiTests(SimpleTestCase):
    """Threat detail: 200 with the exact seed item, 404 for unknown codes."""

    def test_known_threat_code_returns_seed_item(self):
        response = self.client.get("/api/threats/DEMO-T-001/")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response["Content-Type"].startswith("application/json"))
        payload = response.json()
        self.assertEqual(set(payload), {"source", "item"})
        self.assertEqual(payload["source"], "demo")
        self.assertEqual(payload["item"]["code"], "DEMO-T-001")
        self.assertEqual(payload["item"], read_seed("threats")[0])

    def test_unknown_threat_code_returns_404_not_found(self):
        response = self.client.get("/api/threats/DEMO-T-999/")
        self.assertEqual(response.status_code, 404)
        self.assertTrue(response["Content-Type"].startswith("application/json"))
        self.assertEqual(response.json(), {"error": "not_found"})

    def test_case_mismatched_code_returns_404(self):
        self.assertEqual(self.client.get("/api/threats/demo-t-001/").status_code, 404)

    def test_code_from_another_catalog_returns_404(self):
        # Measure codes must not leak through the threat detail endpoint.
        self.assertEqual(self.client.get("/api/threats/DEMO-M-001/").status_code, 404)


class HttpMethodRestrictionTests(SimpleTestCase):
    """Catalog endpoints are GET-only; analysis endpoints are POST-only."""

    NON_GET_METHODS = ("post", "put", "patch", "delete")

    def test_catalog_list_rejects_non_get_methods(self):
        for url in CATALOG_ENDPOINTS.values():
            for method in self.NON_GET_METHODS:
                with self.subTest(url=url, method=method):
                    response = getattr(self.client, method)(url)
                    self.assertEqual(response.status_code, 405)
                    self.assertIn("GET", response.headers.get("Allow", ""))

    def test_catalog_detail_rejects_non_get_methods(self):
        for method in self.NON_GET_METHODS:
            with self.subTest(method=method):
                response = getattr(self.client, method)("/api/threats/DEMO-T-001/")
                self.assertEqual(response.status_code, 405)

    def test_api_analyze_rejects_non_post_methods(self):
        for method in ("get", "put", "patch", "delete"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(API_ANALYZE)
                self.assertEqual(response.status_code, 405)
                self.assertIn("POST", response.headers.get("Allow", ""))

    def test_techniques_catalog_has_no_endpoint(self):
        # techniques.json exists as seed data but is not an MVP API route.
        self.assertEqual(self.client.get("/api/techniques/").status_code, 404)


# ---------------------------------------------------------------------------
# Demo namespace and provenance of seed data
# ---------------------------------------------------------------------------

# Identifier-like uppercase dashed tokens (DEMO-FRAMEWORK-WEB, DEMO-SZI-CLASS-001, ...).
IDENTIFIER_RE = re.compile(r"^[A-Z0-9]+(?:-[A-Z0-9-]+)+$")

# Real (non-demo) regulatory identifier prefixes that must never appear.
REAL_CODE_PREFIXES = ("ЗИС.", "ИАФ.", "УБИ.")
ATTACK_TECHNIQUE_RE = re.compile(r"^T\d{4}$")


class DemoNamespaceDataTests(SimpleTestCase):
    """All seed entities are explicit demo data under the DEMO- namespace."""

    def test_seed_files_are_lists_of_objects(self):
        for name in CATALOG_FILES:
            with self.subTest(catalog=name):
                seed = read_seed(name)
                self.assertIsInstance(seed, list)
                self.assertGreater(len(seed), 0)
                for item in seed:
                    self.assertIsInstance(item, dict)

    def test_every_entity_has_unique_demo_code(self):
        for name in CATALOG_FILES:
            with self.subTest(catalog=name):
                codes = [item["code"] for item in read_seed(name)]
                for code in codes:
                    self.assertIsInstance(code, str)
                    self.assertTrue(code.startswith("DEMO-"), code)
                self.assertEqual(len(codes), len(set(codes)))

    def test_every_entity_is_explicitly_labeled_demo(self):
        for name in CATALOG_FILES:
            with self.subTest(catalog=name):
                for item in read_seed(name):
                    for field in ("name", "description"):
                        value = item.get(field)
                        self.assertIsInstance(value, str, (name, field))
                        self.assertTrue(value.strip(), (name, field, value))

    def test_identifier_like_values_are_demo_namespaced(self):
        for name in CATALOG_FILES:
            with self.subTest(catalog=name):
                for value in walk_strings(read_seed(name)):
                    if IDENTIFIER_RE.match(value):
                        self.assertTrue(value.startswith("DEMO-"), value)

    def test_no_real_regulatory_identifiers_in_seed_data(self):
        for name in CATALOG_FILES:
            with self.subTest(catalog=name):
                seed = read_seed(name)
                for value in walk_strings(seed):
                    self.assertFalse(value.startswith(REAL_CODE_PREFIXES), value)
                    self.assertIsNone(ATTACK_TECHNIQUE_RE.match(value), value)

    def test_seed_files_contain_no_real_regulatory_prefixes_in_text(self):
        for filename in CATALOG_FILES.values():
            with self.subTest(file=filename):
                text = (DATA_DIR / filename).read_text(encoding="utf-8")
                for prefix in REAL_CODE_PREFIXES:
                    self.assertNotIn(f'"{prefix}', text)


class AnalysisProvenanceTests(SimpleTestCase):
    """Successful analysis responses carry explicit demo provenance."""

    def test_api_result_metadata_declares_demo_source(self):
        response = self.client.post(
            API_ANALYZE, data=json.dumps(MVP_PROFILE), content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["metadata"]["source"], "demo")

    def test_html_result_declares_demo_source_and_footer_notice(self):
        response = self.client.post(
            HTML_ANALYZE,
            {
                "system_type": "web",
                "interfaces": ["web"],
                "internet_exposed": "on",
                "data_classes": ["confidentiality"],
                "uses_ai": "on",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Источник: Демонстрационные данные")
        self.assertContains(response, "Демонстрационные данные")


class HtmlPageTests(SimpleTestCase):
    """Home and profile pages render the demo UI."""

    def test_home_page(self):
        response = self.client.get(HOME_PAGE)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "АрхиСек")
        self.assertContains(response, "Демонстрационные данные")
        self.assertContains(response, PROFILE_PAGE)

    def test_profile_page_renders_the_documented_form_fields(self):
        response = self.client.get(PROFILE_PAGE)
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        self.assertIn('action="/profile/analyze/"', html)
        self.assertIn('method="post"', html)
        for field in PROFILE_FIELDS:
            self.assertIn(f'name="{field}"', html)
        self.assertIn('value="web"', html)
        self.assertIn('value="api"', html)
        self.assertIn('value="confidentiality"', html)
        self.assertIn('value="integrity"', html)


# ---------------------------------------------------------------------------
# Scope: no persistence, ORM, auth, sessions, migrations, Redis, Celery
# ---------------------------------------------------------------------------


class SettingsScopeTests(SimpleTestCase):
    """Settings-level guarantees: no DB backend, auth/session apps or middleware."""

    def test_no_database_backend_configured(self):
        # The configured settings source must declare no database backend.
        # Django's connection handler may later materialize an inert ``dummy``
        # default in place of the empty dict; that never selects a real engine.
        settings_source = (BASE_DIR / "config" / "settings.py").read_text(
            encoding="utf-8"
        )
        self.assertRegex(settings_source, r"DATABASES\s*=\s*\{\s*\}")
        for alias, config in settings.DATABASES.items():
            self.assertEqual(
                config.get("ENGINE"), "django.db.backends.dummy", alias
            )
            self.assertEqual(config.get("NAME"), "", alias)

    def test_no_auth_session_or_admin_apps_installed(self):
        forbidden_apps = (
            "django.contrib.auth",
            "django.contrib.sessions",
            "django.contrib.admin",
            "django.contrib.contenttypes",
            "django.contrib.messages",
        )
        for app in forbidden_apps:
            self.assertNotIn(app, settings.INSTALLED_APPS)
        self.assertIn("django.contrib.staticfiles", settings.INSTALLED_APPS)
        self.assertIn("core", settings.INSTALLED_APPS)

    def test_no_session_or_auth_middleware(self):
        for alias in settings.MIDDLEWARE:
            self.assertNotIn("SessionMiddleware", alias)
            self.assertNotIn("AuthenticationMiddleware", alias)
            self.assertNotIn("Authentication", alias)
        self.assertIn("django.middleware.csrf.CsrfViewMiddleware", settings.MIDDLEWARE)

    def test_no_migrations_packages_in_repo(self):
        excluded = {".opencode", "__pycache__", ".git", ".venv"}
        found = [
            str(path)
            for path in BASE_DIR.rglob("migrations")
            if path.is_dir() and not excluded & set(path.parts)
        ]
        self.assertEqual(found, [])


# Patterns that indicate forbidden infrastructure in production code/config.
# The inert ``DEFAULT_AUTO_FIELD`` default in settings.py references
# django.db.models without using the ORM and is explicitly allowed.
FORBIDDEN_CODE_PATTERNS = {
    "Model.objects / queryset access": re.compile(r"\.objects\b"),
    "django.db usage": re.compile(r"django\.db\b"),
    "model class definition": re.compile(r"models\.Model\b"),
    "auth app": re.compile(r"django\.contrib\.auth\b"),
    "sessions app": re.compile(r"django\.contrib\.sessions\b"),
    "admin app": re.compile(r"django\.contrib\.admin\b"),
    "messages app": re.compile(r"django\.contrib\.messages\b"),
    "auth decorator": re.compile(
        r"login_required|permission_required|user_passes_test|LoginRequiredMixin"
    ),
    "authenticate call": re.compile(r"\bauthenticate\s*\("),
    "session/auth middleware": re.compile(r"SessionMiddleware|AuthenticationMiddleware"),
    "migrations infrastructure": re.compile(
        r"\bmakemigrations\b|\bdjango\.db\.migrations\b|MIGRATION_MODULES"
    ),
    "migrate command": re.compile(r"\bmigrate\b"),
    "postgresql driver": re.compile(r"psycopg|postgresql", re.IGNORECASE),
    "sqlite persistence": re.compile(r"sqlite", re.IGNORECASE),
    "redis": re.compile(r"redis", re.IGNORECASE),
    "celery": re.compile(r"celery|kombu", re.IGNORECASE),
    "session engine override": re.compile(r"SESSION_ENGINE"),
    "cache backend": re.compile(r"CACHES\b"),
}

# Directories that are not production runtime code/config.
SCAN_EXCLUDED_DIRS = {
    ".opencode",
    "__pycache__",
    ".git",
    ".venv",
    "data",
    "docs",
    "tests",
    "static",
}

ALLOWED_LINE_MARKERS = ("DEFAULT_AUTO_FIELD",)


def production_code_files():
    """Python sources + requirements.txt of production code and config."""
    files = []
    for path in sorted(BASE_DIR.rglob("*.py")):
        if SCAN_EXCLUDED_DIRS & set(path.parts):
            continue
        files.append(path)
    requirements = BASE_DIR / "requirements.txt"
    if requirements.exists():
        files.append(requirements)
    return files


class ProductionCodeScopeTests(SimpleTestCase):
    """Text-level scan of production code/config for forbidden infrastructure."""

    def test_production_code_and_config_stay_within_mvp_scope(self):
        violations = []
        for path in production_code_files():
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if any(marker in line for marker in ALLOWED_LINE_MARKERS):
                    continue
                for label, pattern in FORBIDDEN_CODE_PATTERNS.items():
                    if pattern.search(line):
                        violations.append(
                            f"{label}: {path.relative_to(BASE_DIR)}:{lineno}: {line.strip()}"
                        )
        self.assertEqual(violations, [])

    def test_requirements_are_django_only(self):
        text = (BASE_DIR / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("Django", text)
        self.assertEqual(len([line for line in text.splitlines() if line.strip()]), 1)


# ---------------------------------------------------------------------------
# Mapping integrity (canonical + reverse) on seed data and synthetic payloads
# ---------------------------------------------------------------------------


class MappingIntegrityTests(SimpleTestCase):
    """Full integrity of data/mappings.json and derived reverse indexes."""

    @staticmethod
    def mappings_module():
        from services import mappings

        return mappings

    @staticmethod
    def invert(section):
        inverted = {}
        for source, targets in section.items():
            for target in targets:
                inverted.setdefault(target, []).append(source)
        return inverted

    def entity_codes(self, catalog):
        return {item["code"] for item in read_seed(catalog)}

    def read_mappings_file(self):
        with (DATA_DIR / "mappings.json").open(encoding="utf-8") as handle:
            return json.load(handle)

    def test_validate_mappings_reports_no_errors_on_seed_data(self):
        self.assertEqual(self.mappings_module().validate_mappings(), [])

    def test_seed_mappings_are_canonical_only(self):
        # The seed file persists exactly the canonical sections (docs/mvp.md,
        # docs/data_schemas.md); reverse indexes are derived in memory only.
        # Legacy canonical+reverse payloads stay covered by the synthetic
        # validation tests in SyntheticMappingValidationTests.
        data = self.read_mappings_file()
        self.assertIsInstance(data, dict)
        self.assertEqual(set(data), {"threat_measure", "measure_tool"})

    def test_all_mapping_codes_are_demo_namespaced(self):
        data = self.read_mappings_file()
        for section_name, section in data.items():
            self.assertIsInstance(section, dict)
            for source, targets in section.items():
                self.assertTrue(source.startswith("DEMO-"), source)
                for target in targets:
                    self.assertTrue(target.startswith("DEMO-"), target)

    def test_canonical_mappings_reference_existing_entities(self):
        data = self.read_mappings_file()
        threats, measures, tools = (
            self.entity_codes("threats"),
            self.entity_codes("measures"),
            self.entity_codes("tools"),
        )
        for threat_code, measure_codes in data["threat_measure"].items():
            self.assertIn(threat_code, threats)
            for code in measure_codes:
                self.assertIn(code, measures)
        for measure_code, tool_codes in data["measure_tool"].items():
            self.assertIn(measure_code, measures)
            for code in tool_codes:
                self.assertIn(code, tools)

    def test_load_mappings_derives_symmetric_reverse_indexes(self):
        mappings = self.mappings_module().load_mappings()
        self.assertEqual(
            set(mappings),
            {"threat_measure", "measure_tool", "measure_threat", "tool_measure"},
        )
        self.assertEqual(mappings["measure_threat"], self.invert(mappings["threat_measure"]))
        self.assertEqual(mappings["tool_measure"], self.invert(mappings["measure_tool"]))
        for source, targets in mappings["threat_measure"].items():
            for target in targets:
                self.assertIn(source, mappings["measure_threat"][target])
        for source, targets in mappings["measure_tool"].items():
            for target in targets:
                self.assertIn(source, mappings["tool_measure"][target])

    def test_load_mappings_rejects_corrupted_payload(self):
        mappings = self.mappings_module()
        corrupted = {"threat_measure": {"DEMO-T-001": []}, "measure_tool": {}}
        with mock.patch.object(mappings, "load", return_value=corrupted):
            with self.assertRaises(mappings.MappingValidationError):
                mappings.load_mappings()

    def test_load_mappings_rejects_unknown_entity_references(self):
        mappings = self.mappings_module()
        bad = {
            "threat_measure": {"DEMO-T-999": ["DEMO-M-001"]},
            "measure_tool": {"DEMO-M-001": ["DEMO-SZI-999"]},
        }
        with mock.patch.object(mappings, "load", return_value=bad):
            with self.assertRaises(mappings.MappingValidationError):
                mappings.load_mappings()


class SyntheticMappingValidationTests(SimpleTestCase):
    """validate_mapping_dict semantics on synthetic in-memory payloads."""

    @staticmethod
    def validate(data, entities=None):
        from services.mappings import validate_mapping_dict

        return validate_mapping_dict(data, entities)

    def setUp(self):
        self.entities = {
            "threat": {"DEMO-T-001", "DEMO-T-002"},
            "measure": {"DEMO-M-001", "DEMO-M-002"},
            "tool": {"DEMO-SZI-001"},
        }

    def valid_payload(self, with_reverse=False):
        data = {
            "threat_measure": {"DEMO-T-001": ["DEMO-M-001"]},
            "measure_tool": {"DEMO-M-001": ["DEMO-SZI-001"]},
        }
        if with_reverse:
            data["measure_threat"] = {"DEMO-M-001": ["DEMO-T-001"]}
            data["tool_measure"] = {"DEMO-SZI-001": ["DEMO-M-001"]}
        return data

    def assert_error(self, errors, fragment):
        self.assertTrue(
            any(fragment in error for error in errors),
            f"expected fragment {fragment!r} in {errors}",
        )

    def test_valid_canonical_only_payload_has_no_errors(self):
        self.assertEqual(self.validate(self.valid_payload(), self.entities), [])

    def test_valid_payload_with_symmetric_reverse_has_no_errors(self):
        self.assertEqual(self.validate(self.valid_payload(True), self.entities), [])

    def test_root_must_be_an_object(self):
        self.assertEqual(
            self.validate(["not", "an", "object"]), ["mappings: root must be an object"]
        )

    def test_missing_canonical_keys_are_reported(self):
        errors = self.validate({})
        self.assert_error(errors, "missing canonical key: threat_measure")
        self.assert_error(errors, "missing canonical key: measure_tool")

    def test_unknown_top_level_key_is_reported(self):
        errors = self.validate({**self.valid_payload(), "extra_key": {}})
        self.assert_error(errors, "unknown top-level key: extra_key")

    def test_section_must_be_an_object(self):
        errors = self.validate(
            {"threat_measure": ["list"], "measure_tool": {}}, self.entities
        )
        self.assert_error(errors, "threat_measure must be an object")

    def test_unknown_references_are_reported(self):
        data = {
            "threat_measure": {"DEMO-T-999": ["DEMO-M-001"], "DEMO-T-001": ["DEMO-M-999"]},
            "measure_tool": {"DEMO-M-001": ["DEMO-SZI-999"]},
        }
        errors = self.validate(data, self.entities)
        self.assert_error(errors, "unknown threat code")
        self.assert_error(errors, "unknown measure code")
        self.assert_error(errors, "unknown tool code")

    def test_reverse_only_entry_is_reported(self):
        data = {
            **self.valid_payload(),
            "measure_threat": {"DEMO-M-001": ["DEMO-T-001", "DEMO-T-002"]},
        }
        self.assert_error(self.validate(data, self.entities), "reverse-only mapping")

    def test_missing_reverse_entry_is_reported(self):
        data = {**self.valid_payload(), "measure_threat": {}}
        errors = self.validate(data, self.entities)
        self.assert_error(errors, "missing reverse mapping")

    def test_duplicate_targets_are_reported(self):
        data = {
            "threat_measure": {"DEMO-T-001": ["DEMO-M-001", "DEMO-M-001"]},
            "measure_tool": {},
        }
        self.assert_error(self.validate(data, self.entities), "duplicate entry")

    def test_empty_target_list_is_reported(self):
        data = {"threat_measure": {"DEMO-T-001": []}, "measure_tool": {}}
        self.assert_error(self.validate(data, self.entities), "mapping list is empty")

    def test_non_list_target_is_reported(self):
        data = {"threat_measure": {"DEMO-T-001": "DEMO-M-001"}, "measure_tool": {}}
        self.assert_error(self.validate(data, self.entities), "value must be a list")

    def test_non_string_source_key_is_reported(self):
        data = {"threat_measure": {42: ["DEMO-M-001"]}, "measure_tool": {}}
        errors = self.validate(data, self.entities)
        self.assert_error(errors, "source code must be a non-empty string")

    def test_empty_string_target_is_reported(self):
        data = {"threat_measure": {"DEMO-T-001": [""]}, "measure_tool": {}}
        errors = self.validate(data, self.entities)
        self.assert_error(errors, "target code must be a non-empty string")

    def test_malformed_nested_targets_return_errors_not_type_error(self):
        # Regression: unhashable targets (dicts/lists/None) inside mapping
        # lists must be reported as errors even when entity reference checks
        # are enabled, never raise TypeError.
        for targets in ([{}], [[]], [None], ["DEMO-M-001", {}], ["DEMO-M-001", []]):
            with self.subTest(targets=targets):
                data = {
                    "threat_measure": {"DEMO-T-001": targets},
                    "measure_tool": {},
                }
                try:
                    errors = self.validate(data, self.entities)
                except TypeError as error:
                    self.fail(f"validate_mapping_dict raised TypeError: {error}")
                self.assertTrue(errors, "malformed targets must be reported")

    def test_mixed_type_root_keys_return_errors_not_type_error(self):
        # Regression: non-string top-level keys mixed with section names must
        # be reported as unknown keys, never crash key ordering/comparison.
        data = {42: {}, **self.valid_payload()}
        try:
            errors = self.validate(data, self.entities)
        except TypeError as error:
            self.fail(f"validate_mapping_dict raised TypeError: {error}")
        self.assertTrue(errors)
        self.assert_error(errors, "unknown top-level key")

    def test_mixed_type_section_source_keys_return_errors_not_type_error(self):
        data = {
            "threat_measure": {"DEMO-T-001": ["DEMO-M-001"], 7: ["DEMO-M-001"]},
            "measure_tool": {},
        }
        try:
            errors = self.validate(data, self.entities)
        except TypeError as error:
            self.fail(f"validate_mapping_dict raised TypeError: {error}")
        self.assertTrue(errors)
        self.assert_error(errors, "source code must be a non-empty string")

    def test_reference_checks_skipped_without_entities(self):
        data = {
            "threat_measure": {"DEMO-T-999": ["DEMO-M-999"]},
            "measure_tool": {},
        }
        # Structural validation still passes when entity sets are not supplied.
        self.assertEqual(self.validate(data), [])
