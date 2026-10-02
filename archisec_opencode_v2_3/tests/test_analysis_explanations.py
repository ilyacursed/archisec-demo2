"""Focused E2E / vertical-slice tests for the additive ``explanations`` field.

Covers the agreed contract (docs/mvp.md, docs/data_schemas.md,
docs/quality_gates.md) independently of the analyzer implementation:

- Hard-coded expected explanations for the documented demo profiles A/B/C,
  plus a second independent reference computed directly from the seed JSON
  files (threats/measures/tools/mappings) per the documented rules — never
  by calling the analyzer.
- Exact schema: one explanation per returned threat, in ``threats`` order,
  ``{threat_code, matched_categories, measures: [{measure_code, tool_codes}]}``
  with ``matched_categories`` the sorted unique intersection of effective
  profile categories and threat categories; canonical link order with stable
  deduplication; references only to returned entities.
- Determinism, duplicate input categories, empty results (``explanations=[]``),
  synthetic graphs with one-to-many/shared mappings, duplicate canonical codes,
  missing edges and unresolved lookups (empty nested lists, no dangling links),
  and hostile HTML-special/script category strings flowing verbatim into
  matched reasons (service) and safely escaped in the rendered page.
- API equals the shared service result including ``explanations``; the URL
  surface stays exactly the documented routes; seed data is never modified.
- HTML vertical slice (Home → profile token → CSRF-protected submit) for A/B/C:
  the rendered page is driven by the same ``AnalysisResult`` as the API, shows
  sections/reasons/chain links without dangling same-page anchors, links chain
  entries to anchors of the referenced entities, shows the demo notice, and
  safely escapes untrusted profile/category text (including a synthetic
  selected threat whose matched category is hostile).

``HtmlVerticalSliceTests`` renders templates; all other classes exercise only
services, the JSON API and config. ``tests/test_quality_gates.py`` keeps the
pre-existing gates; only its exact-key ``AnalysisResult`` assertion was
extended with ``explanations``.
"""

import contextlib
import hashlib
import json
import re
from pathlib import Path
from unittest import mock

from django.test import Client, SimpleTestCase
from django.urls import get_resolver

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

API_ANALYZE = "/api/profile/analyze/"
HTML_ANALYZE = "/profile/analyze/"
PROFILE_PAGE = "/profile/"
HOME_PAGE = "/"

CSRF_TOKEN_RE = re.compile(r'name="csrfmiddlewaretoken" value="([^"]+)"')
HTML_ID_RE = re.compile(r'\bid="([^"]+)"')
HTML_ANCHOR_RE = re.compile(r'href="#([^"]+)"')

# Hostile category strings: preserved verbatim by the validator (no enum), so
# they can become *matched* reasons when a (synthetic) threat carries them.
HOSTILE_SCRIPT_CATEGORY = '<script>alert("match")</script>'
HOSTILE_IMG_CATEGORY = '<img src=x onerror="pwn()">'

# Russian display labels for matched categories (docs/branding.md and
# services/terminology); raw codes stay machine values in API and form data.
CATEGORY_LABELS_RU = {
    "web": "Веб-приложение",
    "api": "Программный интерфейс (API)",
    "internet": "Доступ из интернета",
    "ai": "Искусственный интеллект",
    "confidentiality": "Конфиденциальность",
    "integrity": "Целостность",
}

# ---------------------------------------------------------------------------
# Documented demo profiles A/B/C (docs/mvp.md) and their expected results.
# ---------------------------------------------------------------------------

PROFILE_A = {
    "system_type": "web",
    "interfaces": ["web"],
    "internet_exposed": True,
    "data_classes": ["confidentiality"],
    "uses_ai": False,
}
PROFILE_B = {
    "system_type": "internal",
    "interfaces": ["api"],
    "internet_exposed": True,
    "data_classes": [],
    "uses_ai": False,
}
PROFILE_C = {
    "system_type": "internal",
    "interfaces": [],
    "internet_exposed": True,
    "data_classes": [],
    "uses_ai": True,
}

SCENARIOS = {"A": PROFILE_A, "B": PROFILE_B, "C": PROFILE_C}


def _chain(number):
    return (
        f"DEMO-T-{number:03d}",
        f"DEMO-M-{number:03d}",
        f"DEMO-SZI-{number:03d}",
    )


EXPECTED_CODES = {
    "A": ["DEMO-T-001", "DEMO-T-003", "DEMO-T-004", "DEMO-T-006"],
    "B": ["DEMO-T-002", "DEMO-T-003"],
    "C": ["DEMO-T-003", "DEMO-T-005"],
}
EXPECTED_STATS = {
    "A": {"threats": 4, "measures": 4, "tools": 4},
    "B": {"threats": 2, "measures": 2, "tools": 2},
    "C": {"threats": 2, "measures": 2, "tools": 2},
}
EXPECTED_CHAINS = {
    "A": [_chain(1), _chain(3), _chain(4), _chain(6)],
    "B": [_chain(2), _chain(3)],
    "C": [_chain(3), _chain(5)],
}

# Hand-computed expected explanations per scenario. In A the multi-category
# threat DEMO-T-006 (categories ["web", "integrity"]) matches via "web" only.
EXPECTED_EXPLANATIONS = {
    "A": [
        {
            "threat_code": "DEMO-T-001",
            "matched_categories": ["web"],
            "measures": [
                {"measure_code": "DEMO-M-001", "tool_codes": ["DEMO-SZI-001"]}
            ],
        },
        {
            "threat_code": "DEMO-T-003",
            "matched_categories": ["internet"],
            "measures": [
                {"measure_code": "DEMO-M-003", "tool_codes": ["DEMO-SZI-003"]}
            ],
        },
        {
            "threat_code": "DEMO-T-004",
            "matched_categories": ["confidentiality"],
            "measures": [
                {"measure_code": "DEMO-M-004", "tool_codes": ["DEMO-SZI-004"]}
            ],
        },
        {
            "threat_code": "DEMO-T-006",
            "matched_categories": ["web"],
            "measures": [
                {"measure_code": "DEMO-M-006", "tool_codes": ["DEMO-SZI-006"]}
            ],
        },
    ],
    "B": [
        {
            "threat_code": "DEMO-T-002",
            "matched_categories": ["api"],
            "measures": [
                {"measure_code": "DEMO-M-002", "tool_codes": ["DEMO-SZI-002"]}
            ],
        },
        {
            "threat_code": "DEMO-T-003",
            "matched_categories": ["internet"],
            "measures": [
                {"measure_code": "DEMO-M-003", "tool_codes": ["DEMO-SZI-003"]}
            ],
        },
    ],
    "C": [
        {
            "threat_code": "DEMO-T-003",
            "matched_categories": ["internet"],
            "measures": [
                {"measure_code": "DEMO-M-003", "tool_codes": ["DEMO-SZI-003"]}
            ],
        },
        {
            "threat_code": "DEMO-T-005",
            "matched_categories": ["ai"],
            "measures": [
                {"measure_code": "DEMO-M-005", "tool_codes": ["DEMO-SZI-005"]}
            ],
        },
    ],
}


# ---------------------------------------------------------------------------
# Synthetic graph with hostile categories: matched reasons carry untrusted
# text end-to-end; HTML must escape it (see HtmlVerticalSliceTests).
# ---------------------------------------------------------------------------

HOSTILE_THREATS = [
    {
        "code": "DEMO-T-201",
        "name": "Hostile script reason",
        "description": "Demo",
        "categories": [HOSTILE_SCRIPT_CATEGORY],
    },
    {
        "code": "DEMO-T-202",
        "name": "Hostile img reason",
        "description": "Demo",
        "categories": [HOSTILE_IMG_CATEGORY, "plain"],
    },
]
HOSTILE_MEASURES = [
    {"code": "DEMO-M-201", "name": "Hostile measure one", "description": "Demo"},
    {"code": "DEMO-M-202", "name": "Hostile measure two", "description": "Demo"},
]
HOSTILE_TOOLS = [
    {"code": "DEMO-SZI-201", "name": "Hostile tool one", "description": "Demo"},
    {"code": "DEMO-SZI-202", "name": "Hostile tool two", "description": "Demo"},
]
HOSTILE_MAPPINGS = {
    "threat_measure": {
        "DEMO-T-201": ["DEMO-M-201"],
        "DEMO-T-202": ["DEMO-M-202"],
    },
    "measure_tool": {
        "DEMO-M-201": ["DEMO-SZI-201"],
        "DEMO-M-202": ["DEMO-SZI-202"],
    },
}
HOSTILE_PROFILE = {
    "system_type": "internal",
    "interfaces": [HOSTILE_SCRIPT_CATEGORY, HOSTILE_IMG_CATEGORY],
    "internet_exposed": False,
    "data_classes": [],
    "uses_ai": False,
}
HOSTILE_EXPECTED_EXPLANATIONS = [
    {
        "threat_code": "DEMO-T-201",
        "matched_categories": [HOSTILE_SCRIPT_CATEGORY],
        "measures": [
            {"measure_code": "DEMO-M-201", "tool_codes": ["DEMO-SZI-201"]}
        ],
    },
    {
        "threat_code": "DEMO-T-202",
        "matched_categories": [HOSTILE_IMG_CATEGORY],
        "measures": [
            {"measure_code": "DEMO-M-202", "tool_codes": ["DEMO-SZI-202"]}
        ],
    },
]


# ---------------------------------------------------------------------------
# Independent seed reference: documented rules re-implemented over data/*.json.
# ---------------------------------------------------------------------------


def read_seed(name):
    with (DATA_DIR / f"{name}.json").open(encoding="utf-8") as handle:
        return json.load(handle)


def seed_reference_result(profile):
    """Build the full AnalysisResult expected for ``profile`` from seeds only.

    Implements the documented contract directly (docs/mvp.md selection rules,
    docs/data_schemas.md explanations rules). It never imports the analyzer,
    so agreement between its output and the real service/API is evidence, not
    a tautology.
    """
    threats = read_seed("threats")
    measure_catalog = read_seed("measures")
    tool_catalog = read_seed("tools")
    mappings = read_seed("mappings")

    # Documented normalization: defaults for absent keys, strings verbatim.
    normalized = {
        "system_type": profile.get("system_type", "web"),
        "interfaces": list(profile.get("interfaces", [])),
        "data_classes": list(profile.get("data_classes", [])),
        "internet_exposed": profile.get("internet_exposed", False),
        "uses_ai": profile.get("uses_ai", False),
    }

    categories = set(normalized["interfaces"])
    if normalized["system_type"]:
        categories.add(normalized["system_type"])
    if normalized["internet_exposed"]:
        categories.add("internet")
    categories.update(normalized["data_classes"])
    if normalized["uses_ai"]:
        categories.add("ai")

    selected = [
        threat
        for threat in threats
        if categories.intersection(threat.get("categories", []))
    ]

    measure_index = {item["code"]: item for item in measure_catalog}
    tool_index = {item["code"]: item for item in tool_catalog}
    threat_measure = mappings["threat_measure"]
    measure_tool = mappings["measure_tool"]

    measures, seen_measures = [], set()
    for threat in selected:
        for code in threat_measure.get(threat["code"], []):
            if code in seen_measures or code not in measure_index:
                continue
            seen_measures.add(code)
            measures.append(measure_index[code])

    tools, seen_tools = [], set()
    for measure in measures:
        for code in measure_tool.get(measure["code"], []):
            if code in seen_tools or code not in tool_index:
                continue
            seen_tools.add(code)
            tools.append(tool_index[code])

    resolved_measures = {measure["code"] for measure in measures}
    resolved_tools = {tool["code"] for tool in tools}

    explanations = []
    for threat in selected:
        entry_measures, entry_seen = [], set()
        for code in threat_measure.get(threat["code"], []):
            if code not in resolved_measures or code in entry_seen:
                continue
            entry_seen.add(code)
            tool_codes, tool_seen = [], set()
            for tool_code in measure_tool.get(code, []):
                if tool_code not in resolved_tools or tool_code in tool_seen:
                    continue
                tool_seen.add(tool_code)
                tool_codes.append(tool_code)
            entry_measures.append(
                {"measure_code": code, "tool_codes": tool_codes}
            )
        explanations.append(
            {
                "threat_code": threat["code"],
                "matched_categories": sorted(
                    categories.intersection(threat.get("categories", []))
                ),
                "measures": entry_measures,
            }
        )

    return {
        "profile": normalized,
        "threats": selected,
        "measures": measures,
        "tools": tools,
        "explanations": explanations,
        "statistics": {
            "threats": len(selected),
            "measures": len(measures),
            "tools": len(tools),
        },
        "metadata": {"source": "demo", "version": "MVP-1"},
    }


def post_api_profile(client, payload):
    return client.post(
        API_ANALYZE, data=json.dumps(payload), content_type="application/json"
    )


# ---------------------------------------------------------------------------
# Explanations schema: exact keys, order, containment (no dangling links)
# ---------------------------------------------------------------------------


class ExplanationsShapeTests(SimpleTestCase):
    """Structural contract of ``explanations`` on live API responses."""

    def api_result(self, profile):
        response = post_api_profile(self.client, profile)
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_top_level_keys_are_exactly_documented(self):
        payload = self.api_result(PROFILE_A)
        self.assertEqual(
            set(payload),
            {
                "profile",
                "threats",
                "measures",
                "tools",
                "explanations",
                "statistics",
                "metadata",
            },
        )

    def test_entries_have_exactly_documented_keys_in_threats_order(self):
        for name, profile in SCENARIOS.items():
            with self.subTest(scenario=name):
                payload = self.api_result(profile)
                explanations = payload["explanations"]
                self.assertIsInstance(explanations, list)
                self.assertEqual(len(explanations), len(payload["threats"]))
                self.assertEqual(
                    [entry["threat_code"] for entry in explanations],
                    [threat["code"] for threat in payload["threats"]],
                )
                for entry in explanations:
                    self.assertEqual(
                        set(entry),
                        {"threat_code", "matched_categories", "measures"},
                    )
                    self.assertIsInstance(entry["matched_categories"], list)
                    for measure in entry["measures"]:
                        self.assertEqual(
                            set(measure), {"measure_code", "tool_codes"}
                        )

    def test_matched_categories_are_sorted_unique_strings(self):
        payload = self.api_result(PROFILE_A)
        seed_threats = {t["code"]: t for t in read_seed("threats")}
        for entry in payload["explanations"]:
            values = entry["matched_categories"]
            self.assertTrue(all(isinstance(v, str) for v in values))
            self.assertEqual(values, sorted(values))
            self.assertEqual(len(values), len(set(values)))
            # Every matched category really belongs to the threat.
            self.assertTrue(
                set(values).issubset(set(seed_threats[entry["threat_code"]]["categories"]))
            )

    def test_links_reference_only_returned_entities(self):
        for name, profile in SCENARIOS.items():
            with self.subTest(scenario=name):
                payload = self.api_result(profile)
                measure_codes = {m["code"] for m in payload["measures"]}
                tool_codes = {t["code"] for t in payload["tools"]}
                for entry in payload["explanations"]:
                    for measure in entry["measures"]:
                        self.assertIn(measure["measure_code"], measure_codes)
                        for tool_code in measure["tool_codes"]:
                            self.assertIn(tool_code, tool_codes)

    def test_flat_lists_are_unions_of_explained_links(self):
        payload = self.api_result(PROFILE_A)
        explained_measures = {
            measure["measure_code"]
            for entry in payload["explanations"]
            for measure in entry["measures"]
        }
        explained_tools = {
            tool_code
            for entry in payload["explanations"]
            for measure in entry["measures"]
            for tool_code in measure["tool_codes"]
        }
        self.assertEqual(explained_measures, {m["code"] for m in payload["measures"]})
        self.assertEqual(explained_tools, {t["code"] for t in payload["tools"]})


# ---------------------------------------------------------------------------
# Scenarios A/B/C: hard-coded contract + independent seed reference
# ---------------------------------------------------------------------------


class ScenarioSeedReferenceTests(SimpleTestCase):
    """A/B/C produce exactly the documented chains, counts and explanations."""

    def analyze(self, profile):
        from services.analyzer import analyze_profile

        return analyze_profile(profile)

    def test_scenario_threats_measures_tools_and_statistics(self):
        for name, profile in SCENARIOS.items():
            with self.subTest(scenario=name):
                result = self.analyze(profile)
                codes = [threat["code"] for threat in result["threats"]]
                self.assertEqual(codes, EXPECTED_CODES[name])
                self.assertEqual(
                    [measure["code"] for measure in result["measures"]],
                    [chain[1] for chain in EXPECTED_CHAINS[name]],
                )
                self.assertEqual(
                    [tool["code"] for tool in result["tools"]],
                    [chain[2] for chain in EXPECTED_CHAINS[name]],
                )
                self.assertEqual(result["statistics"], EXPECTED_STATS[name])

    def test_scenario_explanations_equal_hardcoded_contract(self):
        for name, profile in SCENARIOS.items():
            with self.subTest(scenario=name):
                result = self.analyze(profile)
                self.assertEqual(result["explanations"], EXPECTED_EXPLANATIONS[name])

    def test_t006_in_scenario_a_matches_web_not_integrity(self):
        result = self.analyze(PROFILE_A)
        entry = next(
            e for e in result["explanations"] if e["threat_code"] == "DEMO-T-006"
        )
        self.assertEqual(entry["matched_categories"], ["web"])
        self.assertNotIn("integrity", entry["matched_categories"])
        # "integrity" is never a matched reason anywhere in scenario A.
        for explanation in result["explanations"]:
            self.assertNotIn("integrity", explanation["matched_categories"])

    def test_service_equals_independent_seed_reference(self):
        for name, profile in SCENARIOS.items():
            with self.subTest(scenario=name):
                self.assertEqual(self.analyze(profile), seed_reference_result(profile))

    def test_api_equals_independent_seed_reference(self):
        for name, profile in SCENARIOS.items():
            with self.subTest(scenario=name):
                response = post_api_profile(self.client, profile)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json(), seed_reference_result(profile))


# ---------------------------------------------------------------------------
# Determinism and duplicate input categories
# ---------------------------------------------------------------------------


class DeterminismAndDuplicatesTests(SimpleTestCase):
    """Repeated calls and duplicate categories never change explanations."""

    def test_repeated_service_calls_are_identical(self):
        from services.analyzer import analyze_profile

        first = analyze_profile(PROFILE_A)
        second = analyze_profile(PROFILE_A)
        third = analyze_profile(PROFILE_A)
        self.assertEqual(first, second)
        self.assertEqual(second, third)

    def test_repeated_api_calls_are_identical(self):
        first = post_api_profile(self.client, PROFILE_B).json()
        second = post_api_profile(self.client, PROFILE_B).json()
        self.assertEqual(first, second)

    def test_duplicate_profile_categories_do_not_change_analysis(self):
        from services.analyzer import analyze_profile

        duplicated = {
            "system_type": "web",
            "interfaces": ["web", "web", "web"],
            "internet_exposed": True,
            "data_classes": ["confidentiality", "confidentiality"],
            "uses_ai": False,
        }
        reference = analyze_profile(PROFILE_A)
        result = analyze_profile(duplicated)

        self.assertEqual(result["threats"], reference["threats"])
        self.assertEqual(result["measures"], reference["measures"])
        self.assertEqual(result["tools"], reference["tools"])
        self.assertEqual(result["explanations"], EXPECTED_EXPLANATIONS["A"])
        for entry in result["explanations"]:
            categories = entry["matched_categories"]
            self.assertEqual(len(categories), len(set(categories)))
            self.assertEqual(categories, sorted(categories))
        # Normalization keeps the submitted strings verbatim (duplicates and all).
        self.assertEqual(result["profile"]["interfaces"], ["web", "web", "web"])
        self.assertEqual(
            result["profile"]["data_classes"], ["confidentiality", "confidentiality"]
        )

    def test_api_duplicate_categories_equal_reference(self):
        duplicated = {
            "system_type": "internal",
            "interfaces": ["api", "api"],
            "internet_exposed": True,
            "data_classes": [],
            "uses_ai": False,
        }
        response = post_api_profile(self.client, duplicated)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["explanations"], EXPECTED_EXPLANATIONS["B"])

    def test_defaults_are_web_and_empty_lists(self):
        from services.analyzer import analyze_profile

        result = analyze_profile({})
        self.assertEqual(
            result["profile"],
            {
                "system_type": "web",
                "interfaces": [],
                "data_classes": [],
                "internet_exposed": False,
                "uses_ai": False,
            },
        )
        # Default web selects chains 1 and 6 even with nothing else selected.
        self.assertEqual(
            [threat["code"] for threat in result["threats"]],
            ["DEMO-T-001", "DEMO-T-006"],
        )
        self.assertEqual(
            result["explanations"],
            [
                {
                    "threat_code": "DEMO-T-001",
                    "matched_categories": ["web"],
                    "measures": [
                        {"measure_code": "DEMO-M-001", "tool_codes": ["DEMO-SZI-001"]}
                    ],
                },
                {
                    "threat_code": "DEMO-T-006",
                    "matched_categories": ["web"],
                    "measures": [
                        {"measure_code": "DEMO-M-006", "tool_codes": ["DEMO-SZI-006"]}
                    ],
                },
            ],
        )


# ---------------------------------------------------------------------------
# Empty results
# ---------------------------------------------------------------------------


class EmptyResultTests(SimpleTestCase):
    """No matching threats → empty collections and ``explanations=[]``."""

    def test_service_empty_profile_yields_empty_explanations(self):
        from services.analyzer import analyze_profile

        result = analyze_profile({"system_type": "does-not-exist"})
        self.assertEqual(result["threats"], [])
        self.assertEqual(result["measures"], [])
        self.assertEqual(result["tools"], [])
        self.assertEqual(result["explanations"], [])
        self.assertEqual(
            result["statistics"], {"threats": 0, "measures": 0, "tools": 0}
        )

    def test_api_empty_profile_yields_empty_explanations(self):
        response = post_api_profile(self.client, {"system_type": "does-not-exist"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["explanations"], [])
        self.assertEqual(
            payload["statistics"], {"threats": 0, "measures": 0, "tools": 0}
        )
        self.assertEqual(payload, seed_reference_result({"system_type": "does-not-exist"}))


# ---------------------------------------------------------------------------
# Synthetic graphs: one-to-many/shared mappings, dedup, missing edges/lookups
# ---------------------------------------------------------------------------


class SyntheticGraphTests(SimpleTestCase):
    """Explanations semantics on synthetic in-memory fixtures (no seed writes)."""

    THREATS = [
        {"code": "DEMO-T-101", "name": "Alpha", "description": "Demo", "categories": ["alpha"]},
        {"code": "DEMO-T-102", "name": "Beta", "description": "Demo", "categories": ["beta"]},
        {"code": "DEMO-T-103", "name": "Gamma", "description": "Demo", "categories": ["beta", "alpha"]},
        {"code": "DEMO-T-104", "name": "Delta", "description": "Demo", "categories": ["orphan"]},
    ]
    MEASURES = [
        {"code": "DEMO-M-101", "name": "One", "description": "Demo"},
        {"code": "DEMO-M-102", "name": "Two", "description": "Demo"},
        # DEMO-M-103 is referenced by mappings but absent from the catalog.
    ]
    TOOLS = [
        {"code": "DEMO-SZI-101", "name": "Tool one", "description": "Demo"},
        {"code": "DEMO-SZI-102", "name": "Tool two", "description": "Demo"},
        # DEMO-SZI-103 is referenced by mappings but absent from the catalog.
    ]
    MAPPINGS = {
        "threat_measure": {
            # One-to-many, duplicate code (stable dedup keeps first position).
            "DEMO-T-101": ["DEMO-M-101", "DEMO-M-102", "DEMO-M-101"],
            # Shared measure DEMO-M-102 plus an unresolved lookup DEMO-M-103.
            "DEMO-T-102": ["DEMO-M-102", "DEMO-M-103"],
            # Shares DEMO-M-102 with the threats above.
            "DEMO-T-103": ["DEMO-M-102"],
            # DEMO-T-104 has no edge at all.
        },
        "measure_tool": {
            # Two tools with a duplicate; canonical order preserved after dedup.
            "DEMO-M-101": ["DEMO-SZI-101", "DEMO-SZI-102", "DEMO-SZI-101"],
            # Shared tool across measures; DEMO-SZI-103 is an unresolved lookup.
            "DEMO-M-102": ["DEMO-SZI-101", "DEMO-SZI-103"],
            # No entry for DEMO-M-103 (also unresolved as a measure).
        },
    }

    PROFILE = {
        "system_type": "alpha",
        "interfaces": ["beta", "orphan"],
        "internet_exposed": False,
        "data_classes": [],
        "uses_ai": False,
    }

    def analyze_with_fixture(
        self,
        profile=None,
        threats=None,
        measures=None,
        tools=None,
        mappings=None,
    ):
        from services.analyzer import analyze_profile

        threats = self.THREATS if threats is None else threats
        measures = self.MEASURES if measures is None else measures
        tools = self.TOOLS if tools is None else tools
        mappings = self.MAPPINGS if mappings is None else mappings
        measure_index = {item["code"]: item for item in measures}
        tool_index = {item["code"]: item for item in tools}

        def fake_items(name):
            self.assertEqual(name, "threats")
            return threats

        def fake_load(name):
            self.assertEqual(name, "mappings")
            return mappings

        def fake_get_by_code(name, code):
            self.assertIn(name, ("measures", "tools"))
            catalog = measure_index if name == "measures" else tool_index
            return catalog.get(code)

        with mock.patch("services.analyzer.items", side_effect=fake_items), \
                mock.patch("services.analyzer.load", side_effect=fake_load), \
                mock.patch("services.analyzer.get_by_code", side_effect=fake_get_by_code):
            return analyze_profile(profile or self.PROFILE)

    def test_flat_lists_use_canonical_order_with_stable_dedup(self):
        result = self.analyze_with_fixture()
        self.assertEqual(
            [threat["code"] for threat in result["threats"]],
            ["DEMO-T-101", "DEMO-T-102", "DEMO-T-103", "DEMO-T-104"],
        )
        # Duplicates and unresolved lookups removed, canonical order kept.
        self.assertEqual(
            [measure["code"] for measure in result["measures"]],
            ["DEMO-M-101", "DEMO-M-102"],
        )
        self.assertEqual(
            [tool["code"] for tool in result["tools"]],
            ["DEMO-SZI-101", "DEMO-SZI-102"],
        )
        self.assertEqual(
            result["statistics"], {"threats": 4, "measures": 2, "tools": 2}
        )

    def test_explanations_on_synthetic_graph(self):
        result = self.analyze_with_fixture()
        self.assertEqual(
            result["explanations"],
            [
                {
                    "threat_code": "DEMO-T-101",
                    "matched_categories": ["alpha"],
                    "measures": [
                        {
                            "measure_code": "DEMO-M-101",
                            "tool_codes": ["DEMO-SZI-101", "DEMO-SZI-102"],
                        },
                        {"measure_code": "DEMO-M-102", "tool_codes": ["DEMO-SZI-101"]},
                    ],
                },
                {
                    "threat_code": "DEMO-T-102",
                    "matched_categories": ["beta"],
                    "measures": [
                        {"measure_code": "DEMO-M-102", "tool_codes": ["DEMO-SZI-101"]}
                    ],
                },
                {
                    "threat_code": "DEMO-T-103",
                    "matched_categories": ["alpha", "beta"],
                    "measures": [
                        {"measure_code": "DEMO-M-102", "tool_codes": ["DEMO-SZI-101"]}
                    ],
                },
                {
                    "threat_code": "DEMO-T-104",
                    "matched_categories": ["orphan"],
                    "measures": [],
                },
            ],
        )

    def test_missing_edge_gives_empty_measures_but_keeps_category_reason(self):
        result = self.analyze_with_fixture()
        orphan = next(
            e for e in result["explanations"] if e["threat_code"] == "DEMO-T-104"
        )
        self.assertEqual(orphan["matched_categories"], ["orphan"])
        self.assertEqual(orphan["measures"], [])

    def test_shared_entities_appear_in_every_related_explanation(self):
        result = self.analyze_with_fixture()
        entries = {e["threat_code"]: e for e in result["explanations"]}
        for threat_code in ("DEMO-T-101", "DEMO-T-102", "DEMO-T-103"):
            codes = [m["measure_code"] for m in entries[threat_code]["measures"]]
            self.assertIn("DEMO-M-102", codes)
            for measure in entries[threat_code]["measures"]:
                if measure["measure_code"] == "DEMO-M-102":
                    self.assertEqual(measure["tool_codes"], ["DEMO-SZI-101"])

    def test_unresolved_lookups_never_appear_anywhere(self):
        result = self.analyze_with_fixture()
        serialized = json.dumps(result)
        self.assertNotIn("DEMO-M-103", serialized)
        self.assertNotIn("DEMO-SZI-103", serialized)

    def test_explanations_reference_only_returned_entities(self):
        result = self.analyze_with_fixture()
        measure_codes = {m["code"] for m in result["measures"]}
        tool_codes = {t["code"] for t in result["tools"]}
        for entry in result["explanations"]:
            for measure in entry["measures"]:
                self.assertIn(measure["measure_code"], measure_codes)
                self.assertTrue(set(measure["tool_codes"]).issubset(tool_codes))

    def test_hostile_matched_category_flows_verbatim_through_service(self):
        # A synthetic threat carrying HTML-special/script categories is
        # selected by identical hostile profile strings; the matched reason
        # is exactly that untrusted text, untouched and JSON-safe.
        result = self.analyze_with_fixture(
            profile=HOSTILE_PROFILE,
            threats=HOSTILE_THREATS,
            measures=HOSTILE_MEASURES,
            tools=HOSTILE_TOOLS,
            mappings=HOSTILE_MAPPINGS,
        )
        self.assertEqual(result["explanations"], HOSTILE_EXPECTED_EXPLANATIONS)
        self.assertEqual(
            [threat["code"] for threat in result["threats"]],
            ["DEMO-T-201", "DEMO-T-202"],
        )
        # Full result survives a JSON round trip with the hostile text intact.
        self.assertEqual(
            json.loads(json.dumps(result))["explanations"],
            HOSTILE_EXPECTED_EXPLANATIONS,
        )


# ---------------------------------------------------------------------------
# API / service consistency including explanations
# ---------------------------------------------------------------------------


class ApiServiceConsistencyTests(SimpleTestCase):
    """The JSON API returns exactly the shared service result, explanations included."""

    def test_api_equals_service_for_all_scenarios(self):
        from services.analyzer import analyze_profile

        for name, profile in SCENARIOS.items():
            with self.subTest(scenario=name):
                response = post_api_profile(self.client, profile)
                self.assertEqual(response.status_code, 200)
                self.assertTrue(
                    response["Content-Type"].startswith("application/json")
                )
                self.assertEqual(response.json(), analyze_profile(profile))

    def test_api_explanations_equal_service_explanations(self):
        from services.analyzer import analyze_profile

        for name, profile in SCENARIOS.items():
            with self.subTest(scenario=name):
                api = post_api_profile(self.client, profile).json()
                self.assertEqual(
                    api["explanations"], analyze_profile(profile)["explanations"]
                )

    def test_empty_result_also_equals_service(self):
        from services.analyzer import analyze_profile

        profile = {"system_type": "does-not-exist"}
        response = post_api_profile(self.client, profile)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), analyze_profile(profile))

    def test_metadata_unchanged_by_explanations(self):
        payload = post_api_profile(self.client, PROFILE_A).json()
        self.assertEqual(payload["metadata"], {"source": "demo", "version": "MVP-1"})
        self.assertEqual(
            payload["statistics"],
            {
                "threats": len(payload["threats"]),
                "measures": len(payload["measures"]),
                "tools": len(payload["tools"]),
            },
        )


# ---------------------------------------------------------------------------
# URL surface: exactly the documented routes, nothing added
# ---------------------------------------------------------------------------

EXPECTED_ROUTES = {
    ("", "home"),
    ("profile/", "profile"),
    ("profile/analyze/", "profile_analyze"),
    ("api/threats/", "api_threats"),
    ("api/threats/<str:code>/", "api_threat_detail"),
    ("api/measures/", "api_measures"),
    ("api/tools/", "api_tools"),
    ("api/tactics/", "api_tactics"),
    ("api/ai-threats/", "api_ai_threats"),
    ("api/levels/", "api_levels"),
    ("api/profile/analyze/", "api_profile_analyze"),
}


class RouteSurfaceTests(SimpleTestCase):
    """``explanations`` is additive: no new URL routes appear."""

    def test_urlconf_exposes_exactly_the_documented_routes(self):
        routes = {
            (str(pattern.pattern), pattern.name)
            for pattern in get_resolver().url_patterns
        }
        self.assertEqual(routes, EXPECTED_ROUTES)

    def test_explanations_add_no_endpoint_of_their_own(self):
        for url in ("/api/explanations/", "/api/profile/explanations/", "/explanations/"):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 404)


# ---------------------------------------------------------------------------
# No persistence: analysis never mutates the read-only seed data
# ---------------------------------------------------------------------------


def data_snapshot():
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(DATA_DIR.glob("*.json"))
    }


class NoPersistenceTests(SimpleTestCase):
    """Profiles and results live only in the request; data/ stays read-only."""

    def test_analysis_does_not_modify_seed_files(self):
        from services.analyzer import analyze_profile

        before = data_snapshot()
        for profile in SCENARIOS.values():
            self.assertEqual(analyze_profile(profile)["metadata"]["source"], "demo")
            response = post_api_profile(self.client, profile)
            self.assertEqual(response.status_code, 200)
        analyze_profile({})
        post_api_profile(self.client, {"uses_ai": True})
        self.assertEqual(data_snapshot(), before)


# ---------------------------------------------------------------------------
# Profile page scenario guide regression (A/B/C field states)
# ---------------------------------------------------------------------------

DETAILS_RE = re.compile(
    r"<details>\s*<summary>(.*?)</summary>(.*?)</details>", re.DOTALL
)


class ScenarioGuideTests(SimpleTestCase):
    """Guide copy pins the documented field states per scenario.

    Regression for the copy defect where scenario B told the user to leave
    «Доступна из интернета» unchecked, contradicting docs/mvp.md (B/C have
    internet_exposed=true). Assertions are per-field state markers inside
    each <details> block, not exact paragraph text.
    """

    GUIDE_STATES = {
        # scenario: (system_type marker, internet on?, uses_ai on?)
        "A": ("<strong>Веб-приложение</strong>", True, False),
        "B": ("<strong>Внутренняя система</strong>", True, False),
        "C": ("<strong>Внутренняя система</strong>", True, True),
    }

    def guide_blocks(self):
        response = self.client.get(PROFILE_PAGE)
        self.assertEqual(response.status_code, 200)
        blocks = {}
        for summary, body in DETAILS_RE.findall(response.content.decode()):
            for letter in ("A", "B", "C"):
                if f"Сценарий {letter}" in summary:
                    blocks[letter] = body
        self.assertEqual(set(blocks), {"A", "B", "C"})
        return blocks

    @staticmethod
    def field_is_checked(block, label):
        """State of the checkbox named ``label`` per the guide sentence."""
        start = block.find(label)
        assert start != -1, label
        window = block[start + len(label): start + len(label) + 60]
        is_off = "снять" in window or "не отмеча" in window
        is_on = ("отметить" in window or "отметьте" in window) and not is_off
        return is_on, is_off

    def test_guide_states_match_documented_scenarios(self):
        blocks = self.guide_blocks()
        for letter, (type_marker, internet_on, ai_on) in self.GUIDE_STATES.items():
            with self.subTest(scenario=letter):
                block = blocks[letter]
                self.assertIn(type_marker, block)
                internet_state = self.field_is_checked(
                    block, "Доступна из интернета"
                )
                self.assertIs(internet_state[0], internet_on,
                              f"{letter}: internet must be {'ON' if internet_on else 'OFF'}")
                self.assertFalse(internet_state[1] and internet_state[0])
                ai_state = self.field_is_checked(block, "Использует искусственный интеллект")
                self.assertIs(ai_state[0], ai_on,
                              f"{letter}: uses_ai must be {'ON' if ai_on else 'OFF'}")

    def test_guide_lists_every_profile_field_for_every_scenario(self):
        # All five fields are addressed explicitly in each scenario block.
        fields = (
            "Тип системы",
            "Веб-интерфейс",
            "Программный интерфейс (API)",
            "Доступна из интернета",
            "Конфиденциальность",
            "Целостность",
            "Использует искусственный интеллект",
        )
        for letter, block in self.guide_blocks().items():
            for field in fields:
                with self.subTest(scenario=letter, field=field):
                    self.assertIn(field, block)


# ---------------------------------------------------------------------------
# HTML vertical slice (renders templates; run against the final frontend)
# ---------------------------------------------------------------------------


class HtmlVerticalSliceTests(SimpleTestCase):
    """Home → profile token → CSRF-protected submit for A/B/C."""

    FORM_DATA = {
        "A": {
            "system_type": "web",
            "interfaces": ["web"],
            "internet_exposed": "on",
            "data_classes": ["confidentiality"],
        },
        "B": {
            "system_type": "internal",
            "interfaces": ["api"],
            "internet_exposed": "on",
        },
        "C": {
            "system_type": "internal",
            "internet_exposed": "on",
            "uses_ai": "on",
        },
    }

    def csrf_flow(self, form_data):
        """Home → profile page → token-protected analysis POST (real CSRF)."""
        client = Client(enforce_csrf_checks=True)
        home = client.get(HOME_PAGE)
        self.assertEqual(home.status_code, 200)
        page = client.get(PROFILE_PAGE)
        self.assertEqual(page.status_code, 200)
        match = CSRF_TOKEN_RE.search(page.content.decode())
        self.assertIsNotNone(match, "profile form must embed a CSRF token")
        response = client.post(
            HTML_ANALYZE, {"csrfmiddlewaretoken": match.group(1), **form_data}
        )
        self.assertEqual(response.status_code, 200)
        return response

    def test_vertical_slice_scenario_result(self):
        from services.analyzer import analyze_profile

        for name, profile in SCENARIOS.items():
            with self.subTest(scenario=name):
                response = self.csrf_flow(self.FORM_DATA[name])
                html = response.content.decode()

                # The page is rendered from exactly the shared AnalysisResult.
                expected = seed_reference_result(profile)
                self.assertEqual(response.context["result"], expected)
                self.assertEqual(response.context["result"], analyze_profile(profile))
                api = post_api_profile(self.client, profile)
                self.assertEqual(api.status_code, 200)
                self.assertEqual(api.json(), response.context["result"])

                # Codes of every returned entity appear; the matched reasons
                # are displayed with their Russian category labels.
                for threat in expected["threats"]:
                    self.assertIn(threat["code"], html)
                for measure in expected["measures"]:
                    self.assertIn(measure["code"], html)
                for tool in expected["tools"]:
                    self.assertIn(tool["code"], html)
                for entry in expected["explanations"]:
                    for category in entry["matched_categories"]:
                        self.assertIn(CATEGORY_LABELS_RU[category], html)

                # Demo notice and normalized profile stay visible.
                self.assertIn("Демонстрационные данные", html)
                self.assertIn("Источник: Демонстрационные данные", html)
                self.assertIn(profile["system_type"], html)

    def test_scenario_a_reason_is_web_not_integrity(self):
        response = self.csrf_flow(self.FORM_DATA["A"])
        html = response.content.decode()
        self.assertIn("DEMO-T-006", html)
        self.assertIn("web", html)
        explanation = next(
            e
            for e in response.context["result"]["explanations"]
            if e["threat_code"] == "DEMO-T-006"
        )
        self.assertEqual(explanation["matched_categories"], ["web"])

    def test_chain_links_have_no_dangling_same_page_anchors(self):
        for name, profile in SCENARIOS.items():
            with self.subTest(scenario=name):
                response = self.csrf_flow(self.FORM_DATA[name])
                html = response.content.decode()
                ids = set(HTML_ID_RE.findall(html))
                targets = set(HTML_ANCHOR_RE.findall(html))
                self.assertTrue(
                    targets, "result page should link sections via same-page anchors"
                )
                self.assertEqual(
                    targets - ids, set(), "dangling same-page anchor targets"
                )

    def test_empty_selection_still_renders_demo_notice(self):
        response = self.csrf_flow({"system_type": "does-not-exist"})
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        self.assertEqual(response.context["result"]["explanations"], [])
        self.assertIn("Демонстрационные данные", html)

    def test_untrusted_profile_text_is_escaped_in_html(self):
        hostile = {
            "system_type": '<script>alert("pwn")</script>',
            "interfaces": ['<img src=x onerror="pwn()">'],
            "internet_exposed": "on",
            "data_classes": ['<b>&"quoted"</b>'],
        }
        response = self.csrf_flow(hostile)
        html = response.content.decode()
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img src=x", html)
        self.assertNotIn('<b>&"quoted"</b>', html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;img", html)

    def hostile_repository_patches(self):
        """Repository patches serving the hostile-category synthetic graph."""
        measure_index = {item["code"]: item for item in HOSTILE_MEASURES}
        tool_index = {item["code"]: item for item in HOSTILE_TOOLS}

        def fake_get_by_code(name, code):
            catalog = measure_index if name == "measures" else tool_index
            return catalog.get(code)

        return [
            mock.patch("services.analyzer.items", return_value=HOSTILE_THREATS),
            mock.patch("services.analyzer.load", return_value=HOSTILE_MAPPINGS),
            mock.patch(
                "services.analyzer.get_by_code", side_effect=fake_get_by_code
            ),
        ]

    def test_matched_reason_with_hostile_category_is_escaped_in_html(self):
        # The existing hostile-profile test only exercises the summary echo:
        # hostile strings cannot match seed categories. Here the repository
        # mock supplies threats whose *categories* are hostile, so the hostile
        # text must flow into matched_categories and be escaped on render.
        with contextlib.ExitStack() as stack:
            for patch in self.hostile_repository_patches():
                stack.enter_context(patch)
            response = self.csrf_flow(
                {
                    "system_type": "internal",
                    "interfaces": [HOSTILE_SCRIPT_CATEGORY, HOSTILE_IMG_CATEGORY],
                }
            )
        html = response.content.decode()

        # Guard: the rendered result really carries hostile matched reasons,
        # so this tests matched-category rendering, not just the profile echo.
        self.assertEqual(
            response.context["result"]["explanations"],
            HOSTILE_EXPECTED_EXPLANATIONS,
        )
        self.assertIn("DEMO-T-201", html)
        self.assertIn("DEMO-T-202", html)

        # Raw markup must never reach the browser...
        self.assertNotIn('<script>alert("match")', html)
        self.assertNotIn("<img src=x", html)
        self.assertNotIn('onerror="pwn()"', html)
        # ...while an escaped (or JSON-safely encoded) rendering does.
        self.assertTrue(
            "&lt;script" in html or "\\u003cscript" in html,
            "hostile matched reason must appear escaped",
        )
        self.assertTrue(
            "&lt;img" in html or "\\u003cimg" in html,
            "hostile matched reason must appear escaped",
        )

    def test_explanations_visible_and_chain_links_reference_entity_anchors(self):
        # Explanations are rendered visibly and their threat→measure→tool
        # chain links point at anchors of the referenced entities — not
        # merely at global section anchors (ids/hrefs containing the code).
        for name, profile in SCENARIOS.items():
            with self.subTest(scenario=name):
                response = self.csrf_flow(self.FORM_DATA[name])
                html = response.content.decode()
                expected = seed_reference_result(profile)

                for entry in expected["explanations"]:
                    self.assertGreaterEqual(
                        html.count(entry["threat_code"]), 2, entry["threat_code"]
                    )
                    for measure in entry["measures"]:
                        self.assertGreaterEqual(
                            html.count(measure["measure_code"]), 2
                        )
                        for tool_code in measure["tool_codes"]:
                            self.assertGreaterEqual(html.count(tool_code), 2)

                ids = set(HTML_ID_RE.findall(html))
                hrefs = set(HTML_ANCHOR_RE.findall(html))
                referenced = set()
                for entry in expected["explanations"]:
                    referenced.add(entry["threat_code"])
                    for measure in entry["measures"]:
                        referenced.add(measure["measure_code"])
                        referenced.update(measure["tool_codes"])
                for code in sorted(referenced):
                    code_ids = {value for value in ids if code in value}
                    self.assertTrue(code_ids, f"no same-page anchor id for {code}")
                    self.assertTrue(
                        code_ids & hrefs,
                        f"no same-page link points at an anchor of {code}",
                    )

    def test_untrusted_profile_text_is_returned_verbatim_by_api(self):
        hostile = {
            "system_type": '<script>alert("pwn")</script>',
            "interfaces": ["<b>x</b>"],
            "data_classes": [],
            "internet_exposed": False,
            "uses_ai": False,
        }
        response = post_api_profile(self.client, hostile)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["profile"]["system_type"], hostile["system_type"])
        self.assertEqual(payload["explanations"], [])
        self.assertEqual(payload, seed_reference_result(hostile))
