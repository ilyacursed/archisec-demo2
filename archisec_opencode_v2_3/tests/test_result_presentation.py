"""Focused QA tests for the HTML presentation layer (DEMO product slice).

Owned file of the QA agent. Prepared from the documented contract only
(docs/mvp.md, docs/data_schemas.md, docs/quality_gates.md); it must keep
passing against the final backend/frontend implementation without edits to
the pre-existing suites (``test_smoke.py``, ``test_quality_gates.py`,
``test_analysis_explanations.py`` — including their legacy scenario C).

Coverage map (contract → tests):

Pure helper ``services.result_presentation.build_result_presentation``:
- exact keys ``threat_cards``/``measure_cards``/``tool_cards``/``coverage``;
  cards carry ``item`` + ``matched_categories`` / ``threat_codes`` /
  ``measure_codes``; card order follows the result;
- reverse links are derived *only* from the selected ``result.explanations``
  (stable first-seen dedup, restricted to returned entities, foreign threat
  entries ignored);
- ``coverage`` counts threats once: complete iff at least one explained
  returned measure has at least one explained returned tool; mixed
  complete/incomplete branches count complete; empty result → 0/0/0; no
  efficacy/percentage fields;
- non-mutation of the input result, freshness (no aliasing between calls),
  determinism, and no repository/mappings access at all.

Profile form helpers ``build_profile_form`` / ``default_profile_form``:
- ``system_type_options(value, label, selected)``, ``interface_options`` and
  ``data_class_options(value, label, checked)`` plus boolean flags;
- every current list element (original order, duplicates, empty and unknown
  strings) becomes its own checked control, absent standards appended
  unchecked; unknown/empty system type yields exactly one selected option;
  the fresh form keeps UI defaults (``web`` system, ``web`` interface);
- no input mutation, no covert conversion/normalisation of strings.

E2E / HTML (Home → «Начать анализ» → profile token → CSRF submit):
- A → 001/003/004/006, B → 002/003, NEW C → 003/004/005 with hard-coded
  independent expectations (never derived from the analyzer); legacy C
  (3/5, 2-2-2) re-pinned as API regression;
- inline per-card reasons (not a global union), per-card reverse links to
  selected entities only, stats/coverage in context, demo non-recommendation
  notice, unique non-broken same-page anchors, no percentage claims;
- the result edit form is parsed from the actual HTML (HTMLParser,
  successful controls) and resubmitted unchanged — preserving custom/empty/
  duplicate list strings, custom system type and boolean states; changing a
  selection re-POSTs the same endpoint; a fresh GET resets UI defaults; no
  URL payload, no persistence; real CSRF token required (missing/invalid
  rejected);
- hostile quoted attributes/labels/reasons are escaped and non-executing.

Synthetic fixtures cover missing / shared / one-to-many / dangling paths both
at service level and (repository-patched) in rendered HTML. API keys stay
exactly unchanged (7 keys, statistics 3 keys, metadata ``demo / MVP-1``) and
``data/*.json`` hashes are unchanged by every flow below.
"""

import contextlib
import copy
import hashlib
import json
import re
from html import escape
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock

from django.test import Client, SimpleTestCase

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

API_ANALYZE = "/api/profile/analyze/"
HTML_ANALYZE = "/profile/analyze/"
PROFILE_PAGE = "/profile/"
HOME_PAGE = "/"

CSRF_TOKEN_RE = re.compile(r'name="csrfmiddlewaretoken" value="([^"]+)"')
HTML_ID_RE = re.compile(r'\bid="([^"]+)"')
HTML_ANCHOR_RE = re.compile(r'href="#([^"]+)"')
DETAILS_RE = re.compile(r"<details>\s*<summary>(.*?)</summary>(.*?)</details>", re.DOTALL)

# ---------------------------------------------------------------------------
# Documented demo profiles and hard-coded, analyzer-independent expectations.
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
# NEW scenario C (docs/mvp.md): AI + internet + confidentiality.
PROFILE_C_NEW = {
    "system_type": "internal",
    "interfaces": [],
    "internet_exposed": True,
    "data_classes": ["confidentiality"],
    "uses_ai": True,
}
# Legacy scenario C (kept as a regression scenario; also pinned by the
# pre-existing suites which must stay untouched and green).
PROFILE_C_LEGACY = {
    "system_type": "internal",
    "interfaces": [],
    "internet_exposed": True,
    "data_classes": [],
    "uses_ai": True,
}

HTML_FORM_DATA = {
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
        "data_classes": [],
    },
    # No interfaces control is submitted: the unchecked box is simply absent.
    "C_NEW": {
        "system_type": "internal",
        "internet_exposed": "on",
        "data_classes": ["confidentiality"],
        "uses_ai": "on",
    },
}


def _chain(number):
    return (
        f"DEMO-T-{number:03d}",
        f"DEMO-M-{number:03d}",
        f"DEMO-SZI-{number:03d}",
    )


SCENARIOS = {"A": PROFILE_A, "B": PROFILE_B, "C_NEW": PROFILE_C_NEW}

EXPECTED_CODES = {
    "A": ["DEMO-T-001", "DEMO-T-003", "DEMO-T-004", "DEMO-T-006"],
    "B": ["DEMO-T-002", "DEMO-T-003"],
    "C_NEW": ["DEMO-T-003", "DEMO-T-004", "DEMO-T-005"],
}
EXPECTED_STATS = {
    "A": {"threats": 4, "measures": 4, "tools": 4},
    "B": {"threats": 2, "measures": 2, "tools": 2},
    "C_NEW": {"threats": 3, "measures": 3, "tools": 3},
}
EXPECTED_CHAINS = {
    "A": [_chain(1), _chain(3), _chain(4), _chain(6)],
    "B": [_chain(2), _chain(3)],
    "C_NEW": [_chain(3), _chain(4), _chain(5)],
}
# Reverse expectations derived from the documented chain table (docs/mvp.md),
# never from the analyzer or the seed files.
EXPECTED_REVERSE = {
    name: (
        {m: [t] for t, m, _ in chains},
        {s: [m] for _, m, s in chains},
    )
    for name, chains in EXPECTED_CHAINS.items()
}
EXPECTED_COVERAGE = {
    name: {
        "selected_threats": stats["threats"],
        "complete_path_threats": stats["threats"],
        "incomplete_path_threats": 0,
    }
    for name, stats in EXPECTED_STATS.items()
}


def _explanation(number, category):
    threat, measure, tool = _chain(number)
    return {
        "threat_code": threat,
        "matched_categories": [category],
        "measures": [{"measure_code": measure, "tool_codes": [tool]}],
    }


EXPECTED_EXPLANATIONS = {
    "A": [
        _explanation(1, "web"),
        _explanation(3, "internet"),
        _explanation(4, "confidentiality"),
        _explanation(6, "web"),
    ],
    "B": [_explanation(2, "api"), _explanation(3, "internet")],
    "C_NEW": [
        _explanation(3, "internet"),
        _explanation(4, "confidentiality"),
        _explanation(5, "ai"),
    ],
}

# Standard UI option values (docs/mvp.md): demo defaults only, validator
# never restricts category strings to them.
STANDARD_SYSTEM_TYPES = ("web", "internal")
STANDARD_INTERFACES = ("web", "api")
STANDARD_DATA_CLASSES = ("confidentiality", "integrity")

# Russian display labels for matched categories (docs/branding.md and
# services/terminology). Raw category codes stay machine values in the API
# and in form values; only the visible reason text is localized.
CATEGORY_LABELS_RU = {
    "web": "Веб-приложение",
    "api": "Программный интерфейс (API)",
    "internet": "Доступ из интернета",
    "ai": "Искусственный интеллект",
    "confidentiality": "Конфиденциальность",
    "integrity": "Целостность",
}

# Hostile strings for quoting/escaping checks.
HOSTILE_SYSTEM = 'Custom "тип" & <система>'
HOSTILE_INTERFACE = 'x"y&z</option>'
HOSTILE_DATA_CLASS = "секретно&amp;"
PERCENT_RE = re.compile(r"\d\s*%")
NON_RECOMMENDATION_RES = (
    re.compile(r"не\s+рекоменд", re.IGNORECASE),
    # «Не являются нормативной рекомендацией» and close variants.
    re.compile(r"не\s+явля\w+(?:\s+\w+){0,3}\s+рекоменд", re.IGNORECASE),
    re.compile(r"non[-\s]recommendation", re.IGNORECASE),
)


def data_snapshot():
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(DATA_DIR.glob("*.json"))
    }


# ---------------------------------------------------------------------------
# HTML parsing helpers (real browser semantics: successful controls).
# ---------------------------------------------------------------------------


class SuccessfulControlsParser(HTMLParser):
    """Collect the successful controls of the form posting to ``action``.

    Implements the HTML rules that matter here: only controls inside the
    matching form with a ``name`` and without ``disabled`` are successful;
    unchecked checkboxes/radios are not; a selected ``<option>`` submits its
    ``value`` attribute (text content when absent) for the owning ``<select>``;
    submit/button/reset/image/file inputs are ignored. Duplicate names keep
    document order — list fields genuinely round-trip.
    """

    def __init__(self, action):
        super().__init__(convert_charrefs=True)
        self.action = action
        self.in_form = False
        self.form_found = False
        self.controls = []
        self._select_name = None
        self._option = None
        self._textarea_name = None
        self._textarea_text = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "form":
            if attrs_dict.get("action") == self.action:
                self.in_form = True
                self.form_found = True
            return
        if not self.in_form:
            return
        if tag == "input":
            name = attrs_dict.get("name")
            if not name or "disabled" in attrs_dict:
                return
            input_type = (attrs_dict.get("type") or "text").lower()
            if input_type in ("checkbox", "radio"):
                if "checked" in attrs_dict:
                    # HTML: a checked box/radio without a value attribute
                    # submits "on" (the boolean checkboxes rely on this).
                    value = attrs_dict.get("value")
                    if value is None:
                        value = "on"
                    self.controls.append((name, value))
            elif input_type in (
                "hidden", "text", "search", "tel", "url", "email",
                "password", "number",
            ):
                self.controls.append((name, attrs_dict.get("value", "")))
        elif tag == "select":
            self._select_name = attrs_dict.get("name")
        elif tag == "option":
            if self._select_name is not None:
                self._option = {
                    "value": attrs_dict.get("value"),
                    "selected": "selected" in attrs_dict,
                    "text": [],
                }
        elif tag == "textarea":
            self._textarea_name = attrs_dict.get("name")
            self._textarea_text = []

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_data(self, data):
        if self._option is not None:
            self._option["text"].append(data)
        if self._textarea_name is not None:
            self._textarea_text.append(data)

    def handle_endtag(self, tag):
        if tag == "option" and self._option is not None:
            if self._option["selected"] and self._select_name:
                value = self._option["value"]
                if value is None:
                    value = "".join(self._option["text"]).strip()
                self.controls.append((self._select_name, value))
            self._option = None
        elif tag == "select":
            self._select_name = None
        elif tag == "textarea" and self._textarea_name is not None:
            self.controls.append((self._textarea_name, "".join(self._textarea_text)))
            self._textarea_name = None
        elif tag == "form" and self.in_form:
            self.in_form = False


def parse_controls(html, action=HTML_ANALYZE):
    parser = SuccessfulControlsParser(action)
    parser.feed(html)
    parser.close()
    return parser


def controls_to_post_data(controls):
    data = {}
    for name, value in controls:
        data.setdefault(name, []).append(value)
    return data


FORM_STRIP_RE = re.compile(
    r'<form\b[^>]*action="/profile/analyze/"[^>]*>.*?</form>',
    re.DOTALL | re.IGNORECASE,
)
CARD_ID_RE = re.compile(r'\bid="([^"]*?(DEMO-(?:T|M|SZI)-\d{3})[^"]*)"')


def card_blocks(html):
    """Map entity code → its own card markup block (edit form stripped).

    A block spans from the card anchor id containing the code to the card's
    closing ``</li>`` (cards never nest lists), so per-card assertions never
    read a neighbouring card or the later chain-explanation section.
    """
    stripped = FORM_STRIP_RE.sub("", html)
    blocks = {}
    for match in CARD_ID_RE.finditer(stripped):
        code = match.group(2)
        if code in blocks:
            continue
        end = stripped.find("</li>", match.start(1))
        if end == -1:
            end = len(stripped)
        blocks[code] = stripped[match.start(1):end]
    return blocks


CARD_REASON_RE = re.compile(
    r'class="[^"]*card-reason[^"]*"[^>]*>(.*?)</p>', re.DOTALL
)


def card_reason(block):
    """Text of the card's inline reason paragraph (tags stripped)."""
    match = CARD_REASON_RE.search(block)
    assert match, "card must render an inline reason paragraph"
    return re.sub(r"<[^>]+>", "", match.group(1))


def csrf_flow(form_data):
    """Home → profile page → real-token CSRF-protected analysis POST."""
    client = Client(enforce_csrf_checks=True)
    home = client.get(HOME_PAGE)
    assert home.status_code == 200, home.status_code
    page = client.get(PROFILE_PAGE)
    assert page.status_code == 200, page.status_code
    match = CSRF_TOKEN_RE.search(page.content.decode())
    assert match, "profile form must embed a CSRF token"
    response = client.post(
        HTML_ANALYZE, {"csrfmiddlewaretoken": match.group(1), **form_data}
    )
    assert response.status_code == 200, response.status_code
    return client, response


def guide_field_state(block_html, label):
    """(checked?, unchecked?) state of ``label`` inside its own guide clause.

    Clause-scoped (split at ``, ; . ! ?``): scenario C legitimately groups
    «Конфиденциальность» — отметить and «Целостность» — снять in one
    sentence, so a sentence-wide or fixed-window read would misreport the
    ON field as OFF.
    """
    text = re.sub(r"<[^>]+>", "", block_html)
    start = text.find(label)
    assert start != -1, f"label {label!r} missing from guide block"
    tail = text[start + len(label):]
    clause = re.split(r"[,;.!?]", tail, maxsplit=1)[0]
    is_off = "снять" in clause or "не отмеча" in clause or "выключ" in clause
    is_on = (
        "отмети" in clause or "отмечен" in clause or "включ" in clause
    ) and not is_off
    return is_on, is_off


# ---------------------------------------------------------------------------
# Synthetic AnalysisResult fixtures (pure dicts; no repository involved).
# ---------------------------------------------------------------------------


def synth_result(threats, measures, tools, explanations, profile=None):
    return {
        "profile": profile
        or {
            "system_type": "internal",
            "interfaces": [],
            "internet_exposed": False,
            "data_classes": [],
            "uses_ai": False,
        },
        "threats": threats,
        "measures": measures,
        "tools": tools,
        "explanations": explanations,
        "statistics": {
            "threats": len(threats),
            "measures": len(measures),
            "tools": len(tools),
        },
        "metadata": {"source": "demo", "version": "MVP-1"},
    }


def entity(code, **extra):
    item = {"code": code, "name": f"Demo {code}", "description": "Demo"}
    item.update(extra)
    return item


def explanation(threat_code, categories, measures):
    return {
        "threat_code": threat_code,
        "matched_categories": categories,
        "measures": measures,
    }


def measure_link(measure_code, tool_codes):
    return {"measure_code": measure_code, "tool_codes": tool_codes}


BLOCKED_REPO_FUNCTIONS = [
    ("services.data_repository", "load"),
    ("services.data_repository", "items"),
    ("services.data_repository", "get_by_code"),
    ("services.mappings", "load"),
    ("services.mappings", "load_mappings"),
    ("services.mappings", "validate_mappings"),
    ("services.mappings", "validate_mapping_dict"),
    ("services.catalogs", "load"),
    ("services.catalogs", "items"),
    ("services.catalogs", "get_by_code"),
    ("services.analyzer", "analyze_profile"),
    ("services.analyzer", "items"),
    ("services.analyzer", "load"),
    ("services.analyzer", "get_by_code"),
    ("services.result_presentation", "load"),
    ("services.result_presentation", "items"),
    ("services.result_presentation", "get_by_code"),
    ("services.result_presentation", "load_mappings"),
    ("services.result_presentation", "analyze_profile"),
]


class _ForbiddenModule:
    def __getattr__(self, name):
        raise AssertionError(f"presentation accessed repository module .{name}")


def blocked_repository_patches():
    """Patches making any repository/mappings access fail loudly."""
    import importlib

    patches = []
    for module_name, function_name in BLOCKED_REPO_FUNCTIONS:
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        if not hasattr(module, function_name):
            continue
        patches.append(
            mock.patch(
                f"{module_name}.{function_name}",
                side_effect=AssertionError(
                    f"presentation helper accessed {module_name}.{function_name}"
                ),
            )
        )

    import types

    import services.result_presentation as presentation_module

    forbidden_modules = set()
    for module_name in (
        "services.data_repository",
        "services.mappings",
        "services.catalogs",
        "services.analyzer",
    ):
        try:
            forbidden_modules.add(importlib.import_module(module_name))
        except ImportError:
            continue
    for attr_name in dir(presentation_module):
        value = getattr(presentation_module, attr_name, None)
        if isinstance(value, types.ModuleType) and value in forbidden_modules:
            patches.append(
                mock.patch.object(
                    presentation_module, attr_name, new=_ForbiddenModule()
                )
            )
    return patches


def build_presentation(result):
    from services.result_presentation import build_result_presentation

    return build_result_presentation(result)


def build_form(profile):
    from services.result_presentation import build_profile_form

    return build_profile_form(profile)


def default_form():
    from services.result_presentation import default_profile_form

    return default_profile_form()


def assert_deeply_fresh(testcase, build):
    """Two calls are equal, distinct, and share no mutable structure."""
    first = build()
    second = build()
    testcase.assertEqual(first, second)
    testcase.assertIsNot(first, second)

    def mutate(node):
        if isinstance(node, list):
            node.append("ZZZ_MUTATED")
            for item in node:
                mutate(item)
        elif isinstance(node, dict):
            for value in node.values():
                mutate(value)

    mutate(first)
    testcase.assertEqual(build(), second, "a mutated previous output leaked into a new call")


# ---------------------------------------------------------------------------
# build_result_presentation: pure contract on synthetic results
# ---------------------------------------------------------------------------


class PresentationServiceTests(SimpleTestCase):
    """``build_result_presentation`` derives cards/coverage from explanations."""

    def full_graph_result(self):
        """Complete graph: T1→{M1→S1, M2→S2(shared)}, T2→M2, T3 orphan."""
        threats = [
            entity("DEMO-T-001", categories=["a"]),
            entity("DEMO-T-002", categories=["b"]),
            entity("DEMO-T-003", categories=["c"]),
        ]
        measures = [entity("DEMO-M-001"), entity("DEMO-M-002")]
        tools = [entity("DEMO-SZI-001"), entity("DEMO-SZI-002")]
        explanations = [
            explanation(
                "DEMO-T-001",
                ["a"],
                [
                    measure_link("DEMO-M-001", ["DEMO-SZI-001"]),
                    measure_link("DEMO-M-002", ["DEMO-SZI-001", "DEMO-SZI-002"]),
                ],
            ),
            explanation(
                "DEMO-T-002", ["b"], [measure_link("DEMO-M-002", ["DEMO-SZI-001"])]
            ),
            explanation("DEMO-T-003", ["c"], []),
        ]
        return synth_result(threats, measures, tools, explanations)

    def test_top_level_keys_are_exactly_documented(self):
        presentation = build_presentation(self.full_graph_result())
        self.assertEqual(
            set(presentation),
            {"threat_cards", "measure_cards", "tool_cards", "coverage"},
        )

    def test_card_key_sets_and_item_equality_in_result_order(self):
        result = self.full_graph_result()
        presentation = build_presentation(result)
        for cards, collection, extra_key in (
            ("threat_cards", "threats", "matched_categories"),
            ("measure_cards", "measures", "threat_codes"),
            ("tool_cards", "tools", "measure_codes"),
        ):
            card_list = presentation[cards]
            self.assertIsInstance(card_list, list)
            self.assertEqual(len(card_list), len(result[collection]))
            for card, item in zip(card_list, result[collection]):
                self.assertEqual(set(card), {"item", extra_key})
                self.assertEqual(card["item"], item)

    def test_threat_cards_carry_explanation_matched_categories(self):
        presentation = build_presentation(self.full_graph_result())
        reasons = {
            card["item"]["code"]: card["matched_categories"]
            for card in presentation["threat_cards"]
        }
        self.assertEqual(
            reasons,
            {
                "DEMO-T-001": ["a"],
                "DEMO-T-002": ["b"],
                "DEMO-T-003": ["c"],
            },
        )

    def test_measure_cards_reverse_links_follow_threat_order_with_dedup(self):
        presentation = build_presentation(self.full_graph_result())
        reverse = {
            card["item"]["code"]: card["threat_codes"]
            for card in presentation["measure_cards"]
        }
        # Shared measure DEMO-M-002 links both threats in explanation order.
        self.assertEqual(reverse["DEMO-M-001"], ["DEMO-T-001"])
        self.assertEqual(reverse["DEMO-M-002"], ["DEMO-T-001", "DEMO-T-002"])

    def test_tool_cards_reverse_links_follow_measure_order_with_dedup(self):
        presentation = build_presentation(self.full_graph_result())
        reverse = {
            card["item"]["code"]: card["measure_codes"]
            for card in presentation["tool_cards"]
        }
        # Shared tool DEMO-SZI-001 is linked by M1 then M2 (explanation order).
        self.assertEqual(reverse["DEMO-SZI-001"], ["DEMO-M-001", "DEMO-M-002"])
        self.assertEqual(reverse["DEMO-SZI-002"], ["DEMO-M-002"])

    def test_foreign_threat_explanations_are_ignored(self):
        result = self.full_graph_result()
        result["explanations"].append(
            explanation("DEMO-T-999", ["x"], [measure_link("DEMO-M-001", [])])
        )
        presentation = build_presentation(result)
        threat_codes = [card["item"]["code"] for card in presentation["threat_cards"]]
        self.assertEqual(
            threat_codes, ["DEMO-T-001", "DEMO-T-002", "DEMO-T-003"]
        )
        reverse = {
            card["item"]["code"]: card["threat_codes"]
            for card in presentation["measure_cards"]
        }
        self.assertEqual(reverse["DEMO-M-001"], ["DEMO-T-001"])
        self.assertEqual(presentation["coverage"]["selected_threats"], 3)

    def test_returned_threat_without_explanation_gets_empty_reason_card(self):
        result = self.full_graph_result()
        result["explanations"] = result["explanations"][:2]  # drop T-003 entry
        presentation = build_presentation(result)
        reasons = {
            card["item"]["code"]: card["matched_categories"]
            for card in presentation["threat_cards"]
        }
        self.assertEqual(reasons["DEMO-T-003"], [])
        self.assertEqual(presentation["coverage"]["incomplete_path_threats"], 1)

    def test_dangling_references_are_restricted_to_returned_entities(self):
        # Explanation links name a measure/tool that the result does not
        # return: no card may appear for them and reverse links stay clean.
        threats = [entity("DEMO-T-001", categories=["a"])]
        measures = [entity("DEMO-M-001")]
        tools = [entity("DEMO-SZI-001")]
        explanations = [
            explanation(
                "DEMO-T-001",
                ["a"],
                [
                    measure_link("DEMO-M-001", ["DEMO-SZI-001", "DEMO-SZI-999"]),
                    measure_link("DEMO-M-999", ["DEMO-SZI-001"]),
                ],
            )
        ]
        presentation = build_presentation(
            synth_result(threats, measures, tools, explanations)
        )
        measure_codes = [card["item"]["code"] for card in presentation["measure_cards"]]
        tool_codes = [card["item"]["code"] for card in presentation["tool_cards"]]
        self.assertEqual(measure_codes, ["DEMO-M-001"])
        self.assertEqual(tool_codes, ["DEMO-SZI-001"])
        serialized = json.dumps(presentation)
        self.assertNotIn("DEMO-M-999", serialized)
        self.assertNotIn("DEMO-SZI-999", serialized)

    def test_unlinked_returned_entities_get_empty_reverse_lists(self):
        result = self.full_graph_result()
        result["measures"].append(entity("DEMO-M-099"))
        result["tools"].append(entity("DEMO-SZI-099"))
        presentation = build_presentation(result)
        by_code = {card["item"]["code"]: card for card in presentation["measure_cards"]}
        self.assertEqual(by_code["DEMO-M-099"]["threat_codes"], [])
        tool_by_code = {card["item"]["code"]: card for card in presentation["tool_cards"]}
        self.assertEqual(tool_by_code["DEMO-SZI-099"]["measure_codes"], [])

    def test_coverage_counts_threat_once_with_complete_path(self):
        presentation = build_presentation(self.full_graph_result())
        self.assertEqual(
            presentation["coverage"],
            {"selected_threats": 3, "complete_path_threats": 2,
             "incomplete_path_threats": 1},
        )
        self.assertEqual(
            presentation["coverage"]["complete_path_threats"]
            + presentation["coverage"]["incomplete_path_threats"],
            presentation["coverage"]["selected_threats"],
        )

    def test_coverage_mixed_branches_count_complete(self):
        # One complete branch (M1→S1) plus one dead-end branch (M2→nothing):
        # the threat is complete and counted exactly once.
        threats = [entity("DEMO-T-001", categories=["a"])]
        measures = [entity("DEMO-M-001"), entity("DEMO-M-002")]
        tools = [entity("DEMO-SZI-001")]
        explanations = [
            explanation(
                "DEMO-T-001",
                ["a"],
                [
                    measure_link("DEMO-M-001", ["DEMO-SZI-001"]),
                    measure_link("DEMO-M-002", []),
                ],
            )
        ]
        presentation = build_presentation(
            synth_result(threats, measures, tools, explanations)
        )
        self.assertEqual(
            presentation["coverage"],
            {"selected_threats": 1, "complete_path_threats": 1,
             "incomplete_path_threats": 0},
        )

    def test_coverage_threat_with_measure_but_dangling_tools_is_incomplete(self):
        threats = [entity("DEMO-T-001", categories=["a"])]
        measures = [entity("DEMO-M-001")]
        tools = []  # the only linked tool is not returned
        explanations = [
            explanation(
                "DEMO-T-001", ["a"],
                [measure_link("DEMO-M-001", ["DEMO-SZI-999"])],
            )
        ]
        presentation = build_presentation(
            synth_result(threats, measures, tools, explanations)
        )
        self.assertEqual(presentation["coverage"]["complete_path_threats"], 0)
        self.assertEqual(presentation["coverage"]["incomplete_path_threats"], 1)

    def test_coverage_threat_without_measures_is_incomplete(self):
        threats = [entity("DEMO-T-001", categories=["a"]), entity("DEMO-T-002", categories=["b"])]
        explanations = [
            explanation("DEMO-T-001", ["a"], []),
            explanation("DEMO-T-002", ["b"], [measure_link("DEMO-M-001", ["DEMO-SZI-001"])]),
        ]
        presentation = build_presentation(
            synth_result(
                threats,
                [entity("DEMO-M-001")],
                [entity("DEMO-SZI-001")],
                explanations,
            )
        )
        self.assertEqual(
            presentation["coverage"],
            {"selected_threats": 2, "complete_path_threats": 1,
             "incomplete_path_threats": 1},
        )

    def test_coverage_empty_result_is_zero_everywhere(self):
        presentation = build_presentation(synth_result([], [], [], []))
        self.assertEqual(
            presentation["coverage"],
            {"selected_threats": 0, "complete_path_threats": 0,
             "incomplete_path_threats": 0},
        )
        self.assertEqual(presentation["threat_cards"], [])
        self.assertEqual(presentation["measure_cards"], [])
        self.assertEqual(presentation["tool_cards"], [])

    def test_coverage_has_no_efficacy_or_percentage_fields(self):
        presentation = build_presentation(self.full_graph_result())
        self.assertEqual(
            set(presentation["coverage"]),
            {"selected_threats", "complete_path_threats",
             "incomplete_path_threats"},
        )
        for value in presentation["coverage"].values():
            self.assertIsInstance(value, int)
        self.assertNotIn("%", json.dumps(presentation))
        for forbidden in ("efficacy", "percent", "effectiveness", "гарантир"):
            self.assertNotIn(forbidden, json.dumps(presentation).lower())

    def test_input_result_is_not_mutated(self):
        result = self.full_graph_result()
        snapshot = copy.deepcopy(result)
        presentation = build_presentation(result)
        self.assertEqual(result, snapshot)
        self.assertIsNotNone(presentation)
        # A second call after mutating the *presentation* still leaves the
        # result untouched (no aliasing of result internals).
        presentation["threat_cards"][0]["matched_categories"].append("ZZZ")
        self.assertEqual(result, snapshot)

    def test_calls_are_fresh_and_deterministic(self):
        assert_deeply_fresh(self, lambda: build_presentation(self.full_graph_result()))

    def test_no_repository_or_mappings_access(self):
        result = self.full_graph_result()
        profile = dict(result["profile"])
        with contextlib.ExitStack() as stack:
            for patch in blocked_repository_patches():
                stack.enter_context(patch)
            presentation = build_presentation(result)
            form = build_form(profile)
            fresh = default_form()
        # The calls must have produced real output without any blocked access.
        self.assertEqual(
            set(presentation),
            {"threat_cards", "measure_cards", "tool_cards", "coverage"},
        )
        self.assertIn("system_type_options", form)
        self.assertIn("system_type_options", fresh)


# ---------------------------------------------------------------------------
# build_profile_form / default_profile_form contract
# ---------------------------------------------------------------------------


class ProfileFormServiceTests(SimpleTestCase):
    """Profile form options preserve submitted values without conversion."""

    def profile(self, **overrides):
        profile = {
            "system_type": "web",
            "interfaces": ["web"],
            "internet_exposed": False,
            "data_classes": [],
            "uses_ai": False,
        }
        profile.update(overrides)
        return profile

    def option_tuples(self, options):
        return [(option["value"], option) for option in options]

    def test_form_has_exactly_documented_keys(self):
        form = build_form(self.profile())
        self.assertEqual(
            set(form),
            {
                "system_type_options",
                "interface_options",
                "data_class_options",
                "internet_exposed",
                "uses_ai",
            },
        )
        self.assertIsInstance(form["internet_exposed"], bool)
        self.assertIsInstance(form["uses_ai"], bool)

    def test_option_key_sets_are_exactly_documented(self):
        form = build_form(self.profile())
        for option in form["system_type_options"]:
            self.assertEqual(set(option), {"value", "label", "selected"})
        for options in (form["interface_options"], form["data_class_options"]):
            for option in options:
                self.assertEqual(set(option), {"value", "label", "checked"})

    def test_default_profile_form_keeps_ui_defaults(self):
        form = default_form()
        system = {o["value"]: o["selected"] for o in form["system_type_options"]}
        self.assertEqual(
            system, {"web": True, "internal": False}
        )
        interfaces = self.option_tuples(form["interface_options"])
        self.assertEqual([value for value, _ in interfaces], ["web", "api"])
        self.assertEqual(
            [option["checked"] for _, option in interfaces], [True, False]
        )
        data_classes = self.option_tuples(form["data_class_options"])
        self.assertEqual(
            [value for value, _ in data_classes],
            ["confidentiality", "integrity"],
        )
        self.assertTrue(all(not o["checked"] for _, o in data_classes))
        self.assertIs(form["internet_exposed"], False)
        self.assertIs(form["uses_ai"], False)

    def test_standard_system_type_is_selected_exactly_once(self):
        for value in STANDARD_SYSTEM_TYPES:
            with self.subTest(system_type=value):
                form = build_form(self.profile(system_type=value))
                selected = [
                    option["value"]
                    for option in form["system_type_options"]
                    if option["selected"]
                ]
                self.assertEqual(selected, [value])
                self.assertEqual(
                    {option["value"] for option in form["system_type_options"]},
                    set(STANDARD_SYSTEM_TYPES),
                )

    def test_unknown_system_type_gets_own_single_selected_option(self):
        form = build_form(self.profile(system_type="mainframe-хост"))
        values = [option["value"] for option in form["system_type_options"]]
        self.assertIn("mainframe-хост", values)
        self.assertEqual(
            [option["value"] for option in form["system_type_options"] if option["selected"]],
            ["mainframe-хост"],
        )
        for standard in STANDARD_SYSTEM_TYPES:
            self.assertIn(standard, values)
            option = next(o for o in form["system_type_options"] if o["value"] == standard)
            self.assertFalse(option["selected"])

    def test_empty_system_type_gets_single_selected_option(self):
        form = build_form(self.profile(system_type=""))
        selected = [
            option["value"]
            for option in form["system_type_options"]
            if option["selected"]
        ]
        self.assertEqual(selected, [""])

    def test_every_current_list_element_is_a_checked_control_in_order(self):
        current = ["api", "web", "web", "", 'zzz"quoted"&amp;', "api"]
        form = build_form(self.profile(interfaces=current))
        options = form["interface_options"]
        head = options[: len(current)]
        self.assertEqual([option["value"] for option in head], current)
        self.assertTrue(all(option["checked"] for option in head))

    def test_absent_standards_are_appended_unchecked_after_current(self):
        form = build_form(self.profile(interfaces=["api"], data_classes=["integrity"]))
        interfaces = self.option_tuples(form["interface_options"])
        self.assertEqual([v for v, _ in interfaces], ["api", "web"])
        self.assertEqual([o["checked"] for _, o in interfaces], [True, False])
        data_classes = self.option_tuples(form["data_class_options"])
        self.assertEqual(
            [v for v, _ in data_classes], ["integrity", "confidentiality"]
        )
        self.assertEqual([o["checked"] for _, o in data_classes], [True, False])

    def test_labels_are_strings_and_standards_have_visible_labels(self):
        form = build_form(self.profile())
        for option in (
            form["system_type_options"]
            + form["interface_options"]
            + form["data_class_options"]
        ):
            self.assertIsInstance(option["label"], str)
        standard_values = (
            set(STANDARD_SYSTEM_TYPES)
            | set(STANDARD_INTERFACES)
            | set(STANDARD_DATA_CLASSES)
        )
        for options in (
            form["system_type_options"],
            form["interface_options"],
            form["data_class_options"],
        ):
            for option in options:
                if option["value"] in standard_values:
                    self.assertTrue(option["label"].strip(), option["value"])

    def test_boolean_flags_mirror_profile_values(self):
        form = build_form(
            self.profile(internet_exposed=True, uses_ai=True)
        )
        self.assertIs(form["internet_exposed"], True)
        self.assertIs(form["uses_ai"], True)
        off = build_form(self.profile())
        self.assertIs(off["internet_exposed"], False)
        self.assertIs(off["uses_ai"], False)

    def test_input_profile_is_not_mutated_and_strings_stay_verbatim(self):
        profile = self.profile(
            system_type="  Web  ",
            interfaces=["Web ", "web", ""],
            data_classes=["Confidentiality", "confidentiality"],
        )
        snapshot = copy.deepcopy(profile)
        form = build_form(profile)
        self.assertEqual(profile, snapshot)
        values = [option["value"] for option in form["system_type_options"]]
        self.assertIn("  Web  ", values)
        interface_values = [option["value"] for option in form["interface_options"]]
        self.assertEqual(interface_values[:3], ["Web ", "web", ""])
        data_values = [option["value"] for option in form["data_class_options"]]
        self.assertEqual(data_values[:2], ["Confidentiality", "confidentiality"])
        # No covert conversion: nothing was trimmed, lower-cased or dropped.

    def test_form_calls_are_fresh_and_deterministic(self):
        profile = self.profile(interfaces=["api", "api", ""], uses_ai=True)
        assert_deeply_fresh(self, lambda: build_form(profile))

    def test_defaults_profile_builds_the_default_form(self):
        self.assertEqual(
            build_form(
                {
                    "system_type": "web",
                    "interfaces": ["web"],
                    "internet_exposed": False,
                    "data_classes": [],
                    "uses_ai": False,
                }
            ),
            default_form(),
        )


# ---------------------------------------------------------------------------
# E2E flow A / B / NEW C with hard-coded expectations
# ---------------------------------------------------------------------------


class NewScenarioFlowTests(SimpleTestCase):
    """Home CTA → profile token → CSRF submit; NEW C = 003/004/005 (3-3-3)."""

    def test_home_page_links_to_profile_with_start_cta(self):
        response = self.client.get(HOME_PAGE)
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        self.assertIn("Начать анализ", html)
        self.assertTrue(
            re.search(r'<a[^>]+href="/profile/"[^>]*>\s*Начать анализ', html)
            or re.search(r'Начать анализ[\s\S]{0,80}?href="/profile/"', html),
            "home page must offer the «Начать анализ» CTA to /profile/",
        )

    def test_profile_page_form_posts_to_analyze_with_csrf_token(self):
        page = self.client.get(PROFILE_PAGE)
        self.assertEqual(page.status_code, 200)
        html = page.content.decode()
        parser = parse_controls(html)
        self.assertTrue(parser.form_found, "profile page must post to /profile/analyze/")
        names = {name for name, _ in parser.controls}
        self.assertIn("csrfmiddlewaretoken", names)
        self.assertIn("system_type", names)
        # Unchecked checkboxes are not successful controls; the fields
        # themselves must still exist in the markup.
        for field in ("system_type", "interfaces", "data_classes",
                      "internet_exposed", "uses_ai"):
            self.assertIn(f'name="{field}"', html)

    def test_flows_render_expected_codes_and_statistics(self):
        for name, form_data in HTML_FORM_DATA.items():
            with self.subTest(scenario=name):
                _, response = csrf_flow(form_data)
                html = response.content.decode()
                self.assertIn("Результат анализа", html)
                for threat_code in EXPECTED_CODES[name]:
                    self.assertIn(threat_code, html)
                # Independent negative expectations per docs/mvp.md table.
                absent = {
                    "A": ["DEMO-T-002", "DEMO-T-005"],
                    "B": ["DEMO-T-001", "DEMO-T-004", "DEMO-T-005", "DEMO-T-006"],
                    "C_NEW": ["DEMO-T-001", "DEMO-T-002", "DEMO-T-006"],
                }[name]
                for code in absent:
                    self.assertNotIn(code, html)
                self.assertEqual(
                    response.context["result"]["statistics"], EXPECTED_STATS[name]
                )

    def test_flow_context_matches_hardcoded_contract(self):
        for name, profile in SCENARIOS.items():
            with self.subTest(scenario=name):
                _, response = csrf_flow(HTML_FORM_DATA[name])
                result = response.context["result"]
                self.assertEqual(
                    [t["code"] for t in result["threats"]], EXPECTED_CODES[name]
                )
                self.assertEqual(
                    [m["code"] for m in result["measures"]],
                    [chain[1] for chain in EXPECTED_CHAINS[name]],
                )
                self.assertEqual(
                    [t["code"] for t in result["tools"]],
                    [chain[2] for chain in EXPECTED_CHAINS[name]],
                )
                self.assertEqual(result["explanations"], EXPECTED_EXPLANATIONS[name])
                self.assertEqual(
                    result["metadata"], {"source": "demo", "version": "MVP-1"}
                )

    def test_flow_presentation_matches_hardcoded_reverse_and_coverage(self):
        for name in SCENARIOS:
            with self.subTest(scenario=name):
                _, response = csrf_flow(HTML_FORM_DATA[name])
                presentation = response.context["presentation"]
                expected_measures, expected_tools = EXPECTED_REVERSE[name]
                self.assertEqual(
                    {
                        card["item"]["code"]: card["threat_codes"]
                        for card in presentation["measure_cards"]
                    },
                    expected_measures,
                )
                self.assertEqual(
                    {
                        card["item"]["code"]: card["measure_codes"]
                        for card in presentation["tool_cards"]
                    },
                    expected_tools,
                )
                self.assertEqual(
                    {
                        card["item"]["code"]: card["matched_categories"]
                        for card in presentation["threat_cards"]
                    },
                    {
                        entry["threat_code"]: entry["matched_categories"]
                        for entry in EXPECTED_EXPLANATIONS[name]
                    },
                )
                self.assertEqual(presentation["coverage"], EXPECTED_COVERAGE[name])
                # The view uses the shared pure helper for the same result.
                self.assertEqual(
                    presentation, build_presentation(response.context["result"])
                )

    def test_flow_profile_form_matches_pure_helper(self):
        _, response = csrf_flow(HTML_FORM_DATA["C_NEW"])
        result = response.context["result"]
        self.assertEqual(
            response.context["profile_form"], build_form(result["profile"])
        )

    def test_new_c_chains_are_three_full_chains(self):
        _, response = csrf_flow(HTML_FORM_DATA["C_NEW"])
        html = response.content.decode()
        for threat, measure, tool in EXPECTED_CHAINS["C_NEW"]:
            self.assertIn(threat, html)
            self.assertIn(measure, html)
            self.assertIn(tool, html)

    def test_api_new_c_exact_keys_stats_metadata_and_explanations(self):
        response = self.client.post(
            API_ANALYZE,
            data=json.dumps(PROFILE_C_NEW),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(
            set(payload),
            {"profile", "threats", "measures", "tools", "explanations",
             "statistics", "metadata"},
        )
        self.assertEqual(set(payload["statistics"]), {"threats", "measures", "tools"})
        self.assertEqual(payload["statistics"], EXPECTED_STATS["C_NEW"])
        self.assertEqual(
            payload["metadata"], {"source": "demo", "version": "MVP-1"}
        )
        self.assertEqual(
            [t["code"] for t in payload["threats"]], EXPECTED_CODES["C_NEW"]
        )
        self.assertEqual(payload["explanations"], EXPECTED_EXPLANATIONS["C_NEW"])

    def test_api_new_c_equals_shared_service(self):
        from services.analyzer import analyze_profile

        response = self.client.post(
            API_ANALYZE,
            data=json.dumps(PROFILE_C_NEW),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), analyze_profile(PROFILE_C_NEW))

    def test_api_legacy_c_regression_unchanged(self):
        response = self.client.post(
            API_ANALYZE,
            data=json.dumps(PROFILE_C_LEGACY),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(
            [t["code"] for t in payload["threats"]],
            ["DEMO-T-003", "DEMO-T-005"],
        )
        self.assertEqual(
            payload["statistics"], {"threats": 2, "measures": 2, "tools": 2}
        )


# ---------------------------------------------------------------------------
# Result page structure: per-card reasons/links, notice, anchors
# ---------------------------------------------------------------------------


class ResultPageStructureTests(SimpleTestCase):
    """The result page renders per-card data, not a global union."""

    def page(self, name):
        _, response = csrf_flow(HTML_FORM_DATA[name])
        return response.content.decode()

    def test_inline_reasons_belong_to_their_own_threat_card(self):
        html = self.page("A")
        blocks = card_blocks(html)
        # T-003 matched via internet only; T-004 via confidentiality only;
        # T-006 via web only (its integrity category did not match — the
        # card may still list the integrity label among the threat's own
        # categories). Reasons show the Russian category labels.
        self.assertIn(CATEGORY_LABELS_RU["internet"], card_reason(blocks["DEMO-T-003"]))
        self.assertNotIn(
            CATEGORY_LABELS_RU["confidentiality"], card_reason(blocks["DEMO-T-003"])
        )
        self.assertNotIn(CATEGORY_LABELS_RU["web"], card_reason(blocks["DEMO-T-003"]))
        self.assertIn(
            CATEGORY_LABELS_RU["confidentiality"], card_reason(blocks["DEMO-T-004"])
        )
        self.assertNotIn(
            CATEGORY_LABELS_RU["internet"], card_reason(blocks["DEMO-T-004"])
        )
        self.assertIn(CATEGORY_LABELS_RU["web"], card_reason(blocks["DEMO-T-006"]))
        self.assertNotIn(
            CATEGORY_LABELS_RU["integrity"], card_reason(blocks["DEMO-T-006"])
        )

    def test_new_c_reasons_per_card(self):
        html = self.page("C_NEW")
        blocks = card_blocks(html)
        self.assertIn(
            CATEGORY_LABELS_RU["confidentiality"], card_reason(blocks["DEMO-T-004"])
        )
        self.assertNotIn(
            CATEGORY_LABELS_RU["internet"], card_reason(blocks["DEMO-T-004"])
        )
        self.assertIn(CATEGORY_LABELS_RU["ai"], card_reason(blocks["DEMO-T-005"]))
        self.assertNotIn(
            CATEGORY_LABELS_RU["confidentiality"], card_reason(blocks["DEMO-T-005"])
        )

    def test_measure_cards_link_only_their_related_selected_threats(self):
        for name in ("A", "C_NEW"):
            with self.subTest(scenario=name):
                blocks = card_blocks(self.page(name))
                expected_measures, _ = EXPECTED_REVERSE[name]
                selected = set(EXPECTED_CODES[name])
                for measure_code, linked_threats in expected_measures.items():
                    block = blocks[measure_code]
                    for threat_code in linked_threats:
                        self.assertIn(threat_code, block)
                    for threat_code in selected - set(linked_threats):
                        self.assertNotIn(threat_code, block)
                # Unselected threats never appear on the page at all.
                for measure_code in expected_measures:
                    for absent in {
                        "A": ["DEMO-T-002", "DEMO-T-005"],
                        "C_NEW": ["DEMO-T-001", "DEMO-T-002", "DEMO-T-006"],
                    }[name]:
                        self.assertNotIn(absent, blocks[measure_code])

    def test_tool_cards_link_only_their_related_measures(self):
        for name in ("A", "C_NEW"):
            with self.subTest(scenario=name):
                blocks = card_blocks(self.page(name))
                _, expected_tools = EXPECTED_REVERSE[name]
                all_measures = {
                    measure_code
                    for linked in expected_tools.values()
                    for measure_code in linked
                }
                for tool_code, linked_measures in expected_tools.items():
                    block = blocks[tool_code]
                    for measure_code in linked_measures:
                        self.assertIn(measure_code, block)
                    for measure_code in all_measures - set(linked_measures):
                        self.assertNotIn(measure_code, block)

    def test_demo_notice_declares_demonstration_non_recommendation(self):
        for name in HTML_FORM_DATA:
            with self.subTest(scenario=name):
                html = self.page(name)
                self.assertIn("Демонстрационные данные", html)
                self.assertIn("Источник: Демонстрационные данные", html)
                self.assertTrue(
                    any(pattern.search(html) for pattern in NON_RECOMMENDATION_RES),
                    "result page must state its non-recommendation demo nature",
                )

    def test_result_pages_make_no_percentage_claims(self):
        for name in HTML_FORM_DATA:
            with self.subTest(scenario=name):
                html = self.page(name)
                self.assertIsNone(
                    PERCENT_RE.search(html), "no efficacy percentage may be rendered"
                )
                self.assertNotIn("100%", html)

    def test_anchor_ids_are_unique_and_anchors_resolve(self):
        for name in HTML_FORM_DATA:
            with self.subTest(scenario=name):
                html = self.page(name)
                ids = HTML_ID_RE.findall(html)
                self.assertEqual(len(ids), len(set(ids)), "duplicate id attributes")
                targets = set(HTML_ANCHOR_RE.findall(html))
                self.assertTrue(targets, "same-page section links expected")
                self.assertEqual(
                    targets - set(ids), set(), "dangling same-page anchor targets"
                )

    def test_every_returned_entity_has_a_card_anchor(self):
        for name in EXPECTED_CHAINS:
            with self.subTest(scenario=name):
                html = self.page(name)
                ids = set(HTML_ID_RE.findall(html))
                for threat, measure, tool in EXPECTED_CHAINS[name]:
                    for code in (threat, measure, tool):
                        self.assertTrue(
                            any(code in value for value in ids),
                            f"no anchor id for {code}",
                        )


# ---------------------------------------------------------------------------
# Edit form: parse actual successful controls, resubmit unchanged/changed
# ---------------------------------------------------------------------------


class EditFormRoundTripTests(SimpleTestCase):
    """Round-trip the real edit-form controls without rebuilding them."""

    def hostile_flow(self):
        form_data = {
            "system_type": HOSTILE_SYSTEM,
            "interfaces": ["web", "api", "", "web", HOSTILE_INTERFACE],
            "internet_exposed": "on",
            "data_classes": ["confidentiality", "", "", HOSTILE_DATA_CLASS],
            "uses_ai": "on",
        }
        return csrf_flow(form_data)

    def resubmit_unchanged(self, html):
        parser = parse_controls(html)
        self.assertTrue(parser.form_found, "result page must embed the edit form")
        client = Client(enforce_csrf_checks=True)
        page = client.get(PROFILE_PAGE)
        token = CSRF_TOKEN_RE.search(page.content.decode()).group(1)
        data = controls_to_post_data(parser.controls)
        data["csrfmiddlewaretoken"] = [token]
        return client.post(HTML_ANALYZE, data)

    def test_resubmit_unchanged_preserves_custom_values_verbatim(self):
        client, response = self.hostile_flow()
        html = response.content.decode()
        second = self.resubmit_unchanged(html)
        self.assertEqual(second.status_code, 200)
        profile = second.context["result"]["profile"]
        self.assertEqual(profile["system_type"], HOSTILE_SYSTEM)
        self.assertEqual(
            profile["interfaces"],
            ["web", "api", "", "web", HOSTILE_INTERFACE],
        )
        self.assertEqual(
            profile["data_classes"],
            ["confidentiality", "", "", HOSTILE_DATA_CLASS],
        )
        self.assertIs(profile["internet_exposed"], True)
        self.assertIs(profile["uses_ai"], True)
        # The edit form of the resubmitted page round-trips the same values.
        third = self.resubmit_unchanged(second.content.decode())
        self.assertEqual(
            third.context["result"]["profile"]["interfaces"],
            ["web", "api", "", "web", HOSTILE_INTERFACE],
        )
        self.assertEqual(
            third.context["result"]["profile"]["system_type"], HOSTILE_SYSTEM
        )

    def test_resubmit_preserves_empty_and_duplicate_list_entries(self):
        _, response = csrf_flow(
            {
                "system_type": "web",
                "interfaces": ["", "", "web"],
                "data_classes": ["integrity", "integrity", ""],
            }
        )
        second = self.resubmit_unchanged(response.content.decode())
        profile = second.context["result"]["profile"]
        self.assertEqual(profile["interfaces"], ["", "", "web"])
        self.assertEqual(profile["data_classes"], ["integrity", "integrity", ""])

    def test_unchecked_booleans_round_trip_as_false(self):
        _, response = csrf_flow(
            {"system_type": "web", "interfaces": ["web"]}
        )
        parser = parse_controls(response.content.decode())
        names = {name for name, _ in parser.controls}
        self.assertNotIn("internet_exposed", names)
        self.assertNotIn("uses_ai", names)
        second = self.resubmit_unchanged(response.content.decode())
        profile = second.context["result"]["profile"]
        self.assertIs(profile["internet_exposed"], False)
        self.assertIs(profile["uses_ai"], False)

    def test_edit_field_change_via_same_post_endpoint(self):
        _, response = csrf_flow(HTML_FORM_DATA["A"])
        parser = parse_controls(response.content.decode())
        data = controls_to_post_data(parser.controls)
        client = Client(enforce_csrf_checks=True)
        # The token must come from this client's own GET (cookie-bound).
        data["csrfmiddlewaretoken"] = [
            CSRF_TOKEN_RE.search(
                client.get(PROFILE_PAGE).content.decode()
            ).group(1)
        ]
        # Change the selection: system → internal, drop the web interface.
        data["system_type"] = ["internal"]
        data.pop("interfaces", None)
        changed = client.post(HTML_ANALYZE, data)
        self.assertEqual(changed.status_code, 200)
        result = changed.context["result"]
        self.assertEqual(result["profile"]["system_type"], "internal")
        self.assertEqual(result["profile"]["interfaces"], [])
        # Hard-coded expectation: internet + confidentiality → 003/004.
        self.assertEqual(
            [t["code"] for t in result["threats"]],
            ["DEMO-T-003", "DEMO-T-004"],
        )
        self.assertEqual(
            result["statistics"], {"threats": 2, "measures": 2, "tools": 2}
        )

    def test_fresh_get_resets_ui_defaults_after_posts(self):
        self.hostile_flow()
        self.csrf_post(HTML_FORM_DATA["C_NEW"])
        page = self.client.get(PROFILE_PAGE)
        self.assertEqual(page.status_code, 200)
        html = page.content.decode()
        parser = parse_controls(html)
        self.assertTrue(parser.form_found)
        selected_system = [
            value for name, value in parser.controls if name == "system_type"
        ]
        self.assertEqual(selected_system, ["web"])
        checked_interfaces = [
            value for name, value in parser.controls if name == "interfaces"
        ]
        self.assertEqual(checked_interfaces, ["web"])
        checked_data = [
            value for name, value in parser.controls if name == "data_classes"
        ]
        self.assertEqual(checked_data, [])
        names = {name for name, _ in parser.controls}
        self.assertNotIn("internet_exposed", names)
        self.assertNotIn("uses_ai", names)
        for hostile in (HOSTILE_SYSTEM, HOSTILE_INTERFACE, HOSTILE_DATA_CLASS):
            self.assertNotIn(hostile, html)

    def csrf_post(self, form_data):
        client = Client(enforce_csrf_checks=True)
        page = client.get(PROFILE_PAGE)
        token = CSRF_TOKEN_RE.search(page.content.decode()).group(1)
        return client.post(HTML_ANALYZE, {"csrfmiddlewaretoken": token, **form_data})

    def test_result_is_rendered_in_same_response_without_url_payload(self):
        _, response = csrf_flow(HTML_FORM_DATA["B"])
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response["Content-Type"].startswith("text/html"))
        self.assertNotEqual(response.status_code, 302)
        self.assertEqual(response.request["PATH_INFO"], HTML_ANALYZE)
        self.assertEqual(response.request.get("QUERY_STRING", ""), "")
        self.assertIn("DEMO-T-002", response.content.decode())

    def test_edit_resubmission_without_csrf_token_is_rejected(self):
        client = Client(enforce_csrf_checks=True)
        response = client.post(
            HTML_ANALYZE, {"system_type": "web", "interfaces": ["web"]}
        )
        self.assertEqual(response.status_code, 403)

    def test_edit_resubmission_with_invalid_csrf_token_is_rejected(self):
        client = Client(enforce_csrf_checks=True)
        client.get(PROFILE_PAGE)
        response = client.post(
            HTML_ANALYZE,
            {"csrfmiddlewaretoken": "definitely-not-a-token",
             "system_type": "web", "interfaces": ["web"]},
        )
        self.assertEqual(response.status_code, 403)

    def test_edit_resubmission_with_real_token_is_accepted(self):
        client = Client(enforce_csrf_checks=True)
        page = client.get(PROFILE_PAGE)
        token = CSRF_TOKEN_RE.search(page.content.decode()).group(1)
        response = client.post(
            HTML_ANALYZE,
            {"csrfmiddlewaretoken": token, "system_type": "internal",
             "internet_exposed": "on"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("DEMO-T-003", response.content.decode())

    def test_hostile_values_are_escaped_in_edit_form_markup(self):
        _, response = self.hostile_flow()
        html = response.content.decode()
        for hostile in (HOSTILE_SYSTEM, HOSTILE_INTERFACE, HOSTILE_DATA_CLASS):
            self.assertNotIn(hostile.join(['"', '"']), html)
        self.assertNotIn("<script>", html)
        # Quoted attribute values survive as escaped entities.
        self.assertIn(escape(HOSTILE_SYSTEM, quote=True), html)
        self.assertIn(escape(HOSTILE_INTERFACE, quote=True), html)
        self.assertIn(escape(HOSTILE_DATA_CLASS, quote=True), html)
        # Parsed controls still decode back to the exact submitted strings.
        parser = parse_controls(html)
        self.assertIn(
            (u"system_type", HOSTILE_SYSTEM),
            [(name, value) for name, value in parser.controls],
        )


# ---------------------------------------------------------------------------
# Hostile synthetic graph rendered through the real HTML view
# ---------------------------------------------------------------------------

HOSTILE_GRAPH_THREATS = [
    {
        "code": "DEMO-T-301",
        "name": '<script>t()</script> Угроза',
        "description": "Demo",
        "categories": ['<img src=x onerror="pwn()">'],
    },
    {
        "code": "DEMO-T-302",
        "name": 'Кавычки " и & амперсанд',
        "description": "Demo",
        "categories": ["a&b"],
    },
    {
        "code": "DEMO-T-303",
        "name": "Orphan threat",
        "description": "Demo",
        "categories": ["orphan"],
    },
]
HOSTILE_GRAPH_MEASURES = [
    {"code": "DEMO-M-301", "name": '<b>Мера</b> & "q"', "description": "Demo"},
    {"code": "DEMO-M-302", "name": "M2", "description": "Demo"},
    {"code": "DEMO-M-303", "name": "M3", "description": "Demo"},
]
HOSTILE_GRAPH_TOOLS = [
    {"code": "DEMO-SZI-301", "name": "<i>средство</i>", "description": "Demo"},
]
HOSTILE_GRAPH_MAPPINGS = {
    "threat_measure": {
        "DEMO-T-301": ["DEMO-M-301", "DEMO-M-302"],
        "DEMO-T-302": ["DEMO-M-303"],
    },
    "measure_tool": {
        "DEMO-M-301": ["DEMO-SZI-301"],
        "DEMO-M-302": [],
        # DEMO-M-303 links a tool that is not in the catalog (dangling).
        "DEMO-M-303": ["DEMO-SZI-999"],
    },
}


class HostileSyntheticHtmlTests(SimpleTestCase):
    """Escaping and coverage rendering on a patched synthetic repository."""

    def hostile_page(self):
        measure_index = {i["code"]: i for i in HOSTILE_GRAPH_MEASURES}
        tool_index = {i["code"]: i for i in HOSTILE_GRAPH_TOOLS}

        def fake_items(name):
            self.assertEqual(name, "threats")
            return HOSTILE_GRAPH_THREATS

        def fake_load(name):
            self.assertEqual(name, "mappings")
            return HOSTILE_GRAPH_MAPPINGS

        def fake_get_by_code(name, code):
            self.assertIn(name, ("measures", "tools"))
            catalog = measure_index if name == "measures" else tool_index
            return catalog.get(code)

        client = Client(enforce_csrf_checks=True)
        page = client.get(PROFILE_PAGE)
        token = CSRF_TOKEN_RE.search(page.content.decode()).group(1)
        with mock.patch("services.analyzer.items", side_effect=fake_items), \
                mock.patch("services.analyzer.load", side_effect=fake_load), \
                mock.patch(
                    "services.analyzer.get_by_code", side_effect=fake_get_by_code
                ):
            response = client.post(
                HTML_ANALYZE,
                {
                    "csrfmiddlewaretoken": token,
                    "system_type": "internal",
                    "interfaces": [
                        '<img src=x onerror="pwn()">', "a&b", "orphan",
                    ],
                },
            )
        self.assertEqual(response.status_code, 200)
        return response

    def test_hostile_graph_coverage_counts_missing_and_dangling_paths(self):
        response = self.hostile_page()
        presentation = response.context["presentation"]
        # T-301 complete (M-301→SZI-301) although M-302 is a dead end;
        # T-302 incomplete (its only tool dangles); T-303 has no measure.
        self.assertEqual(
            presentation["coverage"],
            {"selected_threats": 3, "complete_path_threats": 1,
             "incomplete_path_threats": 2},
        )
        reverse = {
            card["item"]["code"]: card["threat_codes"]
            for card in presentation["measure_cards"]
        }
        self.assertEqual(reverse["DEMO-M-301"], ["DEMO-T-301"])
        self.assertEqual(reverse["DEMO-M-302"], ["DEMO-T-301"])
        self.assertEqual(reverse["DEMO-M-303"], ["DEMO-T-302"])
        html = response.content.decode()
        self.assertNotIn("DEMO-SZI-999", html)

    def test_hostile_names_categories_and_reasons_are_escaped(self):
        response = self.hostile_page()
        html = response.content.decode()
        # Guard: the hostile graph really was selected and explained.
        self.assertIn("DEMO-T-301", html)
        self.assertIn("DEMO-T-302", html)
        # Raw markup must never reach the browser.
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img src=x", html)
        self.assertNotIn('onerror="pwn()"', html)
        self.assertNotIn('<b>Мера</b>', html)
        self.assertNotIn("<i>средство</i>", html)
        # Escaped renderings do appear (cards, reasons, labels).
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;img", html)
        self.assertIn("&lt;b&gt;Мера&lt;/b&gt;", html)
        self.assertIn("&lt;i&gt;средство&lt;/i&gt;", html)
        self.assertIn("a&amp;b", html)
        # Per-card hostile reasons are escaped inline, not globally duplicated.
        blocks = card_blocks(html)
        self.assertIn("&lt;img", blocks["DEMO-T-301"])
        self.assertNotIn("&lt;img", blocks["DEMO-T-302"])
        self.assertIn("a&amp;b", blocks["DEMO-T-302"])


# ---------------------------------------------------------------------------
# Profile page guide: NEW C marks confidentiality ON
# ---------------------------------------------------------------------------


class GuideNewScenarioCTests(SimpleTestCase):
    """Regression: the guide instructs confidentiality ON for scenario C."""

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

    def test_guide_scenario_c_marks_confidentiality_on(self):
        block = self.guide_blocks()["C"]
        is_on, is_off = guide_field_state(block, "Конфиденциальность")
        self.assertTrue(
            is_on and not is_off,
            "scenario C guide must instruct «Конфиденциальность» ON",
        )

    def test_guide_scenario_c_keeps_internet_and_ai_on(self):
        block = self.guide_blocks()["C"]
        for label in ("Доступна из интернета", "Использует искусственный интеллект"):
            with self.subTest(label=label):
                is_on, _ = guide_field_state(block, label)
                self.assertTrue(is_on)


# ---------------------------------------------------------------------------
# Seed data stays read-only through every presentation flow
# ---------------------------------------------------------------------------


class PresentationDataIntegrityTests(SimpleTestCase):
    """No flow above may touch data/*.json (hash snapshot)."""

    def test_data_hashes_unchanged_after_presentation_flows(self):
        before = data_snapshot()
        # Service-level presentation and form building.
        from services.analyzer import analyze_profile

        for profile in (PROFILE_A, PROFILE_B, PROFILE_C_NEW, PROFILE_C_LEGACY):
            result = analyze_profile(profile)
            build_presentation(result)
            build_form(result["profile"])
        default_form()
        # API flows.
        for profile in (PROFILE_C_NEW, PROFILE_C_LEGACY):
            response = self.client.post(
                API_ANALYZE, data=json.dumps(profile), content_type="application/json"
            )
            self.assertEqual(response.status_code, 200)
        # HTML flows, including edit-form resubmission.
        for form_data in HTML_FORM_DATA.values():
            client, response = csrf_flow(form_data)
            parser = parse_controls(response.content.decode())
            data = controls_to_post_data(parser.controls)
            token_page = client.get(PROFILE_PAGE)
            data["csrfmiddlewaretoken"] = [
                CSRF_TOKEN_RE.search(token_page.content.decode()).group(1)
            ]
            resubmitted = client.post(HTML_ANALYZE, data)
            self.assertEqual(resubmitted.status_code, 200)
        self.client.get(PROFILE_PAGE)
        self.client.get(HOME_PAGE)
        self.assertEqual(data_snapshot(), before)
