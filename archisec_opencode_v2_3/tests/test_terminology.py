"""QA contract tests for the Russian display terminology layer.

Owned file of the QA agent. Contract sources: docs/mvp.md, docs/branding.md,
docs/data_schemas.md, docs/quality_gates.md and the localization task brief.
The expected tables below are QA-owned duplicates: drift between them and
``services/terminology.py`` is a failure, never a reason to edit production.

Coverage map:

``services.terminology`` (pure, no IO):
- ``label(value, domain)`` — exact known pairs per domain; unknown values,
  empty strings, hostile strings and unknown domains are preserved verbatim;
- ``labels(values, domain)`` — fresh list preserving order, duplicates and
  empty strings, never mutating the input;
- ``entity_text(item, field)`` — translation only on exact
  ``(code, field, original)`` match for all 18 canonical demo entities
  (threats/measures/tools); custom, synthetic, same-code-different-wording
  and unknown items keep their own text;
- ``html_error(code, field)`` — fixed Russian texts, never reflecting input;
- no repository/mappings access and no filesystem IO at call time.

``core.templatetags.terminology`` filters:
- ``ui_label`` / ``ui_labels`` / ``entity_name`` / ``entity_description``
  delegate to the service, return plain (non-``SafeData``) strings and stay
  subject to Django autoescaping (rendered hostile values are escaped).

Form option labels (``services.result_presentation``):
- standard options carry the Russian labels; ``value`` stays the raw machine
  code; custom/unknown/empty values label themselves.

API boundary (JSON, no templates rendered):
- entity names/descriptions, category values, ``source: demo`` metadata and
  error codes/messages stay untranslated English/canonical — the translation
  is display-only.

HTML 400 wiring (``core.views.profile_analyze`` error branch):
- plain-text 400 with the fixed Russian message for every profile field;
  different hostile inputs with the same field produce identical bodies.

Classes tagged ``qa_html`` render project templates and therefore run only
after the frontend completion notice (``manage.py test --exclude-tag qa_html``
until then).
"""

import contextlib
import importlib
import json
import types
import unittest
from pathlib import Path
from unittest import mock

from django.template import engines
from django.test import Client, SimpleTestCase, tag
from django.utils.safestring import SafeData

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

API_ANALYZE = "/api/profile/analyze/"
HTML_ANALYZE = "/profile/analyze/"

# ---------------------------------------------------------------------------
# QA-owned expected terminology (independent duplicates of the contract).
# ---------------------------------------------------------------------------

SYSTEM_LABELS = {
    "web": "Веб-приложение",
    "internal": "Внутренняя система",
}
INTERFACE_LABELS = {
    "web": "Веб-интерфейс",
    "api": "Программный интерфейс (API)",
}
CATEGORY_LABELS = {
    "web": "Веб-приложение",
    "api": "Программный интерфейс (API)",
    "internet": "Доступ из интернета",
    "ai": "Искусственный интеллект",
    "confidentiality": "Конфиденциальность",
    "integrity": "Целостность",
    "availability": "Доступность",
    "internal": "Внутренняя система",
}
SEVERITY_LABELS = {
    "high": "Высокая",
    "medium": "Средняя",
    "low": "Низкая",
}
PROVENANCE_LABELS = {
    "demo": "Демонстрационные данные",
    "unverified": "Не подтверждено",
    "non-normative": "Не является нормативной рекомендацией",
}
CLASS_LABELS = {
    "DEMO-SZI-CLASS-001": "Демонстрационный класс: защита веб-приложений",
    "DEMO-SZI-CLASS-002": "Демонстрационный класс: шлюз программного интерфейса",
    "DEMO-SZI-CLASS-003": "Демонстрационный класс: контроль доступа",
    "DEMO-SZI-CLASS-004": "Демонстрационный класс: защита данных",
    "DEMO-SZI-CLASS-005": (
        "Демонстрационный класс: контроль входных данных искусственного интеллекта"
    ),
    "DEMO-SZI-CLASS-006": "Демонстрационный класс: наблюдение за целостностью",
}
FRAMEWORK_LABELS = {
    "DEMO-FRAMEWORK-WEB": "Демонстрационная схема: веб-приложения",
    "DEMO-FRAMEWORK-API": "Демонстрационная схема: программные интерфейсы",
    "DEMO-FRAMEWORK-EXTERNAL": "Демонстрационная схема: внешний доступ",
    "DEMO-FRAMEWORK-DATA": "Демонстрационная схема: данные",
    "DEMO-FRAMEWORK-AI": "Демонстрационная схема: искусственный интеллект",
    "DEMO-FRAMEWORK-APP": "Демонстрационная схема: целостность приложений",
    "DEMO-FRAMEWORK-239": "Демонстрационная схема 239 (не нормативный документ)",
    "DEMO-FRAMEWORK-117": "Демонстрационная схема 117 (не нормативный документ)",
}

ALL_DOMAIN_TABLES = {
    "system": SYSTEM_LABELS,
    "interface": INTERFACE_LABELS,
    "category": CATEGORY_LABELS,
    "severity": SEVERITY_LABELS,
    "provenance": PROVENANCE_LABELS,
    "class": CLASS_LABELS,
    "framework": FRAMEWORK_LABELS,
}

# (code, field) → Russian display text for the 18 canonical demo entities.
ENTITY_TRANSLATIONS = {
    ("DEMO-T-001", "name"): "Манипулирование веб-запросами",
    ("DEMO-T-001", "description"): (
        "Демонстрационный пример угрозы, связанной с изменением веб-запросов."
    ),
    ("DEMO-T-002", "name"): "Злоупотребление программным интерфейсом",
    ("DEMO-T-002", "description"): (
        "Демонстрационный пример угрозы, связанной с использованием "
        "программного интерфейса не по назначению."
    ),
    ("DEMO-T-003", "name"): "Угроза при доступе из интернета",
    ("DEMO-T-003", "description"): (
        "Демонстрационный пример угрозы для системы, доступной из интернета."
    ),
    ("DEMO-T-004", "name"): "Раскрытие конфиденциальных данных",
    ("DEMO-T-004", "description"): (
        "Демонстрационный пример угрозы раскрытия конфиденциальных данных."
    ),
    ("DEMO-T-005", "name"): "Манипулирование запросами к искусственному интеллекту",
    ("DEMO-T-005", "description"): (
        "Демонстрационный пример угрозы, связанной с изменением запросов "
        "к системе искусственного интеллекта."
    ),
    ("DEMO-T-006", "name"): "Демонстрационный пример нарушения целостности приложения",
    ("DEMO-T-006", "description"): (
        "Демонстрационный пример угрозы нарушения целостности приложения."
    ),
    ("DEMO-M-001", "name"): "Фильтрация веб-запросов",
    ("DEMO-M-001", "description"): (
        "Демонстрационный пример меры: фильтрация веб-запросов. "
        "Не является нормативной рекомендацией."
    ),
    ("DEMO-M-002", "name"): "Контроль запросов на шлюзе программного интерфейса",
    ("DEMO-M-002", "description"): (
        "Демонстрационный пример меры: контроль запросов к программному "
        "интерфейсу. Не является нормативной рекомендацией."
    ),
    ("DEMO-M-003", "name"): "Контроль внешнего доступа",
    ("DEMO-M-003", "description"): (
        "Демонстрационный пример меры: контроль внешнего доступа к системе. "
        "Не является нормативной рекомендацией."
    ),
    ("DEMO-M-004", "name"): "Контроль доступа к данным",
    ("DEMO-M-004", "description"): (
        "Демонстрационный пример меры: контроль доступа к конфиденциальным "
        "данным. Не является нормативной рекомендацией."
    ),
    ("DEMO-M-005", "name"): "Проверка входных данных искусственного интеллекта",
    ("DEMO-M-005", "description"): (
        "Демонстрационный пример меры: проверка входных данных системы "
        "искусственного интеллекта. Не является нормативной рекомендацией."
    ),
    ("DEMO-M-006", "name"): "Наблюдение за целостностью приложения",
    ("DEMO-M-006", "description"): (
        "Демонстрационный пример меры: наблюдение за целостностью приложения. "
        "Не является нормативной рекомендацией."
    ),
    ("DEMO-SZI-001", "name"): "Демонстрационное средство защиты веб-приложений",
    ("DEMO-SZI-001", "description"): (
        "Демонстрационный пример средства для веб-приложений. "
        "Свойства и эффективность не подтверждены."
    ),
    ("DEMO-SZI-002", "name"): "Демонстрационный шлюз программного интерфейса",
    ("DEMO-SZI-002", "description"): (
        "Демонстрационный пример шлюза программного интерфейса. "
        "Свойства и эффективность не подтверждены."
    ),
    ("DEMO-SZI-003", "name"): "Демонстрационная система контроля доступа",
    ("DEMO-SZI-003", "description"): (
        "Демонстрационный пример системы контроля доступа. "
        "Свойства и эффективность не подтверждены."
    ),
    ("DEMO-SZI-004", "name"): "Демонстрационная система защиты данных",
    ("DEMO-SZI-004", "description"): (
        "Демонстрационный пример системы защиты данных. "
        "Свойства и эффективность не подтверждены."
    ),
    ("DEMO-SZI-005", "name"): (
        "Демонстрационное средство контроля искусственного интеллекта"
    ),
    ("DEMO-SZI-005", "description"): (
        "Демонстрационный пример средства контроля системы искусственного "
        "интеллекта. Свойства и эффективность не подтверждены."
    ),
    ("DEMO-SZI-006", "name"): "Демонстрационное средство наблюдения за целостностью",
    ("DEMO-SZI-006", "description"): (
        "Демонстрационный пример средства наблюдения за целостностью. "
        "Свойства и эффективность не подтверждены."
    ),
}

# Fixed Russian HTML validation errors (docs/branding.md: no input reflection).
HTML_PROFILE_ERRORS = {
    "system_type": "Тип системы должен быть строкой.",
    "interfaces": "Интерфейсы должны быть списком строк.",
    "data_classes": "Классы данных должны быть списком строк.",
    "internet_exposed": (
        "Признак доступа из интернета должен быть логическим значением."
    ),
    "uses_ai": (
        "Признак использования искусственного интеллекта должен быть "
        "логическим значением."
    ),
}
HTML_ERROR_TEXTS = {
    "object_required": "Профиль системы должен быть объектом.",
    "invalid_json": "Некорректный формат данных запроса.",
    "invalid_profile_unknown_field": "Некорректный профиль системы.",
    "unknown_code": (
        "Не удалось обработать профиль системы. Проверьте введённые данные."
    ),
}

HOSTILE_TEXT = '<script>alert("x")</script>'

PROFILE_A = {
    "system_type": "web",
    "interfaces": ["web"],
    "internet_exposed": True,
    "data_classes": ["confidentiality"],
    "uses_ai": False,
}


def read_seed(name):
    with (DATA_DIR / f"{name}.json").open(encoding="utf-8") as handle:
        return json.load(handle)


def terminology():
    from services import terminology as module

    return module


# ---------------------------------------------------------------------------
# label() / labels(): exact domains, preserved unknowns
# ---------------------------------------------------------------------------


class LabelContractTests(SimpleTestCase):
    """label(): exact known pairs; everything unknown comes back verbatim."""

    def test_known_values_in_every_domain(self):
        service = terminology()
        for domain, table in ALL_DOMAIN_TABLES.items():
            for value, expected in table.items():
                with self.subTest(domain=domain, value=value):
                    self.assertEqual(service.label(value, domain), expected)

    def test_unknown_values_are_preserved_verbatim(self):
        service = terminology()
        cases = [
            ("mainframe-хост", "system"),
            ("", "system"),
            (HOSTILE_TEXT, "category"),
            ("unknown-class", "class"),
            ("", "framework"),
        ]
        for value, domain in cases:
            with self.subTest(value=value, domain=domain):
                result = service.label(value, domain)
                self.assertEqual(result, value)
                self.assertIsInstance(result, str)

    def test_unknown_domain_preserves_value(self):
        self.assertEqual(terminology().label("web", "not-a-domain"), "web")

    def test_default_domain_is_category(self):
        self.assertEqual(terminology().label("confidentiality"), "Конфиденциальность")

    def test_results_are_deterministic_plain_strings(self):
        service = terminology()
        for value, domain, expected in (
            ("web", "system", "Веб-приложение"),
            ("mainframe", "system", "mainframe"),
        ):
            first = service.label(value, domain)
            second = service.label(value, domain)
            self.assertEqual(first, expected)
            self.assertEqual(first, second)
            self.assertNotIsInstance(first, SafeData)


class LabelsContractTests(SimpleTestCase):
    """labels(): fresh list with order, duplicates and empty strings kept."""

    def test_order_duplicates_and_empties_are_preserved(self):
        service = terminology()
        result = service.labels(["web", "api", "web", "", "api"], "interface")
        self.assertEqual(
            result,
            [
                "Веб-интерфейс",
                "Программный интерфейс (API)",
                "Веб-интерфейс",
                "",
                "Программный интерфейс (API)",
            ],
        )

    def test_unknown_members_stay_verbatim_between_known_ones(self):
        result = terminology().labels(["confidentiality", "секретно", "integrity"])
        self.assertEqual(result, ["Конфиденциальность", "секретно", "Целостность"])

    def test_empty_list_returns_fresh_empty_list(self):
        service = terminology()
        first = service.labels([], "system")
        second = service.labels([], "system")
        self.assertEqual(first, [])
        self.assertEqual(second, [])
        self.assertIsNot(first, second)

    def test_input_list_is_not_mutated(self):
        values = ["web", "x", "web"]
        snapshot = list(values)
        terminology().labels(values, "system")
        self.assertEqual(values, snapshot)

    def test_default_domain_is_category(self):
        self.assertEqual(
            terminology().labels(["internet", "ai"]),
            ["Доступ из интернета", "Искусственный интеллект"],
        )

    def test_plain_string_output(self):
        for item in terminology().labels([HOSTILE_TEXT], "system"):
            self.assertNotIsInstance(item, SafeData)


# ---------------------------------------------------------------------------
# entity_text(): the 18 canonical entities and only them
# ---------------------------------------------------------------------------


class EntityTextContractTests(SimpleTestCase):
    """entity_text(): exact (code, field, original) lookups for all 18."""

    def canonical_items(self):
        for catalog in ("threats", "measures", "tools"):
            for item in read_seed(catalog):
                yield catalog, item

    def test_all_canonical_names_and_descriptions_are_translated(self):
        service = terminology()
        seen = set()
        for catalog, item in self.canonical_items():
            for field in ("name", "description"):
                with self.subTest(catalog=catalog, code=item["code"], field=field):
                    expected = ENTITY_TRANSLATIONS[(item["code"], field)]
                    self.assertEqual(service.entity_text(item, field), expected)
                    seen.add((item["code"], field))
        # The table covers exactly the 18 canonical entities × 2 fields.
        self.assertEqual(len(seen), 36)
        self.assertEqual(set(ENTITY_TRANSLATIONS), seen)

    def test_expected_table_originals_match_seed_data(self):
        # Guard the lookup keys themselves: the translation table applies to
        # the *current* seed wording (docs/branding.md: code + field + text).
        seeds = {}
        for catalog in ("threats", "measures", "tools"):
            for item in read_seed(catalog):
                seeds[(item["code"], "name")] = item["name"]
                seeds[(item["code"], "description")] = item["description"]
        self.assertEqual(len(seeds), 36)
        self.assertTrue(all(code.startswith("DEMO-") for code, _ in seeds))

    def test_unknown_codes_keep_their_own_text(self):
        service = terminology()
        item = {"code": "DEMO-T-999", "name": HOSTILE_TEXT, "description": "Кастом"}
        self.assertEqual(service.entity_text(item, "name"), HOSTILE_TEXT)
        self.assertEqual(service.entity_text(item, "description"), "Кастом")

    def test_same_code_with_custom_wording_is_not_substituted(self):
        # A synthetic entity reusing a demo code with different wording must
        # not have its text silently replaced (documented rule).
        service = terminology()
        item = {"code": "DEMO-T-001", "name": "Custom name", "description": "Demo"}
        self.assertEqual(service.entity_text(item, "name"), "Custom name")
        self.assertEqual(service.entity_text(item, "description"), "Demo")

    def test_synthetic_fixture_items_keep_fixture_text(self):
        # The synthetic graphs used by the behavioural suites rely on this.
        service = terminology()
        item = {"code": "DEMO-T-101", "name": "Alpha", "description": "Demo"}
        self.assertEqual(service.entity_text(item, "name"), "Alpha")

    def test_missing_field_returns_empty_string(self):
        self.assertEqual(terminology().entity_text({"code": "DEMO-T-001"}, "name"), "")

    def test_item_is_not_mutated_and_output_is_plain(self):
        service = terminology()
        item = read_seed("threats")[0]
        snapshot = json.dumps(item, sort_keys=True)
        result = service.entity_text(item, "name")
        self.assertEqual(json.dumps(item, sort_keys=True), snapshot)
        self.assertNotIsInstance(result, SafeData)

    def test_calls_are_deterministic(self):
        service = terminology()
        item = read_seed("tools")[0]
        self.assertEqual(
            service.entity_text(item, "name"), service.entity_text(item, "name")
        )


# ---------------------------------------------------------------------------
# html_error(): fixed Russian texts
# ---------------------------------------------------------------------------


class HtmlErrorContractTests(SimpleTestCase):
    """html_error(): fixed Russian strings for every documented error."""

    def test_invalid_profile_message_for_every_field(self):
        service = terminology()
        for field, expected in HTML_PROFILE_ERRORS.items():
            with self.subTest(field=field):
                self.assertEqual(
                    service.html_error("invalid_profile", field), expected
                )

    def test_transport_and_object_errors(self):
        service = terminology()
        self.assertEqual(
            service.html_error("invalid_json"), HTML_ERROR_TEXTS["invalid_json"]
        )
        self.assertEqual(
            service.html_error("invalid_json", None),
            HTML_ERROR_TEXTS["invalid_json"],
        )
        self.assertEqual(
            service.html_error("object_required", None),
            HTML_ERROR_TEXTS["object_required"],
        )

    def test_fallbacks_never_leak_english_or_input(self):
        service = terminology()
        self.assertEqual(
            service.html_error("invalid_profile", "nonexistent_field"),
            HTML_ERROR_TEXTS["invalid_profile_unknown_field"],
        )
        self.assertEqual(
            service.html_error("totally_unknown_code", "system_type"),
            HTML_ERROR_TEXTS["unknown_code"],
        )

    def test_all_messages_are_fixed_russian_plain_text(self):
        service = terminology()
        texts = [
            *HTML_PROFILE_ERRORS.values(),
            *HTML_ERROR_TEXTS.values(),
        ]
        for text in texts:
            self.assertTrue(text.strip())
            # Russian, ends as a sentence, no HTML to reflect or inject.
            self.assertRegex(text, r"[А-Яа-яЁё]")
            self.assertIn(".", text)
            for markup in ("<", ">", "&", "{}", "%s"):
                self.assertNotIn(markup, text)
        # Deterministic across calls.
        self.assertEqual(
            service.html_error("invalid_profile", "system_type"),
            service.html_error("invalid_profile", "system_type"),
        )
        self.assertNotIsInstance(
            service.html_error("invalid_profile", "system_type"), SafeData
        )


# ---------------------------------------------------------------------------
# Purity: no repository access, no filesystem IO
# ---------------------------------------------------------------------------


class TerminologyPurityTests(SimpleTestCase):
    """All four functions are pure lookups without IO or repository access."""

    def blocked_patches(self):
        targets = [
            ("builtins", "open"),
            ("pathlib.Path", "read_text"),
            ("pathlib.Path", "read_bytes"),
            ("pathlib.Path", "open"),
            ("services.data_repository", "load"),
            ("services.data_repository", "items"),
            ("services.data_repository", "get_by_code"),
            ("services.mappings", "load"),
            ("services.mappings", "load_mappings"),
            ("services.catalogs", "list_catalog"),
            ("services.catalogs", "catalog_item"),
            ("services.analyzer", "analyze_profile"),
        ]
        patches = []
        for module_name, attr in targets:
            patches.append(
                mock.patch(
                    f"{module_name}.{attr}",
                    side_effect=AssertionError(
                        f"terminology layer performed IO via {module_name}.{attr}"
                    ),
                )
            )
        return patches

    def test_functions_work_without_any_io_or_repository_access(self):
        service = terminology()
        item = {"code": "DEMO-T-001", "name": "Web request manipulation"}
        with contextlib.ExitStack() as stack:
            for patch in self.blocked_patches():
                stack.enter_context(patch)
            self.assertEqual(service.label("web", "system"), "Веб-приложение")
            self.assertEqual(
                service.labels(["web", "x"], "interface"),
                ["Веб-интерфейс", "x"],
            )
            self.assertEqual(
                service.entity_text(item, "name"),
                ENTITY_TRANSLATIONS[("DEMO-T-001", "name")],
            )
            self.assertEqual(
                service.html_error("invalid_profile", "system_type"),
                HTML_PROFILE_ERRORS["system_type"],
            )

    def test_module_does_not_import_repository_modules(self):
        module = terminology()
        forbidden = set()
        for name in (
            "services.data_repository",
            "services.mappings",
            "services.catalogs",
            "services.analyzer",
        ):
            forbidden.add(importlib.import_module(name))
        leaked = [
            attr
            for attr in dir(module)
            if isinstance(getattr(module, attr), types.ModuleType)
            and getattr(module, attr) in forbidden
        ]
        self.assertEqual(leaked, [])

    def test_module_source_has_no_io_calls(self):
        source = (BASE_DIR / "services" / "terminology.py").read_text("utf-8")
        for forbidden in ("open(", "read_text", "read_bytes", "json.load"):
            self.assertNotIn(forbidden, source)


# ---------------------------------------------------------------------------
# Template filters: thin, plain, escaped
# ---------------------------------------------------------------------------

FILTER_TEMPLATE = '{%% load terminology %%}{{ value|%s }}'


class TerminologyFilterTests(SimpleTestCase):
    """ui_label/ui_labels/entity_name/entity_description stay thin and safe."""

    def tags_module(self):
        from core.templatetags import terminology as module

        return module

    def test_all_four_filters_are_registered(self):
        module = self.tags_module()
        for name in ("ui_label", "ui_labels", "entity_name", "entity_description"):
            with self.subTest(filter=name):
                self.assertTrue(hasattr(module, name))
                self.assertIn(name, module.register.filters)

    def test_filters_delegate_to_the_service(self):
        from services.terminology import label, labels

        module = self.tags_module()
        self.assertEqual(module.ui_label("web", "system"), label("web", "system"))
        self.assertEqual(
            module.ui_labels(["web", "api"], "interface"),
            labels(["web", "api"], "interface"),
        )
        item = read_seed("measures")[0]
        self.assertEqual(
            module.entity_name(item), ENTITY_TRANSLATIONS[("DEMO-M-001", "name")]
        )
        self.assertEqual(
            module.entity_description(item),
            ENTITY_TRANSLATIONS[("DEMO-M-001", "description")],
        )

    def test_filter_outputs_are_plain_not_safe_data(self):
        module = self.tags_module()
        hostile_item = {"code": "DEMO-T-999", "name": HOSTILE_TEXT}
        results = [
            module.ui_label(HOSTILE_TEXT, "system"),
            module.ui_labels([HOSTILE_TEXT], "system"),
            module.entity_name(hostile_item),
            module.entity_description(hostile_item),
        ]
        for result in results:
            self.assertNotIsInstance(result, SafeData)
        for item in results[1]:
            self.assertNotIsInstance(item, SafeData)

    def render(self, template_body, context):
        template = engines["django"].from_string(template_body)
        return template.render(context)

    def test_rendered_known_label_is_russian(self):
        output = self.render(
            FILTER_TEMPLATE % 'ui_label:"system"', {"value": "web"}
        )
        self.assertEqual(output, "Веб-приложение")

    def test_rendered_filter_without_domain_defaults_to_category(self):
        output = self.render(FILTER_TEMPLATE % "ui_label", {"value": "internet"})
        self.assertEqual(output, "Доступ из интернета")

    def test_rendered_unknown_and_hostile_values_are_escaped(self):
        output = self.render(
            FILTER_TEMPLATE % 'ui_label:"system"', {"value": HOSTILE_TEXT}
        )
        self.assertNotIn("<script>", output)
        self.assertIn("&lt;script&gt;", output)

    def test_rendered_ui_labels_iteration_is_escaped(self):
        output = self.render(
            '{% load terminology %}'
            '{% for item in values|ui_labels:"system" %}[{{ item }}]{% endfor %}',
            {"values": ["web", HOSTILE_TEXT]},
        )
        self.assertIn("[Веб-приложение]", output)
        self.assertNotIn("<script>", output)
        self.assertIn("&lt;script&gt;", output)

    def test_rendered_entity_name_is_translated_or_escaped(self):
        canonical = self.render(
            FILTER_TEMPLATE % "entity_name",
            {"value": {"code": "DEMO-SZI-006", "name": "Demo integrity monitor"}},
        )
        self.assertEqual(
            canonical, ENTITY_TRANSLATIONS[("DEMO-SZI-006", "name")]
        )
        hostile = self.render(
            FILTER_TEMPLATE % "entity_description",
            {"value": {"code": "DEMO-T-999", "description": HOSTILE_TEXT}},
        )
        self.assertNotIn("<script>", hostile)
        self.assertIn("&lt;script&gt;", hostile)


# ---------------------------------------------------------------------------
# Form option labels: Russian standards, verbatim customs
# ---------------------------------------------------------------------------


class FormOptionLabelTests(SimpleTestCase):
    """Profile form labels are Russian; values stay machine codes."""

    def build(self, profile):
        from services.result_presentation import build_profile_form

        return build_profile_form(profile)

    def defaults(self):
        from services.result_presentation import default_profile_form

        return default_profile_form()

    def normalized(self, **overrides):
        profile = {
            "system_type": "web",
            "interfaces": ["web"],
            "internet_exposed": False,
            "data_classes": [],
            "uses_ai": False,
        }
        profile.update(overrides)
        return profile

    def test_fresh_form_standard_labels_are_russian(self):
        form = self.defaults()
        self.assertEqual(
            {o["value"]: o["label"] for o in form["system_type_options"]},
            SYSTEM_LABELS,
        )
        self.assertEqual(
            {o["value"]: o["label"] for o in form["interface_options"]},
            INTERFACE_LABELS,
        )
        self.assertEqual(
            {o["value"]: o["label"] for o in form["data_class_options"]},
            {"confidentiality": "Конфиденциальность", "integrity": "Целостность"},
        )

    def test_standard_values_stay_raw_machine_codes(self):
        form = self.defaults()
        self.assertEqual(
            [o["value"] for o in form["system_type_options"]], ["web", "internal"]
        )
        self.assertEqual(
            [o["value"] for o in form["interface_options"]], ["web", "api"]
        )
        self.assertEqual(
            [o["value"] for o in form["data_class_options"]],
            ["confidentiality", "integrity"],
        )

    def test_custom_unknown_and_empty_values_label_themselves(self):
        form = self.build(
            self.normalized(
                system_type=HOSTILE_TEXT,
                interfaces=["web", "секретный", "", HOSTILE_TEXT, "web"],
                data_classes=["", "custom"],
            )
        )
        custom_system = [o for o in form["system_type_options"] if o["selected"]]
        self.assertEqual(custom_system[0]["value"], HOSTILE_TEXT)
        self.assertEqual(custom_system[0]["label"], HOSTILE_TEXT)
        labels = [o["label"] for o in form["interface_options"]]
        self.assertEqual(
            labels[:5],
            [
                "Веб-интерфейс",
                "секретный",
                "",
                HOSTILE_TEXT,
                "Веб-интерфейс",
            ],
        )
        self.assertEqual(
            [o["label"] for o in form["data_class_options"]][:2], ["", "custom"]
        )

    def test_labels_do_not_change_values_or_selection_state(self):
        form = self.build(
            self.normalized(interfaces=["api", "api"], data_classes=["integrity"])
        )
        self.assertEqual(
            [o["value"] for o in form["interface_options"]], ["api", "api", "web"]
        )
        self.assertEqual(
            [o["checked"] for o in form["interface_options"]], [True, True, False]
        )
        self.assertIs(form["internet_exposed"], False)
        self.assertIs(form["uses_ai"], False)


# ---------------------------------------------------------------------------
# API boundary: translation never leaks into JSON
# ---------------------------------------------------------------------------


class ApiUntranslatedContractTests(SimpleTestCase):
    """Machine JSON stays canonical; only the HTML display is localized."""

    def post_profile(self, payload):
        return self.client.post(
            API_ANALYZE, data=json.dumps(payload), content_type="application/json"
        )

    def test_analysis_result_entities_keep_seed_english_text(self):
        response = self.post_profile(PROFILE_A)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        seed_threats = {t["code"]: t for t in read_seed("threats")}
        seed_measures = {m["code"]: m for m in read_seed("measures")}
        seed_tools = {s["code"]: s for s in read_seed("tools")}
        self.assertEqual(
            [t["code"] for t in payload["threats"]],
            ["DEMO-T-001", "DEMO-T-003", "DEMO-T-004", "DEMO-T-006"],
        )
        for threat in payload["threats"]:
            self.assertEqual(threat, seed_threats[threat["code"]])
        for measure in payload["measures"]:
            self.assertEqual(measure, seed_measures[measure["code"]])
        for tool in payload["tools"]:
            self.assertEqual(tool, seed_tools[tool["code"]])

    def test_categories_profile_and_metadata_stay_canonical(self):
        payload = self.post_profile(PROFILE_A).json()
        self.assertEqual(payload["profile"]["system_type"], "web")
        self.assertEqual(payload["metadata"], {"source": "demo", "version": "MVP-1"})
        self.assertEqual(
            [e["matched_categories"] for e in payload["explanations"]],
            [["web"], ["internet"], ["confidentiality"], ["web"]],
        )

    def test_catalog_items_are_untouched_seed_data(self):
        for url, catalog in (
            ("/api/threats/", "threats"),
            ("/api/measures/", "measures"),
            ("/api/tools/", "tools"),
        ):
            with self.subTest(catalog=catalog):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                payload = response.json()
                self.assertEqual(payload["source"], "demo")
                self.assertEqual(payload["items"], read_seed(catalog))

    def test_api_errors_keep_english_codes_and_messages(self):
        invalid_json = self.client.post(
            API_ANALYZE, data=b"{", content_type="application/json"
        )
        self.assertEqual(invalid_json.status_code, 400)
        self.assertEqual(invalid_json.json(), {"error": "invalid_json"})

        non_object = self.client.post(
            API_ANALYZE, data=b"[1]", content_type="application/json"
        )
        self.assertEqual(non_object.status_code, 400)
        self.assertEqual(
            non_object.json(),
            {"error": "object_required", "message": "Profile must be an object."},
        )

        invalid_profile = self.post_profile({"system_type": 7})
        self.assertEqual(invalid_profile.status_code, 400)
        self.assertEqual(
            invalid_profile.json(),
            {
                "error": "invalid_profile",
                "message": "system_type must be a string.",
                "field": "system_type",
            },
        )
        string_boolean = self.post_profile({"uses_ai": "true"})
        self.assertEqual(
            string_boolean.json(),
            {
                "error": "invalid_profile",
                "message": "uses_ai must be a boolean.",
                "field": "uses_ai",
            },
        )


# ---------------------------------------------------------------------------
# HTML 400 wiring: fixed Russian plain text, status preserved
# ---------------------------------------------------------------------------


class HtmlErrorViewTests(SimpleTestCase):
    """profile_analyze error branch: 400 plain text with the fixed message.

    The branch returns ``HttpResponse`` text without rendering a template,
    so these tests are safe to run before the frontend completion notice.
    """

    def post_with_error(self, error, form_data):
        from services.profile_validation import ProfileValidationError

        client = Client()  # CSRF checks disabled: no profile page GET needed.
        with mock.patch(
            "core.views.analyze_profile", side_effect=error
        ), mock.patch(
            "core.views.build_result_presentation"
        ), mock.patch(
            "core.views.build_profile_form"
        ):
            response = client.post(HTML_ANALYZE, form_data)
        return response

    def test_invalid_profile_returns_400_plain_text_russian_message(self):
        from services.profile_validation import ProfileValidationError

        response = self.post_with_error(
            ProfileValidationError(
                "invalid_profile", "system_type must be a string.", "system_type"
            ),
            {"system_type": "web", "interfaces": ["web"]},
        )
        self.assertLess(response.status_code, 500)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response["Content-Type"].startswith("text/plain"))
        self.assertEqual(
            response.content.decode("utf-8"),
            HTML_PROFILE_ERRORS["system_type"],
        )

    def test_every_field_message_reaches_the_response(self):
        from services.profile_validation import ProfileValidationError

        for field, expected in HTML_PROFILE_ERRORS.items():
            with self.subTest(field=field):
                response = self.post_with_error(
                    ProfileValidationError(
                        "invalid_profile", f"{field} invalid.", field
                    ),
                    {"system_type": "web"},
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.content.decode("utf-8"), expected)

    def test_fixed_text_never_reflects_submitted_values(self):
        from services.profile_validation import ProfileValidationError

        error = ProfileValidationError(
            "invalid_profile", "system_type must be a string.", "system_type"
        )
        first = self.post_with_error(
            error, {"system_type": HOSTILE_TEXT, "interfaces": ["web"]}
        )
        second = self.post_with_error(
            error, {"system_type": "another", "interfaces": ["api"]}
        )
        self.assertEqual(first.content, second.content)
        body = first.content.decode("utf-8")
        self.assertNotIn(HOSTILE_TEXT, body)
        self.assertNotIn("another", body)
        self.assertNotIn("<", body)

    def test_object_required_error_is_russian_plain_text(self):
        from services.profile_validation import ProfileValidationError

        response = self.post_with_error(
            ProfileValidationError("object_required", "Profile must be an object."),
            {"system_type": "web"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.content.decode("utf-8"),
            HTML_ERROR_TEXTS["object_required"],
        )


# ---------------------------------------------------------------------------
# Localized display in rendered HTML — run after the frontend final notice.
# ---------------------------------------------------------------------------


@tag("qa_html")
class LocalizedDisplayHtmlTests(SimpleTestCase):
    """Rendered pages show Russian labels; originals stay machine values.

    These tests render ``templates/*`` and therefore belong to the final
    integration pass (``manage.py test`` without ``--exclude-tag qa_html``).
    """

    def result_page(self, form_data=None):
        form_data = form_data or {
            "system_type": "web",
            "interfaces": ["web"],
            "internet_exposed": "on",
            "data_classes": ["confidentiality"],
        }
        response = self.client.post(HTML_ANALYZE, form_data)
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def profile_page(self):
        response = self.client.get("/profile/")
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_profile_page_shows_russian_standard_labels_and_raw_values(self):
        html = self.profile_page()
        for label_text in (
            "Веб-приложение",
            "Внутренняя система",
            "Веб-интерфейс",
            "Программный интерфейс (API)",
            "Конфиденциальность",
            "Целостность",
        ):
            self.assertIn(label_text, html)
        for raw_value in ('value="web"', 'value="internal"', 'value="api"',
                          'value="confidentiality"', 'value="integrity"'):
            self.assertIn(raw_value, html)

    def test_result_page_shows_russian_entity_names_and_descriptions(self):
        html = self.result_page()
        self.assertIn(ENTITY_TRANSLATIONS[("DEMO-T-001", "name")], html)
        self.assertIn(ENTITY_TRANSLATIONS[("DEMO-T-001", "description")], html)
        self.assertIn(ENTITY_TRANSLATIONS[("DEMO-T-003", "name")], html)
        self.assertIn(ENTITY_TRANSLATIONS[("DEMO-M-001", "name")], html)
        self.assertIn(ENTITY_TRANSLATIONS[("DEMO-M-001", "description")], html)
        self.assertIn(ENTITY_TRANSLATIONS[("DEMO-SZI-001", "name")], html)
        self.assertIn(ENTITY_TRANSLATIONS[("DEMO-SZI-001", "description")], html)

    def test_result_page_hides_english_entity_text_from_display(self):
        # The display swaps to Russian; raw English must not remain rendered
        # in data/metadata attributes merely to satisfy legacy expectations.
        html = self.result_page()
        for original in (
            "Web request manipulation",
            "Demo web threat",
            "Internet exposure",
            "Demo external exposure threat",
            "Web filtering",
            "Demo protection measure",
            "Demo web security tool",
            "Demo security product",
        ):
            self.assertNotIn(original, html)

    def test_result_page_shows_russian_severity_and_categories(self):
        html = self.result_page()
        # Scenario A: T-001/T-006 medium, T-003/T-004 high.
        self.assertIn("Средняя", html)
        self.assertIn("Высокая", html)
        self.assertIn("Доступ из интернета", html)
        self.assertIn("Конфиденциальность", html)

    def test_result_page_declares_demo_provenance_in_russian(self):
        html = self.result_page()
        self.assertIn("Источник: Демонстрационные данные", html)
        self.assertNotIn("Источник: demo", html)

    def test_custom_option_label_renders_the_verbatim_value(self):
        response = self.client.post(
            HTML_ANALYZE,
            {"system_type": HOSTILE_TEXT, "interfaces": ["web"]},
        )
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        from html import escape

        self.assertIn(escape(HOSTILE_TEXT, quote=True), html)
        self.assertNotIn(HOSTILE_TEXT + "<", html)
