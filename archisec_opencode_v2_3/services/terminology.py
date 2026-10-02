"""Pure Russian display text; machine values and source entities stay intact.

Lookups are exact, with no trimming, case folding or repository access.
Unknown values are returned verbatim and remain subject to template escaping.
"""


_LABELS = {
    "system": {
        "web": "Веб-приложение",
        "internal": "Внутренняя система",
    },
    "interface": {
        "web": "Веб-интерфейс",
        "api": "Программный интерфейс (API)",
    },
    "category": {
        "web": "Веб-приложение",
        "api": "Программный интерфейс (API)",
        "internet": "Доступ из интернета",
        "ai": "Искусственный интеллект",
        "confidentiality": "Конфиденциальность",
        "integrity": "Целостность",
        "availability": "Доступность",
        "internal": "Внутренняя система",
    },
    "severity": {
        "medium": "Средняя",
        "high": "Высокая",
        "low": "Низкая",
    },
    "provenance": {
        "demo": "Демонстрационные данные",
        "unverified": "Не подтверждено",
        "non-normative": "Не является нормативной рекомендацией",
    },
    "class": {
        "DEMO-SZI-CLASS-001": "Демонстрационный класс: защита веб-приложений",
        "DEMO-SZI-CLASS-002": "Демонстрационный класс: шлюз программного интерфейса",
        "DEMO-SZI-CLASS-003": "Демонстрационный класс: контроль доступа",
        "DEMO-SZI-CLASS-004": "Демонстрационный класс: защита данных",
        "DEMO-SZI-CLASS-005": "Демонстрационный класс: контроль входных данных искусственного интеллекта",
        "DEMO-SZI-CLASS-006": "Демонстрационный класс: наблюдение за целостностью",
    },
    "framework": {
        "DEMO-FRAMEWORK-WEB": "Демонстрационная схема: веб-приложения",
        "DEMO-FRAMEWORK-API": "Демонстрационная схема: программные интерфейсы",
        "DEMO-FRAMEWORK-EXTERNAL": "Демонстрационная схема: внешний доступ",
        "DEMO-FRAMEWORK-DATA": "Демонстрационная схема: данные",
        "DEMO-FRAMEWORK-AI": "Демонстрационная схема: искусственный интеллект",
        "DEMO-FRAMEWORK-APP": "Демонстрационная схема: целостность приложений",
        "DEMO-FRAMEWORK-239": "Демонстрационная схема 239 (не нормативный документ)",
        "DEMO-FRAMEWORK-117": "Демонстрационная схема 117 (не нормативный документ)",
    },
}


# The original text is part of the key: a custom entity that reuses a demo
# code must not have its name or description silently replaced.
_ENTITY_TEXT = {
    ("DEMO-T-001", "name", "Web request manipulation"): "Манипулирование веб-запросами",
    ("DEMO-T-001", "description", "Demo web threat"): "Демонстрационный пример угрозы, связанной с изменением веб-запросов.",
    ("DEMO-T-002", "name", "API abuse"): "Злоупотребление программным интерфейсом",
    ("DEMO-T-002", "description", "Demo API threat"): "Демонстрационный пример угрозы, связанной с использованием программного интерфейса не по назначению.",
    ("DEMO-T-003", "name", "Internet exposure"): "Угроза при доступе из интернета",
    ("DEMO-T-003", "description", "Demo external exposure threat"): "Демонстрационный пример угрозы для системы, доступной из интернета.",
    ("DEMO-T-004", "name", "Confidential data disclosure"): "Раскрытие конфиденциальных данных",
    ("DEMO-T-004", "description", "Demo confidentiality threat"): "Демонстрационный пример угрозы раскрытия конфиденциальных данных.",
    ("DEMO-T-005", "name", "AI prompt manipulation"): "Манипулирование запросами к искусственному интеллекту",
    ("DEMO-T-005", "description", "Demo AI threat"): "Демонстрационный пример угрозы, связанной с изменением запросов к системе искусственного интеллекта.",
    ("DEMO-T-006", "name", "Demo application integrity issue"): "Демонстрационный пример нарушения целостности приложения",
    ("DEMO-T-006", "description", "Demo integrity threat"): "Демонстрационный пример угрозы нарушения целостности приложения.",
    ("DEMO-M-001", "name", "Web filtering"): "Фильтрация веб-запросов",
    ("DEMO-M-001", "description", "Demo protection measure"): "Демонстрационный пример меры: фильтрация веб-запросов. Не является нормативной рекомендацией.",
    ("DEMO-M-002", "name", "API gateway controls"): "Контроль запросов на шлюзе программного интерфейса",
    ("DEMO-M-002", "description", "Demo API protection measure"): "Демонстрационный пример меры: контроль запросов к программному интерфейсу. Не является нормативной рекомендацией.",
    ("DEMO-M-003", "name", "External access control"): "Контроль внешнего доступа",
    ("DEMO-M-003", "description", "Demo perimeter measure"): "Демонстрационный пример меры: контроль внешнего доступа к системе. Не является нормативной рекомендацией.",
    ("DEMO-M-004", "name", "Data access control"): "Контроль доступа к данным",
    ("DEMO-M-004", "description", "Demo confidentiality measure"): "Демонстрационный пример меры: контроль доступа к конфиденциальным данным. Не является нормативной рекомендацией.",
    ("DEMO-M-005", "name", "AI input validation"): "Проверка входных данных искусственного интеллекта",
    ("DEMO-M-005", "description", "Demo AI protection measure"): "Демонстрационный пример меры: проверка входных данных системы искусственного интеллекта. Не является нормативной рекомендацией.",
    ("DEMO-M-006", "name", "Application integrity monitoring"): "Наблюдение за целостностью приложения",
    ("DEMO-M-006", "description", "Demo integrity measure"): "Демонстрационный пример меры: наблюдение за целостностью приложения. Не является нормативной рекомендацией.",
    ("DEMO-SZI-001", "name", "Demo web security tool"): "Демонстрационное средство защиты веб-приложений",
    ("DEMO-SZI-001", "description", "Demo security product"): "Демонстрационный пример средства для веб-приложений. Свойства и эффективность не подтверждены.",
    ("DEMO-SZI-002", "name", "Demo API gateway"): "Демонстрационный шлюз программного интерфейса",
    ("DEMO-SZI-002", "description", "Demo security product"): "Демонстрационный пример шлюза программного интерфейса. Свойства и эффективность не подтверждены.",
    ("DEMO-SZI-003", "name", "Demo access control system"): "Демонстрационная система контроля доступа",
    ("DEMO-SZI-003", "description", "Demo security product"): "Демонстрационный пример системы контроля доступа. Свойства и эффективность не подтверждены.",
    ("DEMO-SZI-004", "name", "Demo data protection system"): "Демонстрационная система защиты данных",
    ("DEMO-SZI-004", "description", "Demo security product"): "Демонстрационный пример системы защиты данных. Свойства и эффективность не подтверждены.",
    ("DEMO-SZI-005", "name", "Demo AI security control"): "Демонстрационное средство контроля искусственного интеллекта",
    ("DEMO-SZI-005", "description", "Demo security product"): "Демонстрационный пример средства контроля системы искусственного интеллекта. Свойства и эффективность не подтверждены.",
    ("DEMO-SZI-006", "name", "Demo integrity monitor"): "Демонстрационное средство наблюдения за целостностью",
    ("DEMO-SZI-006", "description", "Demo security product"): "Демонстрационный пример средства наблюдения за целостностью. Свойства и эффективность не подтверждены.",
}


def label(value, domain="category"):
    """Translate a known exact value in its domain; preserve other values."""
    return _LABELS.get(domain, {}).get(value, value)


def labels(values, domain="category"):
    """Return a fresh list, preserving order, duplicates and empty strings."""
    return [label(value, domain) for value in values]


def entity_text(item, field):
    """Translate only the original demo wording for this code and field."""
    value = item.get(field, "")
    return _ENTITY_TEXT.get((item.get("code"), field, value), value)


_PROFILE_ERRORS = {
    "system_type": "Тип системы должен быть строкой.",
    "interfaces": "Интерфейсы должны быть списком строк.",
    "data_classes": "Классы данных должны быть списком строк.",
    "internet_exposed": "Признак доступа из интернета должен быть логическим значением.",
    "uses_ai": "Признак использования искусственного интеллекта должен быть логическим значением.",
}


def html_error(code, field=None):
    """Return fixed Russian error text without reflecting submitted input."""
    if code == "object_required":
        return "Профиль системы должен быть объектом."
    if code == "invalid_profile":
        return _PROFILE_ERRORS.get(field, "Некорректный профиль системы.")
    if code == "invalid_json":
        return "Некорректный формат данных запроса."
    return "Не удалось обработать профиль системы. Проверьте введённые данные."
