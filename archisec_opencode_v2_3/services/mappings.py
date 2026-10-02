"""Demo mapping integrity: canonical mappings + derived reverse indexes.

Источник истины — canonical mappings ``threat_measure`` и ``measure_tool``
в ``data/mappings.json`` (см. docs/data_schemas.md). Reverse indexes
(``measure_threat``, ``tool_measure``) в JSON не хранятся: они выводятся
в памяти при загрузке и всегда симметричны canonical mappings.

Никакого runtime persistence: каждый вызов читает JSON через repository
и строит свежие производные структуры.
"""

from .data_repository import items, load

CANONICAL_KEYS = ("threat_measure", "measure_tool")
REVERSE_KEYS = ("measure_threat", "tool_measure")
KNOWN_KEYS = CANONICAL_KEYS + REVERSE_KEYS

# Какого типа сущности участвуют в каждом направлении: (источник, цель).
REFERENCE_KINDS = {
    "threat_measure": ("threat", "measure"),
    "measure_tool": ("measure", "tool"),
    "measure_threat": ("measure", "threat"),
    "tool_measure": ("tool", "measure"),
}

# Пары canonical -> reverse, которые должны быть взаимно симметричны.
SYMMETRIC_PAIRS = (
    ("threat_measure", "measure_threat"),
    ("measure_tool", "tool_measure"),
)


class MappingValidationError(ValueError):
    """Mappings повреждены (структура/симметрия/ссылки) — молча не принимаем."""

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def validate_mapping_dict(data, entities=None):
    """Validate a mappings payload; return a list of human-readable errors.

    ``data`` — canonical-only словарь или legacy canonical+reverse.
    Отсутствующие reverse-ключи допустимы (они выводятся в runtime);
    присутствующие обязаны быть полностью симметричны canonical-стороне.

    ``entities`` — опциональные множества известных кодов:
    ``{"threat": {...}, "measure": {...}, "tool": {...}}``.
    Если ``None`` или не dict, referential-проверки пропускаются.

    Гарантия: на malformed-входе (вложенные dict/list, не-строчные ключи и
    коды, mixed-type root keys) функция возвращает errors list и не бросает
    исключений — за исключением ошибок самих аргументов-не-контейнеров
    верхнего уровня, которые являются программными, а не data-ошибками.
    """
    errors = []
    if not isinstance(data, dict):
        return ["mappings: root must be an object"]

    for key in CANONICAL_KEYS:
        if key not in data:
            errors.append(f"mappings: missing canonical key: {key}")
    # key=str: root может содержать ключи разных типов — сортировка не должна падать.
    for key in sorted(data, key=str):
        if key not in KNOWN_KEYS:
            errors.append(f"mappings: unknown top-level key: {key}")

    sections = {}
    for key in KNOWN_KEYS:
        if key not in data:
            continue
        section = data[key]
        if not isinstance(section, dict):
            errors.append(f"mappings: {key} must be an object of code -> list")
            sections[key] = {}
            continue
        sections[key] = section
        for src, targets in section.items():
            if not isinstance(src, str) or not src:
                errors.append(f"mappings: {key}: source code must be a non-empty string")
                continue
            if not isinstance(targets, list):
                errors.append(f"mappings: {key}: {src}: value must be a list of codes")
                continue
            if not targets:
                errors.append(f"mappings: {key}: {src}: mapping list is empty")
            seen = set()
            for dst in targets:
                if not isinstance(dst, str) or not dst:
                    errors.append(f"mappings: {key}: {src}: target code must be a non-empty string")
                    continue
                if dst in seen:
                    errors.append(f"mappings: duplicate entry: {key}: {src} -> {dst}")
                seen.add(dst)

    # Полная симметрия в обе стороны: ловит и missing reverse mapping,
    # и reverse-only entries, которых нет в canonical mappings.
    # Пары reverse-стороны нормализуются к направлению canonical (src, dst);
    # сортировка по repr — защита от смешанных типов в синтетике.
    for canonical_key, reverse_key in SYMMETRIC_PAIRS:
        forward = _pairs(sections.get(canonical_key, {}))
        backward = {(dst, src) for src, dst in _pairs(sections.get(reverse_key, {}))}
        if reverse_key in data:
            for src, dst in sorted(backward - forward, key=repr):
                errors.append(
                    f"mappings: reverse-only mapping: {reverse_key}: {dst} -> {src}"
                    f" (no {canonical_key}: {src} -> {dst})"
                )
            for src, dst in sorted(forward - backward, key=repr):
                errors.append(
                    f"mappings: missing reverse mapping: {reverse_key}: {dst} -> {src}"
                )

    if not isinstance(entities, dict):
        return errors
    for key in KNOWN_KEYS:
        src_kind, dst_kind = REFERENCE_KINDS[key]
        for src, targets in sections.get(key, {}).items():
            if not isinstance(src, str) or not isinstance(targets, list):
                # Структурная ошибка для этого ключа уже записана выше.
                continue
            _check_reference(errors, key, src, src_kind, (src,), entities)
            _check_reference(errors, key, src, dst_kind, targets, entities)

    return errors


def load_mappings():
    """Load canonical mappings from the repository and derive reverse indexes.

    Возвращает словарь с четырьмя ключами: canonical ``threat_measure`` /
    ``measure_tool`` и выведенные ``measure_threat`` / ``tool_measure``.
    Повреждённые mappings вызывают MappingValidationError, а не молчаливое
    принятие.
    """
    data = load("mappings")
    errors = validate_mapping_dict(data, _entity_codes())
    if errors:
        raise MappingValidationError(errors)
    mappings = {key: dict(data[key]) for key in CANONICAL_KEYS}
    mappings["measure_threat"] = _invert(mappings["threat_measure"])
    mappings["tool_measure"] = _invert(mappings["measure_tool"])
    return mappings


def validate_mappings():
    """Backward-compatible contract (tests): [] когда текущие данные консистентны."""
    return validate_mapping_dict(load("mappings"), _entity_codes())


def _pairs(section):
    # Только кортежи не пустых строк: иные типы уже отражены структурными
    # ошибками и не должны попадать в множества/сортировку пар.
    return {
        (src, dst)
        for src, targets in section.items()
        if isinstance(src, str) and isinstance(targets, list)
        for dst in targets
        if isinstance(dst, str) and dst
    }


def _invert(section):
    reverse = {}
    for src, targets in section.items():
        for dst in targets:
            reverse.setdefault(dst, []).append(src)
    return reverse


def _check_reference(errors, key, src, kind, codes, entities):
    known = entities.get(kind)
    if not isinstance(known, (set, frozenset, list, tuple)):
        return
    for code in codes:
        # Нестрочные коды (dict/list/...) unhashable или бессмысленны:
        # структурная ошибка уже записана, здесь не падаем.
        if not isinstance(code, str):
            continue
        if code not in known:
            errors.append(f"mappings: unknown {kind} code: {key}: {src} -> {code}")


def _entity_codes():
    def codes(name):
        return {
            entry["code"]
            for entry in items(name)
            if isinstance(entry, dict) and isinstance(entry.get("code"), str)
        }

    return {
        "threat": codes("threats"),
        "measure": codes("measures"),
        "tool": codes("tools"),
    }
