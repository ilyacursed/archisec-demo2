"""Pure HTML presentation of the current result, never a new analysis.

Coverage counts explained demo paths, not protection or compliance. No
repository reads or inferred edges are used here.
"""

from copy import deepcopy

from services.terminology import label


def build_result_presentation(result):
    """Build fresh cards using only explanations of returned entities."""
    threats = result["threats"]
    measures = result["measures"]
    tools = result["tools"]
    categories = {item["code"]: [] for item in threats}
    measure_threats = {item["code"]: [] for item in measures}
    tool_measures = {item["code"]: [] for item in tools}
    complete = set()

    for explanation in result.get("explanations", []):
        threat_code = explanation["threat_code"]
        if threat_code not in categories:
            continue
        for category in explanation.get("matched_categories", []):
            if category not in categories[threat_code]:
                categories[threat_code].append(category)
        for edge in explanation.get("measures", []):
            measure_code = edge["measure_code"]
            if measure_code not in measure_threats:
                continue
            if threat_code not in measure_threats[measure_code]:
                measure_threats[measure_code].append(threat_code)
            for tool_code in edge.get("tool_codes", []):
                if tool_code not in tool_measures:
                    continue
                if measure_code not in tool_measures[tool_code]:
                    tool_measures[tool_code].append(measure_code)
                complete.add(threat_code)

    selected_count = len(categories)
    return {
        "threat_cards": [
            {"item": deepcopy(item), "matched_categories": list(categories[item["code"]])}
            for item in threats
        ],
        "measure_cards": [
            {"item": deepcopy(item), "threat_codes": list(measure_threats[item["code"]])}
            for item in measures
        ],
        "tool_cards": [
            {"item": deepcopy(item), "measure_codes": list(tool_measures[item["code"]])}
            for item in tools
        ],
        "coverage": {
            "selected_threats": selected_count,
            "complete_path_threats": len(complete),
            "incomplete_path_threats": selected_count - len(complete),
        },
    }


def _list_options(values, standards, domain):
    # Each occurrence is a separate checked control so HTML resubmission
    # preserves even duplicate, unknown and empty category strings verbatim.
    options = [
        {"value": value, "label": label(value, domain), "checked": True}
        for value in values
    ]
    options.extend(
        {"value": value, "label": label(value, domain), "checked": False}
        for value in standards
        if value not in values
    )
    return options


def build_profile_form(profile):
    """Present a normalized profile without changing its category strings."""
    system_types = ("web", "internal")
    system_type = profile["system_type"]
    system_options = [
        {"value": value, "label": label(value, "system"), "selected": value == system_type}
        for value in system_types
    ]
    if system_type not in system_types:
        system_options.append({
            "value": system_type,
            "label": label(system_type, "system"),
            "selected": True,
        })
    return {
        "system_type_options": system_options,
        "interface_options": _list_options(
            profile["interfaces"], ("web", "api"), "interface"
        ),
        "data_class_options": _list_options(
            profile["data_classes"],
            ("confidentiality", "integrity"), "category",
        ),
        "internet_exposed": profile["internet_exposed"],
        "uses_ai": profile["uses_ai"],
    }


def default_profile_form():
    """Keep the UI's checked Web interface, distinct from analyzer defaults."""
    return build_profile_form({
        "system_type": "web",
        "interfaces": ["web"],
        "data_classes": [],
        "internet_exposed": False,
        "uses_ai": False,
    })
