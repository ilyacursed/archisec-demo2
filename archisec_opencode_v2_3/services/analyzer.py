from .data_repository import items, load, get_by_code
from .profile_validation import normalize_profile


def analyze_profile(profile):
    profile = normalize_profile(profile)
    threats = items("threats")
    selected = []
    categories = set(profile.get("interfaces", []))
    if profile.get("system_type"):
        categories.add(profile["system_type"])
    if profile.get("internet_exposed"):
        categories.add("internet")
    categories.update(profile.get("data_classes", []))

    if profile.get("uses_ai"):
        categories.add("ai")

    for threat in threats:
        if categories.intersection(threat.get("categories", [])):
            selected.append(threat)

    mapping = load("mappings")
    measure_codes = []
    for threat in selected:
        measure_codes.extend(mapping["threat_measure"].get(threat["code"], []))
    measure_codes = list(dict.fromkeys(measure_codes))
    measures = [get_by_code("measures", code) for code in measure_codes]
    measures = [m for m in measures if m]

    tool_codes = []
    for measure in measures:
        tool_codes.extend(mapping["measure_tool"].get(measure["code"], []))
    tool_codes = list(dict.fromkeys(tool_codes))
    tools = [get_by_code("tools", code) for code in tool_codes]
    tools = [t for t in tools if t]

    # Trace canonical edges per threat, restricted to resolved result entities.
    # Flat result lists are unions, not positional threat/measure/tool pairs.
    resolved_measure_codes = {measure["code"] for measure in measures}
    resolved_tool_codes = {tool["code"] for tool in tools}
    explanations = []
    for threat in selected:
        explained_measures = []
        for code in dict.fromkeys(mapping["threat_measure"].get(threat["code"], [])):
            if code in resolved_measure_codes:
                explained_measures.append({
                    "measure_code": code,
                    "tool_codes": [
                        tool_code
                        for tool_code in dict.fromkeys(mapping["measure_tool"].get(code, []))
                        if tool_code in resolved_tool_codes
                    ],
                })
        explanations.append({
            "threat_code": threat["code"],
            "matched_categories": sorted(categories.intersection(threat.get("categories", []))),
            "measures": explained_measures,
        })

    return {
        "profile": profile,
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
