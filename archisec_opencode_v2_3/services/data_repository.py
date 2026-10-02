import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

FILES = {
    "threats": "threats.json",
    "measures": "measures.json",
    "tools": "tools.json",
    "tactics": "tactics.json",
    "techniques": "techniques.json",
    "ai_threats": "ai_threats.json",
    "levels": "levels.json",
    "mappings": "mappings.json",
}


def load(name):
    with (DATA_DIR / FILES[name]).open(encoding="utf-8") as fh:
        return json.load(fh)


def items(name):
    return load(name)


def get_by_code(name, code):
    return next((item for item in items(name) if item.get("code") == code), None)
