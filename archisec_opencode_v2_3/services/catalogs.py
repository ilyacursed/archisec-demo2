"""Read-only catalog services shared by HTTP adapters."""

from .data_repository import get_by_code, items


def list_catalog(name):
    return {"source": "demo", "items": items(name)}


def catalog_item(name, code):
    item = get_by_code(name, code)
    if item is None:
        return None
    return {"source": "demo", "item": item}
