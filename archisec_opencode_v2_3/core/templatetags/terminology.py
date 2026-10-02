"""Thin display filters; Django's normal autoescaping remains enabled."""

from django import template

from services.terminology import entity_text, label, labels


register = template.Library()


@register.filter
def ui_label(value, domain="category"):
    return label(value, domain)


@register.filter
def ui_labels(values, domain="category"):
    return labels(values, domain)


@register.filter
def entity_name(item):
    return entity_text(item, "name")


@register.filter
def entity_description(item):
    return entity_text(item, "description")
