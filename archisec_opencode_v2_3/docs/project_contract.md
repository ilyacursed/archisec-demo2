# Project Contract

## One repository

MVP является первой фазой одного проекта. Не создавать параллельные проекты для frontend/backend/data.

## Layering

```text
Django URL
  -> View
  -> Service
  -> Repository
  -> JSON
```

Views не содержат существенной бизнес-логики.

## MVP exclusions

No DB, ORM, migrations, auth, sessions, PostgreSQL, Redis, Celery.

## Data provenance

Все seed data — demo/unverified/non-normative.

## Mappings

Canonical: `threat_measure`, `measure_tool`.
Reverse indexes are derived and QA-validated.

## Model routing

Не фиксировать model IDs, которых нет в `opencode models` пользователя.
