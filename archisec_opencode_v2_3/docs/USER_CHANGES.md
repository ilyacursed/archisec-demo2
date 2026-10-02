# Что нужно изменить пользователю

## Обязательно

Для запуска самого MVP ничего в исходниках менять не требуется.

1. Установить Python 3.10+.
2. Создать venv.
3. `pip install -r requirements.txt`.
4. Запустить `python manage.py check`.
5. Запустить `python manage.py runserver`.
6. Запустить OpenCode из корня проекта.

## Model routing OpenCode

В `.opencode/agents/*.md` уже включены активные назначения моделей:

```text
orchestrator → codexsale/gpt-6.1-sol
architect    → codexsale/gpt-6.1-sol
reviewer     → codexsale/gpt-6.1-sol
backend      → codexsale/gpt-6.1-sol
frontend     → codexsale/glm-5.3
data         → codexsale/glm-5.3-flash
qa           → codexsale/glm-5.3
```

Эти IDs подтверждены текущим каталогом OpenCode (`codexsale`, статус `active`) при проверке 2026-09-30. Строки `model:` не закомментированы; включать routing заново не требуется. Синхронизация документации не меняла routing. Terra/Luna не назначены текущим агентам.

### При переносе или намеренной смене routing

В другом OpenCode provider setup доступность может отличаться. Сначала выполни:

```bash
opencode models
```

Сопоставь текущие активные IDs с доступным каталогом. Пример фактической настройки:

```yaml
model: codexsale/gpt-6.1-sol
```

Не подставляй вымышленные `openai/...` или `zhipu/...` IDs. Меняй назначения только при намеренной перенастройке и только на IDs из своего каталога; для текущего окружения это не требуется.

Subagent использует явно заданную модель; без override наследует модель родительской сессии. Primary session хранит выбранную модель отдельно: выбор агента по ID не переключает её автоматически. Подробности и фактическая таблица — [model_routing.md](model_routing.md), документация V2 — https://opencode.ai/v2/docs/agents.

## Что НЕ нужно менять

Не нужно вручную менять:

- `requirements.txt`;
- `docs/mvp.md`;
- `docs/data_schemas.md`;
- demo JSON;
- Django URLs;
- `DATABASES`;
- middleware;
- mappings;
- OpenCode V2 schema.

## Что можно менять позже

После успешного первого запуска можно адаптировать:

- model routing;
- визуальный стиль;
- demo seed data;
- набор demo rules;
- тексты UI.

Нормативные данные и production storage не добавлять в MVP вручную: для них предусмотрены следующие фазы проекта.
