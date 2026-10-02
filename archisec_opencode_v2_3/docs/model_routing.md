# Model Routing

## Purpose / источник истины

Role-based routing уже настроен активными строками `model:` в `.opencode/agents/*.md`. Это не закомментированные примеры и не placeholder IDs. Источник истины для routing — frontmatter этих файлов; документ описывает фактические назначения, а не предлагает новую схему.

Все три используемых ID подтверждены текущим каталогом OpenCode provider `codexsale` при проверке 2026-09-30 (статус `active`). Routing при синхронизации документации **не менялся**.

## Active routing

| Agent | Role | Model | Active model ID |
|---|---|---|---|
| orchestrator | planning, decomposition, delegation | GPT 6.1 Sol | `codexsale/gpt-6.1-sol` |
| architect | architecture, contracts, trade-offs | GPT 6.1 Sol | `codexsale/gpt-6.1-sol` |
| reviewer | independent read-only review | GPT 6.1 Sol | `codexsale/gpt-6.1-sol` |
| backend | Django, services, API | GPT 6.1 Sol | `codexsale/gpt-6.1-sol` |
| frontend | templates, CSS, UI | GLM 5.3 | `codexsale/glm-5.3` |
| data | JSON schemas, seed data, mappings | GLM 5.3 Flash | `codexsale/glm-5.3-flash` |
| qa | smoke tests, scope checks, validation | GLM 5.3 | `codexsale/glm-5.3` |

Одна модель может обслуживать несколько ролей: специализацию определяют prompts и permissions. Terra/Luna не назначены ни одному из этих агентов; наличие других моделей в каталоге не требует распределять их по ролям.

## Проверка и изменение в будущем

OpenCode использует формат `provider/model-id` (в V2 также возможен suffix `#variant`). Пример существующей активной строки:

```yaml
model: codexsale/gpt-6.1-sol
```

Перед намеренной сменой provider/routing или переносом проекта в другое окружение проверьте доступность IDs в текущем каталоге:

```bash
opencode models
```

Подтверждение относится к текущей установке и не гарантирует доступность этих IDs у другого пользователя. Не придумывайте provider/model ID по имени модели и не заменяйте активные значения прежними `openai/...` или `zhipu/...` placeholders. Для текущего окружения раскомментировать строки или менять routing не требуется.

## Model preference и inheritance

Subagent с явно заданной `model` использует эту настройку; без неё он наследует модель родительской сессии. Primary session хранит выбранную модель отдельно: выбор primary agent по ID сам по себе не переключает модель уже существующей сессии. Поэтому таблица фиксирует настройки агентов, а не гарантирует модель любой открытой primary session.

В `opencode.json` нет общего model override; это не отменяет активных настроек Markdown agents. Для смены модели не нужно менять `description`, `mode` или permissions. Текущая задача не изменяет конфигурацию агентов.

Источник поведения V2: https://opencode.ai/v2/docs/agents
