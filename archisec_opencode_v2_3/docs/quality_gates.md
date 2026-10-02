# Quality Gates

## Bootstrap

- `python manage.py check` passes;
- server starts without traceback;
- GET `/` is 200;
- no database backend;
- no migrations.

## MVP behavior

- GET `/profile/` → 200;
- POST `/profile/analyze/` → 200;
- POST `/api/profile/analyze/` → 200 for valid input;
- GET `/api/profile/analyze/` → 405;
- catalog APIs return JSON;
- invalid API input does not cause 500.
- HTML/API используют один `AnalysisResult`, включая additive `explanations`; metadata остаётся `demo / MVP-1`, маршруты неизменны.
- HTML presentation не изменяет API/result/statistics/entities; причины видны в карточках угроз, меры ссылаются только на связанные выбранные угрозы, средства — только на связанные меры.
- Полнота demo-цепочек считает угрозы с хотя бы одним разрешённым canonical путём до средства; проверить shared/one-to-many, partial/missing/dangling paths и пустой результат (0/0, без заявления 100% защиты).
- Изменение профиля работает через CSRF-protected повторный POST текущей формы без persistence и payload в URL. Неизменённая отправка сохраняет неизвестные/пустые строки, list order/duplicates и boolean states; inputs autoescaped, IDs уникальны. Свежий GET сохраняет UI-defaults.
- Новый demo C (`internal`, interfaces=[], internet=true, confidentiality, AI=true) даёт цепочки 3/4/5 и counts 3-3-3; предыдущий C без confidentiality остаётся regression-сценарием 3/5 и 2-2-2.
- На каждую возвращённую угрозу есть объяснение в том же порядке; `matched_categories` равно sorted unique intersection effective profile categories и threat categories. Повторные вызовы и duplicate input categories не меняют объяснения.
- Цепочки используют только canonical `threat_measure` / `measure_tool`, порядок canonical lists и stable deduplication; ссылки ведут только на возвращённые сущности. Проверить one-to-many/shared mappings синтетическими fixtures без записи seed data.
- Empty result даёт `explanations=[]`; отсутствие связанных мер/средств допускает пустые вложенные списки, без выдуманных связей.
- Профили A/B/C из [mvp.md](mvp.md) имеют ожидаемые коды, причины и количества; в B/C явный `internal` и отсутствие интерфейса `web` изолируют API/AI. Default `web` и OR category matching не меняются.
- HTML отображает объяснения из того же результата, секции и якоря находятся на одной странице; category strings безопасно escaped. Объяснения не заявляют актуальность угрозы, риск, эффективность защиты или нормативное соответствие.

Это критерии проверки, а не заявление о пройденных тестах; результаты подтверждаются отдельным QA-проходом.

## Scope

Reject if production code introduces:

- `Model.objects`;
- authentication decorators;
- session dependency;
- migrations;
- PostgreSQL/SQLite persistence;
- Redis/Celery.

## Data

- all demo entities are clearly demo;
- no real regulatory mappings;
- canonical and reverse mappings are symmetric.
