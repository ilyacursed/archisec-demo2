# MVP — АрхиСек

## Цель и граница

Текущий MVP — локальное демонстрационное decision-support ядро на Django + JSON: профиль системы → релевантные demo-угрозы → связанные demo-меры → demo-средства защиты. Это первая фаза одного проекта, не production-система и не нормативная модель угроз. Долгосрочные возможности из [product.md](product.md) не входят в текущий контракт автоматически.

## Поддерживаемые сценарии

- Открыть главную страницу и форму профиля системы.
- Передать профиль HTML-формой или JSON-запросом и получить результат анализа в том же ответе.
- Просмотреть списки угроз, мер и средств защиты и их количества в HTML-результате или JSON `AnalysisResult`.
- В том же результате прочитать объяснения совпавших категорий и canonical demo-связей «угроза → мера → средство». HTML использует секции угроз, мер, средств и объяснений с якорями внутри одной страницы результата, а не отдельные catalog/detail HTML-страницы.
- В карточке угрозы увидеть причину выбора, у меры — связанные выбранные угрозы, у средства — связанные меры. Summary показывает полноту demo-цепочек: количество выбранных угроз, имеющих хотя бы один разрешённый путь до средства, а не эффективность защиты или нормативное соответствие.
- Изменить профиль в форме текущего результата и явно отправить его повторно на тот же POST endpoint. Значения подставляются из текущего ответа без сохранения; отдельный новый анализ открывает форму с исходными demo-умолчаниями.
- Прочитать demo-каталоги через JSON API и отдельную угрозу по её `code`.

Форма содержит `system_type`, `interfaces`, `internet_exposed`, `data_classes` и `uses_ai`. JSON-профиль использует те же поля: строку, списки строк и boolean соответственно. Встроенные значения формы (`web` / `internal`, `web` / `api`, `confidentiality` / `integrity`) — только demo UI defaults; validator не ограничивает category strings enum-значениями и сохраняет переданные строки без coercion. Пример запроса:

```json
{
  "system_type": "web",
  "interfaces": ["web", "api"],
  "internet_exposed": true,
  "data_classes": ["confidentiality"],
  "uses_ai": false
}
```

Analyzer сопоставляет категории профиля с `categories` угроз. `internet_exposed` добавляет категорию `internet`, `uses_ai` — `ai`. По canonical mappings `threat_measure` и `measure_tool` подбираются меры и средства; повторяющиеся коды мер и средств удаляются. Это простые demo rules, не AI inference, не оценка соответствия требованиям и не оптимизация бюджета.

Поле `explanations` детализирует этот же анализ: для каждой возвращённой угрозы показывает sorted unique intersection категорий профиля и угрозы, затем её связанные меры и средства по canonical mappings. Достаточно любого совпадения категории (OR), а не всех категорий угрозы. Это детерминированное объяснение выбора и demo-связей, не доказательство актуальности угрозы, оценка риска, эффективности защиты или нормативное обоснование. HTML и API получают объяснения из одного analyzer; интерфейс не вычисляет связи самостоятельно.

Перед анализом `services/profile_validation.py` нормализует профиль. Для отсутствующих ключей применяются defaults: `system_type="web"`, `interfaces=[]`, `data_classes=[]`, `internet_exposed=False`, `uses_ai=False`. Значения должны иметь строгие типы: `system_type` — string, `interfaces` и `data_classes` — lists of strings, boolean fields — JSON booleans. `null`, значения другого типа и строковые boolean (`"true"`, `"false"`) отклоняются; значения не преобразуются. Unknown fields игнорируются. Category strings сохраняются verbatim и не проверяются по enum.

## URL / API

Фактические маршруты определены в `config/urls.py`. Все указанные пути, кроме `/`, заканчиваются `/`.

| Метод | URL | Ответ / назначение |
|---|---|---|
| GET | `/` | Главная HTML-страница |
| GET | `/profile/` | HTML-форма профиля |
| POST | `/profile/analyze/` | HTML-результат анализа form data |
| GET | `/api/threats/` | Каталог угроз |
| GET | `/api/threats/<code>/` | Одна угроза по коду, например `DEMO-T-001` |
| GET | `/api/measures/` | Каталог мер |
| GET | `/api/tools/` | Каталог средств защиты |
| GET | `/api/tactics/` | Каталог тактик |
| GET | `/api/ai-threats/` | Каталог AI-угроз |
| GET | `/api/levels/` | Каталог уровней |
| POST | `/api/profile/analyze/` | JSON-профиль → JSON `AnalysisResult` |

Списки каталогов возвращают `{"source": "demo", "items": [...]}`, detail угрозы — `{"source": "demo", "item": {...}}`. Неизвестный код угрозы возвращает 404 с `{"error": "not_found"}`. Catalog endpoints допускают только GET; endpoints анализа — только POST (иначе 405). Пустое тело API и body с invalid encoding/JSON возвращают 400 `{"error": "invalid_json"}`. Ошибки parser из-за integer digit limits или nesting limits также возвращают 400 `invalid_json`, без отражения входных данных или внутренних сообщений parser. JSON не-объект возвращает 400 `{"error": "object_required", "message": ...}`. Некорректный профиль с неверным типом, `null` или string boolean возвращает 400 с `{"error": "invalid_profile", "message": ..., "field": ...}`; messages фиксированы и не отражают пользовательское значение. Поля с неизвестными именами игнорируются.

`AnalysisResult` содержит `profile`, `threats`, `measures`, `tools`, `statistics` (количества threats/measures/tools), `explanations` и `metadata: {"source": "demo", "version": "MVP-1"}`; структура согласована с [data_schemas.md](data_schemas.md). `explanations` — additive детализация существующего результата, без новых endpoints или изменения версии metadata. Запись имеет вид `{threat_code, matched_categories, measures: [{measure_code, tool_codes}]}`. Порядок записей совпадает с возвращёнными угрозами; связи сохраняют порядок canonical lists со stable deduplication и ссылаются только на возвращённые сущности. Пустые списки объяснений и связей допустимы. HTML и API используют один `analyze_profile()`, внутри которого применяется тот же `normalize_profile()`; HTML invalid profile возвращается как safe fixed plain-text 400, JSON — как safe structured 400.

В `data/` также есть `techniques.json`, но отдельного `/api/techniques/` нет. Каталоги не имеют отдельных HTML-страниц, поиска, pagination, CRUD или detail endpoints для всех типов. Тактики, техники, AI-каталог и уровни не являются отдельными этапами текущего analyzer; флаг `uses_ai` лишь участвует в выборе категорий общего каталога угроз.

### Demo-профили A/B/C

Ниже — ожидаемые результаты для текущих seed data, а не заявление о пройденных тестах. Для каждого номера `n` цепочка — `DEMO-T-00n → DEMO-M-00n → DEMO-SZI-00n`.

| Сценарий | Профиль | Ожидаемые цепочки / statistics threats-measures-tools |
|---|---|---|
| A: web, internet, confidentiality | `system_type="web"`, `interfaces=["web"]`, `internet_exposed=true`, `data_classes=["confidentiality"]`, `uses_ai=false` | 1, 3, 4, 6 / 4-4-4 |
| B: API, internet, без AI | `system_type="internal"`, `interfaces=["api"]`, `internet_exposed=true`, `data_classes=[]`, `uses_ai=false` | 2, 3 / 2-2-2 |
| C: AI, internet, confidentiality | `system_type="internal"`, `interfaces=[]`, `internet_exposed=true`, `data_classes=["confidentiality"]`, `uses_ai=true` | 3, 4, 5 / 3-3-3 |
| C legacy: AI, internet, без confidentiality | `system_type="internal"`, `interfaces=[]`, `internet_exposed=true`, `data_classes=[]`, `uses_ai=true` | 3, 5 / 2-2-2 |

В A угроза `DEMO-T-006` совпадает по `web`, даже без `integrity`. В B/C явный `internal` исключает неявную web-категорию: отсутствующий `system_type` по-прежнему получает default `web`, который дополнительно выбирает цепочки 1 и 6 (B: 1, 2, 3, 6 / 4-4-4; C: 1, 3, 4, 5, 6 / 5-5-5; C legacy: 1, 3, 5, 6 / 4-4-4). Для B/C в форме выбрать Internal и снять исходно отмеченный интерфейс Web. Default/normalization не меняются. `uses_ai=false` не запрещает явно переданную категорию `ai` в строковых полях; category strings по-прежнему не ограничены enum.

## Слои и repository boundary

```text
Django URL → View → Service → Repository → JSON
```

- `config/urls.py`: маршрутизация.
- `core/views.py`: HTTP/form/JSON адаптация и rendering; бизнес-анализ делегируется сервису.
- `services/profile_validation.py`: общий storage-independent normalizer и strict profile validation.
- `services/analyzer.py`: общий для HTML/API выбор угроз и связанных мер/средств после normalization.
- `services/result_presentation.py`: чистое HTML-представление существующего результата и controls профиля. Причины, обратные связи и полнота цепочек выводятся только из `AnalysisResult.explanations`, не из второго набора mappings. API и seed entities не дополняются presentation-полями.
- `services/terminology.py` и тонкие template filters: русские подписи HTML без перевода JSON keys, category values, API messages и кодов. Неизвестные строки сохраняются и экранируются. Фирменный стиль и исходный логотип описаны в [branding.md](branding.md).
- `services/catalogs.py`: общий read-only catalog service boundary для list/detail API adapters.
- `services/mappings.py`: `load_mappings()` возвращает canonical mappings и derived in-memory reverse indexes; `validate_mappings()` и pure `validate_mapping_dict(data, entities=None)` возвращают списки ошибок валидации.
- `services/data_repository.py`: единственное место чтения JSON (`load`, `items`, `get_by_code`).
- `data/*.json`: read-only demo seed data; `templates/` и `static/`: server-rendered интерфейс.

Текущий repository — модуль с функциями, не ORM и не отдельная система dependency injection. Services/views не должны открывать JSON-файлы напрямую. При будущей смене хранения сохраняется repository/service contract, чтобы не переписывать бизнес-анализ и HTTP-представления. Database repository в MVP не реализуется.

## Demo-only provenance

Все seed data, правила и mappings — **demo / unverified / non-normative**. Идентификаторы сущностей используют namespace `DEMO-`. Это не официальная выгрузка ФСТЭК, не проверенные нормативные связи и не подтверждение сертификации средств защиты. UI явно обозначает демонстрационный характер данных; успешные JSON-ответы содержат demo provenance.

`data/mappings.json` хранит только canonical mappings `threat_measure` и `measure_tool`. Reverse indexes `measure_threat` и `tool_measure` вычисляются in-memory через `services.mappings.load_mappings()` и не сохраняются как второй источник истины. Analyzer получает mappings через repository и использует только canonical keys.

`validate_mappings()` возвращает список ошибок проверки текущих mappings; pure `validate_mapping_dict(data, entities=None)` проверяет переданный mapping dict и может принимать legacy fixtures с reverse indexes. Проверки охватывают структуру, references на demo-сущности, duplicates и двустороннюю симметрию legacy reverses, включая связи, присутствующие только в reverse index. Поддержка legacy fixtures не меняет canonical-only runtime storage. Нормативные данные и реальные regulatory mappings не добавляются в текущую фазу.

## No persistence и exclusions

Профиль и результат живут только в текущем запросе/ответе. Нет записи профиля, истории анализов, изменения seed JSON, сохранения результата между запросами или client-side persistence. Просмотр ответа в браузере не является сохранением в приложении. Форма редактирования в ответе содержит текущие значения; повторный анализ явно передаёт их новым POST, а не восстанавливает из server-side или browser storage. Неизменённая отправка сохраняет строки, порядок и дубли list-полей, включая нестандартные и пустые category strings.

MVP исключает:

- DB backend, ORM, migrations; `DATABASES = {}`;
- PostgreSQL и SQLite persistence;
- accounts, authentication/auth, sessions;
- Redis, Celery и background jobs;
- production storage, нормативный data pipeline;
- экспорт документов, полноценную модель угроз, сертифицированные рекомендации, budget/resource optimization, LLM/AI inference.

Не выполнять `migrate` и не добавлять инфраструктуру из будущих фаз ради запуска или тестирования MVP.

## Security и quality expectations

HTML-форма использует Django CSRF protection. JSON endpoint анализа имеет явное временное `csrf_exempt` в `core/views.py`; это demo-ограничение и будущая security-задача, не production API strategy. Настройки с `DEBUG = True` и demo secret предназначены для локального запуска, не для публичного deployment.

Quality expectations ([quality_gates.md](quality_gates.md)):

- `python manage.py check` проходит без БД/migrations; тестовое покрытие и прохождение `manage.py test` подтверждаются отдельным QA-проходом;
- главная страница и форма доступны; валидный анализ работает в HTML и JSON;
- API соблюдает методы/status codes и возвращает безопасные 400 для invalid JSON и invalid profile;
- HTML/API используют один analyzer и согласованный `AnalysisResult`;
- объяснения детерминированы, отражают только совпавшие категории и canonical связи возвращённых сущностей; секции и якоря остаются на той же HTML-странице результата;
- JSON корректен, demo IDs и provenance явные, mappings симметричны и referentially valid;
- отсутствуют ORM, auth/session зависимости, persistence и scope drift.

Эти пункты — контрактные ожидания, а не утверждение о полном тестовом покрытии. Отдельный QA должен подтвердить strict validation, defaults, error responses, все URL и data/mapping invariants; документация не объявляет эти проверки уже пройденными.
