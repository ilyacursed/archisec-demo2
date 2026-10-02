# Demo Data Schemas

Все JSON-файлы MVP содержат демонстрационные данные. Они не являются официальной выгрузкой ФСТЭК.

Идентификаторы используют namespace `DEMO-`.

## Threat

```json
{
  "code": "DEMO-T-001",
  "name": "Demo threat",
  "description": "Demonstration-only threat description",
  "categories": ["web"],
  "severity": "medium",
  "frameworks": ["DEMO-FRAMEWORK-WEB"]
}
```

## Measure

```json
{
  "code": "DEMO-M-001",
  "name": "Demo protection measure",
  "description": "Demonstration-only protection measure",
  "categories": ["web"],
  "frameworks": ["DEMO-FRAMEWORK-239", "DEMO-FRAMEWORK-117"]
}
```

Не использовать в MVP реальные нормативные коды или реальные mappings.

## Tool

```json
{
  "code": "DEMO-SZI-001",
  "name": "Demo security tool",
  "class": "DEMO-SZI-CLASS-001",
  "description": "Demonstration-only security product description"
}
```

## Tactic / Technique / AI threat / Level

Все сущности используют `DEMO-` IDs и описания, явно обозначенные как demonstration-only.

## Canonical mappings

`data/mappings.json` хранит **только** два canonical indexes — `threat_measure` и `measure_tool`:

```json
{
  "threat_measure": {
    "DEMO-T-001": ["DEMO-M-001"]
  },
  "measure_tool": {
    "DEMO-M-001": ["DEMO-SZI-001"]
  }
}
```

Каждый index — object с кодами исходных сущностей в качестве ключей и lists of target codes в качестве значений. Связи должны ссылаться на существующие demo-сущности и не содержать duplicate target codes.

Reverse indexes (`measure_threat`, `tool_measure`) не хранятся в JSON. `services.mappings.load_mappings()` возвращает canonical mappings вместе с вычисленными in-memory reverses. Это производное представление, не дополнительный persisted source of truth. Analyzer получает данные через repository и использует только canonical keys.

### Validation contract

- `services.mappings.load_mappings()` → canonical mappings + derived reverse indexes.
- `services.mappings.validate_mappings()` → список ошибок проверки текущих mappings.
- Pure `services.mappings.validate_mapping_dict(data, entities=None)` → список ошибок проверки переданного mapping dict; `entities` позволяет передать сущности для проверки references.

Validation проверяет mapping structure, references, duplicates и, для legacy fixtures с reverse indexes, двустороннюю симметрию с canonical mappings. Legacy reverse-only edges (связи без соответствующей canonical связи) также являются ошибками. Возможность передать legacy fixture pure validator не разрешает дублировать canonical и reverse данные в runtime JSON.

Прохождение QA и полнота тестового покрытия этого контракта подтверждаются отдельным QA-проходом; здесь результаты тестов не заявляются.

## AnalysisResult

HTML-only context `presentation` и `profile_form` не входит в JSON `AnalysisResult`, `statistics` или seed entities. `presentation` содержит `threat_cards` (`item`, `matched_categories`), `measure_cards` (`item`, `threat_codes`), `tool_cards` (`item`, `measure_codes`) и `coverage` (`selected_threats`, `complete_path_threats`, `incomplete_path_threats`). Порядок карточек совпадает с результатом; обратные связи — stable first-seen deduplication объяснений, ограниченная возвращёнными сущностями. Полный путь означает хотя бы одну связанную возвращённую меру с хотя бы одним связанным возвращённым средством; угроза учитывается один раз. Для пустого результата все три counts равны нулю. Это полнота демонстрационных связей, не оценка защиты.

`profile_form` содержит options для system type и list-полей, а также boolean-флаги. Каждый текущий элемент списка, включая дубли, пустые и неизвестные строки, представлен отдельным checked control в исходном порядке. Далее добавлены отсутствующие стандартные unchecked options. Нестандартный system type получает отдельную selected option. Значения не coercion/enum-normalized; controls не используют category strings как HTML IDs. Свежая форма сохраняет UI-defaults, а форма результата — текущий нормализованный профиль без persistence.

```json
{
  "profile": {},
  "threats": [],
  "measures": [],
  "tools": [],
  "statistics": {},
  "explanations": [],
  "metadata": {
    "source": "demo",
    "version": "MVP-1"
  }
}
```

### Explanations: детализация существующего результата

`explanations` — additive поле того же `AnalysisResult`, общее для HTML/API. Версия metadata остаётся `MVP-1`. Пример записи:

```json
{
  "threat_code": "DEMO-T-001",
  "matched_categories": ["web"],
  "measures": [
    {
      "measure_code": "DEMO-M-001",
      "tool_codes": ["DEMO-SZI-001"]
    }
  ]
}
```

- Одна запись на каждую возвращённую угрозу, в порядке `threats`; `threat_code` ссылается на эту угрозу.
- Effective categories — множество `interfaces`, непустого `system_type`, `data_classes` и категорий `internet`/`ai` при соответствующих true-флагах нормализованного профиля. `matched_categories` — sorted unique intersection этого множества и `threat.categories`, без преобразования строк. Выбор угрозы требует любого совпадения, не всех категорий.
- `measures` содержит связи конкретной угрозы из canonical `threat_measure`; `tool_codes` — связи конкретной меры из canonical `measure_tool`. Порядок canonical lists сохраняется; duplicate codes удаляются с сохранением первого появления. Общая мера или средство может участвовать в объяснениях нескольких угроз.
- `measure_code` и `tool_codes` ссылаются только на сущности из возвращённых `measures` и `tools`. Неразрешённые repository lookup ссылки не включаются; это не заменяет mapping integrity QA.
- Если угроз нет, `explanations=[]`. Для угрозы без доступных связанных мер допустимо `measures=[]`; для меры без доступных связанных средств допустимо `tool_codes=[]`. Объяснение категории сохраняется и при отсутствии полной цепочки.
- Объяснения вычисляются в текущем запросе; они не хранятся в seed JSON, не являются новым source of truth и не требуют endpoints или persistence.

Это объяснение совпадения demo-категорий и canonical связей, не доказательство актуальности угрозы, оценка риска/эффективности мер и не нормативное основание. HTML отображает тот же контракт в секциях и якорях существующей страницы результата.
