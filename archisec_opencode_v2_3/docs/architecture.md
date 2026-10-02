# Architecture

```text
Browser
  ↓
Django URL / View
  ↓
Services
  ↓
Data Repository
  ↓
JSON files
```

## Repository boundary

`services/` не должны знать о конкретном способе хранения.

MVP repository читает JSON. В будущей фазе можно добавить database repository и сохранить service/API contracts.

## Analysis flow

```text
Profile
  ↓
analyze_profile()
  ├─ threats
  ├─ measures
  ├─ tools
   ├─ statistics
   ├─ metadata
   └─ explanations (category matches + canonical threat → measure → tool links)
       ↓
  AnalysisResult
```

HTML и JSON используют один analyzer.

HTML дополнительно получает чистое presentation-представление из `services/result_presentation.py`: карточки с причинами и обратными связями, counts полноты demo-цепочек и controls текущего профиля. Helpers не читают repository и не изменяют `AnalysisResult`; API остаётся прежним. Обратные связи выводятся только из объяснений выбранного результата. Редактирование — явная повторная отправка формы текущего ответа на существующий POST, не сохранение состояния.

`explanations` — additive детализация того же `AnalysisResult`, не новый слой или endpoint. Analyzer вычисляет sorted unique category intersections для возвращённых угроз и цепочки по canonical `threat_measure` / `measure_tool`, ссылаясь только на возвращённые сущности. Порядок угроз и canonical lists сохраняется, связи имеют stable deduplication; пустые списки допустимы. Точный контракт — в [data_schemas.md](data_schemas.md).

Views остаются HTTP-адаптерами, templates только отображают готовый результат. Угрозы, меры, средства и объяснения представлены секциями с якорями одной страницы результата; маршруты и repository boundary `services/data_repository.py` не меняются. Metadata остаётся `demo / MVP-1`. Объяснение детерминированного выбора не является оценкой риска, эффективности защиты или нормативным обоснованием.

## No persistence

Результат анализа не сохраняется между запросами.
