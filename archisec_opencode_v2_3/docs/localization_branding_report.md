# Product Localization + Branding — итог

Статус: **PASS**, локальный демонстрационный MVP. Проверка: 2026-10-01.

## Изменённые файлы

- Backend display: `core/views.py`, `services/result_presentation.py`.
- Новые: `services/terminology.py`, `core/templatetags/__init__.py`, `core/templatetags/terminology.py`.
- UI: `templates/base.html`, `templates/home.html`, `templates/profile.html`, `templates/result.html`, `templates/partials/profile_fields.html`, `static/style.css`.
- Документация: `README.md`, `docs/mvp.md`; новые `docs/branding.md` и этот отчёт.
- Узкие обновления ожиданий HTML: `tests/test_quality_gates.py`, `tests/test_analysis_explanations.py`, `tests/test_result_presentation.py`.
- Новые: `tests/test_terminology.py`, `tests/test_branding.py`.

Исходный `static/img/archisec-logo.png` уже находился в static assets: использован, но не изменён. Analyzer, repository, validator, catalogs, mappings, JSON seed data, settings, routes и runtime dependencies не менялись. Их хеши независимо сравнены с предыдущим product-stage baseline. Model routing этой задачей не изменялся.

## Локализация

Переведены navigation, titles/descriptions, формы и подсказки, сценарии, empty states, metadata/provenance в HTML, критичность, категории, причины выбора, классы СЗИ и подписи схем. Локализованы имена и описания всех 18 сущностей текущего HTML-flow: шесть угроз, шесть мер, шесть средств.

Единый pure terminology layer использует точные словари по доменам: system, interface, category, severity, provenance, class, framework. Примеры: confidentiality → «Конфиденциальность», integrity → «Целостность», availability → «Доступность», ai → «Искусственный интеллект», unverified → «Не подтверждено». В интерфейсе применяется термин «Средство защиты информации (СЗИ)».

Машинные идентификаторы, JSON keys, enums/values, коды и API не переводятся. Unknown пользовательский текст остаётся дословным и экранируется. HTML validation errors фиксированы и русскоязычны; API messages остаются прежними. Перевод сущности требует совпадения кода, поля и исходного текста, не подменяя custom fixtures.

## Логотип и палитра

Один предоставленный PNG 1254 × 1254 используется в header, hero главной, favicon и README. SHA-256: `f7fc408a0c9d1d7881ecfbfadfa248c3f8f8f70ba217540abe497c56d3c0d6df`. Исходник не обрезан, не перекрашен, не растянут и не заменён новым дизайном. Производные изображения не потребовались. Проверена загрузка через Django static files.

В `:root` добавлены `--archisec-green: #6AAF9C` и `--archisec-blue: #4182AE`, каждый hex ровно один раз. Синий акцент — верхняя полоса header; зелёный — hero и декоративные границы notices. Остальные области светлые и нейтральные. Buttons, links, checkbox accents и focus используют контрастные производные: `--accent: #2F6285`, `--accent-strong: #254C68`, `--accent-soft`, `--accent-border`. Существующие surface/ink/border/radius tokens сохранены; demo tokens согласованы с новой палитрой.

Контраст с белым: брендовый зелёный 2.55:1, синий 4.18:1 — не применяются как обычный мелкий текст. Тёмные производные дают 6.55:1 и 9.08:1. Primary buttons имеют белый текст на тёмном синем; focus — 3px контрастный outline. Градиенты и дополнительные яркие цвета не добавлены.

## Результаты проверок

Python 3.14.0 / Django 5.2.17; внешний qa_venv, `PYTHONDONTWRITEBYTECODE=1`.

| Проверка | Результат |
|---|---|
| `manage.py check` | 0 issues |
| Полный `manage.py test` | **275/275 PASS** |
| Существующий поведенческий baseline | 203 tests сохранены; обновлён только переводимый HTML-текст |
| Новая локализация / branding | 52 + 20 tests PASS |
| QA live HTTP smoke | **28/28 PASS**, без 500 |
| Независимый browser smoke | Home → Profile → Analysis → Result → Threats → Measures → Tools/SZI → Traceability, PASS |
| Редактирование A → B → C | 4–4–4 → 2–2–2 → 3–3–3, PASS |
| Empty result | Русские states, нет заявления 100% защиты |
| Logo/favicon/CSS | HTTP 200, PNG совпадает с источником; broken images нет |
| Responsive | Home/Profile/Result × 320/768/1280 px: все 9 browsing contexts без overflow/offscreen, image ratio 1 |
| Дополнительный frontend headless audit | 24 responsive checks PASS, включая unknown/hostile значения |
| Console | Предупреждений/ошибок нет |
| Lighthouse Home/Profile | Accessibility / Best Practices / SEO: 100/100, автоматическая проверка |
| Независимый read-only Reviewer | **PASS**, нет blocking findings |

Orchestrator независимо повторил полный suite и новые модули. Тесты logo/data pin portable SHA-256 constants и не зависят от временного baseline. Существующие проверки API, формы, CSRF, escaping, данных и scope сохранены; нет skips или ослабления логических assertions. Reviewer использовал только чтение исходников и desktop screenshot: shell/tests не запускал, responsive evidence оценивал по переданным проверкам и CSS.

Desktop screenshot tool не мог снимать скрытое окно: визуальный просмотр выполнен через headless Chrome screenshot 1280 px и screenshot iframe browsing context 320 px. Замер самого CSS layout проводился в загруженных браузерных документах на каждой ширине, а не по одному уменьшенному изображению.

## Сознательно оставленные ограничения

1. Favicon использует полный PNG со светлыми полями; при малом размере знак менее различим. Не вырезать символ и не менять пользовательский дизайн без согласования.
2. Standard Django debug/CSRF/error pages не переоформлялись; могут содержать английский framework text. Русским сделан предусмотренный HTML validation response. Глобальные handlers и production hardening — отдельная задача.
3. `DEBUG=True`, demo secret и `csrf_exempt` JSON API — прежние ограничения локального MVP. HTML forms остаются CSRF-protected. Production readiness не заявляется.
4. API и другие demo catalogs остаются машинными/англоязычными; для них не добавлены отдельные HTML-страницы, новые endpoints или нормативная аналитика.
5. Lighthouse не заменяет ручной полный accessibility audit; не выполнен отдельный cross-browser/device certification.

Нет DB/ORM/auth/sessions/migrations, сохранения проектов, экспорта, новых внешних сервисов, регуляторных данных или изменения canonical mappings. Commit/push не выполнялись.
