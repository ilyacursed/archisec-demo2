# АрхиСек — Header/UI Polish + Dark Theme

## Граница изменений

Изменено только оформление существующего MVP. Backend, analyzer, services, JSON, mappings, API, URL routing, auth/DB/ORM и model routing не изменялись. Существующие 275 тестов не редактировались.

## Файлы

- `templates/base.html` — компактный full-width header, исходный логотип слева, badge «Демонстрация», навигация справа, инертная «Войти», правый переключатель темы; подключение локального JS до CSS.
- `templates/home.html` — удалены повторный hero-логотип и неиспользуемая загрузка static; hero, тексты и CTA сохранены.
- `static/style.css` — header flex/wrap, 72px пропорциональный логотип, 6px вертикальные отступы, 44px controls, single-column hero, производные токены тёмной темы, контрастные ссылки/кнопки, moon/sun и focus.
- `static/js/theme.js` — небольшой внешний vanilla JS: раннее восстановление темы, привязка кнопки после DOM, обновление темы/иконок/доступного имени/состояния и безопасное сохранение выбора.
- `tests/test_header_theme.py` — 55 новых QA-проверок DOM, порядка элементов, JS/CSS contracts, static assets и контраста.
- `docs/branding.md` — актуализированы границы header/theme, storage и no-JS fallback.
- `docs/header_theme_report.md` — этот отчёт.

## UI и тема

Header занимает **89px** на 768/1280px (72px логотип, 12px padding, 5px брендовые границы), вместо прежних 145px. Логотип расположен на расстоянии 16–28px от левой границы контента viewport; текстовый `brand-name` удалён. На 320px header занимает 189px из-за переноса элементов; это сохраняет читабельность и доступные цели без overflow. Порядок controls: Главная → Профиль системы → Войти → theme.

«Войти» — нативная инертная кнопка `type="button"`, `aria-disabled="true"` с объяснением demo-ограничения. Click не меняет URL/scroll и не отправляет форму.

Светлая тема — default независимо от системной темы; отображается луна и действие «Включить тёмную тему». Тёмная тема показывает солнце и действие «Включить светлую тему». Переключатель доступен с клавиатуры, имеет Russian label/title, `aria-pressed` и видимый focus. Пока JS не привязан, кнопка скрыта.

Только `archisec-theme` (`light`/`dark`) сохраняется в браузерном `localStorage`. Профиль и результаты не сохраняются; серверные preferences отсутствуют. Неверное/отсутствующее значение и недоступный storage дают светлый default. При ошибке записи переключение работает в текущем документе. CSS `color-scheme` согласован с выбранной темой; производные токены меняют фон/поверхности/header/input/notice/текст/границы/ссылки/кнопки, без инверсии страницы. `#6AAF9C` и `#4182AE` сохранены как брендовые accents.

## Проверки — 2026-10-01

Среда: Python 3.14.0, Django 5.2.17, внешний `qa_venv`, `PYTHONDONTWRITEBYTECODE=1`.

| Проверка | Результат |
|---|---|
| Django check | PASS, 0 issues |
| Полный suite | PASS, 330/330: 275 исходных + 55 новых |
| Новые UI-тесты отдельно | PASS, 55/55 |
| Независимая QA: HTTP/static/CSRF/API/сценарии A/B/C/ошибки | PASS, 70/70 |
| Chrome DevTools: Home/Profile/Result × light/dark × 320/768/1280 | PASS, 18/18, нет overflow/offscreen элементов; изображения загружены |
| Result: Threats/Measures/Tools | По 4 карточки сценария A; секции доступны в обеих темах |
| Light → dark / dark → light, moon/sun, storage после reload | PASS |
| Неверное значение storage / blocked read/write | PASS; fallback и переключение без исключений |
| Native keyboard Enter и Space | PASS; видимый 3px focus, тема меняется в обе стороны |
| CSS/JS/logo static | HTTP 200, корректные MIME types |
| Console/runtime errors при финальном CDP smoke | 0 |
| Логотип, JSON, backend/API/config, существующие тесты | Хеши совпадают с предшествующим baseline |
| Независимый read-only Reviewer | PASS, без блокирующих замечаний; первоначальная попытка запуска через системный Python была недоступна |

Браузерный smoke использует реальные viewport overrides Chrome (не уменьшение screenshot большого layout). В 320px desktop viewport scrollbar оставляет 305px client width; в 768/1280px — 753/1265px. Scroll width равен client width во всех 18 вариантах.

Временные browser/HTTP scripts, JSON-результаты и screenshots хранятся вне репозитория в `%TEMP%\opencode`. Независимая QA не заявляет выполнение браузерной части — её выполнил orchestrator. Reviewer не менял production files.

## Ограничения

- «Войти» намеренно не реализует authentication.
- Без JS тема не переключается; основные страницы/формы остаются server-rendered и работают.
- Сохранение выбора между документами/reload требует доступного localStorage; синхронизация одновременно открытых tabs не добавлена.
- Исходный PNG с белыми полями сохранён целиком, поэтому на тёмном header видна светлая квадратная подложка; это не новый asset и не CSS-инверсия.
- Узкий header выше desktop из-за разрешённого переноса navigation/actions.
- Debug/CSRF/error страницы Django и production hardening не входят в задачу.

Commit/push не выполнялись. Ни auth, ни БД, ни новые внешние зависимости/сервисы не добавлялись.
