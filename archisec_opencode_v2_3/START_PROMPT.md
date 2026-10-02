# START PROMPT

Работай над проектом «АрхиСек» как над одним долгоживущим репозиторием.

Сначала прочитай:

1. docs/product.md
2. docs/mvp.md
3. docs/project_contract.md
4. docs/bootstrap.md
5. docs/architecture.md
6. docs/data_schemas.md
7. docs/quality_gates.md
8. docs/workflow.md
9. docs/model_routing.md

Затем:

1. проверь состояние репозитория;
2. если `manage.py` отсутствует, выполни bootstrap;
3. не останавливайся после создания skeleton;
4. реализуй MVP;
5. проверь API/UI;
6. передай работу QA;
7. передай работу reviewer;
8. исправь подтверждённые дефекты;
9. выдай итоговый отчёт.

Критические ограничения MVP:

- без БД;
- без ORM;
- без migrations;
- без auth;
- без sessions;
- без PostgreSQL;
- без Redis/Celery;
- demo data не выдавать за официальные данные;
- не использовать выдуманные model IDs OpenCode;
- не создавать отдельный проект внутри репозитория.
