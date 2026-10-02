# Bootstrap

MVP runs without a database backend.

Requirements:

- Python 3.10+
- Django 5.2.x

Install:

```bash
python -m venv .venv
# activate environment
pip install -r requirements.txt
```

If `manage.py` is absent:

```bash
django-admin startproject config .
python manage.py startapp core
python manage.py startapp threats
python manage.py startapp measures
python manage.py startapp tactics
python manage.py startapp tools
python manage.py startapp ai_threats
python manage.py startapp levels
```

Minimal apps:

```python
INSTALLED_APPS = [
    "django.contrib.staticfiles",
    "core", "threats", "measures", "tactics", "tools", "ai_threats", "levels",
]
```

Middleware:

```python
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
]
```

No admin/auth/contenttypes/sessions/messages. No DB backend. `DATABASES = {}` is acceptable when no DB-dependent components are used.

Static files:

```python
STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
```

No `STATIC_ROOT` and no `collectstatic` requirement in MVP.

Do not run `migrate`.

## Bootstrap DoD

```text
[ ] venv created
[ ] pip install succeeds
[ ] manage.py exists
[ ] python manage.py check passes
[ ] runserver starts without traceback
[ ] GET / → 200 and contains "АрхиСек"
[ ] core/, threats/, measures/, tactics/, tools/, ai_threats/, levels/ exist
[ ] services/, data/, templates/, static/ exist
[ ] no DB backend
[ ] no migrations/
[ ] no Model.objects
[ ] no @login_required
```
