from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = "archisec-mvp-demo-secret"
DEBUG = True
ALLOWED_HOSTS = ["127.0.0.1", "localhost", ".app.github.dev"]

INSTALLED_APPS = [
    "django.contrib.staticfiles",
    "core",
    "threats",
    "measures",
    "tactics",
    "tools",
    "ai_threats",
    "levels",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
]

ROOT_URLCONF = "config.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [BASE_DIR / "templates"],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": []},
}]
WSGI_APPLICATION = "config.wsgi.application"
DATABASES = {}
LANGUAGE_CODE = "ru-ru"
TIME_ZONE = "Europe/Stockholm"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
CSRF_TRUSTED_ORIGINS = [
    "https://*.app.github.dev",
    "https://localhost:8000",
    "http://localhost:8000",
]
