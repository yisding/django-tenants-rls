"""Test settings that turn ON shared-schema RLS mode.

The default ``settings`` run django-tenants in classic schema-per-tenant mode, so
the RLS end-to-end isolation suite (``django_tenants.tests.rls.test_isolation``)
self-skips there. This module enables RLS so CI actually exercises the RLS
backend, policies, bypass and WITH CHECK behaviour:

    python manage.py test django_tenants.tests.rls \
        --settings=dts_test_project.rls_settings

``TENANT_RLS_ALLOW_BYPASS_ROLE`` is True because CI connects as the Postgres
superuser; the isolation test itself creates a dedicated ``NOSUPERUSER
NOBYPASSRLS`` role and switches to it to observe real RLS enforcement (a
superuser would bypass every policy). Without the opt-out, the W003 system check
(an Error) would block ``manage.py test`` at the system-check stage.
"""

from .settings import *  # noqa: F401,F403

# Shared-schema RLS mode on the RLS-aware backend.
DATABASES["default"]["ENGINE"] = "django_tenants.rls.backend"  # noqa: F405
TENANT_RLS_ENABLED = True
TENANT_RLS_ALLOW_BYPASS_ROLE = True  # CI connects as superuser; see module docstring.

# Under RLS the connection serves only ``public``; keep RLS-isolated apps shared
# and drop the schema-per-tenant demo apps (they are not RLS-compatible on this
# connection). ``django_tenants.rls`` is added so its checks + commands load.
SHARED_APPS = (
    "django_tenants",
    "django_tenants.rls",
    "customers",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
)
TENANT_APPS = (
    "django.contrib.contenttypes",
    "django.contrib.auth",
)
INSTALLED_APPS = list(SHARED_APPS) + [a for a in TENANT_APPS if a not in SHARED_APPS]
