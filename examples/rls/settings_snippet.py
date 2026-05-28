"""Settings snippet for django-tenants shared-schema RLS mode.

Copy the relevant pieces into your project's ``settings.py``. This is a minimal,
self-contained example showing the differences from a standard django-tenants
(schema-per-tenant) configuration:

1. ``django_tenants.rls`` is added to ``SHARED_APPS`` and the RLS-isolated data
   app lives in ``SHARED_APPS`` too -- NOT ``TENANT_APPS``. In RLS mode there is
   exactly one schema (``public``), so RLS apps must be shared apps; otherwise
   ``TenantSyncRouter.allow_migrate`` keeps their tables out of ``public`` and
   the app breaks.
2. The database ``ENGINE`` is switched to ``django_tenants.rls.backend`` (which
   subclasses the standard backend; ``ORIGINAL_BACKEND`` still applies).
3. RLS is turned on via the ``DJANGO_TENANTS_RLS`` dict (or an individual
   ``TENANT_RLS_ENABLED = True`` top-level setting).

See ``docs/rls.rst`` for the full drop-in guide.
"""

# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------
# RLS-isolated apps go in SHARED_APPS (everything lives in the public schema).
SHARED_APPS = (
    'django_tenants',          # mandatory
    'django_tenants.rls',      # enables RLS system checks + post_migrate auto-enable
    'customers',               # the app that holds your TENANT_MODEL / DOMAIN model

    'myapp',                   # your RLS-isolated data app (e.g. the Note model)

    # everything below here is optional
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.admin',
)

# In a pure-RLS deployment TENANT_APPS can be empty. A hybrid deployment may keep
# some apps schema-per-tenant here -- but every RLS app must be in SHARED_APPS.
TENANT_APPS = (
)

INSTALLED_APPS = list(SHARED_APPS) + [app for app in TENANT_APPS if app not in SHARED_APPS]

# Your tenant & domain models are unchanged from standard django-tenants, with
# one RLS-specific tweak: set ``auto_create_schema = False`` (and optionally
# ``auto_drop_schema = False``) on your TenantMixin subclass so no empty
# per-tenant schemas are created -- in RLS mode everything lives in ``public``.
# See docs/rls.rst Step 1.
TENANT_MODEL = "customers.Client"          # app.Model (inherits TenantMixin)
TENANT_DOMAIN_MODEL = "customers.Domain"   # app.Model (inherits DomainMixin)

# ---------------------------------------------------------------------------
# Database -- use the RLS backend
# ---------------------------------------------------------------------------
DATABASES = {
    'default': {
        'ENGINE': 'django_tenants.rls.backend',
        # ORIGINAL_BACKEND defaults to 'django.db.backends.postgresql';
        # override only if you use a custom psycopg backend:
        # 'ORIGINAL_BACKEND': 'django.db.backends.postgresql',
        'NAME': 'myproject',
        # The app DB role MUST be NOSUPERUSER NOBYPASSRLS -- a superuser or a
        # role with BYPASSRLS silently bypasses every RLS policy, so isolation
        # is NOT enforced even though the policies exist. Do NOT use 'postgres'
        # (or any superuser) here. Create a least-privilege role first; see the
        # CREATE ROLE recipe in docs/rls.rst ("Database role"). By default a
        # system check (W003, now an ERROR) blocks startup if the connected role
        # bypasses RLS; you can opt out with TENANT_RLS_ALLOW_BYPASS_ROLE=True
        # (see below), but that disables the safety net.
        'USER': 'app_rls',
        'PASSWORD': 'change-me',   # non-empty; supply via env/secret in production
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

# TenantSyncRouter decides what is migrated where; with the RLS backend the
# search_path stays 'public', so SHARED_APPS are created in public.
DATABASE_ROUTERS = (
    'django_tenants.routers.TenantSyncRouter',
)

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
# TenantMainMiddleware resolves request.tenant exactly as in schema-per-tenant
# mode. With the RLS backend the tenant session variable is set on every cursor,
# so TenantRLSMiddleware is OPTIONAL (a fallback for setups that keep the stock
# backend). It is harmless to leave installed; place it AFTER TenantMainMiddleware.
MIDDLEWARE = (
    'django_tenants.middleware.main.TenantMainMiddleware',
    # 'django_tenants.rls.middleware.TenantRLSMiddleware',  # optional fallback
    # ... your other middleware ...
)

# ---------------------------------------------------------------------------
# RLS settings
# ---------------------------------------------------------------------------
# Each value may also be supplied as an individual top-level setting (e.g.
# TENANT_RLS_ENABLED = True), which takes precedence over this dict.
DJANGO_TENANTS_RLS = {
    "TENANT_RLS_ENABLED": True,
    # Defaults shown for reference (all optional):
    # "TENANT_RLS_SESSION_VARIABLE": "django_tenants.tenant_id",
    # "TENANT_RLS_BYPASS_VARIABLE": "django_tenants.bypass_rls",
    # "TENANT_RLS_TENANT_FIELD": "tenant",
    # "TENANT_RLS_FORCE": True,
    # "TENANT_RLS_AUTO_ENABLE": True,
    # Escape hatch (default False): when True, the W003 check no longer blocks
    # startup if the connected DB role bypasses RLS. Leave it False -- enabling
    # it disables the safety net that guarantees the app role actually enforces
    # isolation. Use a NOSUPERUSER NOBYPASSRLS role instead (see USER above).
    # "TENANT_RLS_ALLOW_BYPASS_ROLE": False,
}
