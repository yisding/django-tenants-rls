"""
Tenant-aware cache key functions for shared-schema RLS mode.

These mirror :mod:`django_tenants.cache` (same ``schema:prefix:version:key``
shape, so they are a drop-in replacement for django-redis' ``KEY_FUNCTION`` /
``REVERSE_KEY_FUNCTION``) but source the tenant segment from the *real* active
tenant via :func:`django_tenants.rls.session.current_tenant_schema` instead of
``connection.schema_name``.

Why this matters under RLS
--------------------------
The bundled :func:`django_tenants.cache.make_key` keys on
``connection.schema_name``. In shared-schema RLS mode every tenant shares the
public schema, so the backend pins ``connection.schema_name`` to ``"public"``
for *all* tenants and isolation is enforced by the per-connection session
variable, not the search_path. Keying the cache on ``connection.schema_name``
would therefore collapse every tenant onto a single ``"public:..."`` namespace,
leaking cached values across tenants.

``current_tenant_schema()`` returns the schema name of the connection's *real*
active tenant (``connection.tenant.schema_name``), which remains correct under
RLS, falling back to the public schema name when no tenant is active. Keying on
it restores per-tenant cache isolation.

Usage with django-redis::

    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": "redis://127.0.0.1:6379/1",
            "KEY_FUNCTION": "django_tenants.rls.cache.make_key",
            "REVERSE_KEY_FUNCTION": "django_tenants.rls.cache.reverse_key",
        },
    }
"""

from .session import current_tenant_schema


def make_key(key, key_prefix, version):
    """
    Tenant aware function to generate a cache key.

    Constructs the key used by all other methods. Prepends the *real* active
    tenant ``schema_name`` (valid under RLS, where ``connection.schema_name`` is
    pinned to public) and ``key_prefix``.
    """
    return '%s:%s:%s:%s' % (current_tenant_schema(), key_prefix, version, key)


def reverse_key(key):
    """
    Tenant aware function to reverse a cache key.

    Required for django-redis REVERSE_KEY_FUNCTION setting. Strips the leading
    tenant-schema segment to recover the original key.
    """
    return key.split(':', 3)[3]
