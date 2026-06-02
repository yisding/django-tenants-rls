"""Settings accessors for the django-tenants shared-schema RLS mode.

Every RLS setting may be supplied either as an individual top-level Django
setting (e.g. ``TENANT_RLS_ENABLED = True``) or as a key inside an optional
``DJANGO_TENANTS_RLS`` dict. Resolution order is:

    individual top-level setting > DJANGO_TENANTS_RLS[name] > hardcoded default

Values are re-read on every access (no caching) so that ``override_settings``
works correctly in tests.
"""

import re

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


SETTINGS_DICT_NAME = "DJANGO_TENANTS_RLS"

DEFAULTS = {
    "TENANT_RLS_ENABLED": False,
    "TENANT_RLS_SESSION_VARIABLE": "django_tenants.tenant_id",
    "TENANT_RLS_BYPASS_VARIABLE": "django_tenants.bypass_rls",
    "TENANT_RLS_TENANT_FIELD": "tenant",
    "TENANT_RLS_FORCE": True,
    "TENANT_RLS_AUTO_ENABLE": True,
    "TENANT_RLS_ALLOW_BYPASS_ROLE": False,
    "TENANT_RLS_EXTERNAL_TABLES": (),
}

# Postgres GUC custom variable names must be of the form "<class>.<name>".
# Allow letters, digits, underscore in each part; exactly one dot.
# This is validated because the name is embedded into policy DDL (it cannot be
# a bound parameter there). It is the developer's setting, not user input, but
# we validate defensively to guarantee no injection via misconfiguration.
SESSION_VAR_NAME_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*$")

# Field/identifier names embedded in policy DDL expressions must be plain
# identifiers (they cannot be parameterized inside the expression).
FIELD_NAME_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

# Allowed Postgres cast suffixes for the tenant PK comparison.
ALLOWED_PK_CASTS = frozenset({"integer", "bigint", "uuid", "text"})


def _get(name):
    """Resolve a single RLS setting.

    Order: individual top-level setting > DJANGO_TENANTS_RLS[name] > DEFAULTS[name].
    """
    if hasattr(settings, name):
        return getattr(settings, name)
    rls_settings = getattr(settings, SETTINGS_DICT_NAME, None)
    if rls_settings is not None and name in rls_settings:
        return rls_settings[name]
    return DEFAULTS[name]


def rls_enabled():
    return bool(_get("TENANT_RLS_ENABLED"))


def session_variable():
    name = _get("TENANT_RLS_SESSION_VARIABLE")
    if not SESSION_VAR_NAME_PATTERN.match(name):
        raise ImproperlyConfigured(
            "TENANT_RLS_SESSION_VARIABLE %r is not a valid Postgres GUC "
            "variable name of the form '<class>.<name>'." % (name,)
        )
    return name


def bypass_variable():
    name = _get("TENANT_RLS_BYPASS_VARIABLE")
    if not SESSION_VAR_NAME_PATTERN.match(name):
        raise ImproperlyConfigured(
            "TENANT_RLS_BYPASS_VARIABLE %r is not a valid Postgres GUC "
            "variable name of the form '<class>.<name>'." % (name,)
        )
    return name


def tenant_field():
    name = _get("TENANT_RLS_TENANT_FIELD")
    if not FIELD_NAME_PATTERN.match(name):
        raise ImproperlyConfigured(
            "TENANT_RLS_TENANT_FIELD %r is not a valid field name." % (name,)
        )
    return name


def force_rls():
    return bool(_get("TENANT_RLS_FORCE"))


def auto_enable():
    return bool(_get("TENANT_RLS_AUTO_ENABLE"))


def allow_bypass_role():
    """Whether a DB role that bypasses RLS (superuser/BYPASSRLS) is permitted.

    Default ``False``. When ``False`` the startup check (W003) is an ERROR that
    blocks startup if the connected role bypasses RLS. Setting this to ``True``
    is an explicit, documented opt-out that DISABLES that safety net.
    """
    return bool(_get("TENANT_RLS_ALLOW_BYPASS_ROLE"))


def external_tables():
    """Raw tables that must be RLS-protected but cannot subclass ``TenantRLSModel``.

    Returns the configured ``TENANT_RLS_EXTERNAL_TABLES`` as a validated tuple of
    bare (optionally schema-qualified) identifiers, e.g.
    ``('authtoken_token', 'agent_test_through_x')`` or ``('myschema.foo',)``.

    This is the single source of truth that ``verify_rls``, the doctor, and the
    W008 deploy check consult for external/contrib/M2M tables (auth tokens,
    contrib auth/sessions, isolated M2M through-tables) that every model-only
    verifier would otherwise silently ignore.

    Each entry is validated with the same defensive posture as
    ``session_variable()`` / ``tenant_field()``: every part of a (possibly
    schema-qualified) name must be a plain identifier, since the table name is
    embedded into policy DDL and cannot be parameterized there. A non-identifier
    raises ``ImproperlyConfigured``.
    """
    raw = _get("TENANT_RLS_EXTERNAL_TABLES")
    tables = []
    for entry in raw:
        if not isinstance(entry, str) or not all(
            FIELD_NAME_PATTERN.match(part) for part in entry.split(".")
        ):
            raise ImproperlyConfigured(
                "TENANT_RLS_EXTERNAL_TABLES entry %r is not a valid "
                "(optionally schema-qualified) table identifier." % (entry,)
            )
        tables.append(entry)
    return tuple(tables)


def get_tenant_pk_cast():
    """Resolve the Postgres cast suffix for the tenant model PK type.

    Returns one of: 'integer', 'bigint', 'uuid', 'text'.

    Supported tenant PK types:

    * integer family -> 'integer' or 'bigint'
      (AutoField/SmallAutoField/IntegerField/SmallIntegerField/
      PositiveIntegerField/PositiveSmallIntegerField -> integer;
      BigAutoField/BigIntegerField/PositiveBigIntegerField -> bigint)
    * UUIDField -> 'uuid'
    * text-like (CharField/SlugField/TextField) -> 'text'

    Any other internal type raises ``ImproperlyConfigured`` naming the unmapped
    internal type and the tenant model. We do NOT silently fall back to text:
    casting an integer column to text would miscast the comparison and break
    every RLS-policed query.

    Lazily imports ``django_tenants.utils.get_tenant_model`` so that this module
    never touches the app registry at import time.
    """
    from django_tenants.utils import get_tenant_model

    tenant_model = get_tenant_model()
    pk = tenant_model._meta.pk
    internal = pk.get_internal_type()
    mapping = {
        "AutoField": "integer",
        "SmallAutoField": "integer",
        "BigAutoField": "bigint",
        "IntegerField": "integer",
        "SmallIntegerField": "integer",
        "PositiveIntegerField": "integer",
        "PositiveSmallIntegerField": "integer",
        "BigIntegerField": "bigint",
        "PositiveBigIntegerField": "bigint",
        "UUIDField": "uuid",
        "CharField": "text",
        "SlugField": "text",
        "TextField": "text",
    }
    cast = mapping.get(internal)
    if cast is None:
        raise ImproperlyConfigured(
            "Cannot determine the RLS tenant PK cast for tenant model "
            "%s.%s: its primary key uses the unsupported internal type %r. "
            "Supported tenant PK types are the integer family, UUIDField, and "
            "text-like fields (CharField/SlugField/TextField)."
            % (
                tenant_model._meta.app_label,
                tenant_model._meta.object_name,
                internal,
            )
        )
    return cast


def _quote_literal(value):
    """Embed a validated GUC name as a SQL string literal in DDL.

    Defense in depth even though ``SESSION_VAR_NAME_PATTERN`` already forbids
    single quotes.
    """
    return "'" + value.replace("'", "''") + "'"
