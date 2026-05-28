"""
Connection-level session variable helpers for shared-schema RLS mode.

These helpers set, clear and read the Postgres session (GUC) variables that the
RLS policies consult: the current-tenant variable and the bypass variable.

All variable *values* are passed as bound parameters to ``set_config(%s, %s, false)``
(SESSION scope, the ``false`` third argument) so the value persists across every
statement on a reused / pooled connection within a request, matching the parent
backend's persistent ``search_path`` semantics. Every cursor execute is wrapped
in the same error-in-transaction guard the parent backend uses for ``search_path``
so these helpers are safe to call even inside an already-errored transaction.

The pythonic public surface is the two context managers ``rls_context`` and
``bypass_rls``, which are re-exported from ``django_tenants.rls``.
"""

from contextlib import ContextDecorator

from django.db import connections

from django_tenants.postgresql_backend.base import DatabaseError, psycopg
from django_tenants.utils import get_public_schema_name, get_tenant_database_alias

from . import conf


SET_CONFIG_SQL = "SELECT set_config(%s, %s, false)"
GET_SETTING_SQL = "SELECT current_setting(%s, true)"


def _resolve_connection(using):
    """
    Return the connection for ``using``, defaulting to the tenant database alias.
    """
    if using is None:
        using = get_tenant_database_alias()
    return connections[using]


def current_tenant_schema(using=None):
    """
    Return the schema name of the REAL active tenant on the ``using`` alias
    (defaulting to the tenant database alias).

    Under shared-schema RLS, ``connection.schema_name`` is pinned to ``public``
    for every tenant, so anything keyed on it (cache keys, file storage paths)
    would collapse and leak across tenants. The actual tenant is still tracked on
    ``connection.tenant``, so we read its ``schema_name`` here; if no tenant is
    set (or it has no ``schema_name``, e.g. a FakeTenant) we fall back to the
    public schema name. ``cache.py`` and ``storage.py`` key on this helper.
    """
    connection = _resolve_connection(using)
    return getattr(getattr(connection, "tenant", None), "schema_name", None) or get_public_schema_name()


def _coerce_tenant_id(tenant_or_id):
    """
    Coerce a tenant instance, a bare pk, or None into the string value to store
    in the session variable.

    - None / pk-less instance (e.g. FakeTenant) -> '' (the 'no tenant' sentinel)
    - model instance with a .pk                 -> str(instance.pk)
    - bare value (int / uuid / str)             -> str(value)

    UUIDs str()-ify to their canonical hyphenated form, which casts cleanly to
    ``::uuid`` in the policy expression.
    """
    if tenant_or_id is None:
        return ""

    # A model instance (or FakeTenant) exposes a ``pk`` attribute. A bare pk
    # value (int / uuid / str) does not, so we use it directly.
    if hasattr(tenant_or_id, "pk"):
        pk = tenant_or_id.pk
        if pk is None:
            return ""
        return str(pk)

    return str(tenant_or_id)


def _execute_guarded(connection, sql, params):
    """
    Execute ``sql`` with ``params`` on ``connection`` swallowing the same errors
    the parent backend swallows when applying ``search_path``.

    If an error already happened in this transaction and we are about to roll
    back, setting the session variable would fail too; we ignore it so a
    best-effort restore never raises. If the next instruction is not a rollback
    it will fail anyway, so swallowing here is safe.
    """
    with connection.cursor() as cursor:
        try:
            cursor.execute(sql, params)
        except (DatabaseError, psycopg.InternalError):
            pass


def _fetch_guarded(connection, sql, params):
    """
    Execute a single-row read, returning the first column or None on guard hit.
    """
    with connection.cursor() as cursor:
        try:
            cursor.execute(sql, params)
            row = cursor.fetchone()
        except (DatabaseError, psycopg.InternalError):
            return None
    if row is None:
        return None
    return row[0]


def set_current_tenant(connection, tenant_id, using=None):
    """
    Set the current-tenant session variable on ``connection``.

    ``tenant_id`` may be a tenant instance, a raw pk, or None (None / pk-less
    instances store the empty-string sentinel, making rows invisible).

    Uses ``connection`` if given, else the connection resolved from ``using``
    (defaulting to the tenant database alias).
    """
    if connection is None:
        connection = _resolve_connection(using)
    value = _coerce_tenant_id(tenant_id)
    # Update the connection's Python source-of-truth FIRST so the RLS backend's
    # per-cursor re-assertion (see backend.base.DatabaseWrapper._cursor) carries
    # this value forward instead of overwriting it with a stale one. Harmless on
    # the stock backend, where the attribute is simply never read.
    connection._rls_tenant_id = value
    _execute_guarded(connection, SET_CONFIG_SQL, [conf.session_variable(), value])


def clear_current_tenant(connection=None, using=None):
    """
    Clear the current-tenant session variable (set it to '', the 'no tenant'
    sentinel). This does NOT touch the bypass variable.
    """
    if connection is None:
        connection = _resolve_connection(using)
    connection._rls_tenant_id = ""
    _execute_guarded(connection, SET_CONFIG_SQL, [conf.session_variable(), ""])


def get_current_tenant_id(connection=None, using=None):
    """
    Return the current-tenant session variable value, or None if it is unset or
    the empty-string sentinel.
    """
    if connection is None:
        connection = _resolve_connection(using)
    value = _fetch_guarded(connection, GET_SETTING_SQL, [conf.session_variable()])
    if value is None or value == "":
        return None
    return value


def set_bypass(connection=None, value=True, using=None):
    """
    Set the bypass session variable to the literal 'on' (when ``value`` is true)
    or 'off' (otherwise). 'on' is the only value the policy treats as a bypass.
    """
    if connection is None:
        connection = _resolve_connection(using)
    # Update the Python source-of-truth FIRST so the RLS backend re-asserts the
    # intended bypass state on every subsequent cursor. Without this, a query
    # inside a bypass_rls() block would open a cursor that forces bypass back off
    # and defeat the bypass entirely (see backend.base.DatabaseWrapper._cursor).
    connection._rls_bypass = bool(value)
    literal = "on" if value else "off"
    _execute_guarded(connection, SET_CONFIG_SQL, [conf.bypass_variable(), literal])


def get_bypass(connection=None, using=None):
    """
    Return True if the bypass session variable is currently set to 'on'.
    """
    if connection is None:
        connection = _resolve_connection(using)
    value = _fetch_guarded(connection, GET_SETTING_SQL, [conf.bypass_variable()])
    return value == "on"


class rls_context(ContextDecorator):
    """
    Temporarily set the active tenant session variable for cross-tenant or
    scripting work::

        with rls_context(tenant):
            ...    # queries see only `tenant`'s rows

    On enter the previously active tenant value is remembered and the new tenant
    is applied; on exit the remembered value is restored (an empty string
    restores the 'no tenant' sentinel). Nesting is therefore correct.
    """

    def __init__(self, tenant_or_id, using=None):
        self.tenant_or_id = tenant_or_id
        self.using = using
        self._previous = ""

    def __enter__(self):
        connection = _resolve_connection(self.using)
        # Remember the previous Python source-of-truth (defaulting to '' = no
        # tenant). set_current_tenant updates both the attribute and the GUC, so
        # restoring through it keeps the RLS and the stock backend consistent and
        # nesting correct.
        self._previous = getattr(connection, "_rls_tenant_id", "") or ""
        set_current_tenant(connection, self.tenant_or_id)
        return self

    def __exit__(self, *exc):
        connection = _resolve_connection(self.using)
        set_current_tenant(connection, self._previous)
        return False


class bypass_rls(ContextDecorator):
    """
    Temporarily disable tenant isolation for privileged work such as admin,
    data migrations or cross-tenant aggregation::

        with bypass_rls():
            Model.objects.all()   # sees ALL tenants' rows

    The policy explicitly ORs the bypass clause in, so this works even for the
    table-owner role under FORCE ROW LEVEL SECURITY.

    On enter the previous bypass value is remembered and bypass is turned on; on
    exit the previous value is restored (always, even on exception).
    """

    def __init__(self, using=None):
        self.using = using
        self._previous = False

    def __enter__(self):
        connection = _resolve_connection(self.using)
        # Read the previous Python source-of-truth directly (no DB round-trip);
        # set_bypass keeps the attribute and the GUC in lock-step.
        self._previous = bool(getattr(connection, "_rls_bypass", False))
        set_bypass(connection=connection, value=True)
        return self

    def __exit__(self, *exc):
        connection = _resolve_connection(self.using)
        set_bypass(connection=connection, value=self._previous)
        return False
