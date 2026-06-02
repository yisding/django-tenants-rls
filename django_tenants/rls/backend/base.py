"""Row-Level-Security (RLS) database backend.

This wraps :class:`django_tenants.postgresql_backend.base.DatabaseWrapper` so the
``search_path`` still resolves to ``public`` (single-schema RLS mode), while the
active tenant is communicated to Postgres through a session variable applied on
every cursor. The variable feeds the RLS policies created by
:mod:`django_tenants.rls.schema`.

On every cursor the backend re-asserts the *bypass* variable to match the
connection's :attr:`_rls_bypass` Python flag (``off`` unless an explicit
:func:`django_tenants.rls.session.bypass_rls` block is active). The Python flag
-- not the GUC -- is the source of truth, mirroring how the parent backend drives
``search_path`` from :attr:`schema_name`. This is what makes ``bypass_rls()``
work *and* leak-proof: a query inside a bypass block opens its own cursor, so if
the cursor blindly forced the GUC ``off`` the bypass would be defeated; deriving
it from the flag keeps it ``on`` for the block yet guarantees it returns to
``off`` for the next request on a pooled / persistent connection (the flag is
restored at the Python level on block exit -- never subject to a failed
transaction -- and ``set_tenant`` resets it to ``off`` at every request start).

Layering: this module adds **no new** app-registry coupling beyond the parent
django-tenants backend. Like every Django database backend it is imported when
Django resolves the ENGINE, which happens after ``django.setup()`` -- the parent
backend already imports ``ContentType`` at module load. As a matter of hygiene
this module still keeps its own imports to the registry-free helpers (``conf``,
``session``, ``schema``) and avoids importing ``django_tenants.rls.models`` so it
introduces no additional model/registry dependencies of its own.

When ``TENANT_RLS_ENABLED`` is ``False`` this wrapper is behaviourally identical
to the parent: :meth:`_cursor` returns the parent cursor unchanged and no session
variable is emitted.
"""

from django_tenants.postgresql_backend.base import (
    DatabaseWrapper as TenantDatabaseWrapper,
    FakeTenant,
    DatabaseError,
    psycopg,
    is_psycopg3,
)
from django_tenants.utils import get_public_schema_name

from django_tenants.rls import conf
from django_tenants.rls import session
from django_tenants.rls.schema import RLSSchemaEditorMixin


def _is_fake(tenant):
    """Return True for the public/no-tenant case.

    The public schema is represented by :class:`FakeTenant`, and any object
    without a usable primary key is also treated as "no tenant" so the policy
    falls through to the secure-by-default (rows invisible) branch.
    """
    return isinstance(tenant, FakeTenant) or getattr(tenant, "pk", None) is None


class RLSDatabaseSchemaEditor(RLSSchemaEditorMixin, TenantDatabaseWrapper.SchemaEditorClass):
    """Parent backend's schema editor extended with RLS DDL helpers."""

    pass


class DatabaseWrapper(TenantDatabaseWrapper):
    """Tenant database wrapper that applies RLS session state per cursor.

    Identical to the parent wrapper except that, when RLS is enabled, the
    active tenant primary key is pushed into the configured session variable on
    every cursor so pooled/reused connections always carry the correct tenant.
    """

    SchemaEditorClass = RLSDatabaseSchemaEditor

    # Single round-trip that re-asserts the tenant variable AND forces the
    # bypass variable back to 'off' on every cursor. Both values travel as bound
    # parameters (never interpolated) per constraint #2. SESSION scope (false).
    SET_RLS_SESSION_SQL = (
        "SELECT set_config(%s, %s, false), set_config(%s, %s, false)"
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Remembered tenant pk as a string; '' is the "no tenant" sentinel that
        # the policy interprets (via NULLIF) as NULL -> rows invisible.
        self._rls_tenant_id = ""
        # Python source-of-truth for the bypass GUC, re-asserted on every cursor.
        # Only an active bypass_rls() block flips this True; it defaults False so
        # the secure (isolated) path is the default and a reused connection never
        # inherits a stale bypass. See the module docstring.
        self._rls_bypass = False

    def set_tenant(self, tenant, include_public=True):
        super().set_tenant(tenant, include_public)
        # Remember the pk to (re)apply on every cursor. FakeTenant / pk-less
        # tenants (the public schema) collapse to '' (no tenant).
        if _is_fake(tenant):
            self._rls_tenant_id = session._coerce_tenant_id(None)
        else:
            self._rls_tenant_id = session._coerce_tenant_id(getattr(tenant, "pk", None))

        if not conf.rls_enabled():
            # When RLS is off, behave exactly like the parent (schema-per-tenant).
            return

        # A tenant (re)activation always starts from a secure-by-default,
        # bypass-off state. Each request's middleware calls set_tenant(), so this
        # guarantees no bypass value can survive from a prior request on a pooled
        # connection even if a bypass_rls() block somehow failed to restore it
        # (e.g. the worker was killed mid-block). Explicit cross-tenant work must
        # therefore open its bypass_rls() block at the innermost scope, after any
        # tenant activation.
        self._rls_bypass = False

        # In RLS mode there is exactly one schema: ``public``. Every tenant's data
        # lives there and isolation is enforced by the policies, not the
        # ``search_path``. Pin the schema back to ``public`` so the documented
        # invariant holds -- ``connection.schema_name == get_public_schema_name()``
        # for all tenant operations -- and so ``TenantSyncRouter.allow_migrate``
        # (which keys off ``connection.schema_name``) routes RLS apps to the
        # shared/public migrate. We still remembered ``_rls_tenant_id`` above, so
        # the active tenant is communicated to Postgres via the session variable.
        public = get_public_schema_name()
        self.schema_name = public
        self.set_settings_schema(public)
        self.search_path_set_schemas = None

    def _rls_session_params(self):
        """Return ``(sql, params)`` to re-assert the RLS GUCs, or ``None``.

        Returns ``None`` when RLS is disabled (the caller must then make no
        ``set_config`` call -- zero behaviour change). Otherwise returns the
        single combined ``set_config`` statement plus its bound parameters,
        deriving BOTH values from the connection's Python source-of-truth
        (``_rls_tenant_id`` / ``_rls_bypass``) rather than from whatever the GUC
        currently holds.

        This is the security-critical core, isolated here so it can be unit
        tested without a live database or the ``super()._cursor()`` chain.

        Deriving the bypass value from the flag (not hard-coding ``off``) is
        mandatory for correctness: a query issued inside a ``bypass_rls()`` block
        (or an ``rls_context()`` block) opens its own cursor, so if this
        re-assertion ignored the flags it would clobber the caller's intent --
        forcing bypass back ``off`` or restoring a stale tenant -- and silently
        defeat the context manager. Driving the GUCs from the flags keeps the
        active block in effect while still snapping a reused / pooled connection
        back to the secure default (bypass off) as soon as the block exits and the
        flag is restored.
        """
        if not conf.rls_enabled():
            return None
        bypass_value = "on" if getattr(self, "_rls_bypass", False) else "off"
        return (
            self.SET_RLS_SESSION_SQL,
            [conf.session_variable(), self._rls_tenant_id,
             conf.bypass_variable(), bypass_value],
        )

    def _cursor(self, name=None):
        if name:
            cursor = super()._cursor(name=name)
        else:
            cursor = super()._cursor()

        params = self._rls_session_params()
        if params is None:
            # Zero behaviour change when RLS is disabled.
            return cursor

        # Mirror the parent's search_path handling: a named cursor can only be
        # used once, and psycopg3/Django 4 hit a recursion issue when reusing
        # the cursor, so use a fresh connection cursor in those cases.
        if name or is_psycopg3:
            cursor_for_config = self.connection.cursor()
        else:
            cursor_for_config = cursor

        # In the event that an error already happened in this transaction and we
        # are going to rollback, we just ignore the database error when setting
        # the session variables -- mirroring the parent's search_path guard.
        try:
            cursor_for_config.execute(*params)
        except (DatabaseError, psycopg.InternalError):
            pass
        finally:
            if name or is_psycopg3:
                cursor_for_config.close()

        return cursor
