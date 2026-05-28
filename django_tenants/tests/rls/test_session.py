"""Unit tests for ``django_tenants.rls.session``.

A small recording fake connection emulates just enough of the Postgres cursor
contract (``set_config`` writes into a dict, ``current_setting`` reads from it)
so the session helpers and context managers can be exercised with no database.
The error-in-transaction guard is verified by a cursor that raises
``DatabaseError`` on execute.
"""

import unittest
import uuid

from django_tenants.postgresql_backend.base import DatabaseError
from django_tenants.rls import session


class FakeCursor:
    """A recording cursor backing ``set_config`` / ``current_setting``."""

    def __init__(self, store, calls, raise_on_execute=False):
        self._store = store
        self._calls = calls
        self._raise = raise_on_execute
        self._last_row = None

    def execute(self, sql, params=None):
        self._calls.append((sql, list(params) if params is not None else None))
        if self._raise:
            raise DatabaseError("simulated error in transaction")
        if sql == session.SET_CONFIG_SQL:
            name, value = params
            self._store[name] = value
            self._last_row = (value,)
        elif sql == session.GET_SETTING_SQL:
            (name,) = params
            # current_setting(name, true) returns '' when the GUC is unset.
            self._last_row = (self._store.get(name, ""),)
        else:
            self._last_row = None

    def fetchone(self):
        return self._last_row

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeConnection:
    """A connection whose ``cursor()`` returns a fresh recording cursor."""

    def __init__(self, raise_on_execute=False):
        self.store = {}
        self.calls = []
        self._raise = raise_on_execute

    def cursor(self):
        return FakeCursor(self.store, self.calls, self._raise)


class CoerceTenantIdTestCase(unittest.TestCase):
    def test_none_is_empty_string(self):
        self.assertEqual(session._coerce_tenant_id(None), "")

    def test_bare_int(self):
        self.assertEqual(session._coerce_tenant_id(42), "42")

    def test_bare_string(self):
        self.assertEqual(session._coerce_tenant_id("abc"), "abc")

    def test_uuid_canonical_form(self):
        value = uuid.UUID("12345678-1234-5678-1234-567812345678")
        self.assertEqual(session._coerce_tenant_id(value),
                         "12345678-1234-5678-1234-567812345678")

    def test_instance_with_pk(self):
        class Inst:
            pk = 7
        self.assertEqual(session._coerce_tenant_id(Inst()), "7")

    def test_pk_less_instance_is_empty(self):
        class Inst:
            pk = None
        self.assertEqual(session._coerce_tenant_id(Inst()), "")


class SetCurrentTenantTestCase(unittest.TestCase):
    def test_set_emits_exact_sql_and_params(self):
        conn = FakeConnection()
        session.set_current_tenant(conn, 42)
        self.assertEqual(
            conn.calls,
            [(session.SET_CONFIG_SQL, ["django_tenants.tenant_id", "42"])],
        )
        self.assertEqual(conn.store["django_tenants.tenant_id"], "42")

    def test_set_with_none_writes_empty_sentinel(self):
        conn = FakeConnection()
        session.set_current_tenant(conn, None)
        self.assertEqual(
            conn.calls,
            [(session.SET_CONFIG_SQL, ["django_tenants.tenant_id", ""])],
        )

    def test_clear_writes_empty_sentinel(self):
        conn = FakeConnection()
        session.clear_current_tenant(connection=conn)
        self.assertEqual(
            conn.calls,
            [(session.SET_CONFIG_SQL, ["django_tenants.tenant_id", ""])],
        )

    def test_get_returns_value(self):
        conn = FakeConnection()
        session.set_current_tenant(conn, 99)
        self.assertEqual(session.get_current_tenant_id(connection=conn), "99")

    def test_get_returns_none_when_empty(self):
        conn = FakeConnection()
        self.assertIsNone(session.get_current_tenant_id(connection=conn))

    def test_guard_swallows_database_error(self):
        conn = FakeConnection(raise_on_execute=True)
        # Must not raise even though the cursor raises DatabaseError.
        session.set_current_tenant(conn, 42)
        self.assertEqual(len(conn.calls), 1)


class BypassTestCase(unittest.TestCase):
    def test_set_bypass_on(self):
        conn = FakeConnection()
        session.set_bypass(connection=conn, value=True)
        self.assertEqual(
            conn.calls,
            [(session.SET_CONFIG_SQL, ["django_tenants.bypass_rls", "on"])],
        )

    def test_set_bypass_off(self):
        conn = FakeConnection()
        session.set_bypass(connection=conn, value=False)
        self.assertEqual(
            conn.calls,
            [(session.SET_CONFIG_SQL, ["django_tenants.bypass_rls", "off"])],
        )

    def test_get_bypass_true(self):
        conn = FakeConnection()
        session.set_bypass(connection=conn, value=True)
        self.assertTrue(session.get_bypass(connection=conn))

    def test_get_bypass_false_when_unset(self):
        conn = FakeConnection()
        self.assertFalse(session.get_bypass(connection=conn))


class _PatchResolveMixin(unittest.TestCase):
    """Patch ``session._resolve_connection`` to return our fake connection."""

    def setUp(self):
        self.conn = FakeConnection()
        self._orig = session._resolve_connection
        session._resolve_connection = lambda using: self.conn

    def tearDown(self):
        session._resolve_connection = self._orig


class RlsContextTestCase(_PatchResolveMixin):
    def test_sets_and_restores_empty_previous(self):
        with session.rls_context(5):
            self.assertEqual(self.conn.store["django_tenants.tenant_id"], "5")
        # No previous tenant -> restored to the empty sentinel.
        self.assertEqual(self.conn.store["django_tenants.tenant_id"], "")

    def test_restores_previous_value_nested(self):
        session.set_current_tenant(self.conn, 1)
        with session.rls_context(2):
            self.assertEqual(self.conn.store["django_tenants.tenant_id"], "2")
            with session.rls_context(3):
                self.assertEqual(self.conn.store["django_tenants.tenant_id"], "3")
            # Inner exit restores the value seen on inner enter.
            self.assertEqual(self.conn.store["django_tenants.tenant_id"], "2")
        # Outer exit restores the original.
        self.assertEqual(self.conn.store["django_tenants.tenant_id"], "1")

    def test_restores_on_exception(self):
        session.set_current_tenant(self.conn, 1)
        try:
            with session.rls_context(2):
                raise ValueError("boom")
        except ValueError:
            pass
        self.assertEqual(self.conn.store["django_tenants.tenant_id"], "1")


class BypassRlsContextTestCase(_PatchResolveMixin):
    def test_enables_and_restores_off(self):
        with session.bypass_rls():
            self.assertTrue(session.get_bypass(connection=self.conn))
        self.assertFalse(session.get_bypass(connection=self.conn))

    def test_restores_previous_on_value(self):
        session.set_bypass(connection=self.conn, value=True)
        with session.bypass_rls():
            self.assertTrue(session.get_bypass(connection=self.conn))
        # Previous value was 'on', so it stays on after exit (correct nesting).
        self.assertTrue(session.get_bypass(connection=self.conn))

    def test_restores_on_exception(self):
        try:
            with session.bypass_rls():
                self.assertTrue(session.get_bypass(connection=self.conn))
                raise ValueError("boom")
        except ValueError:
            pass
        self.assertFalse(session.get_bypass(connection=self.conn))


class ConnectionOptionalTestCase(_PatchResolveMixin):
    """``connection`` is optional on set_current_tenant; it resolves from ``using``.

    The public helper documents ``set_current_tenant(tenant_id=...)`` /
    ``set_current_tenant(using=..., tenant_id=...)``; these must not raise a
    TypeError for a missing positional ``connection``.
    """

    def test_connection_omitted_resolves_from_using(self):
        session.set_current_tenant(tenant_id=7)
        self.assertEqual(self.conn.store["django_tenants.tenant_id"], "7")

    def test_connection_none_keyword(self):
        session.set_current_tenant(connection=None, tenant_id=9)
        self.assertEqual(self.conn.store["django_tenants.tenant_id"], "9")
