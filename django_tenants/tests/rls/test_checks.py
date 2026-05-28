"""Unit tests for ``django_tenants.rls.checks`` system checks.

These run without a database. They assert the documented stable check IDs
(W001 / W002 / W003 / E001 / E002) and trigger conditions, so doc/code drift (a
renamed ID or a changed condition) is caught. The checks are gated on
``conf.rls_enabled()``, so every check must return ``[]`` when RLS is disabled.

The role/PK-cast checks (W003, E002) normally open a database connection; here
we swap in a fake connection (whose cursor returns a canned ``pg_roles`` row) so
no real database is required and the Error-vs-silent behavior is asserted
directly.
"""

import contextlib
import unittest
from unittest import mock

from django.core.checks import Error, Warning
from django.test.utils import override_settings

from django_tenants.rls import checks


def _ids(messages):
    return [m.id for m in messages]


class _FakeCursor:
    """Minimal cursor context manager returning a canned single row."""

    def __init__(self, row):
        self._row = row

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        return None

    def fetchone(self):
        return self._row


class _FakeConnection:
    """Fake DB connection for check_rls_role: a vendor + a canned-row cursor.

    ``vendor='postgresql'`` lets the check proceed; the cursor returns
    ``row`` (typically ``(rolname, rolsuper, rolbypassrls)``). Pass ``vendor``
    other than ``'postgresql'`` to exercise the non-postgres early return, or
    set ``raise_on_cursor`` to simulate an unreachable database.
    """

    def __init__(self, row=None, vendor="postgresql", raise_on_cursor=False):
        self._row = row
        self.vendor = vendor
        self._raise_on_cursor = raise_on_cursor

    def cursor(self):
        if self._raise_on_cursor:
            raise Exception("database is unreachable")
        return _FakeCursor(self._row)


@contextlib.contextmanager
def _patched_connection(connection):
    """Make ``connections[<tenant alias>]`` resolve to ``connection``.

    ``check_rls_role`` does ``from django.db import connections`` then indexes
    it by the tenant database alias (``'default'`` in these tests), so patching
    the module attribute with a dict is enough.
    """
    with mock.patch("django.db.connections", {"default": connection}):
        yield


class CheckRlsBackendTestCase(unittest.TestCase):
    @override_settings(TENANT_RLS_ENABLED=False)
    def test_silent_when_disabled(self):
        self.assertEqual(checks.check_rls_backend(None), [])

    @override_settings(
        TENANT_RLS_ENABLED=True,
        DATABASES={"default": {"ENGINE": "django.db.backends.postgresql"}},
        MIDDLEWARE=[],
    )
    def test_warns_w001_for_stock_engine_without_middleware(self):
        messages = checks.check_rls_backend(None)
        self.assertIn(checks.W001_ID, _ids(messages))

    @override_settings(
        TENANT_RLS_ENABLED=True,
        DATABASES={"default": {"ENGINE": "django_tenants.rls.backend"}},
        MIDDLEWARE=[],
    )
    def test_silent_for_rls_engine(self):
        self.assertEqual(checks.check_rls_backend(None), [])

    @override_settings(
        TENANT_RLS_ENABLED=True,
        DATABASES={"default": {"ENGINE": "django.db.backends.postgresql"}},
        MIDDLEWARE=["django_tenants.rls.middleware.TenantRLSMiddleware"],
    )
    def test_silent_when_fallback_middleware_installed(self):
        self.assertEqual(checks.check_rls_backend(None), [])


class EngineIsRlsBackendTestCase(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(checks._engine_is_rls_backend("django_tenants.rls.backend"))

    def test_dotted_prefix_match(self):
        self.assertTrue(
            checks._engine_is_rls_backend("django_tenants.rls.backend.something")
        )

    def test_stock_backend_is_not_rls(self):
        self.assertFalse(
            checks._engine_is_rls_backend("django.db.backends.postgresql")
        )

    def test_empty_is_not_rls(self):
        self.assertFalse(checks._engine_is_rls_backend(""))


class CheckRlsVarNamesTestCase(unittest.TestCase):
    @override_settings(TENANT_RLS_ENABLED=False)
    def test_silent_when_disabled(self):
        self.assertEqual(checks.check_rls_var_names(None), [])

    @override_settings(
        TENANT_RLS_ENABLED=True,
        TENANT_RLS_SESSION_VARIABLE="not a valid guc name",
    )
    def test_error_e001_for_malformed_guc(self):
        messages = checks.check_rls_var_names(None)
        self.assertIn(checks.E001_ID, _ids(messages))

    @override_settings(
        TENANT_RLS_ENABLED=True,
        TENANT_RLS_SESSION_VARIABLE="django_tenants.tenant_id",
        TENANT_RLS_BYPASS_VARIABLE="django_tenants.bypass_rls",
    )
    def test_silent_for_valid_guc_names(self):
        self.assertEqual(checks.check_rls_var_names(None), [])


class CheckTenantFieldTestCase(unittest.TestCase):
    @override_settings(TENANT_RLS_ENABLED=False)
    def test_silent_when_disabled(self):
        self.assertEqual(checks.check_tenant_field(None), [])


class CheckRlsRoleTestCase(unittest.TestCase):
    """W003: a superuser / BYPASSRLS role is now an ERROR (not a Warning).

    The deliberate opt-out ``TENANT_RLS_ALLOW_BYPASS_ROLE=True`` suppresses the
    finding entirely. Non-postgres and unreachable databases stay silent (if we
    cannot check, we cannot block).
    """

    @override_settings(TENANT_RLS_ENABLED=False)
    def test_silent_when_disabled(self):
        self.assertEqual(checks.check_rls_role(None), [])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_superuser_is_error_not_warning(self):
        conn = _FakeConnection(row=("app_rls", True, False))
        with _patched_connection(conn):
            messages = checks.check_rls_role(None)
        self.assertEqual(_ids(messages), [checks.W003_ID])
        msg = messages[0]
        # Promoted from Warning to Error: same id, but Error level (40).
        self.assertIsInstance(msg, Error)
        self.assertNotIsInstance(msg, Warning)
        self.assertEqual(msg.level, 40)
        # The hint must point at the documented opt-out setting.
        self.assertIn("TENANT_RLS_ALLOW_BYPASS_ROLE", msg.hint)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_bypassrls_attribute_is_error(self):
        # rolsuper False but rolbypassrls True -> still bypasses RLS.
        conn = _FakeConnection(row=("app_rls", False, True))
        with _patched_connection(conn):
            messages = checks.check_rls_role(None)
        self.assertEqual(_ids(messages), [checks.W003_ID])
        self.assertEqual(messages[0].level, 40)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_safe_role_is_silent(self):
        # NOSUPERUSER NOBYPASSRLS -> no finding.
        conn = _FakeConnection(row=("app_rls", False, False))
        with _patched_connection(conn):
            self.assertEqual(checks.check_rls_role(None), [])

    @override_settings(TENANT_RLS_ENABLED=True, TENANT_RLS_ALLOW_BYPASS_ROLE=True)
    def test_opt_out_suppresses_even_for_superuser(self):
        # With the explicit opt-out the check must short-circuit and never even
        # consult the connection.
        conn = _FakeConnection(row=("postgres", True, True))
        with _patched_connection(conn):
            self.assertEqual(checks.check_rls_role(None), [])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_non_postgres_is_silent(self):
        conn = _FakeConnection(row=("app_rls", True, True), vendor="sqlite")
        with _patched_connection(conn):
            self.assertEqual(checks.check_rls_role(None), [])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_unreachable_database_is_silent(self):
        conn = _FakeConnection(raise_on_cursor=True)
        with _patched_connection(conn):
            self.assertEqual(checks.check_rls_role(None), [])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_no_row_is_silent(self):
        conn = _FakeConnection(row=None)
        with _patched_connection(conn):
            self.assertEqual(checks.check_rls_role(None), [])


class CheckTenantPkCastTestCase(unittest.TestCase):
    """E002: surface an unsupported tenant PK type from get_tenant_pk_cast()."""

    @override_settings(TENANT_RLS_ENABLED=False)
    def test_silent_when_disabled(self):
        self.assertEqual(checks.check_tenant_pk_cast(None), [])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_silent_when_cast_resolves(self):
        with mock.patch.object(checks.conf, "get_tenant_pk_cast", return_value="bigint"):
            self.assertEqual(checks.check_tenant_pk_cast(None), [])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_error_e002_when_cast_raises(self):
        from django.core.exceptions import ImproperlyConfigured

        def _boom():
            raise ImproperlyConfigured("unsupported internal type 'GenericIPAddressField'")

        with mock.patch.object(checks.conf, "get_tenant_pk_cast", side_effect=_boom):
            messages = checks.check_tenant_pk_cast(None)
        self.assertEqual(_ids(messages), [checks.E002_ID])
        self.assertIsInstance(messages[0], Error)
        self.assertIn("GenericIPAddressField", messages[0].msg)


if __name__ == "__main__":
    unittest.main()
