"""Unit tests for ``django_tenants.rls.checks`` system checks.

These run without a database. They assert the documented stable check IDs
(W001 / W002 / W003 / W004 / W005 / E001 / E002) and trigger conditions, so
doc/code drift (a renamed ID or a changed condition) is caught. The checks are
gated on ``conf.rls_enabled()``, so every check must return ``[]`` when RLS is
disabled.

The role/PK-cast checks (W003, E002) normally open a database connection; here
we swap in a fake connection (whose cursor returns a canned ``pg_roles`` row) so
no real database is required and the Error-vs-silent behavior is asserted
directly.

W004 (``check_rls_live``) introspects the live database to confirm RLS is
actually ON (and FORCEd, and policed, and the tenant column is NOT NULL) for
every concrete ``TenantRLSModel``. The per-model introspection is factored into
the reusable helper ``checks.rls_live_problems(model, connection, *, force)`` ->
list of human-readable problem strings (empty == healthy), which the
``verify_rls`` management command also imports. The W004 tests mock that helper
so no live database is needed.

W005 (``check_tenant_unique_constraints``) is purely model-level (no DB): it
flags any ``unique=True`` field / ``Meta.unique_together`` / ``Meta.constraints``
``UniqueConstraint`` whose field set omits the tenant field, because Postgres
UNIQUE checks BYPASS RLS and so leak cross-tenant existence. Its tests build
real ``TenantRLSModel`` subclasses and patch the model iteration.
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


def _make_unique_models():
    """Build real ``TenantRLSModel`` subclasses exercising W005 conditions.

    Returns ``(global_unique, scoped_unique, global_unique_together,
    scoped_unique_together, abstract)``. Requires the app registry to be
    populated (it is under the project test runner); callers should skip the
    test when construction is not possible (e.g. settings not configured).

    * ``global_unique``            -- a bare ``unique=True`` field (LEAKS).
    * ``scoped_unique``            -- ``UniqueConstraint(fields=[tenant, ...])``
                                      (safe; the tenant is in the field set).
    * ``global_unique_together``   -- ``Meta.unique_together`` omitting tenant
                                      (LEAKS).
    * ``scoped_unique_together``   -- ``Meta.unique_together`` including tenant
                                      (safe).
    * ``abstract``                 -- abstract subclass with a global unique;
                                      must be ignored by the check.
    """
    from django.db import models

    from django_tenants.rls.models import TenantRLSModel

    class W005GlobalUnique(TenantRLSModel):
        email = models.EmailField(unique=True)

        class Meta:
            app_label = "rls"

    class W005ScopedUnique(TenantRLSModel):
        email = models.EmailField()

        class Meta:
            app_label = "rls"
            constraints = [
                models.UniqueConstraint(
                    fields=["tenant", "email"], name="w005_uq_tenant_email"
                )
            ]

    class W005GlobalUniqueTogether(TenantRLSModel):
        slug = models.SlugField()
        ref = models.CharField(max_length=20)

        class Meta:
            app_label = "rls"
            unique_together = [("slug", "ref")]

    class W005ScopedUniqueTogether(TenantRLSModel):
        slug = models.SlugField()

        class Meta:
            app_label = "rls"
            unique_together = [("tenant", "slug")]

    class W005AbstractGlobalUnique(TenantRLSModel):
        email = models.EmailField(unique=True)

        class Meta:
            app_label = "rls"
            abstract = True

    return (
        W005GlobalUnique,
        W005ScopedUnique,
        W005GlobalUniqueTogether,
        W005ScopedUniqueTogether,
        W005AbstractGlobalUnique,
    )


class CheckTenantUniqueConstraintsTestCase(unittest.TestCase):
    """W005: a UNIQUE that omits the tenant field is a cross-tenant leak.

    Postgres enforces UNIQUE/PK constraints *below* row security, so a globally
    unique column lets one tenant probe whether a value exists for ANOTHER
    tenant (an INSERT that should succeed fails with a uniqueness violation).
    The fix is to put the tenant field in the unique key. The check is purely
    model-level, so these tests build real models and patch the model iteration
    rather than touching a database.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            (
                cls.global_unique,
                cls.scoped_unique,
                cls.global_unique_together,
                cls.scoped_unique_together,
                cls.abstract_unique,
            ) = _make_unique_models()
            cls.models_available = True
        except Exception:
            cls.models_available = False

    def setUp(self):
        if not getattr(self, "models_available", False):
            self.skipTest("app registry not configured for TenantRLSModel models")

    @contextlib.contextmanager
    def _models(self, *model_classes):
        """Make ``apps.get_models()`` return exactly ``model_classes``.

        W005 reuses the ``check_tenant_field`` iteration pattern
        (``from django.apps import apps`` then ``apps.get_models()`` filtered by
        ``issubclass(model, TenantRLSModel)``), so patching ``get_models`` is the
        stable seam.
        """
        with mock.patch("django.apps.apps.get_models", return_value=list(model_classes)):
            yield

    @override_settings(TENANT_RLS_ENABLED=False)
    def test_silent_when_disabled(self):
        with self._models(self.global_unique):
            self.assertEqual(checks.check_tenant_unique_constraints(None), [])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_global_unique_field_warns_w005(self):
        with self._models(self.global_unique):
            messages = checks.check_tenant_unique_constraints(None)
        self.assertEqual(_ids(messages), [checks.W005_ID])
        self.assertIsInstance(messages[0], Warning)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_global_unique_together_warns_w005(self):
        with self._models(self.global_unique_together):
            messages = checks.check_tenant_unique_constraints(None)
        self.assertEqual(_ids(messages), [checks.W005_ID])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_tenant_scoped_unique_constraint_is_clean(self):
        with self._models(self.scoped_unique):
            self.assertEqual(checks.check_tenant_unique_constraints(None), [])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_tenant_scoped_unique_together_is_clean(self):
        with self._models(self.scoped_unique_together):
            self.assertEqual(checks.check_tenant_unique_constraints(None), [])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_abstract_models_are_ignored(self):
        # Abstract bases carry no table; the check must skip them even though the
        # abstract base declares a global unique field.
        with self._models(self.abstract_unique):
            self.assertEqual(checks.check_tenant_unique_constraints(None), [])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_mix_flags_only_the_leaky_model(self):
        with self._models(
            self.global_unique, self.scoped_unique, self.global_unique_together
        ):
            messages = checks.check_tenant_unique_constraints(None)
        # Two leaky models -> two W005 warnings; the scoped one stays clean.
        self.assertEqual(_ids(messages), [checks.W005_ID, checks.W005_ID])


def _make_live_model():
    """Build one concrete ``TenantRLSModel`` for the W004 iteration to find."""
    from django.db import models

    from django_tenants.rls.models import TenantRLSModel

    class W004Probe(TenantRLSModel):
        text = models.CharField(max_length=20, blank=True, default="")

        class Meta:
            app_label = "rls"

    return W004Probe


class CheckRlsLiveTestCase(unittest.TestCase):
    """W004: confirm RLS is actually LIVE on every TenantRLSModel table.

    The per-model database introspection is factored into
    ``checks.rls_live_problems(model, connection, *, force)`` (which ``verify_rls``
    also uses) and returns a list of human-readable problem strings -- empty when the
    table is healthy. The check itself is best-effort: any DB error swallows to
    ``[]``. These tests use a real ``TenantRLSModel`` subclass (so the
    ``issubclass`` gate passes) and mock the factored helper plus the connection
    lookup, so no live database is required.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            cls.probe = _make_live_model()
            cls.model_available = True
        except Exception:
            cls.model_available = False

    def setUp(self):
        if not getattr(self, "model_available", False):
            self.skipTest("app registry not configured for TenantRLSModel models")

    @contextlib.contextmanager
    def _harness(self, problems=None, helper_side_effect=None):
        """Patch model iteration, the connection lookup, and the helper.

        ``problems`` is the list ``rls_live_problems`` returns for the single
        probe model (``[]`` == healthy). Pass ``helper_side_effect`` instead to
        make the helper raise (best-effort/swallow path).
        """
        fake_conn = _FakeConnection(row=None)  # never queried; helper is mocked
        helper_kwargs = {}
        if helper_side_effect is not None:
            helper_kwargs["side_effect"] = helper_side_effect
        else:
            helper_kwargs["return_value"] = problems
        with mock.patch(
            "django.apps.apps.get_models", return_value=[self.probe]
        ), mock.patch("django.db.connections", {"default": fake_conn}), mock.patch.object(
            checks, "rls_live_problems", **helper_kwargs
        ) as helper:
            yield helper

    @override_settings(TENANT_RLS_ENABLED=False)
    def test_silent_when_disabled(self):
        with self._harness(problems=["RLS not enabled"]):
            self.assertEqual(checks.check_rls_live(None), [])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_all_good_is_silent(self):
        with self._harness(problems=[]):
            self.assertEqual(checks.check_rls_live(None), [])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_rls_off_warns_w004(self):
        with self._harness(problems=["row level security is not enabled"]):
            messages = checks.check_rls_live(None)
        self.assertEqual(_ids(messages), [checks.W004_ID])
        self.assertIsInstance(messages[0], Warning)
        # The model/table and the specific gap must be named in the message.
        text = messages[0].msg
        self.assertIn(self.probe._meta.db_table, text)
        self.assertIn("row level security is not enabled", text)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_multiple_problems_each_emit_w004(self):
        with self._harness(
            problems=[
                "row level security is not enabled",
                "tenant column is nullable",
            ]
        ):
            messages = checks.check_rls_live(None)
        self.assertEqual(_ids(messages), [checks.W004_ID, checks.W004_ID])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_helper_db_error_is_swallowed(self):
        # Best-effort: if the introspection helper raises (DB unreachable / table
        # missing during checks), the whole check returns [] rather than blowing
        # up the check framework.
        def _boom(*args, **kwargs):
            raise Exception("database is unreachable")

        with self._harness(helper_side_effect=_boom):
            self.assertEqual(checks.check_rls_live(None), [])


if __name__ == "__main__":
    unittest.main()
