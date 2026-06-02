"""Reusable test support for shared-schema RLS isolation tests.

This is a **public, importable** module (``django_tenants.rls.test``) so adopters
do not have to hand-roll the delicate "run the assertions as a non-superuser
role" dance that a *meaningful* RLS isolation test requires.

Why a dedicated role is required
--------------------------------
PostgreSQL ignores every row-security policy for a **superuser** or a
**BYPASSRLS** role -- even with ``FORCE ROW LEVEL SECURITY``. The common dev/CI
setup connects as the Postgres superuser, so an isolation test run as that role
would prove *nothing*: the tables would look protected yet leak in production
under a least-privilege role. To make the assertions trustworthy this mixin, when
the configured role bypasses RLS, creates a dedicated NOSUPERUSER / NOBYPASSRLS
login role, grants it table/sequence access, and points the (default) tenant
connection at it for the duration of the test class -- restoring the original
credentials and dropping the role in teardown. If such a role cannot be created
(no CREATEROLE/superuser rights) the whole test class is skipped cleanly with a
clear reason rather than passing misleadingly.

Usage
-----
Subclass the mixin together with ``TransactionTestCase`` and point it at any
:class:`~django_tenants.rls.models.TenantRLSModel`. The model's table and RLS
policies are created (and torn down) for you, and two tenant rows of your
``TENANT_MODEL`` are created to scope the assertions::

    from django.test import TransactionTestCase

    from django_tenants.rls.test import RLSIsolationTestCaseMixin

    from myapp.models import Note  # a TenantRLSModel subclass


    class NoteIsolationTests(RLSIsolationTestCaseMixin, TransactionTestCase):
        rls_model = Note

        def test_notes_are_isolated(self):
            # Helper that does the full create-under-A / create-under-B /
            # cross-check round trip for you:
            self.assertIsolated(
                self.rls_model,
                self.tenant_a,
                self.tenant_b,
                make_row=lambda tenant: {"text": "hello"},
            )

        def test_no_tenant_sees_nothing(self):
            self.assertInvisibleWithoutTenant(
                self.rls_model,
                make_row=lambda tenant: {"text": "secret"},
            )

        def test_manual_scoping(self):
            with self.as_tenant(self.tenant_a):
                self.rls_model.objects.create(text="a", tenant=self.tenant_a)
            with self.as_tenant(self.tenant_a):
                self.assertEqual(self.rls_model.objects.count(), 1)
            with self.as_tenant(self.tenant_b):
                self.assertEqual(self.rls_model.objects.count(), 0)

The mixin works for any tenant PK type (integer / bigint / uuid / text) and any
``TENANT_MODEL`` -- it only relies on the public ``rls_context`` / ``bypass_rls``
session helpers and on the model's ``enable_rls()`` classmethod.

Customisation hooks (class attributes):

* ``rls_model`` -- **required**: the ``TenantRLSModel`` subclass under test.
* ``tenant_a_schema`` / ``tenant_b_schema`` -- schema names for the two scoping
  tenants (default ``"rls_test_tenant_a"`` / ``"rls_test_tenant_b"``).
* ``app_role`` / ``app_password`` -- the throwaway least-privilege role's name and
  password (sensible fixed defaults; only override if they collide).
"""

import unittest


# Fixed, injection-safe defaults for the throwaway app role. They are class
# attributes on the mixin so a project can override them if they ever collide.
_DEFAULT_APP_ROLE = "django_tenants_rls_isolation_app"
_DEFAULT_APP_PASSWORD = "rls_isolation_app_pw"


def _role_bypasses_rls(connection):
    """Return True if the connection's current role is superuser or BYPASSRLS."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        )
        row = cursor.fetchone()
    return bool(row and (row[0] or row[1]))


class RLSIsolationTestCaseMixin:
    """Mixin for ``TransactionTestCase`` that runs RLS assertions under a
    non-superuser, NOBYPASSRLS role so the policies are actually enforced.

    Set :attr:`rls_model` to the ``TenantRLSModel`` subclass under test. The
    mixin creates the table + policies and two scoping tenants in
    :meth:`setUpClass`, switching the connection to a least-privilege role when
    the configured role would otherwise bypass RLS, and tears everything down in
    :meth:`tearDownClass`. Each test starts from an empty table.

    Helpers:

    * :meth:`as_tenant` -- a context manager wrapping ``rls_context``.
    * :meth:`assertIsolated` -- assert two tenants cannot see each other's rows.
    * :meth:`assertInvisibleWithoutTenant` -- assert no rows are visible with no
      active tenant (secure by default).
    """

    #: The ``TenantRLSModel`` subclass under test. Required.
    rls_model = None

    #: Allow queries against every alias. The tenant database is frequently a
    #: non-``default`` alias, and ``TransactionTestCase`` otherwise blocks queries
    #: to any alias not listed here ("Database queries to '<alias>' are not
    #: allowed in this test"). The isolation assertions run on the tenant alias,
    #: so we opt every alias in.
    databases = "__all__"

    #: Schema names for the two scoping tenants created in ``setUpClass``.
    tenant_a_schema = "rls_test_tenant_a"
    tenant_b_schema = "rls_test_tenant_b"

    #: Name / password of the throwaway least-privilege role.
    app_role = _DEFAULT_APP_ROLE
    app_password = _DEFAULT_APP_PASSWORD

    @classmethod
    def _skip_reason(cls):
        """Return a reason string if the isolation harness cannot run, else None.

        Mirrors the suite's own ``_postgres_configured`` gate: RLS must be
        enabled and the tenant database must be a connectable django-tenants
        Postgres backend.
        """
        try:
            from django.conf import settings
            from django.db import connections
            from django_tenants.rls import conf
            from django_tenants.utils import get_tenant_database_alias
        except Exception:  # pragma: no cover - import-time environment issue
            return "Django / django-tenants not importable"

        if cls.rls_model is None:
            return "set `rls_model` to a TenantRLSModel subclass to use this mixin"

        if not conf.rls_enabled():
            return "TENANT_RLS_ENABLED is False"

        alias = get_tenant_database_alias()
        databases = getattr(settings, "DATABASES", {}) or {}
        engine = (databases.get(alias, {}) or {}).get("ENGINE", "")
        if not (engine.endswith("postgresql_backend") or "rls.backend" in engine):
            return "tenant database ENGINE is not a django-tenants Postgres backend"

        try:
            connection = connections[alias]
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
        except Exception as exc:  # pragma: no cover - depends on environment
            return "Postgres not connectable: %s" % (exc,)

        return None

    # -- role lifecycle (all DDL runs as the original, privileged role) --------

    @classmethod
    def _role_exists(cls):
        with cls._connection.cursor() as cursor:
            cursor.execute(
                "SELECT 1 FROM pg_roles WHERE rolname = %s", [cls.app_role]
            )
            return cursor.fetchone() is not None

    @classmethod
    def _drop_app_role(cls):
        """Best-effort removal of the app role and its grants (admin connection)."""
        try:
            if cls._role_exists():
                with cls._connection.cursor() as cursor:
                    # DROP OWNED BY clears the role's GRANTs so DROP ROLE succeeds.
                    cursor.execute('DROP OWNED BY "%s"' % cls.app_role)
                    cursor.execute('DROP ROLE IF EXISTS "%s"' % cls.app_role)
        except Exception:
            pass

    @classmethod
    def _create_app_role(cls):
        """Create a fresh NOSUPERUSER, NOBYPASSRLS login role (admin connection)."""
        cls._drop_app_role()  # idempotent clean slate
        with cls._connection.cursor() as cursor:
            cursor.execute(
                'CREATE ROLE "%s" LOGIN PASSWORD %%s NOSUPERUSER NOBYPASSRLS'
                % cls.app_role,
                [cls.app_password],
            )

    @classmethod
    def _grant_app_role(cls):
        """Grant the app role the table/sequence privileges it needs (admin)."""
        with cls._connection.cursor() as cursor:
            cursor.execute('GRANT USAGE ON SCHEMA public TO "%s"' % cls.app_role)
            cursor.execute(
                'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public '
                'TO "%s"' % cls.app_role
            )
            cursor.execute(
                'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "%s"'
                % cls.app_role
            )

    @classmethod
    def _switch_to_app_role(cls):
        """Point the (default) connection at the least-privilege role.

        Closing forces a reconnect with the new credentials on the next query.
        """
        cls._grant_app_role()
        cls._orig_user = cls._connection.settings_dict.get("USER")
        cls._orig_pw = cls._connection.settings_dict.get("PASSWORD")
        cls._connection.close()
        cls._connection.settings_dict["USER"] = cls.app_role
        cls._connection.settings_dict["PASSWORD"] = cls.app_password
        cls._switched = True

    @classmethod
    def _restore_role(cls):
        """Restore the original (privileged) credentials so cleanup DDL works."""
        if cls._switched:
            cls._connection.close()
            if cls._orig_user is not None:
                cls._connection.settings_dict["USER"] = cls._orig_user
            if cls._orig_pw is not None:
                cls._connection.settings_dict["PASSWORD"] = cls._orig_pw
            cls._switched = False

    # -- class lifecycle -------------------------------------------------------

    @classmethod
    def setUpClass(cls):
        reason = cls._skip_reason()
        if reason is not None:
            raise unittest.SkipTest(reason)

        from django.db import connections
        from django_tenants.utils import get_tenant_database_alias, get_tenant_model

        cls._connection = connections[get_tenant_database_alias()]
        cls._connection.set_schema_to_public()
        cls._switched = False
        cls._orig_user = None
        cls._orig_pw = None
        cls._created_model = False
        cls.tenant_a = None
        cls.tenant_b = None

        TenantModel = get_tenant_model()

        # If the configured role bypasses RLS (the usual superuser dev/CI setup)
        # a dedicated non-superuser role is required or the test proves nothing.
        cls._needs_role = _role_bypasses_rls(cls._connection)
        if cls._needs_role:
            try:
                cls._create_app_role()
            except Exception as exc:
                raise unittest.SkipTest(
                    "connecting role bypasses RLS and a non-superuser test role "
                    "could not be created (need CREATEROLE/superuser): %s" % exc
                )

        # IMPORTANT: super().setUpClass() (TransactionTestCase) only runs AFTER
        # the role exists and is granted, since the harness may need to switch
        # the connection. We create our own DDL/tenants with the privileged role
        # first, then call up so TransactionTestCase wraps test execution.
        try:
            with cls._connection.schema_editor() as schema_editor:
                schema_editor.create_model(cls.rls_model)
            cls._created_model = True

            # Rebuild the cached default policy under the current settings, then
            # apply RLS + policies to the freshly created table.
            cls.rls_model._rls_policies = None
            cls.rls_model.enable_rls()

            cls.tenant_a = TenantModel(schema_name=cls.tenant_a_schema)
            cls.tenant_a.auto_create_schema = False
            cls.tenant_a.save()
            cls.tenant_b = TenantModel(schema_name=cls.tenant_b_schema)
            cls.tenant_b.auto_create_schema = False
            cls.tenant_b.save()

            if cls._needs_role:
                cls._switch_to_app_role()
        except Exception:
            cls._teardown_db()
            raise

        super().setUpClass()

    @classmethod
    def _teardown_db(cls):
        """Restore credentials and drop everything we created (best effort)."""
        from django_tenants.rls.session import bypass_rls

        # Restore the privileged role first so cleanup DDL has the rights it needs.
        cls._restore_role()
        cls._connection.set_schema_to_public()
        try:
            with bypass_rls():
                if cls._created_model:
                    cls.rls_model.objects.all().delete()
                for tenant in (cls.tenant_a, cls.tenant_b):
                    if tenant is not None and tenant.pk is not None:
                        tenant.delete(force_drop=False)
        except Exception:
            pass
        if cls._created_model:
            try:
                with cls._connection.schema_editor() as schema_editor:
                    schema_editor.delete_model(cls.rls_model)
            except Exception:
                pass
        if getattr(cls, "_needs_role", False):
            cls._drop_app_role()
        cls._connection.set_schema_to_public()

    @classmethod
    def tearDownClass(cls):
        try:
            super().tearDownClass()
        finally:
            cls._teardown_db()

    def setUp(self):
        super().setUp()
        from django_tenants.rls.session import bypass_rls

        # Each test starts from an empty table, regardless of active tenant.
        with bypass_rls():
            self.rls_model.objects.all().delete()

    # -- helpers ---------------------------------------------------------------

    def as_tenant(self, tenant):
        """Context manager / decorator running the block scoped to ``tenant``.

        Thin wrapper around :func:`django_tenants.rls.session.rls_context` on the
        mixin's tenant connection::

            with self.as_tenant(self.tenant_a):
                ...  # queries see only tenant_a's rows
        """
        from django_tenants.rls.session import rls_context

        return rls_context(tenant, using=self._connection.alias)

    @staticmethod
    def _default_row(tenant):
        """Default per-row kwargs: just stamp the tenant FK.

        Override by passing ``make_row=...`` to the assert helpers when the model
        has additional non-nullable fields.
        """
        return {"tenant": tenant}

    def _create_for(self, model, tenant, make_row):
        """Create one row of ``model`` owned by ``tenant`` inside its context."""
        kwargs = dict(self._default_row(tenant))
        if make_row is not None:
            kwargs.update(make_row(tenant))
        kwargs.setdefault("tenant", tenant)
        with self.as_tenant(tenant):
            return model.objects.create(**kwargs)

    def assertIsolated(self, model, tenant_a, tenant_b, make_row=None):
        """Assert ``model`` rows do not leak between ``tenant_a`` and ``tenant_b``.

        Creates one row under each tenant, then asserts that while a given tenant
        is active only that tenant's row is visible and the count is exactly one.
        ``make_row(tenant)`` may return a dict of extra kwargs for ``create()``
        (e.g. to fill non-nullable columns); the ``tenant`` FK is always set.
        """
        self._create_for(model, tenant_a, make_row)
        self._create_for(model, tenant_b, make_row)

        with self.as_tenant(tenant_a):
            visible = list(model.objects.all())
            self.assertEqual(
                len(visible),
                1,
                "tenant_a should see exactly its own row, saw %d" % len(visible),
            )
            self.assertEqual(str(visible[0].tenant_id), str(tenant_a.pk))

        with self.as_tenant(tenant_b):
            visible = list(model.objects.all())
            self.assertEqual(
                len(visible),
                1,
                "tenant_b should see exactly its own row, saw %d" % len(visible),
            )
            self.assertEqual(str(visible[0].tenant_id), str(tenant_b.pk))

    def assertInvisibleWithoutTenant(self, model, make_row=None):
        """Assert no ``model`` rows are visible when no tenant is active.

        Creates a row under :attr:`tenant_a`, clears the active tenant, and
        asserts the secure-by-default semantics: zero rows visible.
        """
        from django_tenants.rls.session import clear_current_tenant

        self._create_for(model, self.tenant_a, make_row)

        clear_current_tenant(connection=self._connection)
        self.assertEqual(
            model.objects.count(),
            0,
            "no rows must be visible with no active tenant (secure by default)",
        )
