"""End-to-end RLS isolation test (Postgres required).

This is the ONE test in the suite that needs a real database. It is SKIPPED
unless a Postgres database is configured on the tenant database alias AND that
database is actually connectable with the RLS-aware backend. When skipped it
reports a clear reason so the rest of the suite passes with no Postgres.

What it verifies (see the spec's secure-by-default semantics):

* rows inserted under tenant A are invisible while tenant B is active and vice
  versa (cross-tenant isolation);
* with no tenant set, no rows are visible (secure by default);
* ``bypass_rls()`` reveals all tenants' rows;
* the policy ``WITH CHECK`` clause rejects inserting a row for the wrong tenant.

Crucially, the assertions run as a **non-superuser, NOBYPASSRLS** role. PostgreSQL
ignores every row-security policy for a superuser or a BYPASSRLS role -- even
with ``FORCE ROW LEVEL SECURITY`` -- so testing as such a role would prove
nothing (the tables would look protected yet leak). The common dev/CI setup
connects as the Postgres superuser, so when the configured role bypasses RLS this
test creates a dedicated least-privilege role, grants it table access, and points
the (default) connection at it for the duration of the test, restoring the
original credentials in teardown.
"""

import unittest


# Fixed, injection-safe identifiers for the throwaway app role.
APP_ROLE = "django_tenants_rls_test_app"
APP_PW = "rls_test_app_pw"


def _postgres_configured():
    """Return (ok, reason) describing whether the isolation test can run."""
    try:
        from django.conf import settings
        from django.db import connections
        from django_tenants.rls import conf
        from django_tenants.utils import get_tenant_database_alias
    except Exception:
        return False, "Django / django-tenants not importable"

    if not conf.rls_enabled():
        return False, "TENANT_RLS_ENABLED is False"

    alias = get_tenant_database_alias()
    databases = getattr(settings, "DATABASES", {}) or {}
    engine = (databases.get(alias, {}) or {}).get("ENGINE", "")
    if not (engine.endswith("postgresql_backend") or "rls.backend" in engine):
        return False, "tenant database ENGINE is not a django-tenants Postgres backend"

    try:
        connection = connections[alias]
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except Exception as exc:  # pragma: no cover - depends on environment
        return False, "Postgres not connectable: %s" % (exc,)

    return True, ""


_OK, _SKIP_REASON = _postgres_configured()


def _role_bypasses_rls(connection):
    """Return True if the connection's current role bypasses RLS."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        )
        row = cursor.fetchone()
    return bool(row and (row[0] or row[1]))


def _role_exists(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [APP_ROLE])
        return cursor.fetchone() is not None


def _drop_app_role(connection):
    """Best-effort removal of the app role and its grants (admin connection)."""
    try:
        if _role_exists(connection):
            with connection.cursor() as cursor:
                # DROP OWNED BY clears the role's GRANTs so DROP ROLE can succeed.
                cursor.execute('DROP OWNED BY "%s"' % APP_ROLE)
                cursor.execute('DROP ROLE IF EXISTS "%s"' % APP_ROLE)
    except Exception:
        pass


def _create_app_role(connection):
    """Create a fresh non-superuser, NOBYPASSRLS login role (admin connection)."""
    _drop_app_role(connection)  # idempotent clean slate
    with connection.cursor() as cursor:
        cursor.execute(
            'CREATE ROLE "%s" LOGIN PASSWORD %%s NOSUPERUSER NOBYPASSRLS' % APP_ROLE,
            [APP_PW],
        )


def _grant_app_role(connection):
    """Grant the app role the table/sequence privileges it needs (admin)."""
    with connection.cursor() as cursor:
        cursor.execute('GRANT USAGE ON SCHEMA public TO "%s"' % APP_ROLE)
        cursor.execute(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public '
            'TO "%s"' % APP_ROLE
        )
        cursor.execute(
            'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "%s"' % APP_ROLE
        )


@unittest.skipUnless(_OK, _SKIP_REASON or "requires a configured, connectable Postgres database")
class RLSIsolationTestCase(unittest.TestCase):
    """Full insert / visibility / bypass / WITH CHECK round-trip on Postgres,
    executed as a non-superuser (NOBYPASSRLS) role so RLS is actually in force."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from django.db import connections
        from django_tenants.utils import get_tenant_database_alias, get_tenant_model

        cls.connection = connections[get_tenant_database_alias()]
        cls.connection.set_schema_to_public()
        cls._switched = False
        cls._orig_user = None
        cls._orig_pw = None

        from .models import Note

        cls.Note = Note
        TenantModel = get_tenant_model()

        # If the configured role bypasses RLS (the usual superuser dev/CI setup),
        # we need a dedicated non-superuser role or the test would prove nothing.
        cls._needs_role = _role_bypasses_rls(cls.connection)
        if cls._needs_role:
            try:
                _create_app_role(cls.connection)
            except Exception as exc:
                raise unittest.SkipTest(
                    "connecting role bypasses RLS and a non-superuser test role "
                    "could not be created (need CREATEROLE/superuser): %s" % exc
                )

        try:
            # All DDL + tenant rows are created with the original (privileged) role.
            with cls.connection.schema_editor() as schema_editor:
                schema_editor.create_model(Note)

            Note._rls_policies = None
            Note.enable_rls()

            cls.tenant_a = TenantModel(schema_name="rls_tenant_a")
            cls.tenant_a.auto_create_schema = False
            cls.tenant_a.save()
            cls.tenant_b = TenantModel(schema_name="rls_tenant_b")
            cls.tenant_b.auto_create_schema = False
            cls.tenant_b.save()

            if cls._needs_role:
                _grant_app_role(cls.connection)
                # Point the (default) connection at the least-privilege role so the
                # ORM assertions below run under enforced RLS. Closing forces a
                # reconnect with the new credentials on the next query.
                cls._orig_user = cls.connection.settings_dict.get("USER")
                cls._orig_pw = cls.connection.settings_dict.get("PASSWORD")
                cls.connection.close()
                cls.connection.settings_dict["USER"] = APP_ROLE
                cls.connection.settings_dict["PASSWORD"] = APP_PW
                cls._switched = True
        except Exception:
            cls._restore_and_cleanup()
            raise

    @classmethod
    def _restore_and_cleanup(cls):
        """Restore the original credentials and drop everything we created."""
        from django_tenants.rls.session import bypass_rls

        # Restore the privileged role first so cleanup DDL has the rights it needs.
        if cls._switched:
            cls.connection.close()
            if cls._orig_user is not None:
                cls.connection.settings_dict["USER"] = cls._orig_user
            if cls._orig_pw is not None:
                cls.connection.settings_dict["PASSWORD"] = cls._orig_pw
            cls._switched = False

        cls.connection.set_schema_to_public()
        try:
            with bypass_rls():
                cls.Note.objects.all().delete()
                for tenant in (getattr(cls, "tenant_a", None), getattr(cls, "tenant_b", None)):
                    if tenant is not None and tenant.pk is not None:
                        tenant.delete(force_drop=False)
        except Exception:
            pass
        try:
            with cls.connection.schema_editor() as schema_editor:
                schema_editor.delete_model(cls.Note)
        except Exception:
            pass
        if getattr(cls, "_needs_role", False):
            _drop_app_role(cls.connection)
        cls.connection.set_schema_to_public()

    @classmethod
    def tearDownClass(cls):
        cls._restore_and_cleanup()
        super().tearDownClass()

    def setUp(self):
        from django_tenants.rls.session import bypass_rls

        with bypass_rls():
            self.Note.objects.all().delete()

    def test_cross_tenant_isolation(self):
        from django_tenants.rls.session import rls_context

        with rls_context(self.tenant_a):
            self.Note.objects.create(text="a-note", tenant=self.tenant_a)
        with rls_context(self.tenant_b):
            self.Note.objects.create(text="b-note", tenant=self.tenant_b)

        with rls_context(self.tenant_a):
            visible = list(self.Note.objects.values_list("text", flat=True))
            self.assertEqual(visible, ["a-note"])

        with rls_context(self.tenant_b):
            visible = list(self.Note.objects.values_list("text", flat=True))
            self.assertEqual(visible, ["b-note"])

    def test_no_tenant_sees_nothing(self):
        from django_tenants.rls.session import rls_context

        with rls_context(self.tenant_a):
            self.Note.objects.create(text="a-note", tenant=self.tenant_a)

        # No tenant set -> secure by default -> no rows visible.
        from django_tenants.rls.session import clear_current_tenant

        clear_current_tenant(connection=self.connection)
        self.assertEqual(self.Note.objects.count(), 0)

    def test_bypass_reveals_all(self):
        from django_tenants.rls.session import bypass_rls, rls_context

        with rls_context(self.tenant_a):
            self.Note.objects.create(text="a-note", tenant=self.tenant_a)
        with rls_context(self.tenant_b):
            self.Note.objects.create(text="b-note", tenant=self.tenant_b)

        with bypass_rls():
            self.assertEqual(self.Note.objects.count(), 2)

    def test_with_check_rejects_wrong_tenant_insert(self):
        from django.db import DatabaseError
        from django_tenants.rls.session import rls_context

        # Active tenant is A, but we try to insert a row owned by B; the policy
        # WITH CHECK clause must reject it.
        with rls_context(self.tenant_a):
            with self.assertRaises(DatabaseError):
                self.Note.objects.create(text="wrong", tenant=self.tenant_b)

    def test_create_without_tenant_resolves_from_rls_context(self):
        """F18/D3: create() under ``rls_context`` WITHOUT passing ``tenant``.

        ``rls_context`` sets ``connection._rls_tenant_id`` / the GUC but never sets
        ``connection.tenant``. ``save()`` must resolve the tenant from the GUC
        source-of-truth first, so the row is stamped with A's pk, the WITH CHECK
        clause accepts it, and it is visible only to A.
        """
        from django_tenants.rls.session import rls_context

        with rls_context(self.tenant_a):
            note = self.Note.objects.create(text="auto-a")
            # The FK was auto-populated from the active RLS context, not passed in.
            self.assertEqual(str(note.tenant_id), str(self.tenant_a.pk))

        with rls_context(self.tenant_a):
            self.assertEqual(
                list(self.Note.objects.values_list("text", flat=True)), ["auto-a"]
            )

        with rls_context(self.tenant_b):
            self.assertEqual(list(self.Note.objects.values_list("text", flat=True)), [])


class _AppRoleSwitch:
    """Reusable NOSUPERUSER role-switch harness for live-PG isolation tests.

    Mirrors :class:`RLSIsolationTestCase`'s class-level setup: if the configured
    role bypasses RLS (the usual superuser dev/CI setup), create a dedicated
    least-privilege role, grant it table/sequence access, and point the (default)
    connection at it for the duration of the test so the assertions run under
    enforced RLS. Everything is restored/dropped in teardown.

    Subclasses must set ``cls.connection`` (the tenant-alias connection) before
    calling :meth:`_switch_to_app_role`, and must have created all DDL + seed rows
    with the original (privileged) role first (the app role is only granted
    privileges on already-existing objects).
    """

    @classmethod
    def _init_role_state(cls):
        cls._switched = False
        cls._orig_user = None
        cls._orig_pw = None
        cls._needs_role = _role_bypasses_rls(cls.connection)

    @classmethod
    def _ensure_app_role(cls):
        """Create the app role if the configured role bypasses RLS."""
        if cls._needs_role:
            try:
                _create_app_role(cls.connection)
            except Exception as exc:
                raise unittest.SkipTest(
                    "connecting role bypasses RLS and a non-superuser test role "
                    "could not be created (need CREATEROLE/superuser): %s" % exc
                )

    @classmethod
    def _switch_to_app_role(cls):
        """Grant + switch the connection to the app role (after DDL/seed rows)."""
        if not cls._needs_role:
            return
        _grant_app_role(cls.connection)
        cls._orig_user = cls.connection.settings_dict.get("USER")
        cls._orig_pw = cls.connection.settings_dict.get("PASSWORD")
        cls.connection.close()
        cls.connection.settings_dict["USER"] = APP_ROLE
        cls.connection.settings_dict["PASSWORD"] = APP_PW
        cls._switched = True

    @classmethod
    def _restore_role(cls):
        """Restore the original (privileged) credentials so cleanup DDL works."""
        if cls._switched:
            cls.connection.close()
            if cls._orig_user is not None:
                cls.connection.settings_dict["USER"] = cls._orig_user
            if cls._orig_pw is not None:
                cls.connection.settings_dict["PASSWORD"] = cls._orig_pw
            cls._switched = False

    @classmethod
    def _drop_role_if_created(cls):
        if getattr(cls, "_needs_role", False):
            _drop_app_role(cls.connection)


@unittest.skipUnless(_OK, _SKIP_REASON or "requires a configured, connectable Postgres database")
class RLSRestrictiveAndAtomicTestCase(_AppRoleSwitch, unittest.TestCase):
    """F26: RESTRICTIVE-only policies grant nothing, and isolation survives an
    ``atomic()`` rollback because the SESSION GUC is re-asserted per cursor.

    Uses a throwaway table driven by raw SQL as the app role (no ORM model), so
    nothing here depends on or mutates the global ``TENANT_MODEL``.
    """

    TABLE = "rls_test_restrictive"
    POLICY = "rls_test_restrictive_isolation"
    # Arbitrary tenant ids -- the table yields 0 rows for everyone regardless of
    # which tenant is active (a sole RESTRICTIVE policy never grants access), so
    # these need not be real tenant pks.
    TENANT_A_PK = 1
    TENANT_B_PK = 2

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from django.db import connections
        from django_tenants.utils import get_tenant_database_alias

        cls.connection = connections[get_tenant_database_alias()]
        cls.connection.set_schema_to_public()
        cls._init_role_state()
        cls._ensure_app_role()

        try:
            # All DDL + seed rows created with the original (privileged) role.
            cls._privileged_setup()
            cls._switch_to_app_role()
        except Exception:
            cls._cleanup()
            raise

    @classmethod
    def _privileged_setup(cls):
        from django_tenants.rls.policies import TenantPolicy

        # A throwaway table whose ONLY policy is RESTRICTIVE. Postgres AND-combines
        # restrictive policies with permissive ones; with no permissive policy to
        # grant access, the table returns zero rows for everyone -- even the right
        # tenant and even under bypass.
        restrictive = TenantPolicy(
            name=cls.POLICY,
            tenant_field="tenant",
            permissive=False,
        )
        expr = restrictive.get_using_expression()
        with cls.connection.cursor() as cursor:
            cursor.execute(
                'CREATE TABLE "%s" (id serial PRIMARY KEY, '
                "tenant_id integer NOT NULL, text varchar(255) NOT NULL DEFAULT '')"
                % cls.TABLE
            )
            # Seed two rows under bypass-free privileged role (it bypasses RLS or
            # the table has no policy yet, so the inserts succeed regardless).
            cursor.execute(
                'INSERT INTO "%s" (tenant_id, text) VALUES (%%s, %%s), (%%s, %%s)'
                % cls.TABLE,
                [cls.TENANT_A_PK, "a", cls.TENANT_B_PK, "b"],
            )
            cursor.execute('ALTER TABLE "%s" ENABLE ROW LEVEL SECURITY' % cls.TABLE)
            cursor.execute('ALTER TABLE "%s" FORCE ROW LEVEL SECURITY' % cls.TABLE)
            cursor.execute(
                'CREATE POLICY "%s" ON "%s" AS RESTRICTIVE FOR ALL TO public '
                "USING (%s)" % (cls.POLICY, cls.TABLE, expr)
            )

    @classmethod
    def _cleanup(cls):
        from django_tenants.rls.session import bypass_rls

        cls._restore_role()
        cls.connection.set_schema_to_public()
        try:
            with bypass_rls():
                with cls.connection.cursor() as cursor:
                    cursor.execute('DROP TABLE IF EXISTS "%s"' % cls.TABLE)
        except Exception:
            try:
                with cls.connection.cursor() as cursor:
                    cursor.execute('DROP TABLE IF EXISTS "%s"' % cls.TABLE)
            except Exception:
                pass
        cls._drop_role_if_created()
        cls.connection.set_schema_to_public()

    @classmethod
    def tearDownClass(cls):
        cls._cleanup()
        super().tearDownClass()

    def _count(self):
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT count(*) FROM "%s"' % self.TABLE)
            return cursor.fetchone()[0]

    def test_restrictive_only_grants_nothing(self):
        from django_tenants.rls.session import bypass_rls, rls_context

        # The "correct" tenant still sees zero rows: a sole RESTRICTIVE policy
        # never grants visibility.
        with rls_context(self.TENANT_A_PK):
            self.assertEqual(self._count(), 0)

        # Even bypass cannot reveal rows: there is no permissive policy to grant
        # access, and RESTRICTIVE AND-combines down to "deny".
        with bypass_rls():
            self.assertEqual(self._count(), 0)

    def test_isolation_survives_atomic_rollback(self):
        from django.db import transaction
        from django_tenants.rls.session import rls_context

        # Inside an atomic block that we roll back, the per-cursor re-assertion of
        # the SESSION GUC must keep isolation intact afterwards. (The RESTRICTIVE
        # table always yields 0; the point is that the rollback does not corrupt
        # the GUC state so a subsequent query still applies the policy.)
        with rls_context(self.TENANT_A_PK):
            try:
                with transaction.atomic(using=self.connection.alias):
                    with self.connection.cursor() as cursor:
                        cursor.execute('SELECT count(*) FROM "%s"' % self.TABLE)
                        cursor.fetchone()
                    raise RuntimeError("force rollback")
            except RuntimeError:
                pass
            # After the rollback the GUC is re-asserted per cursor; the policy is
            # still in force (zero rows for the RESTRICTIVE-only table).
            self.assertEqual(self._count(), 0)


@unittest.skipUnless(_OK, _SKIP_REASON or "requires a configured, connectable Postgres database")
class RLSUuidTenantTestCase(_AppRoleSwitch, unittest.TestCase):
    """F24: a throwaway table with a ``uuid`` tenant_id column isolated by a
    ``TenantPolicy(pk_cast="uuid")`` isolates correctly under the app role.

    Built entirely from raw SQL so the global ``TENANT_MODEL`` (integer PK) is
    left untouched.
    """

    TABLE = "rls_test_uuid"
    POLICY = "rls_test_uuid_isolation"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import uuid

        from django.db import connections
        from django_tenants.utils import get_tenant_database_alias

        cls.connection = connections[get_tenant_database_alias()]
        cls.connection.set_schema_to_public()
        cls._init_role_state()
        cls._ensure_app_role()

        cls.tenant_a = uuid.uuid4()
        cls.tenant_b = uuid.uuid4()

        try:
            cls._privileged_setup()
            cls._switch_to_app_role()
        except Exception:
            cls._cleanup()
            raise

    @classmethod
    def _privileged_setup(cls):
        from django_tenants.rls.policies import TenantPolicy

        policy = TenantPolicy(
            name=cls.POLICY,
            tenant_field="tenant",
            pk_cast="uuid",
        )
        using = policy.get_using_expression()
        check = policy.get_check_expression()
        with cls.connection.cursor() as cursor:
            cursor.execute(
                'CREATE TABLE "%s" (id serial PRIMARY KEY, '
                "tenant_id uuid NOT NULL, text varchar(255) NOT NULL DEFAULT '')"
                % cls.TABLE
            )
            cursor.execute(
                'INSERT INTO "%s" (tenant_id, text) VALUES (%%s, %%s), (%%s, %%s)'
                % cls.TABLE,
                [str(cls.tenant_a), "a", str(cls.tenant_b), "b"],
            )
            cursor.execute('ALTER TABLE "%s" ENABLE ROW LEVEL SECURITY' % cls.TABLE)
            cursor.execute('ALTER TABLE "%s" FORCE ROW LEVEL SECURITY' % cls.TABLE)
            cursor.execute(
                'CREATE POLICY "%s" ON "%s" AS PERMISSIVE FOR ALL TO public '
                "USING (%s) WITH CHECK (%s)"
                % (cls.POLICY, cls.TABLE, using, check)
            )

    @classmethod
    def _cleanup(cls):
        from django_tenants.rls.session import bypass_rls

        cls._restore_role()
        cls.connection.set_schema_to_public()
        try:
            with bypass_rls():
                with cls.connection.cursor() as cursor:
                    cursor.execute('DROP TABLE IF EXISTS "%s"' % cls.TABLE)
        except Exception:
            try:
                with cls.connection.cursor() as cursor:
                    cursor.execute('DROP TABLE IF EXISTS "%s"' % cls.TABLE)
            except Exception:
                pass
        cls._drop_role_if_created()
        cls.connection.set_schema_to_public()

    @classmethod
    def tearDownClass(cls):
        cls._cleanup()
        super().tearDownClass()

    def _texts(self):
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT text FROM "%s" ORDER BY text' % self.TABLE)
            return [row[0] for row in cursor.fetchall()]

    def test_uuid_tenant_isolation(self):
        from django_tenants.rls.session import bypass_rls, rls_context

        with rls_context(self.tenant_a):
            self.assertEqual(self._texts(), ["a"])
        with rls_context(self.tenant_b):
            self.assertEqual(self._texts(), ["b"])

        # No tenant -> secure by default.
        from django_tenants.rls.session import clear_current_tenant

        clear_current_tenant(connection=self.connection)
        self.assertEqual(self._texts(), [])

        # Bypass reveals every tenant's rows.
        with bypass_rls():
            self.assertEqual(self._texts(), ["a", "b"])
