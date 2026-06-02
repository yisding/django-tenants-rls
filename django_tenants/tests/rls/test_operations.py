"""Unit tests for ``django_tenants.rls.operations`` migration operations.

The operations are exercised with fakes: a fake ``from_state`` whose
``apps.get_model`` returns a fake model, and a recording fake schema editor.
This verifies ``describe()`` strings, ``deconstruct()`` tuples (serializability),
that ``database_forwards`` calls the right schema-editor method, and that the
operations are no-ops when the schema editor lacks the RLS methods (the
``hasattr`` guard). No database is touched.
"""

import unittest

from django.test.utils import override_settings

from django_tenants.rls import operations
from django_tenants.rls.policies import CustomPolicy, TenantPolicy


class _FakeMeta:
    def __init__(self, db_table):
        self.db_table = db_table


class FakeModel:
    def __init__(self, db_table="rls_note"):
        self._meta = _FakeMeta(db_table)


class FakeApps:
    def __init__(self, model):
        self._model = model

    def get_model(self, app_label, model_name):
        self.last = (app_label, model_name)
        return self._model


class FakeState:
    def __init__(self, model):
        self.apps = FakeApps(model)


class _EditorBuilder:
    """Builds a schema editor exposing only the requested RLS methods."""

    @staticmethod
    def make(methods=None):
        if methods is None:
            methods = {"enable_rls", "disable_rls", "force_rls", "unforce_rls",
                       "create_policy", "drop_policy", "alter_policy"}
        calls = []

        class SE:
            pass

        se = SE()
        se.calls = calls

        def _record(method_name):
            def _fn(*args):
                calls.append((method_name, args))
            return _fn

        for m in methods:
            setattr(se, m, _record(m))
        return se


class _FakeOps:
    """Minimal ``connection.ops`` exposing ``quote_name`` (double-quote style)."""

    def quote_name(self, name):
        return '"%s"' % name


class _FakeConnection:
    def __init__(self, vendor="postgresql"):
        self.vendor = vendor
        self.ops = _FakeOps()


class _SqlRecordingEditor:
    """A schema editor that records raw ``execute(sql)`` calls (no DB).

    Used for :class:`~django_tenants.rls.operations.IsolateExternalTable`, which
    emits raw DDL via ``schema_editor.execute(...)`` rather than the
    ``create_policy`` / ``enable_rls`` helper methods.
    """

    def __init__(self, vendor="postgresql"):
        self.connection = _FakeConnection(vendor=vendor)
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append(sql)

    @property
    def sql(self):
        return "\n".join(self.executed)


# A fake tenant model so IsolateExternalTable can resolve the TENANT_MODEL table /
# PK without the app registry (it lazily imports django_tenants.utils.get_tenant_model).
class _FakePk:
    def __init__(self, column="id"):
        self.column = column


class _FakeTenantMeta:
    def __init__(self, db_table="customers_tenant", pk_column="id"):
        self.db_table = db_table
        self.pk = _FakePk(pk_column)


class _FakeTenantModel:
    def __init__(self, db_table="customers_tenant", pk_column="id"):
        self._meta = _FakeTenantMeta(db_table, pk_column)


class _TenantModelPatchMixin:
    """Monkeypatch ``django_tenants.utils.get_tenant_model`` for the test body."""

    def setUp(self):
        super().setUp()
        from django_tenants import utils
        self._utils = utils
        self._orig_get_tenant_model = utils.get_tenant_model
        utils.get_tenant_model = lambda: _FakeTenantModel()

    def tearDown(self):
        self._utils.get_tenant_model = self._orig_get_tenant_model
        super().tearDown()


class EnableRLSTestCase(unittest.TestCase):
    def setUp(self):
        self.model = FakeModel()
        self.state = FakeState(self.model)

    def test_describe(self):
        op = operations.EnableRLS("Note")
        self.assertEqual(op.describe(), "Enable RLS on Note")

    def test_deconstruct(self):
        op = operations.EnableRLS("Note")
        name, args, kwargs = op.deconstruct()
        self.assertEqual(name, "EnableRLS")
        self.assertEqual(args, ["Note"])
        self.assertEqual(kwargs, {})

    @override_settings(TENANT_RLS_FORCE=True)
    def test_forwards_enables_and_forces(self):
        se = _EditorBuilder.make()
        op = operations.EnableRLS("Note")
        op.database_forwards("rls", se, self.state, self.state)
        called = [c[0] for c in se.calls]
        self.assertIn("enable_rls", called)
        self.assertIn("force_rls", called)

    @override_settings(TENANT_RLS_FORCE=False)
    def test_forwards_enables_without_force(self):
        se = _EditorBuilder.make()
        op = operations.EnableRLS("Note")
        op.database_forwards("rls", se, self.state, self.state)
        called = [c[0] for c in se.calls]
        self.assertIn("enable_rls", called)
        self.assertNotIn("force_rls", called)

    def test_forwards_noop_without_rls_editor(self):
        se = _EditorBuilder.make(methods=set())  # no RLS methods at all
        op = operations.EnableRLS("Note")
        # Must not raise even though enable_rls is absent.
        op.database_forwards("rls", se, self.state, self.state)
        self.assertEqual(se.calls, [])

    def test_backwards_disables(self):
        se = _EditorBuilder.make()
        op = operations.EnableRLS("Note")
        op.database_backwards("rls", se, self.state, self.state)
        called = [c[0] for c in se.calls]
        self.assertIn("disable_rls", called)


class DisableRLSTestCase(unittest.TestCase):
    def setUp(self):
        self.model = FakeModel()
        self.state = FakeState(self.model)

    def test_describe(self):
        op = operations.DisableRLS("Note")
        self.assertEqual(op.describe(), "Disable RLS on Note")

    def test_deconstruct(self):
        op = operations.DisableRLS("Note")
        name, args, kwargs = op.deconstruct()
        self.assertEqual(name, "DisableRLS")
        self.assertEqual(args, ["Note"])
        self.assertEqual(kwargs, {})

    def test_forwards_disables(self):
        se = _EditorBuilder.make()
        op = operations.DisableRLS("Note")
        op.database_forwards("rls", se, self.state, self.state)
        called = [c[0] for c in se.calls]
        self.assertIn("disable_rls", called)


class CreateTenantPolicyTestCase(unittest.TestCase):
    def setUp(self):
        self.model = FakeModel()
        self.state = FakeState(self.model)

    def test_describe(self):
        op = operations.CreateTenantPolicy("Note")
        self.assertEqual(op.describe(), "Create tenant RLS policy on Note")

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_deconstruct_is_serializable(self):
        op = operations.CreateTenantPolicy("Note", name="note_iso",
                                           tenant_field="tenant", pk_cast="integer")
        name, args, kwargs = op.deconstruct()
        self.assertEqual(name, "CreateTenantPolicy")
        self.assertEqual(args, ["Note"])
        self.assertEqual(kwargs["name"], "note_iso")
        self.assertEqual(kwargs["tenant_field"], "tenant")
        # pk_cast is snapshotted and always emitted for reproducibility.
        self.assertEqual(kwargs["pk_cast"], "integer")

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_policy_kwargs_round_trip_through_operation_writer(self):
        # Regression: with **VAR_KEYWORD on __init__, OperationWriter silently
        # drops kwargs that are not explicit __init__ params (pk_cast, operation,
        # session_variable, ...). Every policy arg is now an explicit param, so
        # they must appear in the rendered migration source.
        from django.db.migrations.writer import OperationWriter

        op = operations.CreateTenantPolicy(
            "Note", name="note_iso", tenant_field="tenant",
            pk_cast="uuid", session_variable="myapp.tid", operation="INSERT",
        )
        rendered, imports = OperationWriter(op).serialize()
        self.assertIn("pk_cast='uuid'", rendered)
        self.assertIn("session_variable='myapp.tid'", rendered)
        self.assertIn("operation='INSERT'", rendered)
        self.assertTrue(
            any("django_tenants.rls.operations" in imp for imp in imports)
        )

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_deconstructed_tuple_rebuilds_equivalent_operation(self):
        op = operations.CreateTenantPolicy(
            "Note", name="note_iso", tenant_field="tenant",
            pk_cast="uuid", operation="INSERT",
        )
        _, args, kwargs = op.deconstruct()
        rebuilt = operations.CreateTenantPolicy(*args, **kwargs)
        self.assertEqual(rebuilt.deconstruct(), op.deconstruct())

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_forwards_creates_policy(self):
        se = _EditorBuilder.make()
        op = operations.CreateTenantPolicy("Note", name="note_iso",
                                           tenant_field="tenant")
        op.database_forwards("rls", se, self.state, self.state)
        created = [c for c in se.calls if c[0] == "create_policy"]
        self.assertEqual(len(created), 1)
        # The created policy is a TenantPolicy on the resolved model.
        _, call_args = created[0]
        self.assertIs(call_args[0], self.model)
        self.assertIsInstance(call_args[1], TenantPolicy)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_backwards_drops_policy(self):
        se = _EditorBuilder.make()
        op = operations.CreateTenantPolicy("Note", name="note_iso",
                                           tenant_field="tenant")
        op.database_backwards("rls", se, self.state, self.state)
        dropped = [c for c in se.calls if c[0] == "drop_policy"]
        self.assertEqual(len(dropped), 1)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_default_name_derives_from_db_table(self):
        # D5/F29: with no explicit name, the policy name is resolved at APPLY time
        # from the model's db_table as "<db_table>_tenant_isolation" -- exactly the
        # name the models auto-enable path produces. (Previously it used model_name,
        # which orphaned the policy on disable.)
        from django_tenants.rls.models import _default_policy_name

        se = _EditorBuilder.make()
        op = operations.CreateTenantPolicy("Note", tenant_field="tenant",
                                           pk_cast="integer")
        op.database_forwards("rls", se, self.state, self.state)
        created = [c for c in se.calls if c[0] == "create_policy"]
        self.assertEqual(len(created), 1)
        _, call_args = created[0]
        policy = call_args[1]
        expected = _default_policy_name(self.model._meta.db_table)
        self.assertEqual(policy.name, expected)
        self.assertEqual(policy.name, "rls_note_tenant_isolation")

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_default_name_enable_and_disable_target_same_policy(self):
        # The name dropped on backwards must equal the name created on forwards so
        # enable/disable operate on the SAME policy rather than orphaning it.
        se = _EditorBuilder.make()
        op = operations.CreateTenantPolicy("Note", tenant_field="tenant",
                                           pk_cast="integer")
        op.database_forwards("rls", se, self.state, self.state)
        op.database_backwards("rls", se, self.state, self.state)
        created_name = [c[1][1].name for c in se.calls if c[0] == "create_policy"][0]
        dropped_name = [c[1][1] for c in se.calls if c[0] == "drop_policy"][0]
        self.assertEqual(created_name, dropped_name)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_default_name_not_emitted_by_deconstruct(self):
        # deconstruct() only emits ``name`` when set explicitly, so the default
        # stays resolved at apply time (in lockstep with the models path).
        op = operations.CreateTenantPolicy("Note", tenant_field="tenant",
                                           pk_cast="integer")
        _, _, kwargs = op.deconstruct()
        self.assertNotIn("name", kwargs)


class CreatePolicyTestCase(unittest.TestCase):
    def setUp(self):
        self.model = FakeModel()
        self.state = FakeState(self.model)
        self.policy = CustomPolicy(name="cp", expression="true")

    def test_describe(self):
        op = operations.CreatePolicy("Note", self.policy)
        self.assertEqual(op.describe(), "Create RLS policy cp on Note")

    def test_deconstruct(self):
        op = operations.CreatePolicy("Note", self.policy)
        name, args, kwargs = op.deconstruct()
        self.assertEqual(name, "CreatePolicy")
        self.assertEqual(args, ["Note", self.policy])
        self.assertEqual(kwargs, {})

    def test_forwards_creates_given_policy(self):
        se = _EditorBuilder.make()
        op = operations.CreatePolicy("Note", self.policy)
        op.database_forwards("rls", se, self.state, self.state)
        created = [c for c in se.calls if c[0] == "create_policy"]
        self.assertEqual(len(created), 1)
        self.assertIs(created[0][1][1], self.policy)


class DropPolicyTestCase(unittest.TestCase):
    def setUp(self):
        self.model = FakeModel()
        self.state = FakeState(self.model)

    def test_describe(self):
        op = operations.DropPolicy("Note", "note_iso")
        self.assertEqual(op.describe(), "Drop RLS policy note_iso on Note")

    def test_deconstruct(self):
        op = operations.DropPolicy("Note", "note_iso")
        name, args, kwargs = op.deconstruct()
        self.assertEqual(name, "DropPolicy")
        self.assertEqual(args, ["Note", "note_iso"])
        self.assertEqual(kwargs, {})

    def test_is_irreversible(self):
        op = operations.DropPolicy("Note", "note_iso")
        self.assertFalse(op.reversible)

    def test_forwards_drops_policy(self):
        se = _EditorBuilder.make()
        op = operations.DropPolicy("Note", "note_iso")
        op.database_forwards("rls", se, self.state, self.state)
        dropped = [c for c in se.calls if c[0] == "drop_policy"]
        self.assertEqual(len(dropped), 1)


class IsolateExternalTableTestCase(_TenantModelPatchMixin, unittest.TestCase):
    """``IsolateExternalTable`` -- isolate a non-TenantRLSModel table under RLS.

    The full prerequisite sequence (ADD COLUMN w/ GUC default + FK -> optional SET
    NOT NULL -> UNIQUE rewrites -> ENABLE/FORCE -> CREATE POLICY) is emitted as raw
    DDL via ``schema_editor.execute``; the tests assert the forward/backward SQL,
    the off-Postgres no-op via the vendor guard, and that the policy matches the
    framework ``TenantPolicy``. No database is touched.
    """

    def _state(self):
        # IsolateExternalTable does not resolve a model from state, but
        # database_forwards/backwards still receive a state argument.
        return FakeState(FakeModel())

    def test_describe(self):
        op = operations.IsolateExternalTable("authtoken_token", pk_cast="integer")
        self.assertEqual(
            op.describe(),
            "Tenant-isolate external table authtoken_token under RLS",
        )

    @override_settings(TENANT_RLS_ENABLED=True, TENANT_RLS_FORCE=True)
    def test_forwards_emits_add_column_with_guc_default_and_fk(self):
        se = _SqlRecordingEditor()
        op = operations.IsolateExternalTable("authtoken_token", pk_cast="integer")
        op.database_forwards("rls", se, self._state(), self._state())
        sql = se.sql
        # ADD COLUMN <tenant_field>_id of the tenant PK type.
        self.assertIn('ALTER TABLE "authtoken_token" ADD COLUMN "tenant_id" integer', sql)
        # Column DEFAULT reads the tenant GUC (NULLIF(current_setting(...), '')::cast).
        self.assertIn(
            "DEFAULT (NULLIF(current_setting('django_tenants.tenant_id', true), '')::integer)",
            sql,
        )
        # FK to the resolved TENANT_MODEL table/PK, ON DELETE CASCADE.
        self.assertIn('REFERENCES "customers_tenant" ("id") ON DELETE CASCADE', sql)

    @override_settings(TENANT_RLS_ENABLED=True, TENANT_RLS_FORCE=True)
    def test_forwards_enables_and_forces_rls(self):
        se = _SqlRecordingEditor()
        op = operations.IsolateExternalTable("authtoken_token", pk_cast="integer")
        op.database_forwards("rls", se, self._state(), self._state())
        sql = se.sql
        self.assertIn('ALTER TABLE "authtoken_token" ENABLE ROW LEVEL SECURITY', sql)
        self.assertIn('ALTER TABLE "authtoken_token" FORCE ROW LEVEL SECURITY', sql)

    @override_settings(TENANT_RLS_ENABLED=True, TENANT_RLS_FORCE=False)
    def test_forwards_does_not_force_when_force_disabled(self):
        se = _SqlRecordingEditor()
        op = operations.IsolateExternalTable("authtoken_token", pk_cast="integer")
        op.database_forwards("rls", se, self._state(), self._state())
        sql = se.sql
        self.assertIn("ENABLE ROW LEVEL SECURITY", sql)
        self.assertNotIn("FORCE ROW LEVEL SECURITY", sql)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_forwards_policy_is_byte_identical_to_framework_policy(self):
        se = _SqlRecordingEditor()
        op = operations.IsolateExternalTable("authtoken_token", pk_cast="integer")
        op.database_forwards("rls", se, self._state(), self._state())
        sql = se.sql
        policy = TenantPolicy(
            name="authtoken_token_tenant_isolation", pk_cast="integer",
        )
        using = policy.get_using_expression()
        check = policy.get_check_expression()
        # The InitPlan sub-SELECT form must be reproduced verbatim.
        self.assertIn("SELECT NULLIF(current_setting(", using)
        self.assertIn(using, sql)
        self.assertIn(check, sql)
        # PERMISSIVE FOR ALL TO public -- the framework's create_policy shape.
        self.assertIn(
            'CREATE POLICY "authtoken_token_tenant_isolation" ON "authtoken_token" '
            "AS PERMISSIVE FOR ALL TO public",
            sql,
        )

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_forwards_not_null_only_when_requested(self):
        se = _SqlRecordingEditor()
        op = operations.IsolateExternalTable("authtoken_token", pk_cast="integer")
        op.database_forwards("rls", se, self._state(), self._state())
        self.assertNotIn("SET NOT NULL", se.sql)

        se2 = _SqlRecordingEditor()
        op2 = operations.IsolateExternalTable(
            "authtoken_token", pk_cast="integer", not_null=True,
        )
        op2.database_forwards("rls", se2, self._state(), self._state())
        self.assertIn(
            'ALTER TABLE "authtoken_token" ALTER COLUMN "tenant_id" SET NOT NULL',
            se2.sql,
        )

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_forwards_unique_rewrites_drop_and_add_tenant_scoped(self):
        se = _SqlRecordingEditor()
        op = operations.IsolateExternalTable(
            "authtoken_token", pk_cast="integer",
            unique_rewrites=[("authtoken_token_user_id_key", ["tenant_id", "user_id"])],
        )
        op.database_forwards("rls", se, self._state(), self._state())
        sql = se.sql
        self.assertIn(
            'ALTER TABLE "authtoken_token" DROP CONSTRAINT "authtoken_token_user_id_key"',
            sql,
        )
        # The new constraint is tenant-scoped over the supplied columns.
        self.assertIn('UNIQUE ("tenant_id", "user_id")', sql)

    @override_settings(TENANT_RLS_ENABLED=True, TENANT_RLS_FORCE=True)
    def test_forwards_ordering_column_before_policy(self):
        # The column (and its GUC default) must be added BEFORE ENABLE/CREATE POLICY
        # so the policy's tenant_id reference is valid.
        se = _SqlRecordingEditor()
        op = operations.IsolateExternalTable("authtoken_token", pk_cast="integer")
        op.database_forwards("rls", se, self._state(), self._state())
        joined = se.sql
        add_idx = joined.index("ADD COLUMN")
        enable_idx = joined.index("ENABLE ROW LEVEL SECURITY")
        policy_idx = joined.index("CREATE POLICY")
        self.assertLess(add_idx, enable_idx)
        self.assertLess(enable_idx, policy_idx)

    @override_settings(TENANT_RLS_ENABLED=True, TENANT_RLS_FORCE=True)
    def test_backwards_drops_policy_disables_rls_and_drops_column(self):
        se = _SqlRecordingEditor()
        op = operations.IsolateExternalTable("authtoken_token", pk_cast="integer")
        op.database_backwards("rls", se, self._state(), self._state())
        sql = se.sql
        self.assertIn(
            'DROP POLICY IF EXISTS "authtoken_token_tenant_isolation" ON "authtoken_token"',
            sql,
        )
        self.assertIn('ALTER TABLE "authtoken_token" NO FORCE ROW LEVEL SECURITY', sql)
        self.assertIn('ALTER TABLE "authtoken_token" DISABLE ROW LEVEL SECURITY', sql)
        self.assertIn('ALTER TABLE "authtoken_token" DROP COLUMN "tenant_id"', sql)
        # Drop policy must precede dropping the column (reverse of forwards order).
        self.assertLess(sql.index("DROP POLICY"), sql.index("DROP COLUMN"))

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_backwards_restores_rewritten_unique(self):
        se = _SqlRecordingEditor()
        op = operations.IsolateExternalTable(
            "authtoken_token", pk_cast="integer",
            unique_rewrites=[("authtoken_token_user_id_key", ["tenant_id", "user_id"])],
        )
        op.database_backwards("rls", se, self._state(), self._state())
        sql = se.sql
        # The tenant-scoped replacement is dropped and the original-named UNIQUE
        # is re-added on the non-tenant columns.
        self.assertIn(
            'DROP CONSTRAINT "authtoken_token_user_id_key_per_tenant"', sql,
        )
        self.assertIn(
            'ADD CONSTRAINT "authtoken_token_user_id_key" UNIQUE ("user_id")', sql,
        )

    def test_forwards_is_noop_off_postgresql(self):
        se = _SqlRecordingEditor(vendor="sqlite")
        op = operations.IsolateExternalTable("authtoken_token", pk_cast="integer")
        op.database_forwards("rls", se, self._state(), self._state())
        self.assertEqual(se.executed, [])

    def test_backwards_is_noop_off_postgresql(self):
        se = _SqlRecordingEditor(vendor="mysql")
        op = operations.IsolateExternalTable("authtoken_token", pk_cast="integer")
        op.database_backwards("rls", se, self._state(), self._state())
        self.assertEqual(se.executed, [])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_uuid_pk_cast_uses_uuid_column_type_and_cast(self):
        se = _SqlRecordingEditor()
        op = operations.IsolateExternalTable("ext_table", pk_cast="uuid")
        op.database_forwards("rls", se, self._state(), self._state())
        sql = se.sql
        self.assertIn('ADD COLUMN "tenant_id" uuid', sql)
        self.assertIn("::uuid", sql)
        self.assertNotIn("::integer", sql)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_custom_tenant_field_changes_column_name(self):
        se = _SqlRecordingEditor()
        op = operations.IsolateExternalTable(
            "ext_table", tenant_field="org", pk_cast="bigint",
        )
        op.database_forwards("rls", se, self._state(), self._state())
        sql = se.sql
        self.assertIn('ADD COLUMN "org_id" bigint', sql)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_deconstruct_emits_table_and_snapshotted_pk_cast(self):
        op = operations.IsolateExternalTable(
            "authtoken_token", tenant_field="tenant", pk_cast="integer",
        )
        name, args, kwargs = op.deconstruct()
        self.assertEqual(name, "IsolateExternalTable")
        self.assertEqual(args, ["authtoken_token"])
        self.assertEqual(kwargs["tenant_field"], "tenant")
        # pk_cast is snapshotted and always emitted for reproducibility.
        self.assertEqual(kwargs["pk_cast"], "integer")
        # Defaults are omitted to keep makemigrations stable.
        self.assertNotIn("not_null", kwargs)
        self.assertNotIn("unique_rewrites", kwargs)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_deconstruct_emits_non_default_options(self):
        op = operations.IsolateExternalTable(
            "authtoken_token", pk_cast="integer", not_null=True,
            unique_rewrites=[("authtoken_token_user_id_key", ["tenant_id", "user_id"])],
        )
        _, _, kwargs = op.deconstruct()
        self.assertEqual(kwargs["not_null"], True)
        self.assertEqual(
            kwargs["unique_rewrites"],
            [("authtoken_token_user_id_key", ["tenant_id", "user_id"])],
        )

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_deconstructed_tuple_rebuilds_equivalent_operation(self):
        op = operations.IsolateExternalTable(
            "authtoken_token", pk_cast="uuid", not_null=True,
            unique_rewrites=[("uniq_old", ["tenant_id", "key"])],
        )
        _, args, kwargs = op.deconstruct()
        rebuilt = operations.IsolateExternalTable(*args, **kwargs)
        self.assertEqual(rebuilt.deconstruct(), op.deconstruct())


class OperationWriterSerializationTestCase(unittest.TestCase):
    """Round-trip the operations through Django's real migration serializer.

    Asserting only the ``deconstruct()`` tuple shape would not catch a
    non-serializable embedded value (e.g. a ``TenantPolicy`` that cannot be
    written into a migration file). ``OperationWriter.serialize()`` is the actual
    code path ``makemigrations`` uses.
    """

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_enable_rls_serializes(self):
        from django.db.migrations.writer import OperationWriter

        rendered, imports = OperationWriter(operations.EnableRLS("Note")).serialize()
        self.assertIsInstance(rendered, str)
        self.assertTrue(
            any("django_tenants.rls.operations" in imp for imp in imports)
        )

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_create_policy_with_tenant_policy_serializes(self):
        from django.db.migrations.writer import OperationWriter

        policy = TenantPolicy(
            name="note_iso", tenant_field="tenant",
            session_variable="django_tenants.tenant_id",
            bypass_variable="django_tenants.bypass_rls", pk_cast="integer",
        )
        op = operations.CreatePolicy("Note", policy)
        rendered, imports = OperationWriter(op).serialize()
        self.assertIsInstance(rendered, str)
        self.assertIn("TenantPolicy", rendered)
        self.assertTrue(
            any("django_tenants.rls.policies" in imp for imp in imports)
        )

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_isolate_external_table_serializes(self):
        from django.db.migrations.writer import OperationWriter

        op = operations.IsolateExternalTable(
            "authtoken_token", tenant_field="tenant", pk_cast="integer",
            not_null=True,
            unique_rewrites=[("authtoken_token_user_id_key", ["tenant_id", "user_id"])],
        )
        rendered, imports = OperationWriter(op).serialize()
        self.assertIsInstance(rendered, str)
        self.assertIn("'authtoken_token'", rendered)
        self.assertIn("pk_cast='integer'", rendered)
        self.assertIn("not_null=True", rendered)
        self.assertTrue(
            any("django_tenants.rls.operations" in imp for imp in imports)
        )
