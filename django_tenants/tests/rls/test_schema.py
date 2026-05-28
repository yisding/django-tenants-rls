"""Unit tests for ``django_tenants.rls.schema.RLSSchemaEditorMixin``.

A fake schema editor mixes the production mixin with a stub ``quote_name`` and a
recording ``execute`` so the exact emitted DDL strings can be asserted without a
database. Particular attention is paid to the absence of dangling ``USING`` /
``WITH CHECK`` keywords when an expression is empty.
"""

import unittest

from django_tenants.rls.policies import CustomPolicy, PolicyError, TenantPolicy
from django_tenants.rls.schema import RLSSchemaEditorMixin


class FakeSchemaEditor(RLSSchemaEditorMixin):
    """Records executed SQL; quotes identifiers with simple double quotes."""

    def __init__(self):
        self.executed = []

    def quote_name(self, name):
        return '"%s"' % name

    def execute(self, sql, params=None):
        self.executed.append(sql)


class _FakeMeta:
    def __init__(self, db_table):
        self.db_table = db_table


class FakeModel:
    def __init__(self, db_table="rls_note"):
        self._meta = _FakeMeta(db_table)


def _tenant_policy(**overrides):
    kwargs = dict(
        name="rls_note_tenant_isolation",
        tenant_field="tenant",
        session_variable="django_tenants.tenant_id",
        bypass_variable="django_tenants.bypass_rls",
        pk_cast="integer",
    )
    kwargs.update(overrides)
    return TenantPolicy(**kwargs)


class EnableForceTestCase(unittest.TestCase):
    def setUp(self):
        self.se = FakeSchemaEditor()
        self.model = FakeModel()

    def test_enable_rls(self):
        self.se.enable_rls(self.model)
        self.assertEqual(
            self.se.executed,
            ['ALTER TABLE "rls_note" ENABLE ROW LEVEL SECURITY'],
        )

    def test_disable_rls(self):
        self.se.disable_rls(self.model)
        self.assertEqual(
            self.se.executed,
            ['ALTER TABLE "rls_note" DISABLE ROW LEVEL SECURITY'],
        )

    def test_force_rls(self):
        self.se.force_rls(self.model)
        self.assertEqual(
            self.se.executed,
            ['ALTER TABLE "rls_note" FORCE ROW LEVEL SECURITY'],
        )

    def test_unforce_rls(self):
        self.se.unforce_rls(self.model)
        self.assertEqual(
            self.se.executed,
            ['ALTER TABLE "rls_note" NO FORCE ROW LEVEL SECURITY'],
        )


class CreatePolicyTestCase(unittest.TestCase):
    def setUp(self):
        self.se = FakeSchemaEditor()
        self.model = FakeModel()

    def test_create_tenant_policy_sql(self):
        self.se.create_policy(self.model, _tenant_policy())
        expected = (
            'CREATE POLICY "rls_note_tenant_isolation" ON "rls_note" '
            "AS PERMISSIVE FOR ALL TO public "
            "USING ((tenant_id = NULLIF(current_setting('django_tenants.tenant_id', true), "
            "'')::integer OR current_setting('django_tenants.bypass_rls', true) = 'on')) "
            "WITH CHECK ((tenant_id = NULLIF(current_setting('django_tenants.tenant_id', true), "
            "'')::integer OR current_setting('django_tenants.bypass_rls', true) = 'on'))"
        )
        self.assertEqual(self.se.executed, [expected])

    def test_create_select_policy_has_no_dangling_with_check(self):
        policy = _tenant_policy(operation=TenantPolicy.SELECT)
        self.se.create_policy(self.model, policy)
        sql = self.se.executed[0]
        self.assertIn("FOR SELECT", sql)
        self.assertIn("USING (", sql)
        self.assertNotIn("WITH CHECK", sql)
        # A SELECT policy has an empty check clause; nothing dangling is left.
        self.assertTrue(sql.rstrip().endswith("'on'))"))

    def test_create_restrictive_policy(self):
        policy = _tenant_policy(permissive=False)
        self.se.create_policy(self.model, policy)
        self.assertIn("AS RESTRICTIVE", self.se.executed[0])

    def test_create_policy_with_named_role(self):
        policy = CustomPolicy(name="cp", expression="true", roles=["app_role"])
        self.se.create_policy(self.model, policy)
        self.assertIn('TO "app_role"', self.se.executed[0])

    def test_create_custom_policy_with_explicit_check(self):
        policy = CustomPolicy(name="cp", expression="a", check_expression="b")
        self.se.create_policy(self.model, policy)
        sql = self.se.executed[0]
        self.assertIn("USING (a)", sql)
        self.assertIn("WITH CHECK (b)", sql)

    def test_create_delete_custom_policy_has_no_check(self):
        policy = CustomPolicy(name="cp", expression="a",
                              operation=CustomPolicy.DELETE)
        self.se.create_policy(self.model, policy)
        sql = self.se.executed[0]
        self.assertIn("USING (a)", sql)
        self.assertNotIn("WITH CHECK", sql)


class AlterPolicyTestCase(unittest.TestCase):
    def setUp(self):
        self.se = FakeSchemaEditor()
        self.model = FakeModel()

    def test_alter_policy_sql(self):
        self.se.alter_policy(self.model, _tenant_policy())
        expected = (
            'ALTER POLICY "rls_note_tenant_isolation" ON "rls_note" '
            "USING ((tenant_id = NULLIF(current_setting('django_tenants.tenant_id', true), "
            "'')::integer OR current_setting('django_tenants.bypass_rls', true) = 'on')) "
            "WITH CHECK ((tenant_id = NULLIF(current_setting('django_tenants.tenant_id', true), "
            "'')::integer OR current_setting('django_tenants.bypass_rls', true) = 'on'))"
        )
        self.assertEqual(self.se.executed, [expected])


class DropPolicyTestCase(unittest.TestCase):
    def setUp(self):
        self.se = FakeSchemaEditor()
        self.model = FakeModel()

    def test_drop_policy_sql(self):
        self.se.drop_policy(self.model, "rls_note_tenant_isolation")
        self.assertEqual(
            self.se.executed,
            ['DROP POLICY IF EXISTS "rls_note_tenant_isolation" ON "rls_note"'],
        )

    def test_drop_policy_rejects_injection(self):
        with self.assertRaises(PolicyError):
            self.se.drop_policy(self.model, "p; DROP TABLE users")


class RenderRolesTestCase(unittest.TestCase):
    def setUp(self):
        self.se = FakeSchemaEditor()

    def test_public_keyword(self):
        self.assertEqual(self.se._render_roles("public"), "public")

    def test_public_uppercase_keyword(self):
        self.assertEqual(self.se._render_roles("PUBLIC"), "public")

    def test_single_named_role_quoted(self):
        self.assertEqual(self.se._render_roles("app_role"), '"app_role"')

    def test_list_of_roles_quoted_and_joined(self):
        self.assertEqual(
            self.se._render_roles(["role_a", "role_b"]),
            '"role_a", "role_b"',
        )

    def test_injection_role_rejected(self):
        with self.assertRaises(PolicyError):
            self.se._render_roles(["bad; DROP TABLE"])
