"""Unit tests for ``django_tenants.rls.scaffold`` -- the migration/SQL generators.

No database is touched: every generator returns a STRING and writes nothing. The
four generators (the "generate scaffolds" half of the migration assistant) are:

* ``staged_fk_migration(model)``        -- the staged tenant-FK migration text:
  ``AddField`` with ``null=True``, a commented ``RunPython`` backfill STUB, and a
  clearly-delimited ``AlterField`` to ``null=False`` gated to run only AFTER the
  backfill (Step 3 / 5).
* ``enable_rls_migration(model)``       -- a migration using
  ``operations.EnableRLS`` + ``operations.CreateTenantPolicy`` (Step 6).
* ``third_party_policy_sql(table, *, pk_cast="integer")`` -- raw ENABLE / FORCE /
  CREATE POLICY DDL for a table you cannot subclass (e.g. ``authtoken_token``),
  whose ``USING`` / ``WITH CHECK`` is built from
  ``policies.TenantPolicy(...).get_using_expression()`` / ``get_check_expression()``
  so it is byte-identical to the framework policy (Step 7).
* ``unique_constraint_migration(model, fields)`` -- ``AddConstraint`` of a
  tenant-scoped ``UniqueConstraint([tenant_field, *fields])`` plus a
  ``RemoveConstraint`` of the old global one (Step 8).

The migration texts must be valid Python a human can drop into ``migrations/``;
several tests ``compile()`` the generated text to prove that.
"""

import unittest

from django.test.utils import override_settings

from django_tenants.rls import scaffold
from django_tenants.rls.policies import TenantPolicy


def _make_models():
    """Build concrete ``TenantRLSModel`` subclasses for the migration generators.

    Returns ``(simple, global_unique)``:

    * ``simple``        -- a plain tenant-scoped model (for the FK / enable-RLS
                           migration generators).
    * ``global_unique`` -- a model with a global ``unique=True`` field plus a
                           ``unique_together`` omitting the tenant (for the
                           unique-constraint migration generator).

    Requires the app registry to be populated; callers skip when construction is
    not possible (settings not configured).
    """
    from django.db import models

    from django_tenants.rls.models import TenantRLSModel

    class ScaffoldThing(TenantRLSModel):
        text = models.CharField(max_length=50, blank=True, default="")

        class Meta:
            app_label = "rls"

    class ScaffoldGlobalUnique(TenantRLSModel):
        email = models.EmailField(unique=True)
        slug = models.SlugField()

        class Meta:
            app_label = "rls"
            unique_together = [("slug",)]

    return ScaffoldThing, ScaffoldGlobalUnique


class _ScaffoldBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            cls.simple, cls.global_unique = _make_models()
            cls.models_available = True
        except Exception:
            cls.models_available = False

    def setUp(self):
        if not getattr(self, "models_available", False):
            self.skipTest("app registry not configured for TenantRLSModel models")


class StagedFkMigrationTestCase(_ScaffoldBase):
    """``staged_fk_migration`` -- AddField(null=True) + backfill stub + NOT NULL."""

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_returns_non_empty_string(self):
        text = scaffold.staged_fk_migration(self.simple)
        self.assertIsInstance(text, str)
        self.assertTrue(text.strip())

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_is_a_migration_module(self):
        text = scaffold.staged_fk_migration(self.simple)
        # A drop-in migration: imports migrations, declares dependencies and a
        # Migration class with operations.
        self.assertIn("from django.db import migrations", text)
        self.assertIn("class Migration", text)
        self.assertIn("dependencies", text)
        self.assertIn("operations", text)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_adds_nullable_tenant_fk_first(self):
        text = scaffold.staged_fk_migration(self.simple)
        self.assertIn("AddField", text)
        # The staged add must be nullable so it can be applied before backfill.
        self.assertIn("null=True", text)
        # The added field is the configured tenant field.
        self.assertIn("tenant", text)
        # It is a ForeignKey to the tenant model.
        self.assertIn("ForeignKey", text)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_contains_backfill_stub_marked_todo(self):
        text = scaffold.staged_fk_migration(self.simple)
        # A commented RunPython backfill stub the human must complete (Step 4).
        self.assertIn("RunPython", text)
        self.assertIn("TODO", text)
        # The backfill is DANGEROUS / app-specific and must be flagged as such.
        self.assertIn("backfill", text.lower())

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_contains_set_not_null_alterfield_gated_after_backfill(self):
        text = scaffold.staged_fk_migration(self.simple)
        # The SET NOT NULL step (Step 5): an AlterField to null=False.
        self.assertIn("AlterField", text)
        self.assertIn("null=False", text)
        # It must be gated by a comment so it is run ONLY after the backfill.
        lowered = text.lower()
        self.assertTrue(
            "after" in lowered and "backfill" in lowered,
            "the NOT NULL step must be gated to run only after the backfill",
        )

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_generated_text_is_valid_python(self):
        text = scaffold.staged_fk_migration(self.simple)
        # Must at least be syntactically valid Python a human can drop in.
        compile(text, "<staged_fk_migration>", "exec")


class EnableRlsMigrationTestCase(_ScaffoldBase):
    """``enable_rls_migration`` -- EnableRLS + CreateTenantPolicy operations."""

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_returns_non_empty_string(self):
        text = scaffold.enable_rls_migration(self.simple)
        self.assertIsInstance(text, str)
        self.assertTrue(text.strip())

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_uses_rls_operations(self):
        text = scaffold.enable_rls_migration(self.simple)
        # Composes the existing operations rather than re-emitting DDL by hand.
        self.assertIn("EnableRLS", text)
        self.assertIn("CreateTenantPolicy", text)
        # The operations live in the rls.operations module; the migration must
        # import them from there.
        self.assertIn("django_tenants.rls", text)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_references_the_model_name(self):
        text = scaffold.enable_rls_migration(self.simple)
        # EnableRLS / CreateTenantPolicy take the model name; it must appear.
        self.assertIn(self.simple._meta.model_name, text)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_is_a_migration_module(self):
        text = scaffold.enable_rls_migration(self.simple)
        self.assertIn("from django.db import migrations", text)
        self.assertIn("class Migration", text)
        self.assertIn("dependencies", text)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_generated_text_is_valid_python(self):
        text = scaffold.enable_rls_migration(self.simple)
        compile(text, "<enable_rls_migration>", "exec")


class ThirdPartyPolicySqlTestCase(_ScaffoldBase):
    """``third_party_policy_sql`` -- raw DDL byte-identical to the framework policy.

    For a table you cannot subclass (e.g. ``authtoken_token``) the generator emits
    ENABLE / FORCE / CREATE POLICY DDL whose USING / WITH CHECK clauses are built
    from ``TenantPolicy(...).get_using_expression()`` / ``get_check_expression()``
    so the third-party table is policed exactly like a ``TenantRLSModel`` (Step 7).
    """

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_returns_non_empty_string(self):
        sql = scaffold.third_party_policy_sql("authtoken_token")
        self.assertIsInstance(sql, str)
        self.assertTrue(sql.strip())

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_contains_enable_force_and_create_policy_ddl(self):
        sql = scaffold.third_party_policy_sql("authtoken_token")
        upper = sql.upper()
        self.assertIn("ENABLE ROW LEVEL SECURITY", upper)
        self.assertIn("FORCE ROW LEVEL SECURITY", upper)
        self.assertIn("CREATE POLICY", upper)
        # The DDL targets the supplied table name.
        self.assertIn("authtoken_token", sql)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_using_clause_is_byte_identical_to_framework_policy(self):
        # The whole point of Step 7: the third-party table must be policed with
        # EXACTLY the framework expression, including the InitPlan sub-SELECT form.
        sql = scaffold.third_party_policy_sql("authtoken_token", pk_cast="integer")
        policy = TenantPolicy(name="authtoken_token_tenant_isolation", pk_cast="integer")
        using = policy.get_using_expression()
        # Sanity-check the expected InitPlan shape, then assert exact containment.
        self.assertIn("SELECT NULLIF(current_setting(", using)
        self.assertIn("::integer)", using)
        self.assertIn(using, sql)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_with_check_clause_is_byte_identical_to_framework_policy(self):
        sql = scaffold.third_party_policy_sql("authtoken_token", pk_cast="integer")
        policy = TenantPolicy(name="authtoken_token_tenant_isolation", pk_cast="integer")
        check = policy.get_check_expression()
        self.assertIsNotNone(check)
        self.assertIn(check, sql)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_pk_cast_is_honoured(self):
        # A uuid tenant PK must cast as ::uuid, not ::integer.
        sql = scaffold.third_party_policy_sql("authtoken_token", pk_cast="uuid")
        policy = TenantPolicy(name="authtoken_token_tenant_isolation", pk_cast="uuid")
        self.assertIn(policy.get_using_expression(), sql)
        self.assertIn("::uuid", sql)
        self.assertNotIn("::integer", sql)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_default_pk_cast_is_integer(self):
        # The documented default keyword is pk_cast="integer".
        sql = scaffold.third_party_policy_sql("authtoken_token")
        self.assertIn("::integer", sql)


class UniqueConstraintMigrationTestCase(_ScaffoldBase):
    """``unique_constraint_migration`` -- tenant-scope a leaky UNIQUE (Step 8)."""

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_returns_non_empty_string(self):
        text = scaffold.unique_constraint_migration(self.global_unique, ["email"])
        self.assertIsInstance(text, str)
        self.assertTrue(text.strip())

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_adds_tenant_scoped_unique_constraint(self):
        text = scaffold.unique_constraint_migration(self.global_unique, ["email"])
        self.assertIn("AddConstraint", text)
        self.assertIn("UniqueConstraint", text)
        # The new constraint must include the tenant field alongside the old field.
        self.assertIn("tenant", text)
        self.assertIn("email", text)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_removes_the_old_constraint(self):
        text = scaffold.unique_constraint_migration(self.global_unique, ["email"])
        # The leaky global UNIQUE must be removed (Step 8).
        self.assertIn("RemoveConstraint", text)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_is_a_migration_module(self):
        text = scaffold.unique_constraint_migration(self.global_unique, ["email"])
        self.assertIn("from django.db import migrations", text)
        self.assertIn("class Migration", text)
        self.assertIn("dependencies", text)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_generated_text_is_valid_python(self):
        text = scaffold.unique_constraint_migration(self.global_unique, ["email"])
        compile(text, "<unique_constraint_migration>", "exec")

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_multi_field_constraint(self):
        # A composite unique (slug, ref) becomes (tenant, slug, ref).
        text = scaffold.unique_constraint_migration(
            self.global_unique, ["slug", "email"]
        )
        self.assertIn("slug", text)
        self.assertIn("email", text)
        self.assertIn("tenant", text)


class ReviewFixScaffoldTestCase(_ScaffoldBase):
    """Regression tests for the PR review fixes to the scaffold generators."""

    def test_quote_ident_doubles_embedded_quote(self):
        # Postgres identifier escaping: an embedded double quote is doubled so the
        # identifier cannot break out of the surrounding quotes.
        self.assertEqual(scaffold._quote_ident('we"ird'), '"we""ird"')
        self.assertEqual(scaffold._quote_ident("plain"), '"plain"')

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_third_party_policy_sql_quotes_table_identifier(self):
        # The raw third-party DDL must wrap the table identifier in double quotes
        # so a reserved word / mixed-case name (here the SQL keyword ``order``) is
        # emitted safely rather than as a bare identifier.
        sql = scaffold.third_party_policy_sql("order", pk_cast="integer")
        self.assertIn('ALTER TABLE "order" ENABLE ROW LEVEL SECURITY', sql)
        self.assertIn('CREATE POLICY', sql)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_notnull_migration_has_no_addfield(self):
        # For a model that already HAS the (nullable) FK, the scaffold must NOT
        # emit AddField (a duplicate-column error) -- only the NOT NULL AlterField.
        text = scaffold.notnull_migration(self.simple)
        self.assertNotIn("AddField", text)
        self.assertIn("AlterField", text)
        self.assertIn("null=False", text)
        compile(text, "<notnull>", "exec")  # valid Python module

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_field_level_unique_removal_uses_alterfield(self):
        # ``email`` is a field-level unique=True -> the removal *operation* must be
        # migrations.AlterField, NOT migrations.RemoveConstraint (which cannot
        # remove a field-level unique=True). The op names all appear in the
        # explanatory comment, so assert on the actual ``migrations.X(`` call.
        text = scaffold.unique_constraint_migration(self.global_unique, ["email"])
        self.assertIn("migrations.AlterField(", text)
        self.assertNotIn("migrations.RemoveConstraint(", text)
        compile(text, "<unique>", "exec")  # valid Python module

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_unique_together_removal_uses_alteruniquetogether(self):
        # ``slug`` comes from unique_together -> the removal *operation* must be
        # migrations.AlterUniqueTogether, NOT migrations.RemoveConstraint.
        text = scaffold.unique_constraint_migration(self.global_unique, ["slug"])
        self.assertIn("migrations.AlterUniqueTogether(", text)
        self.assertNotIn("migrations.RemoveConstraint(", text)
        compile(text, "<unique>", "exec")  # valid Python module


if __name__ == "__main__":
    unittest.main()
