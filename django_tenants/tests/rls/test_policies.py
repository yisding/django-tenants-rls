"""Unit tests for ``django_tenants.rls.policies``.

These tests assert the *exact* SQL expression strings the policies generate
(the load-bearing contract that feeds the ``USING`` / ``WITH CHECK`` clauses),
verify identifier-injection rejection, and check ``deconstruct()`` round-trips
for migration serialization. No database is touched.
"""

import unittest

from django_tenants.rls.policies import (
    BasePolicy,
    CustomPolicy,
    PolicyError,
    TenantPolicy,
)


class TenantPolicySQLTestCase(unittest.TestCase):
    def test_integer_cast_expression(self):
        policy = TenantPolicy(
            name="note_isolation",
            tenant_field="tenant",
            session_variable="django_tenants.tenant_id",
            bypass_variable="django_tenants.bypass_rls",
            pk_cast="integer",
        )
        # DEC-1: each current_setting() is wrapped in a scalar sub-SELECT so
        # Postgres evaluates it once per statement (InitPlan), not once per row.
        self.assertEqual(
            policy.get_sql_expression(),
            "(tenant_id = (SELECT NULLIF(current_setting('django_tenants.tenant_id', "
            "true), '')::integer) OR (SELECT current_setting('django_tenants.bypass_rls', "
            "true)) = 'on')",
        )

    def test_uuid_cast_expression(self):
        policy = TenantPolicy(
            name="note_isolation",
            tenant_field="tenant",
            session_variable="django_tenants.tenant_id",
            bypass_variable="django_tenants.bypass_rls",
            pk_cast="uuid",
        )
        self.assertEqual(
            policy.get_sql_expression(),
            "(tenant_id = (SELECT NULLIF(current_setting('django_tenants.tenant_id', "
            "true), '')::uuid) OR (SELECT current_setting('django_tenants.bypass_rls', "
            "true)) = 'on')",
        )

    def test_custom_field_and_variable_names(self):
        policy = TenantPolicy(
            name="org_isolation",
            tenant_field="organisation",
            session_variable="myapp.org",
            bypass_variable="myapp.bypass",
            pk_cast="bigint",
        )
        self.assertEqual(
            policy.get_sql_expression(),
            "(organisation_id = (SELECT NULLIF(current_setting('myapp.org', true), "
            "'')::bigint) OR (SELECT current_setting('myapp.bypass', true)) = 'on')",
        )

    def test_current_setting_is_initplan_wrapped(self):
        # DEC-1: both current_setting() calls must sit inside a scalar
        # sub-SELECT (the InitPlan-once-per-statement optimisation). Assert the
        # structural markers so a regression that drops the wrapping is caught
        # independently of exact whitespace.
        policy = TenantPolicy(
            name="note_isolation",
            tenant_field="tenant",
            session_variable="django_tenants.tenant_id",
            bypass_variable="django_tenants.bypass_rls",
            pk_cast="integer",
        )
        expr = policy.get_sql_expression()
        # The tenant comparison reads the GUC through a sub-SELECT.
        self.assertIn(
            "(SELECT NULLIF(current_setting('django_tenants.tenant_id', true), "
            "'')::integer)",
            expr,
        )
        # The bypass disjunct reads its GUC through a sub-SELECT too.
        self.assertIn(
            "(SELECT current_setting('django_tenants.bypass_rls', true)) = 'on'",
            expr,
        )
        # No *bare* current_setting( should survive: every occurrence must be
        # immediately preceded by "(SELECT ". There are exactly two GUC reads.
        self.assertEqual(expr.count("current_setting("), 2)
        self.assertEqual(expr.count("(SELECT current_setting("), 1)
        self.assertEqual(expr.count("(SELECT NULLIF(current_setting("), 1)

    def test_using_and_check_are_identical_for_all(self):
        policy = TenantPolicy(
            name="note_isolation",
            tenant_field="tenant",
            session_variable="django_tenants.tenant_id",
            bypass_variable="django_tenants.bypass_rls",
            pk_cast="integer",
        )
        self.assertEqual(policy.get_using_expression(), policy.get_sql_expression())
        self.assertEqual(policy.get_check_expression(), policy.get_sql_expression())

    def test_check_expression_none_for_select(self):
        policy = TenantPolicy(
            name="note_isolation",
            tenant_field="tenant",
            session_variable="django_tenants.tenant_id",
            bypass_variable="django_tenants.bypass_rls",
            pk_cast="integer",
            operation=BasePolicy.SELECT,
        )
        self.assertIsNone(policy.get_check_expression())
        self.assertIsNotNone(policy.get_using_expression())


class OperationValidationTestCase(unittest.TestCase):
    def test_valid_operations_accepted(self):
        for op in (BasePolicy.ALL, BasePolicy.SELECT, BasePolicy.INSERT,
                   BasePolicy.UPDATE, BasePolicy.DELETE):
            policy = CustomPolicy(name="p", expression="true", operation=op)
            self.assertEqual(policy.operation, op)

    def test_invalid_operation_rejected(self):
        with self.assertRaises(PolicyError):
            CustomPolicy(name="p", expression="true", operation="TRUNCATE")


class InjectionRejectionTestCase(unittest.TestCase):
    def test_field_injection_rejected(self):
        with self.assertRaises(PolicyError):
            TenantPolicy(name="x", tenant_field="id; DROP TABLE",
                         session_variable="a.b", bypass_variable="c.d",
                         pk_cast="integer")

    def test_bad_policy_name_rejected(self):
        with self.assertRaises(PolicyError):
            TenantPolicy(name="bad name; DROP", tenant_field="tenant",
                         session_variable="a.b", bypass_variable="c.d",
                         pk_cast="integer")

    def test_overlong_policy_name_rejected(self):
        # A Postgres identifier is capped at 63 bytes; longer names are silently
        # truncated by the server, so DROP/CREATE would target a different name.
        # The name must be a *valid* identifier so it is the length check (not the
        # pattern check) that rejects it.
        long_name = "a" * 64  # 64 bytes > 63-byte identifier limit
        self.assertGreater(len(long_name.encode("utf-8")), 63)
        with self.assertRaises(PolicyError):
            CustomPolicy(name=long_name, expression="true")

    def test_max_length_policy_name_accepted(self):
        # Exactly 63 bytes is the limit and must be accepted.
        ok_name = "b" * 63
        self.assertEqual(len(ok_name.encode("utf-8")), 63)
        policy = CustomPolicy(name=ok_name, expression="true")
        self.assertEqual(policy.name, ok_name)

    def test_bad_session_variable_rejected(self):
        with self.assertRaises(PolicyError):
            TenantPolicy(name="x", tenant_field="tenant",
                         session_variable="no_dot", bypass_variable="c.d",
                         pk_cast="integer")

    def test_session_variable_with_quote_rejected(self):
        with self.assertRaises(PolicyError):
            TenantPolicy(name="x", tenant_field="tenant",
                         session_variable="a.b'; --", bypass_variable="c.d",
                         pk_cast="integer")

    def test_bad_pk_cast_rejected(self):
        with self.assertRaises(PolicyError):
            TenantPolicy(name="x", tenant_field="tenant",
                         session_variable="a.b", bypass_variable="c.d",
                         pk_cast="integer; DROP TABLE")

    def test_role_injection_rejected(self):
        with self.assertRaises(PolicyError):
            CustomPolicy(name="p", expression="true",
                         roles=["valid_role", "bad; DROP TABLE"])

    def test_public_role_keyword_allowed(self):
        policy = CustomPolicy(name="p", expression="true", roles="public")
        self.assertEqual(policy.roles, "public")

    def test_named_role_allowed(self):
        policy = CustomPolicy(name="p", expression="true", roles=["app_role"])
        self.assertEqual(policy.roles, ["app_role"])

    def test_empty_roles_list_rejected(self):
        # An empty roles list would render an invalid '... TO  USING (...)' clause.
        with self.assertRaises(PolicyError):
            CustomPolicy(name="p", expression="true", roles=[])

    def test_empty_roles_tuple_rejected(self):
        with self.assertRaises(PolicyError):
            CustomPolicy(name="p", expression="true", roles=())


class CustomPolicyTestCase(unittest.TestCase):
    def test_expression_passthrough(self):
        policy = CustomPolicy(name="p", expression="tenant_id = 1")
        self.assertEqual(policy.get_sql_expression(), "tenant_id = 1")

    def test_check_expression_defaults_to_expression(self):
        policy = CustomPolicy(name="p", expression="tenant_id = 1")
        self.assertEqual(policy.get_check_expression(), "tenant_id = 1")

    def test_explicit_check_expression(self):
        policy = CustomPolicy(name="p", expression="a", check_expression="b")
        self.assertEqual(policy.get_using_expression(), "a")
        self.assertEqual(policy.get_check_expression(), "b")

    def test_empty_expression_rejected(self):
        with self.assertRaises(PolicyError):
            CustomPolicy(name="p", expression="")

    def test_whitespace_expression_rejected(self):
        with self.assertRaises(PolicyError):
            CustomPolicy(name="p", expression="   ")

    def test_check_expression_none_for_delete(self):
        policy = CustomPolicy(name="p", expression="a", operation=BasePolicy.DELETE)
        self.assertIsNone(policy.get_check_expression())


class DeconstructTestCase(unittest.TestCase):
    def test_tenant_policy_deconstruct_path(self):
        policy = TenantPolicy(
            name="note_isolation",
            tenant_field="tenant",
            session_variable="django_tenants.tenant_id",
            bypass_variable="django_tenants.bypass_rls",
            pk_cast="integer",
        )
        path, args, kwargs = policy.deconstruct()
        self.assertEqual(path, "django_tenants.rls.policies.TenantPolicy")
        self.assertEqual(args, [])
        self.assertEqual(kwargs["name"], "note_isolation")
        self.assertEqual(kwargs["tenant_field"], "tenant")
        self.assertEqual(kwargs["pk_cast"], "integer")

    def test_tenant_policy_deconstruct_round_trip(self):
        policy = TenantPolicy(
            name="note_isolation",
            tenant_field="tenant",
            session_variable="django_tenants.tenant_id",
            bypass_variable="django_tenants.bypass_rls",
            pk_cast="integer",
        )
        _, args, kwargs = policy.deconstruct()
        rebuilt = TenantPolicy(*args, **kwargs)
        self.assertEqual(rebuilt.get_sql_expression(), policy.get_sql_expression())
        self.assertEqual(rebuilt, policy)

    def test_custom_policy_deconstruct_round_trip(self):
        policy = CustomPolicy(name="p", expression="a", check_expression="b",
                              operation=BasePolicy.UPDATE, roles=["app_role"])
        path, args, kwargs = policy.deconstruct()
        self.assertEqual(path, "django_tenants.rls.policies.CustomPolicy")
        rebuilt = CustomPolicy(*args, **kwargs)
        self.assertEqual(rebuilt, policy)
        self.assertEqual(rebuilt.get_using_expression(), "a")
        self.assertEqual(rebuilt.get_check_expression(), "b")

    def test_non_default_attrs_serialized(self):
        policy = TenantPolicy(
            name="p",
            tenant_field="tenant",
            session_variable="a.b",
            bypass_variable="c.d",
            pk_cast="integer",
            operation=BasePolicy.INSERT,
            permissive=False,
            roles=["app_role"],
        )
        _, _, kwargs = policy.deconstruct()
        self.assertEqual(kwargs["operation"], BasePolicy.INSERT)
        self.assertEqual(kwargs["permissive"], False)
        self.assertEqual(kwargs["roles"], ["app_role"])
