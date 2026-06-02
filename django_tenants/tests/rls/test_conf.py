"""Unit tests for ``django_tenants.rls.conf`` settings accessors.

No database is required: ``get_tenant_pk_cast`` is exercised by monkeypatching
the lazily-imported ``get_tenant_model`` with stub model classes whose PK field
reports the desired internal type.
"""

import unittest

from django.core.exceptions import ImproperlyConfigured
from django.test.utils import override_settings

from django_tenants.rls import conf


class _FakePK:
    """Stand-in for a Django field exposing ``get_internal_type``."""

    def __init__(self, internal_type):
        self._internal_type = internal_type

    def get_internal_type(self):
        return self._internal_type


class _FakeMeta:
    def __init__(self, internal_type):
        self.pk = _FakePK(internal_type)
        # Surfaced in the ImproperlyConfigured message for an unmapped type.
        self.app_label = "rls"
        self.object_name = "FakeTenant"


class _FakeModel:
    def __init__(self, internal_type):
        self._meta = _FakeMeta(internal_type)


class DefaultsTestCase(unittest.TestCase):
    def test_rls_disabled_by_default(self):
        self.assertFalse(conf.rls_enabled())

    def test_default_session_variable(self):
        self.assertEqual(conf.session_variable(), "django_tenants.tenant_id")

    def test_default_bypass_variable(self):
        self.assertEqual(conf.bypass_variable(), "django_tenants.bypass_rls")

    def test_default_tenant_field(self):
        self.assertEqual(conf.tenant_field(), "tenant")

    def test_force_rls_default_true(self):
        self.assertTrue(conf.force_rls())

    def test_auto_enable_default_true(self):
        self.assertTrue(conf.auto_enable())

    def test_allow_bypass_role_default_false(self):
        # The DB-role bypass safety net is on by default: opting out is explicit.
        self.assertFalse(conf.allow_bypass_role())


class IndividualSettingTestCase(unittest.TestCase):
    @override_settings(TENANT_RLS_ENABLED=True)
    def test_individual_enable(self):
        self.assertTrue(conf.rls_enabled())

    @override_settings(TENANT_RLS_SESSION_VARIABLE="myapp.tenant")
    def test_individual_session_variable(self):
        self.assertEqual(conf.session_variable(), "myapp.tenant")

    @override_settings(TENANT_RLS_FORCE=False)
    def test_individual_force(self):
        self.assertFalse(conf.force_rls())


class DictSettingTestCase(unittest.TestCase):
    @override_settings(DJANGO_TENANTS_RLS={"TENANT_RLS_ENABLED": True})
    def test_dict_enable(self):
        self.assertTrue(conf.rls_enabled())

    @override_settings(DJANGO_TENANTS_RLS={"TENANT_RLS_SESSION_VARIABLE": "d.tenant"})
    def test_dict_session_variable(self):
        self.assertEqual(conf.session_variable(), "d.tenant")

    @override_settings(
        TENANT_RLS_ENABLED=False,
        DJANGO_TENANTS_RLS={"TENANT_RLS_ENABLED": True},
    )
    def test_individual_setting_wins_over_dict(self):
        # Individual top-level setting takes precedence over the dict.
        self.assertFalse(conf.rls_enabled())

    @override_settings(DJANGO_TENANTS_RLS={"TENANT_RLS_FORCE": False})
    def test_dict_wins_over_default(self):
        self.assertFalse(conf.force_rls())


class BadVariableNameTestCase(unittest.TestCase):
    @override_settings(TENANT_RLS_SESSION_VARIABLE="no_dot_here")
    def test_session_variable_without_dot_raises(self):
        with self.assertRaises(ImproperlyConfigured):
            conf.session_variable()

    @override_settings(TENANT_RLS_SESSION_VARIABLE="bad.name; DROP TABLE users")
    def test_session_variable_injection_raises(self):
        with self.assertRaises(ImproperlyConfigured):
            conf.session_variable()

    @override_settings(TENANT_RLS_BYPASS_VARIABLE="too.many.dots")
    def test_bypass_variable_too_many_dots_raises(self):
        with self.assertRaises(ImproperlyConfigured):
            conf.bypass_variable()

    @override_settings(TENANT_RLS_TENANT_FIELD="tenant; DROP TABLE")
    def test_tenant_field_injection_raises(self):
        with self.assertRaises(ImproperlyConfigured):
            conf.tenant_field()


class QuoteLiteralTestCase(unittest.TestCase):
    def test_simple_value(self):
        self.assertEqual(conf._quote_literal("django_tenants.tenant_id"),
                         "'django_tenants.tenant_id'")

    def test_escapes_single_quote(self):
        # Defense in depth: embedded single quotes are doubled.
        self.assertEqual(conf._quote_literal("a'b"), "'a''b'")


class GetTenantPkCastTestCase(unittest.TestCase):
    """Resolve the PK cast by monkeypatching the lazily-imported model getter."""

    def setUp(self):
        from django_tenants import utils
        self._orig_get_tenant_model = utils.get_tenant_model
        self._utils = utils

    def tearDown(self):
        self._utils.get_tenant_model = self._orig_get_tenant_model

    def _patch_pk(self, internal_type):
        self._utils.get_tenant_model = lambda: _FakeModel(internal_type)

    def test_autofield_maps_to_integer(self):
        self._patch_pk("AutoField")
        self.assertEqual(conf.get_tenant_pk_cast(), "integer")

    def test_smallautofield_maps_to_integer(self):
        self._patch_pk("SmallAutoField")
        self.assertEqual(conf.get_tenant_pk_cast(), "integer")

    def test_bigautofield_maps_to_bigint(self):
        self._patch_pk("BigAutoField")
        self.assertEqual(conf.get_tenant_pk_cast(), "bigint")

    def test_bigintegerfield_maps_to_bigint(self):
        self._patch_pk("BigIntegerField")
        self.assertEqual(conf.get_tenant_pk_cast(), "bigint")

    def test_positivebigintegerfield_maps_to_bigint(self):
        self._patch_pk("PositiveBigIntegerField")
        self.assertEqual(conf.get_tenant_pk_cast(), "bigint")

    def test_positivesmallintegerfield_maps_to_integer(self):
        self._patch_pk("PositiveSmallIntegerField")
        self.assertEqual(conf.get_tenant_pk_cast(), "integer")

    def test_uuidfield_maps_to_uuid(self):
        self._patch_pk("UUIDField")
        self.assertEqual(conf.get_tenant_pk_cast(), "uuid")

    def test_charfield_maps_to_text(self):
        # Text-like PKs are legitimately compared as text.
        self._patch_pk("CharField")
        self.assertEqual(conf.get_tenant_pk_cast(), "text")

    def test_slugfield_maps_to_text(self):
        self._patch_pk("SlugField")
        self.assertEqual(conf.get_tenant_pk_cast(), "text")

    def test_unmapped_internal_type_raises(self):
        # D6: we must NOT silently fall back to text -- casting an integer column
        # to text would miscast the comparison and break every RLS query. An
        # unsupported PK type must raise ImproperlyConfigured naming the type.
        self._patch_pk("SomethingExotic")
        with self.assertRaises(ImproperlyConfigured) as cm:
            conf.get_tenant_pk_cast()
        self.assertIn("SomethingExotic", str(cm.exception))

    def test_cast_is_always_in_allowlist(self):
        for internal in ("AutoField", "BigAutoField", "UUIDField", "CharField"):
            self._patch_pk(internal)
            self.assertIn(conf.get_tenant_pk_cast(), conf.ALLOWED_PK_CASTS)
