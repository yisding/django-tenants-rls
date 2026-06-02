"""Tests for the core ``DjangoTenantsConfig`` RLS-awareness (``apps.py``).

In shared-schema RLS mode there is exactly one schema (``public``) and every
isolated app lives in ``SHARED_APPS``, so an empty ``TENANT_APPS`` is the correct
RLS-only end state. ``DjangoTenantsConfig.ready()`` must therefore NOT reject an
empty ``TENANT_APPS`` when RLS is enabled (it still rejects it otherwise).
"""

import unittest

from django.test.utils import override_settings

from django_tenants.apps import _rls_enabled


class RlsEnabledResolutionTestCase(unittest.TestCase):
    """``_rls_enabled()`` mirrors conf's resolution order, dependency-free."""

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_top_level_true(self):
        self.assertTrue(_rls_enabled())

    @override_settings(TENANT_RLS_ENABLED=False)
    def test_top_level_false_wins_over_dict(self):
        with override_settings(DJANGO_TENANTS_RLS={"TENANT_RLS_ENABLED": True}):
            # Individual top-level setting wins over the grouped dict.
            self.assertFalse(_rls_enabled())

    @override_settings(DJANGO_TENANTS_RLS={"TENANT_RLS_ENABLED": True})
    def test_grouped_dict_true(self):
        self.assertTrue(_rls_enabled())

    def test_absent_defaults_off(self):
        # Neither the top-level setting nor the dict is present in the base test
        # settings, so RLS resolves to off (preserving the non-RLS default).
        self.assertFalse(_rls_enabled())


class EmptyTenantAppsRuleTestCase(unittest.TestCase):
    """The empty-``TENANT_APPS`` guard is only enforced when RLS is OFF.

    Exercises the exact boolean the guard in ``DjangoTenantsConfig.ready()`` uses
    (``not settings.TENANT_APPS and not _rls_enabled()``) without standing up the
    whole app registry.
    """

    @override_settings(TENANT_APPS=(), TENANT_RLS_ENABLED=True)
    def test_empty_tenant_apps_allowed_under_rls(self):
        from django.conf import settings
        guard_would_raise = (not settings.TENANT_APPS) and (not _rls_enabled())
        self.assertFalse(guard_would_raise)

    @override_settings(TENANT_APPS=(), TENANT_RLS_ENABLED=False)
    def test_empty_tenant_apps_rejected_without_rls(self):
        from django.conf import settings
        guard_would_raise = (not settings.TENANT_APPS) and (not _rls_enabled())
        self.assertTrue(guard_would_raise)

    @override_settings(TENANT_APPS=("myapp",), TENANT_RLS_ENABLED=False)
    def test_non_empty_tenant_apps_always_ok(self):
        from django.conf import settings
        guard_would_raise = (not settings.TENANT_APPS) and (not _rls_enabled())
        self.assertFalse(guard_would_raise)


if __name__ == "__main__":
    unittest.main()
