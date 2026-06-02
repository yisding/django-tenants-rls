"""Unit tests for ``django_tenants.rls.backend.base.DatabaseWrapper``.

The security-critical part of the backend is the per-cursor re-assertion of the
RLS session variables. That logic lives in ``_rls_session_params()`` -- a pure,
``super()``-free helper that returns ``(sql, params)`` (or ``None`` when RLS is
off) -- precisely so it can be exercised here without a live database or the real
``super()._cursor()`` chain. We assert:

* with ``TENANT_RLS_ENABLED=False`` the helper returns ``None`` (the caller then
  emits NO ``set_config`` -- byte-for-byte passthrough of the parent cursor);
* with it ``True`` and a remembered ``_rls_tenant_id`` the helper returns exactly
  one combined ``set_config`` round-trip that sets the tenant var to the pk AND
  sets the bypass var from the connection's ``_rls_bypass`` flag -- ``off`` by
  default and ``on`` while a ``bypass_rls()`` block is active (the regression that
  guards against the per-cursor re-assertion silently defeating ``bypass_rls()``);
* a pk-less / ``FakeTenant`` collapses to the ``''`` sentinel via ``_is_fake``.
"""

import unittest

from django.test.utils import override_settings

from django_tenants.postgresql_backend.base import FakeTenant
from django_tenants.rls import conf
from django_tenants.rls.backend import base as backend_base


class _ParamsStub:
    """Minimal carrier for the connection attributes ``_rls_session_params`` reads.

    The real method uses no ``super()`` and only touches ``SET_RLS_SESSION_SQL``,
    ``_rls_tenant_id`` and ``_rls_bypass``, so binding it onto this stub exercises
    the production logic exactly, without constructing a real DatabaseWrapper.
    """

    SET_RLS_SESSION_SQL = backend_base.DatabaseWrapper.SET_RLS_SESSION_SQL
    _rls_session_params = backend_base.DatabaseWrapper._rls_session_params

    def __init__(self, tenant_id="", bypass=False):
        self._rls_tenant_id = tenant_id
        self._rls_bypass = bypass


class SessionParamsDisabledTestCase(unittest.TestCase):
    @override_settings(TENANT_RLS_ENABLED=False)
    def test_disabled_returns_none(self):
        # None signals the caller to make no set_config call at all.
        self.assertIsNone(_ParamsStub()._rls_session_params())


class SessionParamsEnabledTestCase(unittest.TestCase):
    @override_settings(TENANT_RLS_ENABLED=True)
    def test_sets_tenant_and_bypass_off_by_default(self):
        sql, params = _ParamsStub(tenant_id="42")._rls_session_params()
        self.assertEqual(sql, backend_base.DatabaseWrapper.SET_RLS_SESSION_SQL)
        self.assertEqual(
            params,
            [conf.session_variable(), "42", conf.bypass_variable(), "off"],
        )

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_no_tenant_uses_empty_sentinel(self):
        _sql, params = _ParamsStub(tenant_id="")._rls_session_params()
        self.assertEqual(params[1], "")  # tenant var value is the '' sentinel
        self.assertEqual(params[3], "off")  # bypass off by default

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_bypass_flag_emits_on(self):
        # Regression guard: when a bypass_rls() block has flipped the connection's
        # _rls_bypass flag True, the per-cursor re-assertion MUST emit 'on'. If it
        # ever hard-coded 'off' again, every query inside bypass_rls() would run
        # isolated and the bypass would be silently defeated.
        _sql, params = _ParamsStub(tenant_id="42", bypass=True)._rls_session_params()
        self.assertEqual(params[1], "42")
        self.assertEqual(params[3], "on")  # bypass honored, not clobbered to off


class _FakeRealTenant:
    schema_name = "acme"
    pk = 7


class IsFakeTestCase(unittest.TestCase):
    """``_is_fake`` decides whether a tenant collapses to the '' sentinel."""

    def test_fake_tenant_is_fake(self):
        self.assertTrue(backend_base._is_fake(FakeTenant(schema_name="public")))

    def test_pk_less_object_is_fake(self):
        class NoPk:
            pk = None

        self.assertTrue(backend_base._is_fake(NoPk()))

    def test_real_tenant_is_not_fake(self):
        self.assertFalse(backend_base._is_fake(_FakeRealTenant()))


if __name__ == "__main__":
    unittest.main()
