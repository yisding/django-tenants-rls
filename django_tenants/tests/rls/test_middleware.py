"""Unit tests for ``django_tenants.rls.middleware.TenantRLSMiddleware``.

No database is touched: the ``session`` helpers the middleware calls are replaced
with recording stubs, and a tiny fake request carries ``request.tenant``. We
assert the documented behavior: set the tenant var from ``request.tenant`` on
process_request, clear it on response/exception, FORCE the bypass variable off
at request start (and on response/exception) so a leaked ``bypass=on`` cannot
carry over, and be a no-op when RLS is off.
"""

import unittest

from django.test.utils import override_settings

from django_tenants.rls import middleware as mw


class _Recorder:
    """Records the ordered sequence of session-helper calls.

    ``set_bypass`` is modeled with a tiny ``bypass`` flag so a "leaked" on-state
    from a previous (interrupted) request can be simulated and we can assert the
    middleware drives it back off.
    """

    def __init__(self):
        self.set_calls = []
        self.clear_calls = 0
        self.bypass_calls = []  # ordered list of the value= passed to set_bypass
        self.bypass = False     # simulated current bypass GUC state

    def set_current_tenant(self, connection=None, tenant_id=None, using=None):
        self.set_calls.append(tenant_id)

    def clear_current_tenant(self, connection=None, using=None):
        self.clear_calls += 1

    def set_bypass(self, connection=None, value=True, using=None):
        self.bypass_calls.append(value)
        self.bypass = bool(value)


class _Request:
    def __init__(self, tenant=None):
        self.tenant = tenant


class _Tenant:
    pk = 3


class TenantRLSMiddlewareTestCase(unittest.TestCase):
    def setUp(self):
        self.rec = _Recorder()
        self._orig_set = mw.session.set_current_tenant
        self._orig_clear = mw.session.clear_current_tenant
        self._orig_bypass = mw.session.set_bypass
        mw.session.set_current_tenant = self.rec.set_current_tenant
        mw.session.clear_current_tenant = self.rec.clear_current_tenant
        mw.session.set_bypass = self.rec.set_bypass
        self.middleware = mw.TenantRLSMiddleware(get_response=lambda r: r)

    def tearDown(self):
        mw.session.set_current_tenant = self._orig_set
        mw.session.clear_current_tenant = self._orig_clear
        mw.session.set_bypass = self._orig_bypass

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_process_request_sets_tenant(self):
        tenant = _Tenant()
        self.middleware.process_request(_Request(tenant=tenant))
        self.assertEqual(self.rec.set_calls, [tenant])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_process_request_forces_bypass_off(self):
        # F25: process_request must reset bypass=off at request start.
        self.middleware.process_request(_Request(tenant=_Tenant()))
        self.assertIn(False, self.rec.bypass_calls)
        self.assertFalse(self.rec.bypass)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_leaked_bypass_is_reset_on_next_request(self):
        # F25: simulate a prior request whose bypass_rls().__exit__ never ran,
        # leaving bypass=on on a pooled / persistent connection. The next
        # request's process_request must drive it back off before any query.
        self.rec.bypass = True  # leaked on-state carried over
        self.middleware.process_request(_Request(tenant=_Tenant()))
        self.assertFalse(self.rec.bypass)
        self.assertEqual(self.rec.bypass_calls[-1], False)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_process_response_clears(self):
        self.middleware.process_response(_Request(), object())
        self.assertEqual(self.rec.clear_calls, 1)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_process_response_resets_bypass(self):
        self.rec.bypass = True
        self.middleware.process_response(_Request(), object())
        self.assertFalse(self.rec.bypass)
        self.assertIn(False, self.rec.bypass_calls)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_process_exception_clears(self):
        self.middleware.process_exception(_Request(), Exception("boom"))
        self.assertEqual(self.rec.clear_calls, 1)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_process_exception_resets_bypass(self):
        self.rec.bypass = True
        self.middleware.process_exception(_Request(), Exception("boom"))
        self.assertFalse(self.rec.bypass)
        self.assertIn(False, self.rec.bypass_calls)

    @override_settings(TENANT_RLS_ENABLED=False)
    def test_disabled_is_noop(self):
        self.middleware.process_request(_Request(tenant=_Tenant()))
        self.middleware.process_response(_Request(), object())
        self.middleware.process_exception(_Request(), Exception("boom"))
        self.assertEqual(self.rec.set_calls, [])
        self.assertEqual(self.rec.clear_calls, 0)
        self.assertEqual(self.rec.bypass_calls, [])


if __name__ == "__main__":
    unittest.main()
