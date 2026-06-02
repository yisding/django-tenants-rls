"""Fallback middleware for django-tenants shared-schema RLS mode.

This middleware is for setups that keep the stock
``django_tenants.postgresql_backend`` database ENGINE (i.e. are NOT using the
RLS backend at ``django_tenants.rls.backend``) but still want row-level-security
tenant isolation. It sets the tenant session variable from ``request.tenant``
after ``TenantMainMiddleware`` has resolved it, and clears it again when the
response (or an exception) finishes the request. It also forces the bypass
session variable off at request start (and again on response/exception) so a
leaked ``bypass=on`` from a prior request's interrupted ``bypass_rls()`` block
cannot carry over on a pooled / persistent connection.

Place this middleware AFTER ``TenantMainMiddleware`` in ``MIDDLEWARE``.

When the RLS backend is in use this middleware is redundant: the backend's
``_cursor`` already applies the tenant session variable on every cursor.
It remains harmless in that case (the backend re-applies the value on the next
request's first cursor anyway), so it can be left installed.

Every behavior here is gated on ``conf.rls_enabled()`` so installs with RLS
disabled get a zero-cost no-op. The underlying ``session`` helpers swallow
errors-in-transaction, so this middleware never raises from setting/clearing
the session variable.
"""

from django.utils.deprecation import MiddlewareMixin

from . import conf
from . import session


class TenantRLSMiddleware(MiddlewareMixin):
    """Set/clear the tenant RLS session variable around each request.

    Should be placed AFTER ``django_tenants.middleware.TenantMainMiddleware``
    so that ``request.tenant`` is already resolved. Safe no-op when RLS is
    disabled or when the request has no tenant (the ``''`` sentinel makes the
    policy evaluate false, hiding all rows).
    """

    def process_request(self, request):
        if not conf.rls_enabled():
            return
        # FORCE bypass off at request start. On the stock backend a pooled /
        # persistent connection whose ``bypass_rls().__exit__`` never ran (e.g.
        # the process died mid-block) could carry a leaked ``bypass=on`` into the
        # next request, defeating isolation. Resetting it here closes that gap;
        # the RLS backend re-asserts state per cursor anyway, so this is harmless
        # there.
        session.set_bypass(connection=None, value=False)
        tenant = getattr(request, "tenant", None)
        # ``set_current_tenant`` coerces None / FakeTenant / pk-less instances
        # to the '' sentinel, which is secure-by-default (no rows visible).
        session.set_current_tenant(connection=None, tenant_id=tenant)

    def process_response(self, request, response):
        if conf.rls_enabled():
            session.clear_current_tenant()
            session.set_bypass(connection=None, value=False)
        return response

    def process_exception(self, request, exception):
        if conf.rls_enabled():
            session.clear_current_tenant()
            session.set_bypass(connection=None, value=False)
        return None
