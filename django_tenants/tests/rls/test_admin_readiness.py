"""Tests for the read-only RLS readiness admin dashboard.

These run WITHOUT a live server and WITHOUT a database. The dashboard view
(:func:`django_tenants.rls.admin.rls_readiness_view`) is the in-browser
counterpart of the ``rls_doctor`` command: it calls
:func:`django_tenants.rls.doctor.scan` and renders the result. We drive it with
``RequestFactory`` + a mocked staff user, and patch ``doctor.scan`` so no
Postgres is needed.

We assert the contract that matters for safety:

* an authorised request (active, staff, holding the readiness permission) gets a
  200 response whose context carries the patched scan result;
* an unauthorised request (not staff, or staff lacking the permission, or
  inactive) is rejected -- the view raises ``PermissionDenied`` (the admin's
  behaviour for an authenticated-but-unauthorised staff user);
* the dashboard is strictly READ-ONLY: the view has no POST branch, a POST is
  handled identically to a GET (no mutation), and it never calls any
  RLS-mutating symbol (``enable_rls`` / a ``fix`` path). The page may DISPLAY
  copy-paste commands but must never execute anything.

The view's ``each_context`` call pulls in the admin chrome, so these tests
require ``django.contrib.admin`` (+ auth/contenttypes/sessions/messages) and a
template engine with ``APP_DIRS`` to be configured; when that is not the case
(e.g. a stripped-down bootstrap) the tests skip rather than error.
"""

import inspect
import types
import unittest
from unittest import mock

from django.apps import apps as django_apps
from django.test import RequestFactory, SimpleTestCase
from django.test.utils import override_settings


REQUIRED_APPS = (
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
)


def _admin_available():
    return all(django_apps.is_installed(app) for app in REQUIRED_APPS)


def _make_user(*, is_staff=True, is_active=True, perm=True, is_superuser=False):
    """A mock user that satisfies the readiness gate AND admin ``each_context``.

    ``has_module_perms`` returns False so ``AdminSite.each_context`` builds an
    empty app list (it does not need a real DB-backed user); ``has_perm`` drives
    the readiness permission gate.
    """
    user = mock.Mock(name="user")
    user.is_active = is_active
    user.is_staff = is_staff
    user.is_superuser = is_superuser
    user.is_authenticated = True
    user.has_perm.return_value = perm
    user.has_perms.return_value = perm
    user.has_module_perms.return_value = False
    return user


def _fake_scan(*, blocked=False):
    return {
        "rls_enabled": True,
        "database": "default",
        "settings": [
            {"id": "W001", "level": "warning", "title": "wrong ENGINE",
             "detail": "use the rls backend", "remedy": "set ENGINE", "step": 1},
        ],
        "models": [
            {"label": "shop.Order", "table": "shop_order",
             "classification": "done", "problems": [],
             "unscoped_rows": False, "remedy": "already protected", "step": 6},
            {"label": "shop.Legacy", "table": "shop_legacy",
             "classification": "generate_migration",
             "problems": ["tenant column is nullable"],
             "unscoped_rows": False, "remedy": "add a staged FK migration",
             "step": 3},
        ],
        "summary": {"done": 1, "auto_fixable": 0, "generate_migration": 1,
                    "manual": 0, "blocked": 0},
        "blocked": blocked,
    }


@unittest.skipUnless(
    _admin_available(),
    "requires django.contrib.admin (+ auth/contenttypes) to be installed",
)
@override_settings(TENANT_RLS_ENABLED=True)
class RlsReadinessViewTestCase(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        from django_tenants.rls import admin as rls_admin
        self.rls_admin = rls_admin

    # --- authorisation gate ------------------------------------------------

    def test_authorised_staff_with_permission_gets_200_and_scan(self):
        scan = _fake_scan()
        request = self.factory.get("/admin/rls-readiness/")
        request.user = _make_user()
        with mock.patch(
            "django_tenants.rls.doctor.scan", return_value=scan
        ) as scan_mock:
            response = self.rls_admin.rls_readiness_view(request)
        self.assertEqual(response.status_code, 200)
        scan_mock.assert_called_once()
        # The patched scan flows into the template context untouched.
        self.assertIs(response.context_data["report"], scan)
        self.assertEqual(response.template_name, self.rls_admin.RLS_READINESS_TEMPLATE)

    def test_database_query_param_is_forwarded_to_scan(self):
        request = self.factory.get("/admin/rls-readiness/?database=replica")
        request.user = _make_user()
        with mock.patch(
            "django_tenants.rls.doctor.scan", return_value=_fake_scan()
        ) as scan_mock:
            self.rls_admin.rls_readiness_view(request)
        _, kwargs = scan_mock.call_args
        passed = kwargs.get("database")
        if passed is None and scan_mock.call_args.args:
            passed = scan_mock.call_args.args[0]
        self.assertEqual(passed, "replica")

    def test_non_staff_user_is_rejected(self):
        from django.core.exceptions import PermissionDenied

        request = self.factory.get("/admin/rls-readiness/")
        request.user = _make_user(is_staff=False)
        with mock.patch(
            "django_tenants.rls.doctor.scan", return_value=_fake_scan()
        ) as scan_mock:
            with self.assertRaises(PermissionDenied):
                self.rls_admin.rls_readiness_view(request)
        # Rejected BEFORE scanning -- no work is done for an unauthorised user.
        scan_mock.assert_not_called()

    def test_staff_without_permission_is_rejected(self):
        from django.core.exceptions import PermissionDenied

        request = self.factory.get("/admin/rls-readiness/")
        request.user = _make_user(is_staff=True, perm=False)
        with mock.patch(
            "django_tenants.rls.doctor.scan", return_value=_fake_scan()
        ) as scan_mock:
            with self.assertRaises(PermissionDenied):
                self.rls_admin.rls_readiness_view(request)
        scan_mock.assert_not_called()

    def test_inactive_user_is_rejected(self):
        from django.core.exceptions import PermissionDenied

        request = self.factory.get("/admin/rls-readiness/")
        request.user = _make_user(is_active=False)
        with mock.patch(
            "django_tenants.rls.doctor.scan", return_value=_fake_scan()
        ):
            with self.assertRaises(PermissionDenied):
                self.rls_admin.rls_readiness_view(request)

    # --- read-only contract ------------------------------------------------

    def test_view_has_no_post_handling(self):
        # The view must not branch on the request method or read POST data:
        # there is no apply/fix action by construction.
        src = inspect.getsource(self.rls_admin.rls_readiness_view)
        self.assertNotIn("request.POST", src)
        self.assertNotIn('request.method', src)

    def test_post_is_handled_identically_and_does_not_mutate(self):
        # Even if a POST reaches the view, it is read-only: it returns the same
        # 200 dashboard and performs no mutation.
        request = self.factory.post("/admin/rls-readiness/", {"apply": "1"})
        request.user = _make_user()
        with mock.patch(
            "django_tenants.rls.doctor.scan", return_value=_fake_scan()
        ) as scan_mock:
            response = self.rls_admin.rls_readiness_view(request)
        self.assertEqual(response.status_code, 200)
        scan_mock.assert_called_once()

    def test_view_never_calls_a_mutating_symbol(self):
        # Guard against accidental wiring of an apply path: the view touches
        # doctor.scan and nothing that would enable RLS or run a fix.
        request = self.factory.get("/admin/rls-readiness/")
        request.user = _make_user()
        with mock.patch(
            "django_tenants.rls.doctor.scan", return_value=_fake_scan()
        ):
            # If the module exposed an apply/fix/enable helper, ensure the view
            # does not call it. Patch any such names defensively; absence is fine.
            patchers = []
            for name in ("enable_rls_for", "apply_fix", "fix", "enable_rls"):
                if hasattr(self.rls_admin, name):
                    p = mock.patch.object(self.rls_admin, name)
                    patchers.append((name, p, p.start()))
            try:
                self.rls_admin.rls_readiness_view(request)
            finally:
                for _name, p, _m in patchers:
                    p.stop()
            for name, _p, m in patchers:
                m.assert_not_called()

    def test_blocked_scan_is_passed_through_for_display(self):
        scan = _fake_scan(blocked=True)
        request = self.factory.get("/admin/rls-readiness/")
        request.user = _make_user()
        with mock.patch("django_tenants.rls.doctor.scan", return_value=scan):
            response = self.rls_admin.rls_readiness_view(request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context_data["report"]["blocked"])

    def test_displayed_commands_never_include_an_apply_url(self):
        # The page DISPLAYS copy-paste manage.py commands; they are shell
        # commands the operator runs, not anything the page executes.
        request = self.factory.get("/admin/rls-readiness/")
        request.user = _make_user()
        with mock.patch("django_tenants.rls.doctor.scan", return_value=_fake_scan()):
            response = self.rls_admin.rls_readiness_view(request)
        commands = response.context_data.get("commands") or []
        self.assertTrue(commands)
        for label, cmd in commands:
            # Commands are CLI strings (manage.py ...), not HTTP actions.
            self.assertIn("manage.py", cmd)


@unittest.skipUnless(
    _admin_available(),
    "requires django.contrib.admin (+ auth/contenttypes) to be installed",
)
@override_settings(TENANT_RLS_ENABLED=True)
class RegisterRlsAdminTestCase(SimpleTestCase):
    """``register_rls_admin`` wires a single read-only GET URL into the admin."""

    def test_register_adds_named_admin_url_and_renders(self):
        from django.contrib import admin as django_admin
        from django.urls import clear_url_caches, path, reverse

        from django_tenants.rls.admin import register_rls_admin

        site = django_admin.AdminSite(name="rls_test_admin")
        register_rls_admin(site)

        # Build a throwaway urlconf hosting this site, and point ROOT_URLCONF at
        # it so reverse()/the URL resolver can find the readiness view.
        urlconf = types.ModuleType("_rls_readiness_test_urls")
        urlconf.urlpatterns = [path("admin/", site.urls)]
        import sys
        sys.modules["_rls_readiness_test_urls"] = urlconf
        try:
            with override_settings(ROOT_URLCONF="_rls_readiness_test_urls"):
                clear_url_caches()
                url = reverse("%s:rls_readiness" % site.name)
                self.assertEqual(url, "/admin/rls-readiness/")

                request = RequestFactory().get(url)
                request.user = _make_user()
                from django_tenants.rls import admin as rls_admin
                with mock.patch(
                    "django_tenants.rls.doctor.scan", return_value=_fake_scan()
                ):
                    response = rls_admin.rls_readiness_view(
                        request, admin_site=site
                    )
                    rendered = response.render()
                body = rendered.content.decode()
                self.assertEqual(rendered.status_code, 200)
                # The scan content is actually rendered into the page.
                self.assertIn("shop.Order", body)
                self.assertIn("shop.Legacy", body)
                # The read-only rationale is visible to the operator.
                self.assertIn("read-only", body)
        finally:
            sys.modules.pop("_rls_readiness_test_urls", None)
            clear_url_caches()

    def test_registered_content_block_has_no_apply_form(self):
        # The page's OWN content block (not the admin chrome's logout form) must
        # contain no form / apply / fix button: the dashboard cannot mutate.
        from django.template.loader import get_template
        from django_tenants.rls.admin import RLS_READINESS_TEMPLATE

        template = get_template(RLS_READINESS_TEMPLATE)
        source = template.template.source
        # Isolate the content block to ignore inherited admin chrome.
        start = source.find("{% block content %}")
        self.assertNotEqual(start, -1)
        content_block = source[start:]
        lowered = content_block.lower()
        self.assertNotIn("<form", lowered)
        self.assertNotIn('method="post"', lowered)
        self.assertNotIn("apply", lowered)


if __name__ == "__main__":
    unittest.main()
