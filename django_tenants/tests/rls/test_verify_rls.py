"""Unit tests for the ``verify_rls`` management command (CI RLS gate).

These run without a database. The command delegates the per-model introspection
to ``checks.rls_live_problems`` and the model discovery to
``checks._iter_concrete_rls_models``; both are mocked here, and the connection is
stubbed, so no live Postgres is needed. We assert the exit contract:

* all models report no problems  -> exit 0 (no SystemExit)
* any model reports a problem     -> SystemExit(1)
* the introspection helper raises -> SystemExit(1) (cannot verify == fail in CI)
"""

import io
import unittest
from unittest import mock

from django.core.management import call_command
from django.test import SimpleTestCase
from django.test.utils import override_settings


class _FakeMeta:
    def __init__(self, label, db_table):
        self.label = label
        self.db_table = db_table
        self.abstract = False


class _FakeModel:
    def __init__(self, label, db_table):
        self._meta = _FakeMeta(label, db_table)


def _run(monkeypatched_problems=None, models=None, side_effect=None):
    """Call verify_rls with the helper/iterator/connection patched out.

    Returns (raised_systemexit_code_or_None, stdout, stderr).
    """
    if models is None:
        models = [_FakeModel("app.Widget", "app_widget")]

    out, err = io.StringIO(), io.StringIO()

    helper_kwargs = {}
    if side_effect is not None:
        helper_kwargs["side_effect"] = side_effect
    else:
        # rls_live_problems(model, connection, *, force) -> list of problems.
        helper_kwargs["side_effect"] = (
            lambda model, connection, *, force: list(monkeypatched_problems or [])
        )

    code = None
    with mock.patch(
        "django_tenants.rls.checks._iter_concrete_rls_models",
        return_value=iter(models),
    ), mock.patch(
        "django_tenants.rls.checks.rls_live_problems", **helper_kwargs
    ), mock.patch(
        "django.db.connections", {"default": object()}
    ):
        try:
            call_command("verify_rls", stdout=out, stderr=err)
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


@override_settings(TENANT_RLS_ENABLED=True, TENANT_RLS_FORCE=True)
class VerifyRlsCommandTestCase(SimpleTestCase):
    def test_exits_zero_when_all_good(self):
        code, out, err = _run(monkeypatched_problems=[])
        self.assertIsNone(code)  # no SystemExit -> success
        self.assertIn("OK app.Widget", out)
        self.assertIn("verify_rls OK", out)

    def test_exits_one_when_problem_reported(self):
        code, out, err = _run(
            monkeypatched_problems=["RLS not enabled on table 'app_widget'"]
        )
        self.assertEqual(code, 1)
        self.assertIn("PROBLEM app.Widget", out)
        self.assertIn("RLS not enabled", out)
        self.assertIn("verify_rls FAILED", err)

    def test_exits_one_when_helper_raises(self):
        # An introspection error is a HARD failure for the CI command (unlike the
        # best-effort W004 system check which swallows it).
        code, out, err = _run(side_effect=RuntimeError("relation does not exist"))
        self.assertEqual(code, 1)
        self.assertIn("PROBLEM app.Widget", out)
        self.assertIn("could not verify RLS", out)

    def test_one_bad_model_fails_even_with_good_ones(self):
        good = _FakeModel("app.Good", "app_good")
        bad = _FakeModel("app.Bad", "app_bad")

        def helper(model, connection, *, force):
            if model._meta.label == "app.Bad":
                return ["no RLS policy exists for table 'app_bad'"]
            return []

        with mock.patch(
            "django_tenants.rls.checks._iter_concrete_rls_models",
            return_value=iter([good, bad]),
        ), mock.patch(
            "django_tenants.rls.checks.rls_live_problems", side_effect=helper
        ), mock.patch(
            "django.db.connections", {"default": object()}
        ):
            out = io.StringIO()
            with self.assertRaises(SystemExit) as cm:
                call_command("verify_rls", stdout=out)
            self.assertEqual(cm.exception.code, 1)
            self.assertIn("OK app.Good", out.getvalue())
            self.assertIn("PROBLEM app.Bad", out.getvalue())

    def test_no_models_is_success(self):
        code, out, err = _run(models=[])
        self.assertIsNone(code)
        self.assertIn("No concrete TenantRLSModel", out)

    def test_database_option_selects_alias(self):
        # --database must pick the connection by alias; using an alias that is
        # NOT present would KeyError, so verify the chosen alias is consulted.
        sentinel = object()
        captured = {}

        def helper(model, connection, *, force):
            captured["connection"] = connection
            return []

        with mock.patch(
            "django_tenants.rls.checks._iter_concrete_rls_models",
            return_value=iter([_FakeModel("app.Widget", "app_widget")]),
        ), mock.patch(
            "django_tenants.rls.checks.rls_live_problems", side_effect=helper
        ), mock.patch(
            "django.db.connections", {"default": object(), "replica": sentinel}
        ):
            out = io.StringIO()
            call_command("verify_rls", "--database", "replica", stdout=out)
        self.assertIs(captured["connection"], sentinel)


if __name__ == "__main__":
    unittest.main()
