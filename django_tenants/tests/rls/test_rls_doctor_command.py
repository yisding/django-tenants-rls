"""Unit tests for the ``rls_doctor`` management command (migration assistant).

These run WITHOUT a database. ``rls_doctor`` is a thin CLI over
``django_tenants.rls.doctor.scan()``: it groups the scan result into a readable
report, honours a CI exit-code contract, can auto-apply ONLY the provably-safe
slice (``--fix``), can write migration/SQL scaffolds (``--generate``), and can
emit the raw scan as JSON (``--format json``). We mock ``doctor.scan`` so the
command's *orchestration* (exit codes, the ``--fix`` refusals, the safe-apply
path, scaffold file writing, JSON output) is asserted directly with no live
Postgres and without coupling to the scan internals.

The single source of truth the command consumes is the scan dict described in
``doctor.scan``::

    {"rls_enabled", "database", "settings": [...], "models": [...],
     "summary": {classification: n, ...}, "blocked": bool}

EXIT-CODE contract under test: a scan-only run exits 0 only when there are zero
non-"done" model items AND no error-level settings; otherwise it exits 1 (so it
is CI-usable). ``--fix`` re-scans after fixing and applies the same rule, but
REFUSES (non-zero, with a message) if the scan is blocked (W003 role bypass) or a
target model has unscoped (NULL) rows that need a backfill first.
"""

import io
import json
import os
import tempfile
import unittest
from unittest import mock

from django.core.management import CommandError, call_command
from django.test import SimpleTestCase
from django.test.utils import override_settings


# --- scan-dict builders ----------------------------------------------------
# Small helpers so each test states only what it cares about. Mirrors the
# doctor.scan() contract; the command must not depend on extra keys.


def _model(label, classification, *, table=None, problems=None,
           unscoped_rows=False, remedy="do the thing", step=6):
    return {
        "label": label,
        "table": table or label.replace(".", "_").lower(),
        "classification": classification,
        "problems": list(problems or []),
        "unscoped_rows": unscoped_rows,
        "remedy": remedy,
        "step": step,
    }


def _setting(sid, level, *, title="t", detail="d", remedy="r", step=1):
    return {
        "id": sid,
        "level": level,
        "title": title,
        "detail": detail,
        "remedy": remedy,
        "step": step,
    }


def _scan(*, rls_enabled=True, database="default", settings=None, models=None,
          blocked=False):
    models = list(models or [])
    summary = {
        "done": 0,
        "auto_fixable": 0,
        "generate_migration": 0,
        "manual": 0,
        "blocked": 0,
    }
    for m in models:
        summary[m["classification"]] = summary.get(m["classification"], 0) + 1
    return {
        "rls_enabled": rls_enabled,
        "database": database,
        "settings": list(settings or []),
        "models": models,
        "summary": summary,
        "blocked": blocked,
    }


def _call(scan_result=None, *, scan_side_effect=None, argv=(), **kwargs):
    """Run ``rls_doctor`` with ``doctor.scan`` patched.

    ``scan_result`` may be a single dict (used for every scan call) or a list of
    dicts (used in order -- the FIRST is the pre-fix scan, the SECOND the
    post-fix re-scan). Returns (systemexit_code_or_None, stdout, stderr, scan_mock).
    """
    out, err = io.StringIO(), io.StringIO()

    patch_kwargs = {}
    if scan_side_effect is not None:
        patch_kwargs["side_effect"] = scan_side_effect
    elif isinstance(scan_result, (list, tuple)):
        patch_kwargs["side_effect"] = list(scan_result)
    else:
        patch_kwargs["return_value"] = scan_result

    code = None
    with mock.patch("django_tenants.rls.doctor.scan", **patch_kwargs) as scan_mock:
        try:
            call_command("rls_doctor", *argv, stdout=out, stderr=err, **kwargs)
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue(), scan_mock


@override_settings(TENANT_RLS_ENABLED=True)
class RlsDoctorReportTestCase(SimpleTestCase):
    """Default (report) mode: grouped output + exit-code contract."""

    def test_exits_zero_when_everything_done(self):
        scan = _scan(models=[
            _model("app.Widget", "done"),
            _model("app.Gadget", "done"),
        ])
        code, out, err, scan_mock = _call(scan)
        self.assertIsNone(code)  # no SystemExit -> success
        scan_mock.assert_called_once()

    def test_exits_one_when_a_model_is_not_done(self):
        scan = _scan(models=[
            _model("app.Widget", "done"),
            _model("app.Gadget", "auto_fixable"),
        ])
        code, out, err, _ = _call(scan)
        self.assertEqual(code, 1)

    def test_exits_one_on_error_level_setting_even_if_models_done(self):
        # Error-level settings finding (e.g. E001/E002) fails CI on its own.
        scan = _scan(
            models=[_model("app.Widget", "done")],
            settings=[_setting("E001", "error", title="bad GUC name")],
        )
        code, out, err, _ = _call(scan)
        self.assertEqual(code, 1)

    def test_warning_setting_alone_does_not_fail(self):
        # A warning-level settings finding with all models done is still green.
        scan = _scan(
            models=[_model("app.Widget", "done")],
            settings=[_setting("W001", "warning", title="wrong ENGINE")],
        )
        code, out, err, _ = _call(scan)
        self.assertIsNone(code)

    def test_report_groups_and_shows_remedy_and_doc_step(self):
        scan = _scan(models=[
            _model(
                "app.Gadget", "generate_migration",
                problems=["tenant column is nullable"],
                remedy="add a staged tenant FK migration",
                step=3,
            ),
        ])
        code, out, err, _ = _call(scan)
        self.assertEqual(code, 1)
        # The item's label, its problem, its remedy and a doc pointer to the
        # step all appear in the report.
        self.assertIn("app.Gadget", out)
        self.assertIn("tenant column is nullable", out)
        self.assertIn("add a staged tenant FK migration", out)
        self.assertIn("rls_migration.rst", out)
        self.assertIn("step 3", out.lower())

    def test_report_surfaces_blocked_loudly(self):
        scan = _scan(
            models=[_model("app.Widget", "blocked")],
            blocked=True,
        )
        code, out, err, _ = _call(scan)
        self.assertEqual(code, 1)
        combined = (out + err).lower()
        self.assertIn("blocked", combined)

    def test_database_option_is_forwarded_to_scan(self):
        scan = _scan(database="replica", models=[_model("app.W", "done")])
        code, out, err, scan_mock = _call(scan, argv=("--database", "replica"))
        self.assertIsNone(code)
        # scan(database=...) must receive the requested alias (kwarg or positional).
        _, kwargs = scan_mock.call_args
        passed = kwargs.get("database")
        if passed is None and scan_mock.call_args.args:
            passed = scan_mock.call_args.args[0]
        self.assertEqual(passed, "replica")


@override_settings(TENANT_RLS_ENABLED=True)
class RlsDoctorJsonTestCase(SimpleTestCase):
    """``--format json`` dumps the scan dict verbatim for tooling."""

    def test_json_is_parseable_and_matches_scan(self):
        scan = _scan(
            models=[
                _model("app.Widget", "done"),
                _model("app.Gadget", "auto_fixable"),
            ],
            settings=[_setting("W001", "warning")],
        )
        # capture the SAME stream the command writes JSON to.
        code, out, err, _ = _call(scan, argv=("--format", "json"))
        # JSON mode still honours the exit contract (a non-done model -> 1).
        self.assertEqual(code, 1)
        parsed = json.loads(out)
        self.assertEqual(parsed["database"], scan["database"])
        self.assertEqual(parsed["summary"]["done"], 1)
        self.assertEqual(parsed["summary"]["auto_fixable"], 1)
        self.assertEqual(len(parsed["models"]), 2)
        self.assertEqual(parsed["settings"][0]["id"], "W001")

    def test_json_all_done_exits_zero(self):
        scan = _scan(models=[_model("app.Widget", "done")])
        code, out, err, _ = _call(scan, argv=("--format", "json"))
        self.assertIsNone(code)
        self.assertEqual(json.loads(out)["summary"]["done"], 1)


@override_settings(TENANT_RLS_ENABLED=True)
class RlsDoctorFixTestCase(SimpleTestCase):
    """``--fix`` applies ONLY the safe slice and refuses on danger."""

    def _model_obj(self, label, *, has_unscoped=False):
        """A fake model whose enable_rls/has_unscoped_rows are recorded."""
        m = mock.Mock(name=label)
        m._meta = mock.Mock()
        m._meta.label = label
        m._meta.db_table = label.replace(".", "_").lower()
        m.has_unscoped_rows.return_value = has_unscoped
        return m

    def test_fix_refuses_when_blocked(self):
        # W003: the connecting role bypasses RLS -> enforcement is theatre, and
        # --fix MUST refuse (non-zero) without touching any model.
        scan = _scan(
            models=[_model("app.Widget", "auto_fixable")],
            blocked=True,
        )
        widget = self._model_obj("app.Widget")
        with mock.patch(
            "django_tenants.rls.checks._iter_concrete_rls_models",
            return_value=iter([widget]),
        ):
            code, out, err, scan_mock = _call(scan, argv=("--fix",))
        self.assertNotEqual(code, None)
        self.assertNotEqual(code, 0)
        widget.enable_rls.assert_not_called()
        # The refusal must name the reason (the role bypasses RLS); the command
        # exits before printing the full report banner.
        combined = (out + err).lower()
        self.assertIn("refused", combined)
        self.assertIn("bypass", combined)
        # It must NOT re-scan after refusing (nothing was changed).
        scan_mock.assert_called_once()

    def test_fix_refuses_when_target_has_unscoped_rows(self):
        # A model classified auto_fixable but reporting unscoped rows at apply
        # time needs a backfill (Step 4 -- DANGEROUS): refuse, do not enable.
        scan = _scan(models=[_model("app.Widget", "auto_fixable")])
        widget = self._model_obj("app.Widget", has_unscoped=True)
        with mock.patch(
            "django_tenants.rls.checks._iter_concrete_rls_models",
            return_value=iter([widget]),
        ):
            code, out, err, _ = _call(scan, argv=("--fix",))
        self.assertNotEqual(code, 0)
        self.assertIsNotNone(code)
        widget.enable_rls.assert_not_called()
        combined = (out + err).lower()
        self.assertTrue(
            "unscoped" in combined or "backfill" in combined or "null" in combined,
            "refusal must explain the unscoped-rows reason; got:\n%s" % (out + err),
        )

    def test_fix_enables_rls_for_auto_fixable_models(self):
        # Pre-fix scan has one auto_fixable; after enable_rls the re-scan is clean.
        pre = _scan(models=[
            _model("app.Widget", "auto_fixable"),
            _model("app.Other", "done"),
        ])
        post = _scan(models=[
            _model("app.Widget", "done"),
            _model("app.Other", "done"),
        ])
        widget = self._model_obj("app.Widget")
        other = self._model_obj("app.Other")
        with mock.patch(
            "django_tenants.rls.checks._iter_concrete_rls_models",
            return_value=iter([widget, other]),
        ):
            code, out, err, scan_mock = _call([pre, post], argv=("--fix",))
        # Only the auto_fixable model was enabled.
        widget.enable_rls.assert_called_once_with()
        other.enable_rls.assert_not_called()
        # Re-scanned after fixing (post scan was clean) -> success.
        self.assertEqual(scan_mock.call_count, 2)
        self.assertIsNone(code)

    def test_fix_rescans_and_still_fails_when_residual_problems(self):
        # auto_fixable enabled, but a SEPARATE model still needs a migration:
        # the post-fix re-scan keeps the command red.
        pre = _scan(models=[
            _model("app.Widget", "auto_fixable"),
            _model("app.Legacy", "generate_migration",
                   problems=["missing tenant FK"], step=3),
        ])
        post = _scan(models=[
            _model("app.Widget", "done"),
            _model("app.Legacy", "generate_migration",
                   problems=["missing tenant FK"], step=3),
        ])
        widget = self._model_obj("app.Widget")
        legacy = self._model_obj("app.Legacy")
        with mock.patch(
            "django_tenants.rls.checks._iter_concrete_rls_models",
            return_value=iter([widget, legacy]),
        ):
            code, out, err, scan_mock = _call([pre, post], argv=("--fix",))
        widget.enable_rls.assert_called_once_with()
        legacy.enable_rls.assert_not_called()
        self.assertEqual(code, 1)
        self.assertEqual(scan_mock.call_count, 2)

    def test_fix_with_nothing_fixable_is_noop_but_honours_contract(self):
        # No auto_fixable items; a generate_migration item keeps it red, and no
        # model is enabled.
        scan = _scan(models=[
            _model("app.Legacy", "generate_migration",
                   problems=["nullable tenant column"], step=5),
        ])
        legacy = self._model_obj("app.Legacy")
        with mock.patch(
            "django_tenants.rls.checks._iter_concrete_rls_models",
            return_value=iter([legacy]),
        ):
            code, out, err, _ = _call(scan, argv=("--fix",))
        legacy.enable_rls.assert_not_called()
        self.assertEqual(code, 1)


@override_settings(TENANT_RLS_ENABLED=True)
class RlsDoctorGenerateTestCase(SimpleTestCase):
    """``--generate [DIR]`` writes scaffolds; never into real migrations dirs."""

    def _model_obj(self, label):
        m = mock.Mock(name=label)
        m._meta = mock.Mock()
        m._meta.label = label
        m._meta.object_name = label.split(".")[-1]
        m._meta.db_table = label.replace(".", "_").lower()
        m.has_unscoped_rows.return_value = False
        return m

    def test_generate_writes_files_for_generate_migration_items(self):
        scan = _scan(models=[
            _model("app.Legacy", "generate_migration",
                   problems=["missing tenant FK"], step=3),
            _model("app.Widget", "done"),
        ])
        legacy = self._model_obj("app.Legacy")
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = os.path.join(tmp, "rls_scaffold")
            with mock.patch(
                "django_tenants.rls.checks._iter_concrete_rls_models",
                return_value=iter([legacy]),
            ), mock.patch(
                "django_tenants.rls.checks._unique_fieldsets",
                return_value=[],
            ), mock.patch(
                "django_tenants.rls.scaffold.staged_fk_migration",
                return_value="# staged fk migration\n",
            ) as staged, mock.patch(
                "django_tenants.rls.scaffold.enable_rls_migration",
                return_value="# enable rls migration\n",
            ), mock.patch(
                "django_tenants.rls.scaffold.unique_constraint_migration",
                return_value="# unique fix\n",
            ):
                code, out, err, _ = _call(scan, argv=("--generate", out_dir))
            # At least one scaffold generator was invoked for the legacy model.
            staged.assert_called()
            # Files were written under the requested dir (and not into any real
            # app migrations/ directory).
            self.assertTrue(os.path.isdir(out_dir))
            written = []
            for root, _dirs, files in os.walk(out_dir):
                written.extend(os.path.join(root, f) for f in files)
            self.assertTrue(written, "expected scaffold files to be written")
            # Each written path is printed so the human can find it.
            for path in written:
                self.assertIn(os.path.basename(path), out)
            # Generated content reached disk.
            blob = ""
            for path in written:
                with open(path) as fh:
                    blob += fh.read()
            self.assertIn("migration", blob.lower())

    def test_generate_uses_default_dir_when_none_given(self):
        scan = _scan(models=[
            _model("app.Legacy", "generate_migration",
                   problems=["missing tenant FK"], step=3),
        ])
        legacy = self._model_obj("app.Legacy")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "django_tenants.rls.checks._iter_concrete_rls_models",
                return_value=iter([legacy]),
            ), mock.patch(
                "django_tenants.rls.checks._unique_fieldsets",
                return_value=[],
            ), mock.patch(
                "django_tenants.rls.scaffold.staged_fk_migration",
                return_value="# staged\n",
            ), mock.patch(
                "django_tenants.rls.scaffold.enable_rls_migration",
                return_value="# enable\n",
            ), mock.patch(
                "django_tenants.rls.scaffold.unique_constraint_migration",
                return_value="# unique\n",
            ):
                # Run with cwd inside the tmp dir so the default
                # ./rls_migrations_scaffold/ lands somewhere disposable.
                cwd = os.getcwd()
                os.chdir(tmp)
                try:
                    code, out, err, _ = _call(scan, argv=("--generate",))
                finally:
                    os.chdir(cwd)
                default_dir = os.path.join(tmp, "rls_migrations_scaffold")
                self.assertTrue(
                    os.path.isdir(default_dir),
                    "default scaffold dir was not created",
                )
                self.assertTrue(any(os.scandir(default_dir)))

    def test_generate_never_applies(self):
        # --generate must NOT enable RLS on any model (it only writes text).
        scan = _scan(models=[
            _model("app.Legacy", "generate_migration",
                   problems=["missing tenant FK"], step=3),
        ])
        legacy = self._model_obj("app.Legacy")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "django_tenants.rls.checks._iter_concrete_rls_models",
                return_value=iter([legacy]),
            ), mock.patch(
                "django_tenants.rls.checks._unique_fieldsets",
                return_value=[],
            ), mock.patch(
                "django_tenants.rls.scaffold.staged_fk_migration",
                return_value="# staged\n",
            ), mock.patch(
                "django_tenants.rls.scaffold.enable_rls_migration",
                return_value="# enable\n",
            ), mock.patch(
                "django_tenants.rls.scaffold.unique_constraint_migration",
                return_value="# unique\n",
            ):
                _call(scan, argv=("--generate", os.path.join(tmp, "out")))
            legacy.enable_rls.assert_not_called()


@override_settings(TENANT_RLS_ENABLED=True)
class RlsDoctorArgValidationTestCase(SimpleTestCase):
    """Bad flag combinations are rejected before any scan side effects."""

    def test_bad_format_is_rejected(self):
        # argparse choices: an unknown --format value errors out (CommandError or
        # SystemExit from the parser), never silently ignored.
        with mock.patch("django_tenants.rls.doctor.scan", return_value=_scan()):
            with self.assertRaises((CommandError, SystemExit)):
                call_command(
                    "rls_doctor", "--format", "yaml",
                    stdout=io.StringIO(), stderr=io.StringIO(),
                )


if __name__ == "__main__":
    unittest.main()
