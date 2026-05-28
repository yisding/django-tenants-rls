"""Unit tests for ``django_tenants.rls.doctor`` -- the RLS readiness scanner.

These run WITHOUT a live database. ``doctor`` is the single source of truth for
the ``rls_doctor`` command and the read-only admin dashboard: it composes the
existing check predicates (``checks.check_rls_*``), the per-model live
introspection (``checks.rls_live_problems``) and ``TenantRLSModel.has_unscoped_rows``
into a classification per model and a list of settings findings.

The classification enum is the shared contract used everywhere:

    "done" | "auto_fixable" | "generate_migration" | "manual" | "blocked"

* done               -- RLS fully live (``rls_live_problems`` empty).
* auto_fixable       -- has the tenant field, NO unscoped (NULL) rows, NOT NULL
                        column, but RLS/FORCE/policy not yet applied; a plain
                        ``model.enable_rls()`` would fix it safely (Step 6).
* generate_migration -- needs a migration/scaffold: missing tenant FK, a nullable
                        tenant column, or a UNIQUE constraint omitting the tenant
                        (Step 3 / 5 / 8).
* manual             -- needs human action that must NOT be auto-run: unscoped
                        (NULL) rows needing a cross-schema backfill (Step 4), or
                        app-side cache/storage code.
* blocked            -- the connecting role bypasses RLS (W003): enforcement is
                        theatre. Surfaced loudly; ``--fix`` must refuse.

Both ``classify_model(model, connection, *, force)`` and ``scan(database=None)``
are exercised here by mocking the composed primitives (``rls_live_problems``,
``has_unscoped_rows``) and a fake connection/role, so no Postgres is required.
The fake-cursor / patched-connections helpers mirror ``test_checks.py``.
"""

import contextlib
import unittest
from unittest import mock

from django.test.utils import override_settings

from django_tenants.rls import checks, doctor


# The shared classification enum (string values). These literals are the
# cross-file contract; asserting on them here pins doc/code drift.
CLASSIFICATIONS = {
    "done",
    "auto_fixable",
    "generate_migration",
    "manual",
    "blocked",
}


def _patch_doctor_attr(name, **kwargs):
    """Patch a composed primitive wherever the doctor module references it.

    ``doctor`` composes ``rls_live_problems`` / ``_iter_concrete_rls_models``
    (defined in ``checks``). Depending on how the implementation imports them
    they may be a name on the ``doctor`` module (``from .checks import ...``) or
    only on ``checks`` (``checks.rls_live_problems``). Patch the one that exists
    so the tests do not couple to a particular import style. ``doctor`` wins when
    it carries its own reference, since that is what ``doctor`` actually calls.
    """
    if hasattr(doctor, name):
        return mock.patch.object(doctor, name, **kwargs)
    return mock.patch.object(checks, name, **kwargs)


def _settings_seam():
    """Return the name of the doctor helper that collects settings findings.

    The spec leaves the exact private helper name to the implementation; we probe
    the conventional candidates. Returns ``None`` when no such seam exists (the
    implementation inlined the introspection), in which case the real settings
    collection simply runs -- harmless with no database (the DB-best-effort
    checks return no findings).
    """
    for name in ("_settings_findings", "_scan_settings", "_settings"):
        if hasattr(doctor, name) and callable(getattr(doctor, name)):
            return name
    return None


class _FakeMeta:
    """Enough of ``Model._meta`` for ``classify_model`` and ``checks._unique_fieldsets``.

    ``classify_model`` reads ``label`` / ``db_table`` / ``get_field`` and -- via
    ``checks._unique_fieldsets`` (which the doctor composes for the W005 "UNIQUE
    omits tenant" finding) -- ``local_fields`` / ``unique_together`` /
    ``constraints``. We default those three to empty so a plain fake model reports
    no UNIQUE problems; tests that need them can set them.
    """

    def __init__(self, label, db_table, field_names):
        self.label = label
        self.db_table = db_table
        self.abstract = False
        self._field_names = set(field_names)
        # Consumed by checks._unique_fieldsets(); empty == no UNIQUE declarations.
        self.local_fields = []
        self.unique_together = ()
        self.constraints = []

    def get_field(self, name):
        if name in self._field_names:
            return mock.Mock(name="field<%s>" % name)
        raise Exception("no field named %r" % name)


class _FakeModel:
    """A stand-in for a concrete ``TenantRLSModel`` subclass.

    ``classify_model`` needs ``_meta`` (label / db_table / get_field plus the
    UNIQUE-declaration attributes) and a ``has_unscoped_rows`` method; all are
    controllable so each classification branch can be driven without a database.
    By default the model carries the tenant field, declares no UNIQUE constraints
    and reports no unscoped rows.
    """

    def __init__(self, *, label="app.Thing", db_table="app_thing",
                 has_tenant_field=True, unscoped_rows=False):
        fields = {"tenant"} if has_tenant_field else set()
        self._meta = _FakeMeta(label, db_table, fields)
        self._unscoped_rows = unscoped_rows

    def has_unscoped_rows(self):
        return self._unscoped_rows


class _FakeCursor:
    """Minimal cursor context manager returning a canned single row."""

    def __init__(self, row):
        self._row = row

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        return None

    def fetchone(self):
        return self._row


class _FakeConnection:
    """Fake DB connection: a vendor + a canned-row cursor (``pg_roles`` row).

    ``vendor='postgresql'`` lets the role/live introspection proceed; the cursor
    returns ``row`` (typically ``(rolname, rolsuper, rolbypassrls)``). Set
    ``raise_on_cursor`` to simulate an unreachable database.
    """

    def __init__(self, row=None, vendor="postgresql", raise_on_cursor=False):
        self._row = row
        self.vendor = vendor
        self._raise_on_cursor = raise_on_cursor

    def cursor(self):
        if self._raise_on_cursor:
            raise Exception("database is unreachable")
        return _FakeCursor(self._row)


@contextlib.contextmanager
def _patched_connections(connection, alias="default"):
    """Make ``connections[<tenant alias>]`` resolve to ``connection``.

    ``doctor`` resolves the tenant alias connection the same way the checks do
    (``from django.db import connections`` then index by alias), so patching the
    module attribute with a dict is sufficient.
    """
    with mock.patch("django.db.connections", {alias: connection}):
        yield


# ---------------------------------------------------------------------------
# classify_model
# ---------------------------------------------------------------------------


class ClassifyModelTestCase(unittest.TestCase):
    """``classify_model(model, connection, *, force) -> (classification, problems)``.

    Each branch is driven by mocking the live introspection helper
    (``rls_live_problems``, composed from ``checks``) and the model's
    ``has_unscoped_rows`` so no real database is touched. The connection passed in
    reports a non-bypassing role (a ``None`` ``pg_roles`` row), so the up-front
    ``blocked`` short-circuit does not fire. ``problems`` is always a list of strings.
    """

    def _classify(self, model, *, live_problems, force=True, connection=None):
        # rls_live_problems is the live-introspection primitive the doctor
        # composes; patch it wherever the doctor references it (mirrors
        # test_checks patching checks.rls_live_problems).
        conn = connection if connection is not None else _FakeConnection()
        with _patch_doctor_attr("rls_live_problems", return_value=list(live_problems)):
            return doctor.classify_model(model, conn, force=force)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_blocked_when_connection_role_bypasses_rls(self):
        # classify_model checks the connecting role FIRST: a superuser / BYPASSRLS
        # role makes every other signal meaningless -> blocked (W003).
        model = _FakeModel()
        conn = _FakeConnection(row=(True, False))  # (rolsuper, rolbypassrls)
        classification, problems = self._classify(
            model, live_problems=[], connection=conn
        )
        self.assertEqual(classification, "blocked")
        self.assertTrue(problems)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_done_when_live_problems_empty(self):
        model = _FakeModel()
        classification, problems = self._classify(model, live_problems=[])
        self.assertEqual(classification, "done")
        self.assertEqual(problems, [])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_auto_fixable_when_only_rls_not_enabled(self):
        # Has tenant field, NOT NULL column, no unscoped rows: the ONLY problems
        # are that RLS / FORCE / the policy are not applied yet. enable_rls()
        # would fix this safely -> auto_fixable (Step 6).
        model = _FakeModel(has_tenant_field=True, unscoped_rows=False)
        classification, problems = self._classify(
            model,
            live_problems=[
                "RLS not enabled on table 'app_thing'",
                "no RLS policy exists for table 'app_thing'",
            ],
        )
        self.assertEqual(classification, "auto_fixable")
        self.assertTrue(problems)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_auto_fixable_when_only_rls_not_forced(self):
        model = _FakeModel()
        classification, _ = self._classify(
            model,
            live_problems=["RLS not forced on table 'app_thing'"],
        )
        self.assertEqual(classification, "auto_fixable")

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_generate_migration_for_nullable_tenant_column(self):
        # A NULLABLE tenant column needs a SET NOT NULL migration (Step 5) even
        # though there are no NULL rows right now -> generate_migration, not
        # auto_fixable (enable_rls would leave the column nullable / unsafe).
        model = _FakeModel(unscoped_rows=False)
        classification, problems = self._classify(
            model,
            live_problems=[
                "tenant column 'tenant_id' on table 'app_thing' is NULLABLE",
            ],
        )
        self.assertEqual(classification, "generate_migration")
        self.assertTrue(problems)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_generate_migration_for_missing_tenant_field(self):
        # No tenant FK at all: the staged-FK migration must be generated (Step 3).
        model = _FakeModel(has_tenant_field=False)
        classification, problems = self._classify(
            model,
            live_problems=["table 'app_thing' not found / tenant column missing"],
        )
        self.assertEqual(classification, "generate_migration")
        self.assertTrue(problems)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_manual_when_unscoped_rows_present(self):
        # Unscoped (tenant IS NULL) rows owe an app-specific cross-schema backfill
        # (Step 4) that must NEVER be auto-run -> manual. This is reached when the
        # NOT NULL column is fine but RLS/FORCE/policy are still missing AND the
        # table holds NULL-tenant rows: enable_rls() would silently hide them.
        model = _FakeModel(unscoped_rows=True)
        classification, problems = self._classify(
            model,
            live_problems=["RLS not enabled on table 'app_thing'"],
        )
        self.assertEqual(classification, "manual")
        self.assertTrue(problems)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_unscoped_rows_beats_auto_fixable(self):
        # With only "RLS not enabled" (a NOT NULL column), the difference between
        # auto_fixable and manual is whether there are unscoped NULL rows: when
        # there are, enable_rls() would silently hide data -> manual.
        model = _FakeModel(unscoped_rows=True)
        classification, _ = self._classify(
            model,
            live_problems=["RLS not enabled on table 'app_thing'"],
        )
        self.assertEqual(classification, "manual")

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_nullable_column_routes_to_generate_migration_even_with_unscoped_rows(self):
        # A NULLABLE tenant column is a SCHEMA gap (Steps 3/5) that must be fixed
        # via a migration before NULL rows (data) can be discussed: the doctor
        # routes a NULLABLE column to generate_migration regardless of unscoped rows.
        model = _FakeModel(unscoped_rows=True)
        classification, problems = self._classify(
            model,
            live_problems=[
                "tenant column 'tenant_id' on table 'app_thing' is NULLABLE",
            ],
        )
        self.assertEqual(classification, "generate_migration")
        self.assertTrue(problems)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_classification_is_in_the_enum(self):
        model = _FakeModel()
        classification, problems = self._classify(model, live_problems=[])
        self.assertIn(classification, CLASSIFICATIONS)
        self.assertIsInstance(problems, list)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_has_unscoped_rows_db_error_degrades_not_raises(self):
        # Best-effort: has_unscoped_rows() raising (DB unreachable) must not crash
        # classify_model -- it degrades to a finding / a non-"done" classification.
        model = _FakeModel()

        def _boom():
            raise Exception("database is unreachable")

        model.has_unscoped_rows = _boom
        with _patch_doctor_attr("rls_live_problems", return_value=["RLS not enabled"]):
            classification, problems = doctor.classify_model(
                model, _FakeConnection(), force=True
            )
        self.assertIn(classification, CLASSIFICATIONS)
        self.assertIsInstance(problems, list)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_live_problems_db_error_degrades_not_raises(self):
        # If the live introspection helper raises (table missing / DB down), the
        # model must degrade to a finding rather than propagating the exception.
        model = _FakeModel()
        with _patch_doctor_attr(
            "rls_live_problems", side_effect=Exception("relation missing")
        ):
            classification, problems = doctor.classify_model(
                model, _FakeConnection(), force=True
            )
        self.assertIn(classification, CLASSIFICATIONS)
        self.assertNotEqual(classification, "done")
        self.assertIsInstance(problems, list)


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _scan_harness(models, *, role_row=(False, False),
                  classifications=None, settings_findings=None, alias="default"):
    """Patch the seams ``scan()`` composes so it can run with no database.

    * the concrete-model iteration (``checks._iter_concrete_rls_models``);
    * the tenant alias connection lookup (``django.db.connections``), whose cursor
      returns ``role_row`` = ``(rolsuper, rolbypassrls)`` -- the two columns
      ``doctor._role_bypasses_rls`` selects -- so the W003 role-bypass detection
      (the top-level ``blocked`` flag) can be exercised;
    * ``doctor.classify_model`` -- mapped per model via ``classifications`` (a
      list of ``(classification, problems)`` aligned with ``models``);
    * the settings-finding collection helper (discovered via ``_settings_seam``)
      so the ``settings`` list is deterministic. When no such seam exists the real
      settings introspection runs (harmless with no database).
    """
    conn = _FakeConnection(row=role_row)
    cm = []
    if classifications is not None:
        side_effect = list(classifications)

        def _classify(model, connection, *, force):
            return side_effect.pop(0)

        cm.append(mock.patch.object(doctor, "classify_model", side_effect=_classify))
    if settings_findings is not None:
        seam = _settings_seam()
        if seam is not None:
            cm.append(
                mock.patch.object(
                    doctor, seam, return_value=list(settings_findings)
                )
            )
    cm.append(
        _patch_doctor_attr("_iter_concrete_rls_models", return_value=list(models))
    )
    cm.append(mock.patch("django.db.connections", {alias: conn}))
    with contextlib.ExitStack() as stack:
        for ctx in cm:
            stack.enter_context(ctx)
        yield conn


class ScanShapeTestCase(unittest.TestCase):
    """``scan(database=None)`` returns the documented dict (the source of truth)."""

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_returns_documented_top_level_keys(self):
        with _scan_harness(
            [_FakeModel()],
            classifications=[("done", [])],
            settings_findings=[],
        ):
            result = doctor.scan()
        for key in ("rls_enabled", "database", "settings", "models",
                    "summary", "blocked"):
            self.assertIn(key, result)
        self.assertIsInstance(result["settings"], list)
        self.assertIsInstance(result["models"], list)
        self.assertIsInstance(result["summary"], dict)
        self.assertIsInstance(result["blocked"], bool)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_summary_counts_each_classification(self):
        models = [_FakeModel(label="app.A"), _FakeModel(label="app.B"),
                  _FakeModel(label="app.C")]
        with _scan_harness(
            models,
            classifications=[
                ("done", []),
                ("auto_fixable", ["RLS not enabled"]),
                ("generate_migration", ["tenant column NULLABLE"]),
            ],
            settings_findings=[],
        ):
            result = doctor.scan()
        summary = result["summary"]
        for key in ("done", "auto_fixable", "generate_migration",
                    "manual", "blocked"):
            self.assertIn(key, summary)
        self.assertEqual(summary["done"], 1)
        self.assertEqual(summary["auto_fixable"], 1)
        self.assertEqual(summary["generate_migration"], 1)
        # Summary totals must add up to the number of models scanned.
        self.assertEqual(sum(summary.values()), len(models))

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_model_entries_have_documented_keys(self):
        with _scan_harness(
            [_FakeModel(label="app.Thing", db_table="app_thing")],
            classifications=[("auto_fixable", ["RLS not enabled"])],
            settings_findings=[],
        ):
            result = doctor.scan()
        self.assertEqual(len(result["models"]), 1)
        entry = result["models"][0]
        for key in ("label", "table", "classification", "problems",
                    "unscoped_rows", "remedy", "step"):
            self.assertIn(key, entry)
        self.assertIn(entry["classification"], CLASSIFICATIONS)
        self.assertEqual(entry["label"], "app.Thing")
        self.assertEqual(entry["table"], "app_thing")

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_database_alias_recorded(self):
        with _scan_harness(
            [_FakeModel()],
            classifications=[("done", [])],
            settings_findings=[],
            alias="default",
        ):
            result = doctor.scan(database="default")
        self.assertEqual(result["database"], "default")


class ScanBlockedTestCase(unittest.TestCase):
    """W003 role-bypass -> ``scan["blocked"]`` is True (and ``--fix`` must refuse).

    A superuser / BYPASSRLS role means RLS enforcement is theatre, so the scan
    surfaces it loudly via the top-level ``blocked`` flag. The flag is derived
    from the live ``pg_roles`` row of the connecting role.
    """

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_blocked_true_for_superuser_role(self):
        with _scan_harness(
            [_FakeModel()],
            role_row=(True, False),  # rolsuper=True
            classifications=[("done", [])],
            settings_findings=[],
        ):
            result = doctor.scan()
        self.assertTrue(result["blocked"])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_blocked_true_for_bypassrls_role(self):
        with _scan_harness(
            [_FakeModel()],
            role_row=(False, True),  # rolbypassrls=True
            classifications=[("done", [])],
            settings_findings=[],
        ):
            result = doctor.scan()
        self.assertTrue(result["blocked"])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_not_blocked_for_safe_role(self):
        with _scan_harness(
            [_FakeModel()],
            role_row=(False, False),  # NOSUPERUSER NOBYPASSRLS
            classifications=[("done", [])],
            settings_findings=[],
        ):
            result = doctor.scan()
        self.assertFalse(result["blocked"])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_blocked_when_role_row_missing(self):
        # If the pg_roles lookup returns no row (cannot positively confirm a
        # bypass) the scan must NOT falsely declare everything blocked.
        with _scan_harness(
            [_FakeModel()],
            role_row=None,
            classifications=[("done", [])],
            settings_findings=[],
        ):
            result = doctor.scan()
        self.assertFalse(result["blocked"])


class ScanBestEffortTestCase(unittest.TestCase):
    """scan() must be best-effort on DB access -- it never raises."""

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_unreachable_database_degrades_not_raises(self):
        # Connection raising on cursor() (DB unreachable) must not propagate; the
        # scan still returns the documented dict (role-bypass simply unknown ->
        # not blocked).
        conn = _FakeConnection(raise_on_cursor=True)
        with _scan_harness(
            [_FakeModel()],
            classifications=[("manual", ["table missing"])],
            settings_findings=[],
        ):
            # Override the harness connection with the unreachable one so the
            # role-bypass probe must swallow the cursor() failure.
            with mock.patch("django.db.connections", {"default": conn}):
                result = doctor.scan()
        self.assertIn("summary", result)
        self.assertIsInstance(result["blocked"], bool)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_problematic_model_degrades_to_a_finding_via_real_classify(self):
        # Best-effort is owned by classify_model (it catches its own DB errors and
        # returns a finding), so scan() produces an entry for EVERY model even when
        # one cannot be introspected. Drive this through the REAL classify_model by
        # making rls_live_problems raise for one model -- it must degrade to a
        # non-"done" finding, and the healthy model must still be classified.
        bad = _FakeModel(label="app.Bad", db_table="app_bad")
        good = _FakeModel(label="app.Good", db_table="app_good")

        def _live(model, connection, *, force):
            if model._meta.db_table == "app_bad":
                raise Exception("relation does not exist")
            return []  # good model: fully live -> done

        # Keep the settings section out of the way (it is exercised separately);
        # this test is about per-model degradation under the real classify_model.
        seam = _settings_seam()
        ctxs = [
            _patch_doctor_attr("_iter_concrete_rls_models", return_value=[bad, good]),
            _patch_doctor_attr("rls_live_problems", side_effect=_live),
            mock.patch(
                "django.db.connections", {"default": _FakeConnection(row=(False, False))}
            ),
        ]
        if seam is not None:
            ctxs.append(mock.patch.object(doctor, seam, return_value=[]))
        with contextlib.ExitStack() as stack:
            for ctx in ctxs:
                stack.enter_context(ctx)
            result = doctor.scan()
        # Both models still appear; the bad one is a non-"done" finding.
        self.assertEqual(len(result["models"]), 2)
        by_label = {m["label"]: m for m in result["models"]}
        self.assertEqual(set(by_label), {"app.Bad", "app.Good"})
        self.assertNotEqual(by_label["app.Bad"]["classification"], "done")
        self.assertTrue(by_label["app.Bad"]["problems"])
        self.assertEqual(by_label["app.Good"]["classification"], "done")


class ScanSettingsFindingsTestCase(unittest.TestCase):
    """The ``settings`` list maps the existing check outputs + cache/storage notes.

    The exact set of finding ids is owned by the doctor implementation; here we
    only pin the documented per-entry shape and that ``rls_enabled`` is reflected.
    """

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_settings_entries_have_documented_shape(self):
        if _settings_seam() is None:
            self.skipTest(
                "no discoverable settings-collection seam to inject a finding"
            )
        findings = [
            {
                "id": "django_tenants_rls.W001",
                "level": "warning",
                "title": "Backend not the RLS wrapper",
                "detail": "ENGINE is not the RLS backend",
                "remedy": "Set ENGINE='django_tenants.rls.backend'",
                "step": 1,
            }
        ]
        with _scan_harness(
            [_FakeModel()],
            classifications=[("done", [])],
            settings_findings=findings,
        ):
            result = doctor.scan()
        self.assertEqual(len(result["settings"]), 1)
        entry = result["settings"][0]
        for key in ("id", "level", "title", "detail", "remedy", "step"):
            self.assertIn(key, entry)
        self.assertIn(entry["level"], ("ok", "warning", "error"))

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_rls_enabled_reflected(self):
        with _scan_harness(
            [_FakeModel()],
            classifications=[("done", [])],
            settings_findings=[],
        ):
            result = doctor.scan()
        self.assertTrue(result["rls_enabled"])


if __name__ == "__main__":
    unittest.main()
