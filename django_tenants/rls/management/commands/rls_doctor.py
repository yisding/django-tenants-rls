"""RLS migration assistant: scan readiness, auto-enable the safe step, scaffold.

``manage.py rls_doctor`` is the operator-facing front end for the RLS migration
assistant. It does NOT reimplement any analysis: it calls
:func:`django_tenants.rls.doctor.scan` (the single source of truth) and presents
the result, then optionally acts on the ONE provably-safe slice of the result.

What it does (and, deliberately, what it never does):

* default -- print a readable report grouped by classification (``done`` /
  ``auto_fixable`` / ``generate_migration`` / ``manual`` / ``blocked``); every
  non-``done`` item shows its problems, remedy, and the migration step to read in
  ``docs/rls_migration.rst``;
* ``--fix`` -- apply ONLY the ``auto_fixable`` slice (Step 6: ``enable_rls`` on a
  table that already has a NOT NULL tenant column and no unscoped rows). It
  REFUSES (and exits non-zero) when the connecting role bypasses RLS (W003, the
  scan is ``blocked``) or when a target table has unscoped NULL-tenant rows -- it
  never runs a backfill, ``SET NOT NULL``, ``DROP SCHEMA`` or any DDL beyond the
  safe enable path. It re-scans and re-reports afterwards;
* ``--generate [DIR]`` -- write scaffold files (from
  :mod:`django_tenants.rls.scaffold`) for ``generate_migration`` items into DIR
  (default ``./rls_migrations_scaffold/``), printing each path. It NEVER writes
  into a real app ``migrations/`` directory and NEVER applies anything;
* ``--format json`` -- dump ``scan()`` verbatim for tooling/CI;
* ``--database`` -- which alias to introspect (default: the tenant alias).

Exit codes (CI-usable, matching ``verify_rls``): a scan exits ``0`` only when
there are zero non-``done`` model items AND no error-level settings findings;
otherwise ``1``. ``--fix`` re-scans after fixing and applies the same rule.
"""

import json
import os
import sys

from django.core.management.base import BaseCommand

# Order in which classifications are reported and the human-facing heading for
# each. ``done`` is listed last (and summarized rather than detailed) so the
# actionable groups surface first.
_GROUP_ORDER = (
    "blocked",
    "manual",
    "generate_migration",
    "auto_fixable",
    "done",
)
_GROUP_TITLES = {
    "blocked": "BLOCKED (role bypasses RLS -- enforcement is theatre)",
    "manual": "MANUAL (human action required; never auto-run)",
    "generate_migration": "NEEDS MIGRATION (run --generate for a scaffold)",
    "auto_fixable": "AUTO-FIXABLE (run --fix to enable RLS safely)",
    "done": "DONE (RLS fully live)",
}

# Scaffold filename suffix per generator, used for --generate output names.
_DEFAULT_GENERATE_DIR = "rls_migrations_scaffold"


class Command(BaseCommand):
    help = (
        "Scan the project + database for shared-schema RLS readiness, report a "
        "grouped plan, optionally auto-enable the one provably-safe step "
        "(--fix), and/or write migration scaffolds (--generate). Never runs "
        "backfills, SET NOT NULL, DROP SCHEMA or any unsafe DDL. CI-usable exit "
        "code."
    )

    def add_arguments(self, parser):
        from django_tenants.utils import get_tenant_database_alias

        parser.add_argument(
            "--database",
            type=str,
            default=get_tenant_database_alias(),
            help=(
                "Database alias to introspect (default: the tenant database "
                "alias, normally 'default')."
            ),
        )
        parser.add_argument(
            "--fix",
            action="store_true",
            default=False,
            help=(
                "Apply ONLY the provably-safe step: enable RLS + policy on tables "
                "that already have a NOT NULL tenant column and no unscoped rows "
                "(Step 6). Refuses if the role bypasses RLS or a target has "
                "unscoped rows. Never backfills or alters columns."
            ),
        )
        parser.add_argument(
            "--generate",
            nargs="?",
            const=_DEFAULT_GENERATE_DIR,
            default=None,
            metavar="DIR",
            help=(
                "Write migration/SQL scaffolds for items needing a migration "
                "into DIR (default: ./%s/). Prints each path. Never writes into "
                "a real migrations/ directory and never applies anything." % _DEFAULT_GENERATE_DIR
            ),
        )
        parser.add_argument(
            "--format",
            dest="fmt",
            choices=("text", "json"),
            default="text",
            help="Output format: 'text' (grouped report) or 'json' (dumps scan()).",
        )

    # -- helpers ---------------------------------------------------------------

    def _scan_failed(self, scan):
        """Return True if ``scan`` represents a non-clean state (exit code 1).

        The contract: a scan is clean only when there are zero non-``done`` model
        items AND no error-level settings findings. The role-bypass ``blocked``
        flag forces a failure too (a blocked install is never clean).
        """
        if scan.get("blocked"):
            return True
        for setting in scan.get("settings", []):
            if setting.get("level") == "error":
                return True
        for model in scan.get("models", []):
            if model.get("classification") != "done":
                return True
        return False

    def _models_by_label(self):
        """Map ``model._meta.label`` -> model class for concrete RLS models.

        Used by ``--fix`` to resolve a scan item (which carries only a label)
        back to its model class so we can call ``enable_rls`` / ``has_unscoped_rows``.
        """
        from django_tenants.rls import checks

        return {m._meta.label: m for m in checks._iter_concrete_rls_models()}

    # -- report rendering ------------------------------------------------------

    def _print_report(self, scan):
        """Render the grouped, human-readable report to stdout."""
        alias = scan.get("database")
        enabled = scan.get("rls_enabled")
        self.stdout.write(self.style.MIGRATE_HEADING(
            "RLS readiness report (database %r, TENANT_RLS_ENABLED=%s)"
            % (alias, enabled)
        ))

        # Loud banner first if the connecting role bypasses RLS.
        if scan.get("blocked"):
            self.stdout.write(self.style.ERROR(
                "\nBLOCKED: the connecting database role bypasses RLS (superuser "
                "or BYPASSRLS). Any policies are theatre -- there is NO tenant "
                "isolation, and --fix is disabled. Connect as a NOSUPERUSER "
                "NOBYPASSRLS role first (see W003)."
            ))

        self._print_settings(scan.get("settings", []))
        self._print_models(scan.get("models", []))
        self._print_summary(scan.get("summary", {}))

    def _print_settings(self, settings):
        self.stdout.write(self.style.MIGRATE_HEADING("\nSettings findings:"))
        actionable = [s for s in settings if s.get("level") != "ok"]
        if not actionable:
            self.stdout.write(self.style.SUCCESS("  all settings checks pass."))
            return
        for setting in actionable:
            style = self.style.ERROR if setting.get("level") == "error" else self.style.WARNING
            self.stdout.write(style(
                "  [%s] %s" % (setting.get("id", "?"), setting.get("title", ""))
            ))
            detail = setting.get("detail")
            if detail:
                self.stdout.write("      %s" % detail)
            remedy = setting.get("remedy")
            if remedy:
                self.stdout.write("      remedy: %s" % remedy)
            step = setting.get("step")
            if step:
                self.stdout.write(
                    "      see docs/rls_migration.rst step %s" % step
                )

    def _print_models(self, models):
        self.stdout.write(self.style.MIGRATE_HEADING("\nModel findings:"))
        if not models:
            self.stdout.write(self.style.WARNING(
                "  no concrete TenantRLSModel subclasses found."
            ))
            self._print_scope_hint()
            return

        by_class = {}
        for model in models:
            by_class.setdefault(model.get("classification"), []).append(model)

        for classification in _GROUP_ORDER:
            items = by_class.get(classification)
            if not items:
                continue
            title = _GROUP_TITLES.get(classification, classification)
            heading_style = {
                "blocked": self.style.ERROR,
                "manual": self.style.WARNING,
                "generate_migration": self.style.WARNING,
                "auto_fixable": self.style.NOTICE,
                "done": self.style.SUCCESS,
            }.get(classification, self.style.HTTP_INFO)
            self.stdout.write(heading_style(
                "  %s -- %d model(s)" % (title, len(items))
            ))

            for model in sorted(items, key=lambda m: m.get("label") or ""):
                label = model.get("label")
                table = model.get("table")
                if classification == "done":
                    # Keep the happy path terse: one line, no problem dump.
                    self.stdout.write(self.style.SUCCESS(
                        "    OK %s (%s)" % (label, table)
                    ))
                    continue
                self.stdout.write("    %s (%s)" % (label, table))
                for problem in model.get("problems") or []:
                    self.stdout.write("        - %s" % problem)
                remedy = model.get("remedy")
                if remedy:
                    self.stdout.write("        remedy: %s" % remedy)
                step = model.get("step")
                if step:
                    self.stdout.write(
                        "        see docs/rls_migration.rst step %s" % step
                    )

    # Known third-party apps whose tables are commonly tenant-resident but can
    # NEVER subclass TenantRLSModel, so the doctor cannot see or fix them -- they
    # need a hand-written tenant_id column + policy (migration guide, Step 7).
    _THIRD_PARTY_TENANT_APPS = {
        "rest_framework.authtoken": "authtoken_token",
        "django.contrib.auth": "auth_user / auth_group",
        "django.contrib.sessions": "django_session",
    }

    def _print_scope_hint(self):
        """Explain the doctor's blind spots when no model subclasses the base.

        Prevents the false-comfort of an empty, exit-0 report mid-migration: the
        doctor only inspects ``TenantRLSModel`` subclasses (plus settings), so it
        is silent about un-converted models and third-party tenant tables.
        """
        from django.conf import settings

        self.stdout.write(self.style.NOTICE(
            "  Note: rls_doctor only inspects concrete TenantRLSModel subclasses\n"
            "  (plus the settings checks above). It does NOT see models you have\n"
            "  not converted yet, nor third-party tables that cannot subclass the\n"
            "  base. An empty/all-clear report does NOT mean the migration is done."
        ))
        installed = set(getattr(settings, "INSTALLED_APPS", ()) or ())
        present = [(app, tbl) for app, tbl in self._THIRD_PARTY_TENANT_APPS.items()
                   if app in installed]
        if present:
            self.stdout.write(self.style.NOTICE(
                "  Third-party apps installed whose tenant data needs a HAND-WRITTEN\n"
                "  tenant_id column + policy (if they hold per-tenant data):"
            ))
            for app, tbl in present:
                self.stdout.write("      - %s (%s)" % (app, tbl))
            self.stdout.write(
                "  See docs/rls_migration.rst 'Third-party / non-policied tables'."
            )

    def _print_summary(self, summary):
        self.stdout.write(self.style.MIGRATE_HEADING("\nSummary:"))
        self.stdout.write(
            "  done=%d  auto_fixable=%d  generate_migration=%d  manual=%d  blocked=%d"
            % (
                summary.get("done", 0),
                summary.get("auto_fixable", 0),
                summary.get("generate_migration", 0),
                summary.get("manual", 0),
                summary.get("blocked", 0),
            )
        )

    # -- --fix -----------------------------------------------------------------

    def _do_fix(self, scan):
        """Apply ONLY the auto_fixable slice; refuse on any unsafe condition.

        Returns the (re)scan dict to report from. Refusals raise SystemExit(1)
        after a clear message so both the CLI runner and call_command() see the
        non-zero exit. enable_rls() operates on the tenant alias internally; we
        re-resolve models from the scan labels and re-check has_unscoped_rows at
        fix time (defence in depth -- rows may have been written since the scan).
        """
        # (1) A bypassing role makes enforcement theatre: refuse outright.
        if scan.get("blocked"):
            self.stderr.write(self.style.ERROR(
                "--fix REFUSED: the connecting database role bypasses RLS "
                "(superuser or BYPASSRLS), so enabling RLS would create no real "
                "isolation. Connect as a NOSUPERUSER NOBYPASSRLS role first (see "
                "W003), then re-run."
            ))
            sys.exit(1)

        auto = [m for m in scan.get("models", [])
                if m.get("classification") == "auto_fixable"]
        if not auto:
            self.stdout.write(self.style.WARNING(
                "--fix: nothing to do -- no auto_fixable models. (Tables needing "
                "a migration or a backfill are not auto-fixed; see the report.)"
            ))
            return scan

        models_by_label = self._models_by_label()

        # (2) Pre-flight: refuse if ANY target has unscoped (NULL tenant) rows.
        # Enabling RLS on such a table silently hides those rows from every
        # tenant; that is a backfill (Step 4), which we must never run.
        blocking = []
        for item in auto:
            label = item.get("label")
            model = models_by_label.get(label)
            if model is None:
                continue
            try:
                if model.has_unscoped_rows():
                    blocking.append(label)
            except Exception as exc:
                # Cannot prove safety -> treat as unsafe and refuse.
                self.stderr.write(self.style.ERROR(
                    "--fix REFUSED: could not verify %s is free of unscoped rows: %s"
                    % (label, exc)
                ))
                sys.exit(1)
        if blocking:
            self.stderr.write(self.style.ERROR(
                "--fix REFUSED: the following auto_fixable table(s) have rows with "
                "a NULL tenant; enabling RLS would make those rows invisible to "
                "every tenant. Backfill the tenant column first (Step 4 -- this "
                "command never runs a backfill): %s" % ", ".join(sorted(blocking))
            ))
            sys.exit(1)

        # (3) Safe to enable: this is Step 6 only (ENABLE/FORCE RLS + policy).
        for item in sorted(auto, key=lambda m: m.get("label") or ""):
            label = item.get("label")
            model = models_by_label.get(label)
            if model is None:
                self.stderr.write(self.style.WARNING(
                    "--fix: skipping %s (could not resolve model class)." % label
                ))
                continue
            try:
                model.enable_rls()
                self.stdout.write(self.style.SUCCESS(
                    "--fix: enabled RLS + policy for %s" % label
                ))
            except Exception as exc:
                self.stderr.write(self.style.ERROR(
                    "--fix: failed to enable RLS for %s: %s" % (label, exc)
                ))

        # Re-scan so the report and the exit code reflect the post-fix state.
        from django_tenants.rls import doctor

        self.stdout.write(self.style.MIGRATE_HEADING("\nRe-scanning after --fix..."))
        return doctor.scan(database=scan.get("database"))

    # -- --generate ------------------------------------------------------------

    def _do_generate(self, scan, out_dir):
        """Write scaffold files for generate_migration items into ``out_dir``.

        Never writes into a real migrations/ directory and never applies. Each
        scaffold's text comes from :mod:`django_tenants.rls.scaffold`; we only
        choose filenames and write the strings. Prints every path written.
        """
        from django_tenants.rls import scaffold

        targets = [m for m in scan.get("models", [])
                   if m.get("classification") == "generate_migration"]
        if not targets:
            self.stdout.write(self.style.WARNING(
                "--generate: nothing to do -- no models need a migration scaffold."
            ))
            return

        # Defensive: refuse to write into anything that looks like a real
        # migrations package, so a scaffold can never be mistaken for / clobber a
        # tracked migration.
        norm = os.path.normpath(out_dir)
        if os.path.basename(norm) == "migrations":
            self.stderr.write(self.style.ERROR(
                "--generate REFUSED: %r looks like a real migrations/ directory. "
                "Scaffolds are advisory -- point --generate at a scratch dir "
                "(default ./%s/) and copy what you want into your app yourself."
                % (out_dir, _DEFAULT_GENERATE_DIR)
            ))
            sys.exit(1)

        os.makedirs(out_dir, exist_ok=True)
        self.stdout.write(self.style.MIGRATE_HEADING(
            "Writing scaffolds to %s (advisory -- never applied, never your "
            "migrations/ dir):" % os.path.abspath(out_dir)
        ))

        models_by_label = self._models_by_label()
        pk_cast = self._safe_pk_cast()

        for item in sorted(targets, key=lambda m: m.get("label") or ""):
            label = item.get("label")
            table = item.get("table")
            model = models_by_label.get(label)
            slug = (label or table or "model").replace(".", "_").lower()

            written = []
            if model is not None:
                from django_tenants.rls import doctor as _doctor

                # Choose scaffolds by the ACTUAL problem -- generate_migration also
                # covers models that already HAVE the tenant FK (nullable column,
                # or only a tenant-omitting UNIQUE), where a staged AddField would
                # fail with a duplicate column.
                problems = item.get("problems") or []
                missing_fk = not _doctor._has_tenant_field(model)
                nullable = any("NULLABLE" in p for p in problems)

                if missing_fk:
                    # Step 3-5: add the FK (null=True) + backfill stub + NOT NULL.
                    written.append(self._write_scaffold(
                        out_dir, "%s_staged_fk.py" % slug,
                        scaffold.staged_fk_migration(model),
                    ))
                elif nullable:
                    # FK exists but is nullable: tighten it -- NO AddField (that
                    # would be a duplicate-column error). Steps 4-5.
                    written.append(self._write_scaffold(
                        out_dir, "%s_notnull.py" % slug,
                        scaffold.notnull_migration(model),
                    ))

                # Step 6: enable RLS + policy follow-up (idempotent if already on).
                written.append(self._write_scaffold(
                    out_dir, "%s_enable_rls.py" % slug,
                    scaffold.enable_rls_migration(model),
                ))

                # Step 8: tenant-scoped UNIQUE rewrites for any constraint that
                # omits the tenant. One scaffold per offending field set.
                for idx, fields in enumerate(self._unique_fields_omitting_tenant(model)):
                    written.append(self._write_scaffold(
                        out_dir, "%s_unique_%d.py" % (slug, idx),
                        scaffold.unique_constraint_migration(model, fields),
                    ))
            else:
                # Could not resolve a model class (e.g. third-party table): emit
                # the raw policy DDL keyed on the bare table name instead.
                written.append(self._write_scaffold(
                    out_dir, "%s_policy.sql" % slug,
                    scaffold.third_party_policy_sql(table, pk_cast=pk_cast),
                ))

            self.stdout.write("  %s (%s):" % (label, table))
            for path in written:
                self.stdout.write(self.style.SUCCESS("    wrote %s" % path))

        self.stdout.write(self.style.WARNING(
            "\nThese are SCAFFOLDS, not migrations: review them, fill in the "
            "backfill TODOs (Step 4), set 'dependencies', and copy the parts you "
            "want into your app's migrations/ yourself. Nothing was applied."
        ))

    def _write_scaffold(self, out_dir, filename, text):
        path = os.path.join(out_dir, filename)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return os.path.abspath(path)

    def _unique_fields_omitting_tenant(self, model):
        """Yield each UNIQUE field set on ``model`` that omits the tenant field."""
        from django_tenants.rls import checks, conf

        tenant = conf.tenant_field()
        for _label, fields in checks._unique_fieldsets(model):
            if tenant not in fields:
                yield list(fields)

    def _safe_pk_cast(self):
        """Best-effort tenant PK cast for third-party policy DDL.

        ``get_tenant_pk_cast`` raises on an unsupported PK; a generate run should
        not crash on that (E002 already surfaces it), so fall back to 'integer'.
        """
        from django.core.exceptions import ImproperlyConfigured
        from django_tenants.rls import conf

        try:
            return conf.get_tenant_pk_cast()
        except ImproperlyConfigured:
            return "integer"

    # -- entrypoint ------------------------------------------------------------

    def handle(self, *args, **options):
        from django_tenants.rls import conf, doctor

        alias = options["database"]
        fmt = options["fmt"]
        do_fix = options["fix"]
        generate_dir = options["generate"]

        if not conf.rls_enabled():
            # Mirror the other RLS commands: proceed, but say so (the assistant is
            # explicitly for installs mid-adoption, where the flag may be off).
            self.stderr.write(self.style.WARNING(
                "TENANT_RLS_ENABLED is False; scanning readiness anyway."
            ))

        scan = doctor.scan(database=alias)

        # In --format json, stdout must contain ONLY the JSON document. --fix /
        # --generate write progress to self.stdout, so temporarily route that to
        # stderr while they run; the JSON dump below then has stdout to itself.
        json_mode = fmt == "json"
        saved_stdout = self.stdout
        if json_mode:
            self.stdout = self.stderr
        try:
            if do_fix:
                # _do_fix refuses (SystemExit 1) on blocked / unscoped rows,
                # applies the safe slice, and returns the post-fix re-scan.
                scan = self._do_fix(scan)

            if generate_dir is not None:
                self._do_generate(scan, generate_dir)
        finally:
            if json_mode:
                self.stdout = saved_stdout

        if json_mode:
            # Dump the (possibly post-fix) scan verbatim for tooling. default=str
            # keeps any non-JSON-native value (e.g. a stray Decimal) serializable.
            self.stdout.write(json.dumps(scan, indent=2, default=str))
        else:
            self._print_report(scan)

        # Exit code contract (same rule for plain scan and post-fix re-scan):
        # clean only when no non-done models and no error-level settings.
        if self._scan_failed(scan):
            sys.exit(1)
