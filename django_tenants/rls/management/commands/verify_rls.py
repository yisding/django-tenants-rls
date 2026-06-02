"""CI command that verifies RLS is actually LIVE on every TenantRLSModel table.

System checks (W004) are best-effort: they swallow all database errors so a
missing/unreachable database never blocks ``manage.py``. CI wants the opposite
-- a hard, greppable pass/fail. This command runs the SAME per-model
introspection helper used by W004 (``checks.rls_live_problems``) but treats any
gap (RLS off / unforced / no policy / nullable tenant column) or database error
as a FAILURE: it prints ``OK``/``PROBLEM`` per model and exits non-zero if any
model is not fully protected, so a pipeline can gate a deploy on it::

    python manage.py verify_rls --database default

External/contrib/M2M tables that cannot subclass ``TenantRLSModel`` (auth
tokens, contrib auth/sessions, isolated M2M through-tables) are invisible to the
per-model loop, so a green per-model run can still hide an unpoliced
``authtoken_token`` in ``public``. This command also verifies every table
registered in ``TENANT_RLS_EXTERNAL_TABLES`` (``conf.external_tables()``) plus
any passed with the repeatable ``--table`` argument, reusing the SAME catalog
introspection (``checks.rls_live_problems_for_table``)::

    python manage.py verify_rls --database default --table authtoken_token

Exit status is ``0`` only when every concrete ``TenantRLSModel`` table AND every
registered/``--table`` external table has RLS enabled (and forced, when
``TENANT_RLS_FORCE`` is on), at least one policy, and a NOT NULL tenant column;
otherwise it is ``1``.
"""

import sys

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = (
        "Verify that RLS is live on every TenantRLSModel table and every "
        "registered external table (CI gate). Exits 1 if any table has RLS "
        "off/unforced, no policy, or a nullable tenant column."
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
            "--table",
            action="append",
            default=[],
            dest="tables",
            metavar="TABLE",
            help=(
                "Extra raw table name to verify, in addition to those in "
                "TENANT_RLS_EXTERNAL_TABLES. Repeatable. Use for external/"
                "contrib/M2M tables that cannot subclass TenantRLSModel "
                "(e.g. --table authtoken_token)."
            ),
        )

    def handle(self, *args, **options):
        from django.db import connections

        from django_tenants.rls import checks, conf

        alias = options["database"]

        if not conf.rls_enabled():
            self.stdout.write(self.style.WARNING(
                "TENANT_RLS_ENABLED is False; verifying RLS anyway as requested."
            ))

        models = list(checks._iter_concrete_rls_models())
        external_tables = list(conf.external_tables()) + list(options["tables"])
        if not models and not external_tables:
            self.stdout.write(self.style.WARNING(
                "No concrete TenantRLSModel subclasses or external tables found; "
                "nothing to verify."
            ))
            return

        connection = connections[alias]
        force = conf.force_rls()
        any_problem = False

        # Stable, sorted, greppable output: one line per model.
        for model in sorted(models, key=lambda m: m._meta.label):
            label = model._meta.label
            table = model._meta.db_table
            try:
                problems = checks.rls_live_problems(model, connection, force=force)
            except Exception as exc:
                # The command (unlike the W004 system check) treats an
                # introspection error as a hard failure: in CI we cannot verify,
                # so we must not report green.
                any_problem = True
                self.stdout.write(self.style.ERROR(
                    "PROBLEM %s (%s): could not verify RLS: %s"
                    % (label, table, exc)
                ))
                continue

            if problems:
                any_problem = True
                self.stdout.write(self.style.ERROR(
                    "PROBLEM %s (%s):" % (label, table)
                ))
                for problem in problems:
                    self.stdout.write(self.style.ERROR("    - %s" % problem))
            else:
                self.stdout.write(self.style.SUCCESS(
                    "OK %s (%s)" % (label, table)
                ))

        # External/contrib/M2M tables that cannot subclass TenantRLSModel are
        # invisible to the per-model loop above, so a model-only "OK" run can
        # still hide an unpoliced table in public. Verify each table registered
        # in TENANT_RLS_EXTERNAL_TABLES plus any passed via --table, reusing the
        # SAME catalog introspection (rls_live_problems_for_table) so the same
        # gaps (RLS off / unforced / no policy / nullable tenant column) and the
        # same database-error-is-a-hard-failure semantics apply.
        for table in sorted(set(external_tables)):
            try:
                problems = checks.rls_live_problems_for_table(
                    table, connection, force=force
                )
            except Exception as exc:
                any_problem = True
                self.stdout.write(self.style.ERROR(
                    "PROBLEM external table %s: could not verify RLS: %s"
                    % (table, exc)
                ))
                continue

            if problems:
                any_problem = True
                self.stdout.write(self.style.ERROR(
                    "PROBLEM external table %s:" % table
                ))
                for problem in problems:
                    self.stdout.write(self.style.ERROR("    - %s" % problem))
            else:
                self.stdout.write(self.style.SUCCESS(
                    "OK external table %s" % table
                ))

        if any_problem:
            self.stderr.write(self.style.ERROR(
                "verify_rls FAILED: one or more TenantRLSModel tables or "
                "registered external tables are not fully protected by RLS "
                "(see PROBLEM lines above)."
            ))
            # sys.exit raises SystemExit(1): honored by the CLI runner AND
            # propagated by call_command(), so CI and tests both see the failure.
            sys.exit(1)

        self.stdout.write(self.style.SUCCESS(
            "verify_rls OK: all %d TenantRLSModel table(s) + %d external "
            "table(s) are protected by RLS on database %r."
            % (len(models), len(set(external_tables)), alias)
        ))
