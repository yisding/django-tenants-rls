"""Census of integer-PK values that COLLIDE across tenant schemas.

Run this against a **schema-per-tenant** database BEFORE a shared-schema (RLS)
cutover. When every tenant lives in its own schema, two tenants can perfectly
legitimately both own ``blog_note`` row ``id = 1`` -- the schemas keep them
apart. The moment you merge those schemas into one shared ``public`` schema, the
two rows compete for the same ``(id)`` primary-key slot and the merge fails (or,
worse, silently clobbers data during a hand-rolled copy). This command finds
those collisions ahead of time so you can plan an id re-key.

For every concrete model with an integer **auto** primary key
(``AutoField`` / ``BigAutoField``; see ``model._meta.pk``), it builds a
``UNION ALL`` of ``SELECT <pk> FROM "<schema>"."<table>"`` across every tenant
schema, then ``GROUP BY <pk> HAVING count(*) > 1`` to surface every id that
appears in more than one schema. With ``--unique-int`` it does the same for any
single-column ``unique`` integer field (those become shared-schema UNIQUE
constraints too, and collide the same way). It reports, per table:

* how many distinct colliding values there are and how many schemas are involved;
* a sample of the colliding ids (capped by ``--limit``);

and finally a recommended **FK-dependency re-key order** (topological over the
foreign keys *among the surveyed models*) so that, when you renumber ids, you
rewrite parents before the children that point at them.

It makes NO assumptions about RLS (this runs on the pre-migration database, where
RLS is typically not yet enabled) and never writes anything -- it is a read-only
census. Identifiers are quoted defensively; schema/table names come from the
catalog and model ``_meta``, never from request input.

Flags::

    --database DB        alias to introspect (default: the tenant DB alias)
    --apps a,b           only models in these app labels
    --models app.Model   only these models (label, case-insensitive); repeatable
    --schemas s1,s2      only these tenant schemas (default: all but public)
    --unique-int         ALSO census single-column unique integer fields, not
                         just the primary key
    --limit N            max sample colliding ids to print per column (default 20)

Exit status is ``1`` when any collision is found (so CI / a migration script can
gate on a clean census), ``0`` when every surveyed column is collision-free.
"""

import sys

from django.core.management.base import BaseCommand, CommandError


# Internal types of an *integer* primary key we can census. We deliberately
# restrict to the AUTO fields (sequence-backed) because those are the ids that
# were assigned per-schema and therefore overlap across schemas; a UUID or a
# natural/text PK does not collide this way and is out of scope here.
_INT_AUTO_PK_TYPES = frozenset({"AutoField", "BigAutoField", "SmallAutoField"})

# Integer field internal types eligible for the optional --unique-int census.
_INT_FIELD_TYPES = frozenset({
    "AutoField",
    "BigAutoField",
    "SmallAutoField",
    "IntegerField",
    "BigIntegerField",
    "SmallIntegerField",
    "PositiveIntegerField",
    "PositiveBigIntegerField",
    "PositiveSmallIntegerField",
})


class Command(BaseCommand):
    help = (
        "Census of integer primary-key (and optionally unique integer) values "
        "that collide across tenant schemas BEFORE a shared-schema RLS cutover. "
        "Read-only. Exits 1 if any collision is found."
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
            "--apps",
            type=str,
            default=None,
            help=(
                "Comma-separated app labels to restrict the census to (e.g. "
                "'myapp,blog'). Default: every app."
            ),
        )
        parser.add_argument(
            "--models",
            action="append",
            default=None,
            metavar="LABEL",
            help=(
                "Restrict to this model label (e.g. 'myapp.Note'), "
                "case-insensitive. Repeat the flag for several models. Combined "
                "with --apps via AND (a model must satisfy both filters)."
            ),
        )
        parser.add_argument(
            "--schemas",
            type=str,
            default=None,
            help=(
                "Comma-separated tenant schema names to survey (default: every "
                "schema on the tenant model except the public schema)."
            ),
        )
        parser.add_argument(
            "--unique-int",
            dest="unique_int",
            action="store_true",
            default=False,
            help=(
                "Also census every single-column unique integer field, not just "
                "the primary key (those become shared-schema UNIQUE constraints "
                "and collide the same way)."
            ),
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=20,
            help=(
                "Maximum number of sample colliding ids to print per column "
                "(default: 20). Counts are always exact regardless of this."
            ),
        )

    # -- entrypoint ------------------------------------------------------------

    def handle(self, *args, **options):
        from django.db import connections

        from django_tenants.utils import (
            get_public_schema_name,
            get_tenant_model,
        )

        alias = options["database"]
        limit = options["limit"]
        if limit < 0:
            raise CommandError("--limit must be a non-negative integer.")

        if alias not in connections:
            raise CommandError(
                "Unknown database alias %r. Configured aliases: %s."
                % (alias, ", ".join(sorted(connections)))
            )
        connection = connections[alias]
        if connection.vendor != "postgresql":
            raise CommandError(
                "rls_pk_collision_census only supports PostgreSQL (the tenant "
                "database alias %r uses the %r backend). Schema-per-tenant "
                "collisions are a PostgreSQL-schema concept." % (alias, connection.vendor)
            )

        public = get_public_schema_name()
        schemas = self._resolve_schemas(options.get("schemas"), public, get_tenant_model)
        if not schemas:
            raise CommandError(
                "No tenant schemas to survey (after excluding the public schema "
                "%r). Nothing to census." % public
            )

        models = self._select_models(options.get("apps"), options.get("models"))
        if not models:
            raise CommandError(
                "No concrete models with an integer auto primary key matched the "
                "given filters (--apps / --models)."
            )

        self.stdout.write(self.style.MIGRATE_HEADING(
            "Cross-tenant PK collision census (database %r, %d schema(s), %d model(s))"
            % (alias, len(schemas), len(models))
        ))
        self.stdout.write(
            "  schemas: %s" % ", ".join(schemas)
        )
        self.stdout.write(self.style.WARNING(
            "  This is a PRE-migration, read-only census. A collision means two "
            "tenants share an id that would clash once the schemas are merged "
            "into one shared schema; plan an id re-key before cutover."
        ))

        # Confirm which schemas actually exist so a typo or a half-dropped tenant
        # never makes a missing schema look collision-free.
        present = self._existing_schemas(connection, schemas)
        missing = [s for s in schemas if s not in present]
        if missing:
            self.stdout.write(self.style.WARNING(
                "  NOTE: skipping schema(s) absent from the database: %s"
                % ", ".join(missing)
            ))
        survey_schemas = [s for s in schemas if s in present]
        if len(survey_schemas) < 2:
            self.stdout.write(self.style.WARNING(
                "  Only %d schema(s) present; a collision needs at least two "
                "schemas. Reporting anyway." % len(survey_schemas)
            ))

        any_collision = False
        total_columns = 0
        for model in models:
            columns = self._columns_to_census(model, options["unique_int"])
            total_columns += len(columns)
            for field in columns:
                found = self._census_column(
                    connection, model, field, survey_schemas, limit,
                )
                any_collision = any_collision or found

        self.stdout.write(self.style.MIGRATE_HEADING("\nRecommended FK-dependency re-key order:"))
        self._print_rekey_order(models)

        if any_collision:
            self.stderr.write(self.style.ERROR(
                "\nrls_pk_collision_census: collisions found -- the surveyed "
                "schemas cannot be merged as-is. Re-key the colliding ids (in the "
                "FK-dependency order above) before the shared-schema cutover."
            ))
            sys.exit(1)

        self.stdout.write(self.style.SUCCESS(
            "\nrls_pk_collision_census OK: no cross-tenant collisions across %d "
            "column(s) in %d model(s)." % (total_columns, len(models))
        ))

    # -- schema / model selection ---------------------------------------------

    def _resolve_schemas(self, raw, public, get_tenant_model):
        """Return the ordered, de-duplicated list of tenant schema names to survey.

        Either the explicit ``--schemas`` list (public still excluded, since a
        merge by definition targets public) or every ``schema_name`` on the tenant
        model except public.
        """
        if raw:
            requested = [s.strip() for s in raw.split(",") if s.strip()]
            return self._dedupe([s for s in requested if s != public])

        tenant_model = get_tenant_model()
        try:
            names = list(
                tenant_model.objects.values_list("schema_name", flat=True)
            )
        except Exception as exc:
            raise CommandError(
                "Could not read tenant schema names from %s: %s. Pass --schemas "
                "explicitly to survey a known list." % (tenant_model._meta.label, exc)
            )
        return self._dedupe([n for n in names if n and n != public])

    @staticmethod
    def _dedupe(items):
        """Stable de-duplicate preserving first-seen order."""
        seen = set()
        out = []
        for item in items:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out

    def _select_models(self, apps_raw, models_raw):
        """Concrete models with an integer auto PK, filtered by --apps / --models.

        Census is for collisions of sequence-assigned integer ids, so a model is
        eligible only when ``model._meta.pk`` is an integer auto field. Abstract
        and proxy models (no own table) are skipped.
        """
        from django.apps import apps as django_apps

        app_filter = None
        if apps_raw:
            app_filter = {a.strip() for a in apps_raw.split(",") if a.strip()}
        model_filter = None
        if models_raw:
            model_filter = {label.strip().lower() for label in models_raw if label.strip()}

        out = []
        for model in django_apps.get_models():
            meta = model._meta
            if meta.abstract or meta.proxy:
                continue
            if not self._has_int_auto_pk(model):
                continue
            if app_filter is not None and meta.app_label not in app_filter:
                continue
            if model_filter is not None and meta.label.lower() not in model_filter:
                continue
            out.append(model)

        # Surface a clear error if --models named something that does not exist or
        # has no integer auto PK, rather than silently censusing nothing.
        if model_filter is not None:
            found = {m._meta.label.lower() for m in out}
            unknown = sorted(model_filter - found)
            if unknown:
                raise CommandError(
                    "--models named model(s) that are not concrete with an "
                    "integer auto primary key: %s" % ", ".join(unknown)
                )

        return sorted(out, key=lambda m: m._meta.label)

    @staticmethod
    def _has_int_auto_pk(model):
        pk = model._meta.pk
        if pk is None:
            return False
        return pk.get_internal_type() in _INT_AUTO_PK_TYPES

    def _columns_to_census(self, model, unique_int):
        """Return the field objects to census for ``model``.

        Always the primary key. With ``--unique-int`` also every concrete,
        single-column unique integer field (excluding the PK, already covered).
        Multi-column uniques are out of scope (they are handled by the
        tenant-scoped UNIQUE rewrite, RLS migration Step 8, not by an id re-key).
        """
        columns = [model._meta.pk]
        if not unique_int:
            return columns
        pk_attname = model._meta.pk.attname
        for field in model._meta.local_concrete_fields:
            if field.attname == pk_attname:
                continue
            if not getattr(field, "unique", False):
                continue
            if field.get_internal_type() not in _INT_FIELD_TYPES:
                continue
            columns.append(field)
        return columns

    # -- the census query ------------------------------------------------------

    def _census_column(self, connection, model, field, schemas, limit):
        """Run the cross-schema collision query for one column. Returns bool found.

        Builds ``SELECT <col> FROM "<schema>"."<table>"`` per schema, ``UNION ALL``
        them, then ``GROUP BY <col> HAVING count(*) > 1`` to find every value that
        appears in more than one schema's rows. Counts are exact; a sample of the
        colliding values (capped by ``limit``) is fetched for the report.
        """
        table = model._meta.db_table
        column = field.column
        label = "%s.%s" % (model._meta.label, field.name)

        if len(schemas) < 2:
            # A single schema cannot collide with itself on a primary key, and we
            # never want to imply otherwise; report nothing for this column.
            return False

        q_table = self._quote_ident(table)
        q_column = self._quote_ident(column)
        # NULL ids cannot collide as a PK and are not interesting for a unique
        # column census either; filter them so they never inflate a group.
        union = "\nUNION ALL\n".join(
            'SELECT %s AS v FROM %s.%s WHERE %s IS NOT NULL'
            % (q_column, self._quote_ident(schema), q_table, q_column)
            for schema in schemas
        )
        sql = (
            "SELECT v, count(*) AS n FROM (\n%s\n) AS census "
            "GROUP BY v HAVING count(*) > 1 ORDER BY n DESC, v ASC" % union
        )

        try:
            with connection.cursor() as cursor:
                cursor.execute(sql)
                rows = cursor.fetchall()
        except Exception as exc:
            # Best-effort: a missing table in one schema (a tenant that never ran
            # this app's migrations) should not abort the whole census. Surface it
            # and move on -- treat as "could not determine", not "clean".
            self.stdout.write(self.style.WARNING(
                "  ? %s (%s.%s): could not census across schemas: %s"
                % (label, table, column, exc)
            ))
            return False

        if not rows:
            self.stdout.write(self.style.SUCCESS(
                "  OK %s (%s.%s): no cross-tenant collisions." % (label, table, column)
            ))
            return False

        # rows is [(value, count), ...]; count = how many schemas hold that value.
        total_values = len(rows)
        max_schemas = max(n for _v, n in rows)
        self.stdout.write(self.style.ERROR(
            "  COLLISION %s (%s.%s): %d value(s) shared across tenants "
            "(worst value appears in %d schemas)."
            % (label, table, column, total_values, max_schemas)
        ))
        sample = rows[:limit] if limit else []
        for value, count in sample:
            self.stdout.write("        %s = %r appears in %d schemas" % (column, value, count))
        if limit and total_values > limit:
            self.stdout.write(
                "        ... and %d more colliding value(s) (raise --limit to see)."
                % (total_values - limit)
            )
        return True

    @staticmethod
    def _quote_ident(name):
        """Quote a SQL identifier, doubling embedded double-quotes (Postgres rule).

        Mirrors :func:`django_tenants.rls.scaffold._quote_ident`. Schema and table
        names come from the catalog / model ``_meta``, but a schema name can be an
        arbitrary (operator-chosen) identifier, so quoting it keeps a name with a
        ``"`` from breaking out of the ``"schema"."table"`` reference.
        """
        return '"' + str(name).replace('"', '""') + '"'

    def _existing_schemas(self, connection, schemas):
        """Return the subset of ``schemas`` that actually exist in the database.

        One parameterized catalog lookup (no identifier interpolation) so a typo'd
        or half-dropped schema is reported as skipped rather than erroring the
        whole run on the first missing schema.
        """
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT nspname FROM pg_catalog.pg_namespace "
                    "WHERE nspname = ANY(%s)",
                    [list(schemas)],
                )
                return {row[0] for row in cursor.fetchall()}
        except Exception:
            # If the catalog lookup itself fails, assume all requested schemas are
            # present and let the per-column query surface any real problem.
            return set(schemas)

    # -- FK-dependency re-key order -------------------------------------------

    def _print_rekey_order(self, models):
        """Print a topological re-key order over FKs AMONG the surveyed models.

        When you renumber colliding ids you must rewrite a parent row's new id
        everywhere a child FK references it, so parents should be re-keyed before
        their children. This computes a topological order of the surveyed models by
        the foreign keys that point from one surveyed model to another; models in a
        reference cycle (self-FK or mutual FK) are reported together since they need
        a deferred-constraint / two-pass re-key.
        """
        labels = {m._meta.label for m in models}
        by_label = {m._meta.label: m for m in models}

        # deps[child] = set of OTHER surveyed parent labels it references.
        # self_ref = models with a FK to themselves: still a re-key cycle (a row
        # points at another row in the same table) but a SELF-edge would deadlock
        # the topo sort, so it is tracked separately and folded into ``cyclic``.
        deps = {m._meta.label: set() for m in models}
        self_ref = set()
        for model in models:
            child = model._meta.label
            for field in model._meta.local_concrete_fields:
                if not getattr(field, "is_relation", False):
                    continue
                related = getattr(field, "related_model", None)
                if related is None:
                    continue
                parent = related._meta.label
                if parent == child:
                    self_ref.add(child)
                elif parent in labels:
                    deps[child].add(parent)

        order, cyclic = self._toposort(deps)
        cyclic |= self_ref
        for idx, label in enumerate(order, start=1):
            model = by_label[label]
            self.stdout.write(
                "  %2d. %s (%s)" % (idx, label, model._meta.db_table)
            )
        if cyclic:
            self.stdout.write(self.style.WARNING(
                "  Models in a FK cycle (re-key with deferred constraints / a "
                "two-pass update): %s" % ", ".join(sorted(cyclic))
            ))
        self.stdout.write(
            "  (Re-key parents before children: update the parent's new id, then "
            "every child FK that points at it. Self-referential FKs need a "
            "two-pass / deferred-constraint update.)"
        )

    @staticmethod
    def _toposort(deps):
        """Kahn topological sort. ``deps[node] = {nodes it depends on}``.

        Returns ``(order, cyclic)`` where ``order`` is a dependency-first ordering
        (a node appears after everything it depends on) and ``cyclic`` is the set of
        nodes left unresolved because they sit in a cycle. Ties are broken
        alphabetically so the output is deterministic.
        """
        remaining = {node: set(parents) for node, parents in deps.items()}
        order = []
        while True:
            ready = sorted(
                node for node, parents in remaining.items() if not parents
            )
            if not ready:
                break
            for node in ready:
                order.append(node)
                del remaining[node]
            for parents in remaining.values():
                parents.difference_update(ready)
        cyclic = set(remaining)
        return order, cyclic
