"""Unit tests for the ``rls_pk_collision_census`` management command.

These run WITHOUT a live database. The command is a read-only census that, for a
schema-per-tenant PostgreSQL database BEFORE a shared-schema (RLS) cutover, finds
integer primary-key (and optionally unique-integer) values that collide across
tenant schemas -- because those would clash once the schemas are merged. The
heavy lifting is one ``UNION ALL ... GROUP BY ... HAVING count(*) > 1`` query per
column; we stub the connection cursor so the command's *orchestration* (model /
schema selection, the per-column query shape, collision reporting, the exit-code
contract, and the FK-dependency re-key order) is asserted with no Postgres.

Exit contract under test: exit ``0`` only when every surveyed column is
collision-free; exit ``1`` (SystemExit) when any collision is found. Misuse
(unknown alias, non-postgres backend, no schemas, no matching models, bad
``--models`` / ``--limit``) raises ``CommandError``.
"""

import io
from unittest import mock

from django.core.management import CommandError, call_command
from django.test import SimpleTestCase


# --- tiny fakes -------------------------------------------------------------
# Just enough of the Django model/field surface the command introspects, so the
# tests never touch the app registry or a database.


class _FakeField:
    def __init__(self, name, internal_type, *, unique=False, is_relation=False,
                 related_model=None, attname=None, column=None):
        self.name = name
        self._internal_type = internal_type
        self.unique = unique
        self.is_relation = is_relation
        self.related_model = related_model
        self.attname = attname or name
        self.column = column or self.attname

    def get_internal_type(self):
        return self._internal_type


class _FakeMeta:
    def __init__(self, label, db_table, pk, fields):
        self.label = label
        self.app_label = label.split(".")[0]
        self.db_table = db_table
        self.pk = pk
        self.local_concrete_fields = fields
        self.abstract = False
        self.proxy = False


class _FakeModel:
    def __init__(self, label, db_table, pk, fields=None):
        fields = fields if fields is not None else [pk]
        self._meta = _FakeMeta(label, db_table, pk, fields)


def _int_pk(name="id", internal="AutoField"):
    return _FakeField(name, internal, attname=name, column=name)


def _model(label, db_table=None, *, pk_type="AutoField", extra_fields=None):
    db_table = db_table or label.replace(".", "_").lower()
    pk = _int_pk(internal=pk_type)
    fields = [pk] + list(extra_fields or [])
    return _FakeModel(label, db_table, pk, fields)


class _FakeCursor:
    """Context-manager cursor that answers the two query shapes the command runs.

    * the ``pg_namespace`` existence probe -> returns each requested schema as
      present (so the census proceeds over all of them);
    * the per-column ``UNION ALL ... GROUP BY ... HAVING count(*) > 1`` -> returns
      whatever ``collisions`` maps for the table+column embedded in the SQL.
    """

    def __init__(self, collisions, existing=None):
        self._collisions = collisions
        self._existing = existing
        self._result = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        if "pg_namespace" in sql:
            requested = (params or [[]])[0]
            present = self._existing if self._existing is not None else requested
            self._result = [(s,) for s in present if s in requested]
            return
        # Per-column census. Find which (table, column) this query is for by the
        # quoted "table"."column" reference embedded in the SQL.
        self._result = []
        for (table, column), rows in self._collisions.items():
            if '"%s"' % table in sql and '"%s"' % column in sql:
                self._result = rows
                return

    def fetchall(self):
        return self._result


class _FakeConnection:
    def __init__(self, collisions=None, vendor="postgresql", existing=None):
        self.vendor = vendor
        self._collisions = collisions or {}
        self._existing = existing

    def cursor(self):
        return _FakeCursor(self._collisions, existing=self._existing)


def _run(model_objs, *, connection=None, schemas=("t1", "t2"), argv=(), **options):
    """Invoke the command with the tenant model, connections and discovery patched.

    Returns ``(systemexit_code_or_None, stdout, stderr)``.
    """
    if connection is None:
        connection = _FakeConnection()

    out, err = io.StringIO(), io.StringIO()

    # A fake tenant model whose objects.values_list yields the schema names.
    tenant_model = mock.Mock()
    tenant_model.objects.values_list.return_value = list(schemas)
    tenant_model._meta.label = "customers.Tenant"

    code = None
    with mock.patch("django.db.connections", {"default": connection}), \
         mock.patch(
             "django_tenants.utils.get_tenant_database_alias",
             return_value="default",
         ), \
         mock.patch(
             "django_tenants.utils.get_public_schema_name",
             return_value="public",
         ), \
         mock.patch(
             "django_tenants.utils.get_tenant_model",
             return_value=tenant_model,
         ), \
         mock.patch(
             "django.apps.apps.get_models",
             return_value=list(model_objs),
         ):
        try:
            call_command(
                "rls_pk_collision_census", *argv,
                stdout=out, stderr=err, **options,
            )
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class CollisionCensusSelectionTestCase(SimpleTestCase):
    """Model/schema selection and misuse errors."""

    def test_no_models_raises(self):
        # Only a UUID/non-auto-PK model present -> nothing to census.
        m = _model("app.Thing", pk_type="UUIDField")
        with self.assertRaises(CommandError):
            _run([m])

    def test_unknown_database_raises(self):
        m = _model("app.Note")
        with self.assertRaises(CommandError):
            _run([m], database="nope")

    def test_non_postgres_backend_raises(self):
        m = _model("app.Note")
        conn = _FakeConnection(vendor="sqlite")
        with self.assertRaises(CommandError):
            _run([m], connection=conn)

    def test_no_schemas_raises(self):
        m = _model("app.Note")
        with self.assertRaises(CommandError):
            _run([m], schemas=())  # only public would remain -> none

    def test_negative_limit_raises(self):
        m = _model("app.Note")
        with self.assertRaises(CommandError):
            _run([m], limit=-1)

    def test_models_filter_unknown_raises(self):
        m = _model("app.Note")
        with self.assertRaises(CommandError):
            _run([m], models=["app.DoesNotExist"])

    def test_apps_filter_narrows(self):
        a = _model("app.Note")
        b = _model("other.Doc")
        # Restrict to app 'app': only Note censused, exit 0 (no collisions).
        code, out, err = _run([a, b], apps="app")
        self.assertIsNone(code)
        self.assertIn("app.Note", out)
        self.assertNotIn("other.Doc", out)

    def test_public_schema_always_excluded(self):
        m = _model("app.Note")
        # 'public' passed explicitly is dropped; only t1/t2 survive.
        code, out, err = _run([m], schemas=("public", "t1", "t2"))
        self.assertIsNone(code)
        self.assertIn("t1", out)
        self.assertIn("t2", out)
        # The reported schema line should not list public as a surveyed schema.
        schema_line = [ln for ln in out.splitlines() if ln.strip().startswith("schemas:")]
        self.assertTrue(schema_line)
        self.assertNotIn("public", schema_line[0])


class CollisionCensusReportTestCase(SimpleTestCase):
    """Collision detection, exit code and query shape."""

    def test_clean_census_exits_zero(self):
        m = _model("app.Note")
        code, out, err = _run([m])
        self.assertIsNone(code)
        self.assertIn("no cross-tenant collisions", out)
        self.assertIn("OK", out)

    def test_collision_exits_one_and_reports(self):
        m = _model("app.Note", "blog_note")
        # id=1 shared across both schemas, id=7 across both.
        conn = _FakeConnection(collisions={("blog_note", "id"): [(1, 2), (7, 2)]})
        code, out, err = _run([m], connection=conn)
        self.assertEqual(code, 1)
        self.assertIn("COLLISION", out)
        self.assertIn("app.Note", out)
        self.assertIn("blog_note", out)
        self.assertIn("= 1", out)
        self.assertIn("collisions found", err)

    def test_limit_caps_sample_but_not_count(self):
        m = _model("app.Note", "blog_note")
        rows = [(i, 2) for i in range(1, 6)]  # 5 colliding values
        conn = _FakeConnection(collisions={("blog_note", "id"): rows})
        code, out, err = _run([m], connection=conn, limit=2)
        self.assertEqual(code, 1)
        # Reports the true count of 5 values...
        self.assertIn("5 value(s)", out)
        # ...but only 2 sample lines + an "and N more" note.
        self.assertIn("and 3 more", out)

    def test_unique_int_columns_censused_only_with_flag(self):
        legacy = _FakeField(
            "legacy_id", "IntegerField", unique=True,
            attname="legacy_id", column="legacy_id",
        )
        m = _model("app.Note", "blog_note", extra_fields=[legacy])
        conn = _FakeConnection(collisions={("blog_note", "legacy_id"): [(99, 2)]})

        # Without the flag: only the PK is censused -> no collision seen, exit 0.
        code, out, err = _run([m], connection=conn)
        self.assertIsNone(code)
        self.assertNotIn("legacy_id", out)

        # With --unique-int: the unique integer column is censused too -> exit 1.
        code, out, err = _run([m], connection=conn, unique_int=True)
        self.assertEqual(code, 1)
        self.assertIn("legacy_id", out)

    def test_query_unions_each_schema_and_filters_null(self):
        captured = {}

        class _CapturingCursor(_FakeCursor):
            def execute(self, sql, params=None):
                if "GROUP BY" in sql:
                    captured["sql"] = sql
                super().execute(sql, params)

        class _CapturingConn(_FakeConnection):
            def cursor(self):
                return _CapturingCursor(self._collisions, existing=self._existing)

        m = _model("app.Note", "blog_note")
        conn = _CapturingConn()
        _run([m], connection=conn, schemas=("t1", "t2", "t3"))
        sql = captured.get("sql", "")
        self.assertIn('"t1"."blog_note"', sql)
        self.assertIn('"t2"."blog_note"', sql)
        self.assertIn('"t3"."blog_note"', sql)
        self.assertEqual(sql.count("UNION ALL"), 2)  # 3 schemas -> 2 unions
        self.assertIn("IS NOT NULL", sql)
        self.assertIn("HAVING count(*) > 1", sql)

    def test_missing_schema_skipped(self):
        m = _model("app.Note", "blog_note")
        # Only t1 exists; t2 absent -> single-schema survey, reported & exit 0.
        conn = _FakeConnection(existing=["t1"])
        code, out, err = _run([m], connection=conn, schemas=("t1", "t2"))
        self.assertIsNone(code)
        self.assertIn("absent from the database", out)


class CollisionCensusRekeyOrderTestCase(SimpleTestCase):
    """The recommended FK-dependency re-key order."""

    def test_parent_listed_before_child(self):
        parent = _model("app.Author", "blog_author")
        fk = _FakeField(
            "author", "ForeignKey", is_relation=True,
            related_model=parent, attname="author_id", column="author_id",
        )
        child = _model("app.Note", "blog_note", extra_fields=[fk])
        code, out, err = _run([parent, child])
        self.assertIsNone(code)
        # In the re-key section, Author must appear before Note.
        # Use the re-key listing region (after the heading).
        rekey = out[out.index("re-key order"):]
        self.assertLess(rekey.index("app.Author"), rekey.index("app.Note"))

    def test_fk_cycle_reported(self):
        # Self-referential FK -> a cycle the command must flag.
        cat = _model("app.Category", "blog_category")
        self_fk = _FakeField(
            "parent", "ForeignKey", is_relation=True,
            related_model=cat, attname="parent_id", column="parent_id",
        )
        cat._meta.local_concrete_fields = [cat._meta.pk, self_fk]
        code, out, err = _run([cat])
        self.assertIsNone(code)
        self.assertIn("FK cycle", out)
        self.assertIn("app.Category", out)
