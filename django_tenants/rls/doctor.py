"""Readiness scanner for adopting shared-schema RLS (the ``rls_doctor`` engine).

This module is the single source of truth behind the ``rls_doctor`` management
command and the optional read-only admin dashboard. It SCANS the project plus the
tenant database and classifies every concrete :class:`TenantRLSModel` table and
every relevant setting into one of five buckets so a human (or CI) can tell at a
glance how far an existing django-tenants install is from safe RLS isolation, and
which of the nine documented migration steps (see ``docs/rls_migration.rst``) each
finding maps to.

It does **not** reimplement the existing safety primitives -- it COMPOSES them:

* the system-check predicates in :mod:`django_tenants.rls.checks`
  (``check_rls_backend``/W001, ``check_rls_role``/W003,
  ``check_rls_var_names``/E001, ``check_tenant_pk_cast``/E002) are *called* and
  their ``Warning``/``Error`` objects mapped to ``settings`` findings;
* :func:`checks.rls_live_problems` decides "is RLS already fully live?";
* :meth:`TenantRLSModel.has_unscoped_rows` decides "is there a NULL-tenant
  backfill still owed (Step 4)?";
* :func:`checks._iter_concrete_rls_models` / :func:`checks._unique_fieldsets`
  enumerate the models and their UNIQUE declarations.

Two new, lightweight settings introspections live here (and only here): the cache
``KEY_FUNCTION`` check and the default-storage check, which advise switching the
schema-name-based helpers to their RLS-correct counterparts.

CLASSIFICATION enum (a plain string, shared across the command and admin)::

    "done"               RLS fully live (rls_live_problems empty).
    "auto_fixable"       has the tenant field, NO unscoped (NULL) rows and a
                         NOT NULL tenant column, but RLS / FORCE / policy is not
                         yet applied -> model.enable_rls() fixes it safely (Step 6).
    "generate_migration" needs a migration/scaffold: missing tenant FK, a nullable
                         tenant column, or a UNIQUE constraint omitting the tenant
                         (Steps 3 / 5 / 8).
    "manual"             needs human action that must NOT be auto-run: unscoped
                         (NULL) rows owing a backfill (Step 4).
    "blocked"            the connecting role bypasses RLS (W003) so enforcement is
                         theatre -- surface loudly; any --fix must refuse.

:func:`scan` is BEST-EFFORT on database access: a model whose table is missing, or
a database that is unreachable, degrades to a finding rather than raising.
"""

from . import checks, conf


# The classification strings, exported as a tuple so callers (the command's
# report grouping, the admin table, the tests) share one ordering / spelling.
CLASSIFICATIONS = (
    "done",
    "auto_fixable",
    "generate_migration",
    "manual",
    "blocked",
)

# Dotted paths used by the two new settings introspections below.
_SCHEMA_BASED_CACHE_KEY_FUNCTION = "django_tenants.cache.make_key"
_RLS_CACHE_KEY_FUNCTION = "django_tenants.rls.cache.make_key"
_SCHEMA_BASED_STORAGE = "django_tenants.files.storage.TenantFileSystemStorage"
# The deprecated wrapper re-exported from files/storages.py (note the plural)
# has the same schema-name-based behaviour, so it is an offender too.
_LEGACY_SCHEMA_BASED_STORAGE = "django_tenants.files.storages.TenantFileSystemStorage"
_SCHEMA_BASED_STORAGES = (_SCHEMA_BASED_STORAGE, _LEGACY_SCHEMA_BASED_STORAGE)
_RLS_STORAGE = "django_tenants.rls.storage.RLSTenantFileSystemStorage"


def _role_bypasses_rls(connection):
    """Best-effort: does ``connection``'s current role bypass RLS (W003)?

    Returns True only when we can positively confirm the role is a superuser or
    has the BYPASSRLS attribute. Any inability to check (non-PostgreSQL, DB not
    reachable, permission denied) returns False -- if we cannot prove the role
    bypasses RLS we must not falsely declare every model ``blocked``. This mirrors
    the best-effort posture of :func:`checks.check_rls_role`, but operates on the
    caller-owned connection (so ``scan(database=...)`` can target any alias).

    Honors ``TENANT_RLS_ALLOW_BYPASS_ROLE``: when the operator has explicitly
    opted into a bypassing role (isolation guaranteed by another mechanism),
    :func:`checks.check_rls_role` suppresses W003, so we must not declare the scan
    ``blocked`` either -- otherwise the documented opt-out would make ``scan()``
    mark every model blocked and ``--fix`` refuse.
    """
    if conf.allow_bypass_role():
        return False
    try:
        if connection.vendor != "postgresql":
            return False
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT rolsuper, rolbypassrls "
                "FROM pg_roles WHERE rolname = current_user"
            )
            row = cursor.fetchone()
    except Exception:
        return False
    if not row:
        return False
    is_super, is_bypass = row
    return bool(is_super or is_bypass)


def _unique_problems(model):
    """Return human-readable strings for each UNIQUE declaration omitting tenant.

    Composes :func:`checks._unique_fieldsets` (the same enumeration W005 uses) so
    the doctor's "UNIQUE omits the tenant" finding is byte-for-byte the same set
    the system check would flag. Pure model introspection -- no DB access.

    Mirrors the W005 entropy-aware annotation: when the offending UNIQUE is a
    single high-entropy, non-enumerable value (a OneToOne to a random-UUID PK, or
    a ``UUIDField(unique=True)``) the finding is NOT dropped -- the global
    one-per-value semantics still change -- but the same residual note the W005
    check appends (:data:`checks._W005_UUID_RESIDUAL_NOTE`, via
    :func:`checks._is_high_entropy_uuid_unique`) is appended here too, so the
    doctor output stays byte-aligned with the system check.
    """
    field = conf.tenant_field()
    problems = []
    for label, fields in checks._unique_fieldsets(model):
        if field in fields:
            continue
        problem = (
            "UNIQUE constraint %s spans %r and omits the tenant field %r "
            "(checked with RLS BYPASSED -> cross-tenant uniqueness/leak)"
            % (label, tuple(fields), field)
        )
        if checks._is_high_entropy_uuid_unique(model, fields):
            problem += checks._W005_UUID_RESIDUAL_NOTE
        problems.append(problem)
    return problems


def _has_tenant_field(model):
    """Whether ``model`` declares the configured tenant field (W002 inverse)."""
    try:
        model._meta.get_field(conf.tenant_field())
        return True
    except Exception:
        return False


def _collision_problems(model):
    """Return human-readable strings for non-FK columns colliding with tenant FK.

    Composes :func:`checks.tenant_column_collisions` (the same enumeration the E003
    system check uses) so the doctor's "column collides with the tenant FK" finding
    is exactly the set the check would flag. A classic pre-cutover foot-gun is a
    denormalized integer ``tenant_id`` carried over from schema-per-tenant data,
    which clashes with the tenant ForeignKey's ``<tenant_field>_id`` column. Pure
    model introspection -- no DB access.
    """
    field = conf.tenant_field()
    problems = []
    for name, column in checks.tenant_column_collisions(model):
        problems.append(
            "field %r occupies column %r, which collides with the tenant "
            "ForeignKey %r (also column %r): RLS is enforced through that column, "
            "so rename/drop the field or set TENANT_RLS_TENANT_FIELD to another "
            "name (Django reports this clash as models.E006)"
            % (name, column, field, column)
        )
    return problems


def _has_unscoped_rows(model, connection):
    """Whether ``model``'s table has rows with a NULL tenant FK, on ``connection``.

    :meth:`TenantRLSModel.has_unscoped_rows` always queries the default tenant
    alias; the doctor must check the alias actually being scanned
    (``scan(database=...)`` / the admin ``?database=`` knob) or it could miss NULL
    rows on a non-default database and wrongly report an unsafe table as
    ``auto_fixable``. So it runs the same cheap ``EXISTS`` on the caller-owned
    connection. Best-effort: a missing / unreadable table returns False (by the
    time this runs, ``rls_live_problems`` has already queried the same connection,
    so the table is readable).
    """
    field = conf.tenant_field()
    attname = "%s_id" % field
    table = model._meta.db_table
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT EXISTS(SELECT 1 FROM %s WHERE %s IS NULL)"
                % (connection.ops.quote_name(table), connection.ops.quote_name(attname))
            )
            row = cursor.fetchone()
        return bool(row and row[0])
    except Exception:
        return False


# The classification strings for a registered external table. A subset of the
# model :data:`CLASSIFICATIONS`: an external table is either fully isolated
# (``done``), owed isolation DDL (``needs_isolation``), or unprovable because the
# connecting role bypasses RLS (``blocked``). It is intentionally narrower than
# the model enum -- the doctor cannot scaffold a per-app migration for a raw table
# (that is ``isolate_external_table_sql`` / ``IsolateExternalTable``), so it never
# emits ``auto_fixable`` / ``generate_migration`` / ``manual`` for one.
EXTERNAL_TABLE_CLASSIFICATIONS = (
    "done",
    "needs_isolation",
    "blocked",
)


def classify_external_table(table, connection, *, force):
    """Classify a single registered external table against the live database.

    Returns ``(classification, problems)`` where ``classification`` is one of
    :data:`EXTERNAL_TABLE_CLASSIFICATIONS` and ``problems`` is a list of
    human-readable strings (empty for ``"done"``). External/contrib/M2M tables
    cannot subclass :class:`TenantRLSModel`, so the model-only introspection in
    :func:`classify_model` never sees them; this runs the SAME table-name catalog
    introspection ``verify_rls`` and the W008 check use
    (:func:`checks.rls_live_problems_for_table`) so a table registered in
    ``TENANT_RLS_EXTERNAL_TABLES`` is judged by exactly the same RLS-live bar as a
    first-party model table.

    Decision order mirrors :func:`classify_model`:

    1. ``blocked`` -- the connecting role bypasses RLS (W003): enforcement is
       theatre, so nothing below it can be proven. Surfaced loudly; ``--fix`` must
       refuse.
    2. ``done`` -- :func:`checks.rls_live_problems_for_table` is empty: RLS is
       enabled (and forced when ``force``), a policy exists and the tenant column
       is NOT NULL.
    3. ``needs_isolation`` -- any live problem (RLS off / unforced / no policy /
       nullable tenant column), or a database error introspecting the table. The
       fix is the external-table isolation DDL (``isolate_external_table_sql`` /
       :class:`~django_tenants.rls.operations.IsolateExternalTable`), not an
       auto-run enable, so it is never ``auto_fixable``.

    BEST-EFFORT: a database error introspecting the table degrades to a single
    ``needs_isolation`` finding describing the failure rather than raising, so a
    missing table or unreachable DB never aborts the whole scan.
    """
    if _role_bypasses_rls(connection):
        return "blocked", [
            "the connecting role bypasses RLS (superuser or BYPASSRLS); "
            "isolation of external table %r is NOT enforced for this connection "
            "(W003)" % table
        ]

    try:
        live_problems = checks.rls_live_problems_for_table(
            table, connection, force=force
        )
    except Exception as exc:
        return "needs_isolation", [
            "could not introspect RLS state on external table %r: %s"
            % (table, exc)
        ]

    if not live_problems:
        return "done", []
    return "needs_isolation", list(live_problems)


def classify_model(model, connection, *, force):
    """Classify a single concrete ``TenantRLSModel`` against the live database.

    Returns ``(classification, problems)`` where ``classification`` is one of
    :data:`CLASSIFICATIONS` and ``problems`` is a list of human-readable strings
    describing what is wrong (empty for ``"done"``). This is the shared decision
    function reused by :func:`scan`, the management command and the admin view, so
    all three agree on what each model needs.

    Decision order (each level subsumes the cheaper checks above it):

    1. ``blocked`` -- the connecting role bypasses RLS (W003). Enforcement is
       theatre, so this is surfaced loudly and a ``--fix`` must refuse. Checked
       first because nothing below it matters while the role can see everything.
    2. ``done`` -- :func:`checks.rls_live_problems` is empty: RLS is enabled (and
       forced when ``force``), a policy exists and the tenant column is NOT NULL.
    3. ``generate_migration`` -- a schema/code change is owed that must go through a
       migration/scaffold (never auto-run): no tenant FK at all (Step 3), a non-FK
       column colliding with the tenant FK column (the denormalized-``tenant_id``
       foot-gun; reported by Django as models.E006), a nullable tenant column
       (Steps 3/5), or a UNIQUE constraint omitting the tenant (Step 8). The
       nullable-column signal is taken from ``rls_live_problems`` (the word
       "NULLABLE" in a problem string) so we do not duplicate its
       information_schema query.
    4. ``manual`` -- the table has unscoped (tenant IS NULL) rows: a cross-schema
       backfill (Step 4) is owed, which is app-specific and must not be auto-run.
       Ranked below ``generate_migration`` because a NULL *column* (schema) must
       be fixed before NULL *rows* (data) can even be discussed sensibly.
    5. ``auto_fixable`` -- the table has the tenant field, a NOT NULL column and no
       unscoped rows, yet RLS / FORCE / the policy are not applied. This is the one
       provably-safe step: ``model.enable_rls()`` (Step 6) fixes it without risking
       data loss.

    BEST-EFFORT: any database error introspecting the model degrades to a single
    ``generate_migration`` finding describing the failure rather than raising, so a
    missing table or unreachable DB never aborts a whole scan.
    """
    # (1) A bypassing role makes every other signal meaningless: report loudly.
    if _role_bypasses_rls(connection):
        return "blocked", [
            "the connecting role bypasses RLS (superuser or BYPASSRLS); "
            "tenant isolation is NOT enforced for this connection (W003)"
        ]

    # Pure-model UNIQUE problems (no DB) are always worth surfacing; they force at
    # least a generate_migration regardless of the live RLS state.
    unique_problems = _unique_problems(model)

    # A non-FK column colliding with the tenant FK column (the denormalized
    # ``tenant_id`` foot-gun, reported by Django as models.E006) makes RLS
    # unworkable: the policy is enforced through that very column. This is a
    # code/schema fix that must NOT be auto-run, so short-circuit to
    # generate_migration before any (misleading) DB introspection.
    collision_problems = _collision_problems(model)
    if collision_problems:
        return "generate_migration", collision_problems + unique_problems

    # A model with no tenant field at all cannot be live and needs the staged FK
    # migration (Step 3). rls_live_problems would also fail to find the column, so
    # short-circuit here with a clear, DB-free message.
    if not _has_tenant_field(model):
        return "generate_migration", [
            "no tenant field %r on the model; add a ForeignKey (Step 3)"
            % conf.tenant_field()
        ] + unique_problems

    # Live RLS state. rls_live_problems owns the four catalog queries; we do not
    # duplicate them. Any DB failure (missing table / unreachable) -> a finding.
    try:
        live_problems = checks.rls_live_problems(model, connection, force=force)
    except Exception as exc:
        return "generate_migration", [
            "could not introspect RLS state on table %r: %s"
            % (model._meta.db_table, exc)
        ] + unique_problems

    # (2) Fully live and no UNIQUE leak -> done.
    if not live_problems and not unique_problems:
        return "done", []

    # A nullable tenant column means a schema change (Step 3/5) is owed: route to
    # generate_migration. rls_live_problems flags it with "NULLABLE" in the text.
    nullable_column = any("NULLABLE" in p for p in live_problems)
    if nullable_column or unique_problems:
        # Keep every live problem so the report is complete, then add UNIQUE ones.
        return "generate_migration", list(live_problems) + unique_problems

    # No nullable column and no UNIQUE leak: the remaining live_problems are some
    # combination of RLS-not-enabled / not-forced / no-policy. Whether this is
    # safely auto-fixable hinges on unscoped (NULL) rows.
    # Check unscoped rows on the SCANNED connection (not always the default
    # tenant alias) so scan(database=...) classifies the requested database.
    unscoped = _has_unscoped_rows(model, connection)

    if unscoped:
        # (4) Unscoped rows owe an app-specific backfill (Step 4) -- never auto-run.
        return "manual", list(live_problems) + [
            "table has rows with a NULL tenant; they will become invisible to "
            "every tenant once RLS is enabled. Backfill the tenant before "
            "enabling (Step 4)"
        ]

    # (5) Has the field, NOT NULL column, no unscoped rows: enable_rls is safe.
    return "auto_fixable", list(live_problems)


def _setting_entry(check_result, *, ok_title, ok_detail, step, ok_remedy=""):
    """Map a system-check function's result list to one ``settings`` entry.

    The check functions return a list of ``Warning``/``Error`` objects (empty when
    fine). We collapse that to a single settings finding: ``ok`` when empty,
    otherwise ``warning``/``error`` carrying the first message's text + hint. The
    ``id`` is taken from the check message so the docs/tests can key on W001/W003/etc.
    """
    from django.core.checks import Error

    if not check_result:
        return {
            "id": "ok",
            "level": "ok",
            "title": ok_title,
            "detail": ok_detail,
            "remedy": ok_remedy,
            "step": step,
        }
    message = check_result[0]
    level = "error" if isinstance(message, Error) else "warning"
    return {
        "id": getattr(message, "id", "") or "",
        "level": level,
        "title": ok_title,
        "detail": str(getattr(message, "msg", message)),
        "remedy": str(getattr(message, "hint", "") or ""),
        "step": step,
    }


def _cache_key_function_finding():
    """New introspection: warn if a cache KEY_FUNCTION is the schema-name one.

    Under shared-schema RLS every tenant shares the public schema, so the bundled
    :func:`django_tenants.cache.make_key` (keyed on ``connection.schema_name``)
    collapses all tenants onto one ``"public:..."`` namespace and leaks cached
    values across tenants. Advise switching to the RLS-correct
    :func:`django_tenants.rls.cache.make_key`. Pure settings introspection -- it
    resolves the configured dotted path / callable without touching the cache.
    """
    from django.conf import settings

    caches = getattr(settings, "CACHES", None) or {}
    offenders = []
    for alias, cfg in caches.items():
        if not isinstance(cfg, dict):
            continue
        key_function = cfg.get("KEY_FUNCTION")
        dotted = _callable_dotted_path(key_function)
        if dotted == _SCHEMA_BASED_CACHE_KEY_FUNCTION:
            offenders.append(alias)

    if not offenders:
        return {
            "id": "ok",
            "level": "ok",
            "title": "Cache KEY_FUNCTION",
            "detail": (
                "No cache uses the schema-name-based "
                "%r KEY_FUNCTION." % _SCHEMA_BASED_CACHE_KEY_FUNCTION
            ),
            "remedy": "",
            "step": 1,
        }
    return {
        "id": "django_tenants_rls.cache",
        "level": "warning",
        "title": "Cache KEY_FUNCTION",
        "detail": (
            "CACHES %s use KEY_FUNCTION %r, which keys on connection.schema_name. "
            "Under RLS every tenant shares the public schema, so this collapses "
            "all tenants onto one namespace and leaks cached values across "
            "tenants." % (offenders, _SCHEMA_BASED_CACHE_KEY_FUNCTION)
        ),
        "remedy": (
            "Switch KEY_FUNCTION (and REVERSE_KEY_FUNCTION) to %r, which keys on "
            "the real active tenant." % _RLS_CACHE_KEY_FUNCTION
        ),
        "step": 1,
    }


def _storage_finding():
    """New introspection: note if the default file storage is schema-name-based.

    Best-effort: if the default storage backend resolves to
    :class:`django_tenants.files.storage.TenantFileSystemStorage` (which derives
    the per-tenant media path from ``connection.schema_name``, pinned to public
    under RLS) advise the RLS-correct
    :class:`django_tenants.rls.storage.RLSTenantFileSystemStorage`. Reads
    ``STORAGES["default"]["BACKEND"]`` first (Django 4.2+), then the legacy
    ``DEFAULT_FILE_STORAGE``. Never instantiates a storage.
    """
    from django.conf import settings

    backend = None
    storages = getattr(settings, "STORAGES", None)
    if isinstance(storages, dict):
        default = storages.get("default")
        if isinstance(default, dict):
            backend = default.get("BACKEND")
    if backend is None:
        backend = getattr(settings, "DEFAULT_FILE_STORAGE", None)

    if backend in _SCHEMA_BASED_STORAGES:
        return {
            "id": "django_tenants_rls.storage",
            "level": "warning",
            "title": "Default file storage",
            "detail": (
                "The default file storage is %r, which derives the per-tenant "
                "media path from connection.schema_name. Under RLS that is pinned "
                "to 'public' for every tenant, so all tenants' files share one "
                "directory (a cross-tenant file leak)." % backend
            ),
            "remedy": (
                "Point STORAGES['default']['BACKEND'] (or DEFAULT_FILE_STORAGE) at "
                "%r; see docs/rls.rst. For django-storages/S3, prefix the location "
                "with the real tenant (see django_tenants.rls.storage)." % _RLS_STORAGE
            ),
            "step": 1,
        }
    return {
        "id": "ok",
        "level": "ok",
        "title": "Default file storage",
        "detail": (
            "The default file storage is not a schema-name-based "
            "TenantFileSystemStorage (neither %r nor the deprecated %r)."
            % (_SCHEMA_BASED_STORAGE, _LEGACY_SCHEMA_BASED_STORAGE)
        ),
        "remedy": "",
        "step": 1,
    }


def _callable_dotted_path(value):
    """Resolve ``value`` (a dotted string or a callable) to its dotted path.

    A ``KEY_FUNCTION`` may be configured either as an import string or as the
    imported callable itself. Returns the ``"module.attr"`` path in both cases (or
    ``None`` if it cannot be determined), so the comparison against the known
    schema-name helper works regardless of how the project wrote it.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value
    module = getattr(value, "__module__", None)
    qualname = getattr(value, "__qualname__", None) or getattr(value, "__name__", None)
    if module and qualname:
        return "%s.%s" % (module, qualname)
    return None


def _role_finding(connection):
    """W003 settings finding computed on the SCANNED ``connection``.

    :func:`checks.check_rls_role` always opens the default tenant alias; the
    doctor must report the role for the alias actually being scanned so the
    finding stays consistent with the per-model classifications and the top-level
    ``blocked`` flag (which both use the scanned connection). Honors
    ``TENANT_RLS_ALLOW_BYPASS_ROLE`` (ok when opted out) and degrades to ok when
    the role cannot be determined (non-PostgreSQL / unreachable).
    """
    ok = {
        "id": "ok", "level": "ok", "title": "Database role (W003)",
        "detail": (
            "The connecting role does not bypass RLS (not a superuser and no "
            "BYPASSRLS attribute), so policies are actually enforced."
        ),
        "remedy": "", "step": 1,
    }
    if conf.allow_bypass_role():
        return ok
    try:
        if connection.vendor != "postgresql":
            return ok
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT rolname, rolsuper, rolbypassrls "
                "FROM pg_roles WHERE rolname = current_user"
            )
            row = cursor.fetchone()
    except Exception:
        return ok
    if not row:
        return ok
    rolname, is_super, is_bypass = row
    if not (is_super or is_bypass):
        return ok
    reason = "is a superuser" if is_super else "has the BYPASSRLS attribute"
    return {
        "id": checks.W003_ID, "level": "error", "title": "Database role (W003)",
        "detail": (
            "The database role %r %s, so PostgreSQL bypasses ALL row-security "
            "policies on this connection: tenant isolation is NOT enforced (even "
            "with FORCE ROW LEVEL SECURITY)." % (rolname, reason)
        ),
        "remedy": (
            "Connect django-tenants as a NOSUPERUSER NOBYPASSRLS role. The "
            "documented opt-out TENANT_RLS_ALLOW_BYPASS_ROLE=True suppresses this."
        ),
        "step": 1,
    }


def _settings_findings(connection):
    """Assemble the ``settings`` section by composing the check predicates + the
    two new introspections. Each entry follows the shared contract shape. The
    role (W003) finding is computed on the caller-supplied ``connection`` so it
    matches the alias being scanned.
    """
    findings = [
        _setting_entry(
            checks.check_rls_backend(None),
            ok_title="Database ENGINE / backend (W001)",
            ok_detail=(
                "RLS isolation will be applied (the RLS backend is in use or the "
                "fallback middleware is installed)."
            ),
            step=1,
        ),
        _role_finding(connection),
        _setting_entry(
            checks.check_rls_var_names(None),
            ok_title="Session/bypass GUC variable names (E001)",
            ok_detail="The configured GUC variable names are well-formed.",
            step=1,
        ),
        _setting_entry(
            checks.check_tenant_pk_cast(None),
            ok_title="Tenant PK cast (E002)",
            ok_detail="The tenant model primary key maps to a supported RLS cast.",
            step=1,
        ),
        _cache_key_function_finding(),
        _storage_finding(),
    ]
    return findings


def unsafe_tenant_fk_migration_findings(connection=None):
    """Best-effort static scan for an unsafe, UNAPPLIED tenant-FK ``AddField``.

    Every other doctor introspection (``classify_model`` and its helpers) is
    live-DB only -- by construction it cannot see a migration that has not run
    yet. The classic G1 landmine is exactly that: running ``makemigrations`` after
    adding the tenant FK against an EMPTY (CI / throwaway) database makes Django
    emit ``AddField(<tenant_field>, ForeignKey(default=1, ...),
    preserve_default=False)``. On the empty DB it is harmless and sails through
    review, but applied to a POPULATED prod DB it stamps every pre-existing row
    into whatever tenant has pk=1 -- silently corrupting ownership before RLS is
    even enabled. The only safe shape is nullable-add -> per-row backfill -> SET
    NOT NULL, which :func:`scaffold.staged_fk_migration` emits.

    This walks each app's UNAPPLIED migrations via Django's ``MigrationLoader``
    and flags every ``AddField`` whose field name equals
    ``conf.tenant_field()`` AND whose field carries a non-``NOT_PROVIDED`` default
    (the ``default=1, preserve_default=False`` shape). It deliberately matches
    ONLY the tenant FK column name (and only relation fields) to avoid false
    positives on legitimate scalar fields that carry an ordinary default.

    Returns a list of ``settings``-shaped findings (warning level -- this is an
    opt-in heuristic with an AST/serialized-state false-positive surface, NOT a
    hard gate; it is non-fatal so it never changes the exit code). It is wholly
    best-effort: any failure loading migrations (no migrations dir, an
    un-importable migration, ``MigrationLoader`` unavailable, no database) yields
    an empty list rather than raising, mirroring the rest of this module.
    """
    findings = []
    try:
        from django.db import connections
        from django.db.migrations.loader import MigrationLoader
        from django.db.models import NOT_PROVIDED
        from django_tenants.utils import get_tenant_database_alias
    except Exception:
        return findings

    if connection is None:
        try:
            connection = connections[get_tenant_database_alias()]
        except Exception:
            return findings

    field = conf.tenant_field()

    try:
        # ignore_no_migrations: a project may have apps without a migrations
        # package; we only care about the ones that DO have unapplied migrations.
        loader = MigrationLoader(connection, ignore_no_migrations=True)
    except Exception:
        return findings

    # Unapplied = on disk but not in the applied set. graph.nodes keys are
    # (app_label, migration_name); loader.applied_migrations is the same key set.
    try:
        applied = set(loader.applied_migrations or {})
        disk_keys = list(loader.disk_migrations.keys())
    except Exception:
        return findings

    for key in disk_keys:
        if key in applied:
            continue
        migration = loader.disk_migrations.get(key)
        if migration is None:
            continue
        app_label, migration_name = key
        for operation in getattr(migration, "operations", []) or []:
            # Only AddField operations; match by class name so we do not import
            # the operations module just to isinstance-check it.
            if operation.__class__.__name__ != "AddField":
                continue
            op_field_name = getattr(operation, "name", None)
            if op_field_name != field:
                continue
            op_field = getattr(operation, "field", None)
            if op_field is None:
                continue
            # Only the tenant FK column: a relation field (skip an unrelated
            # scalar that happens to share the configured name).
            if not getattr(op_field, "is_relation", False):
                continue
            default = getattr(op_field, "default", NOT_PROVIDED)
            if default is NOT_PROVIDED:
                continue
            findings.append({
                "id": "django_tenants_rls.unsafe_tenant_fk_migration",
                "level": "warning",
                "title": "Unsafe unapplied tenant-FK AddField (G1)",
                "detail": (
                    "Unapplied migration %s.%s adds the tenant field %r with a "
                    "non-null default (default=%r, the 'default=1, "
                    "preserve_default=False' shape makemigrations emits against an "
                    "empty DB). Applied to a POPULATED database this stamps every "
                    "pre-existing row into a single tenant, silently corrupting "
                    "ownership before RLS is enabled."
                    % (app_label, migration_name, field, default)
                ),
                "remedy": (
                    "Rewrite this as the safe staged shape -- add the FK null=True, "
                    "backfill each row's real owner, THEN SET NOT NULL -- as "
                    "emitted by scaffold.staged_fk_migration (or 'manage.py "
                    "rls_doctor --generate'). Do NOT apply the one-off-default "
                    "AddField to a populated database."
                ),
                "step": 3,
            })

    return findings


def scan(database=None):
    """Scan the project + tenant database and return the readiness report dict.

    This is the single source of truth behind the ``rls_doctor`` command, its
    ``--format json`` output and the admin dashboard. The shape is::

        {
          "rls_enabled": bool,
          "database": <alias>,
          "settings": [ {id, level, title, detail, remedy, step}, ... ],
          "models":   [ {label, table, classification, problems,
                         unscoped_rows, remedy, step}, ... ],
          "external_tables": [ {table, classification, problems, remedy,
                                step}, ... ],
          "summary":  {done, auto_fixable, generate_migration, manual, blocked},
          "blocked":  bool,   # True if the role bypasses RLS (W003) -> --fix refuses
        }

    The ``external_tables`` section classifies every ``conf.external_tables()``
    entry (``TENANT_RLS_EXTERNAL_TABLES``) -- contrib/third-party/M2M tables that
    cannot subclass ``TenantRLSModel`` and so are invisible to the per-model scan
    -- using the same table-name introspection as ``verify_rls`` / the W008 check
    (:func:`classify_external_table`). Each entry is ``done`` /
    ``needs_isolation`` / ``blocked``. When any registered table is not ``done``,
    an error-level ``settings`` finding (id ``django_tenants_rls.W008``) is also
    emitted so the ``rls_doctor`` exit-code rule (which already fails on any
    error-level settings finding) gates the deploy on it -- a green scan now means
    the registered external tables are isolated too, not just the model tables.

    ``database`` defaults to the tenant database alias. The scan is BEST-EFFORT on
    database access: a model whose table is missing, or a DB that is unreachable,
    degrades to a per-model finding (never raises). It composes the existing check
    predicates, :func:`checks.rls_live_problems` and
    :meth:`TenantRLSModel.has_unscoped_rows` via :func:`classify_model`; it does not
    duplicate their SQL beyond the one cheap ``pg_roles`` lookup needed to set the
    top-level ``blocked`` flag.
    """
    from django.db import connections
    from django_tenants.utils import get_tenant_database_alias

    alias = database or get_tenant_database_alias()
    connection = connections[alias]
    force = conf.force_rls()

    settings_findings = _settings_findings(connection)

    # Top-level blocked flag: the connecting role bypasses RLS (W003). This is the
    # same predicate classify_model uses per model, computed once for the summary
    # and for the command's --fix refusal.
    blocked = _role_bypasses_rls(connection)

    summary = {name: 0 for name in CLASSIFICATIONS}
    model_findings = []

    # Step each classification maps to, for the report's "see step N" pointer.
    step_for = {
        "done": 6,
        "auto_fixable": 6,
        "generate_migration": 3,
        "manual": 4,
        "blocked": 1,
    }
    remedy_for = {
        "done": "RLS is fully live; nothing to do.",
        "auto_fixable": (
            "Run 'manage.py rls_doctor --fix' (or 'manage.py enable_rls') to "
            "enable RLS, FORCE ROW LEVEL SECURITY and the tenant policy."
        ),
        "generate_migration": (
            "Run 'manage.py rls_doctor --generate' to scaffold the migration(s), "
            "review them, then add to the app's migrations and migrate."
        ),
        "manual": (
            "Backfill the tenant for every NULL-tenant row (Step 4, app-specific), "
            "then re-run rls_doctor. This step is never auto-run."
        ),
        "blocked": (
            "Connect django-tenants as a NOSUPERUSER, NOBYPASSRLS role; RLS is not "
            "enforced for a bypassing role even with FORCE ROW LEVEL SECURITY."
        ),
    }

    for model in sorted(checks._iter_concrete_rls_models(), key=lambda m: m._meta.label):
        classification, problems = classify_model(model, connection, force=force)
        # unscoped_rows is reported only when it is meaningful (a model that needs
        # a backfill); otherwise None so JSON consumers see "not determined here".
        unscoped = None
        if classification == "manual":
            unscoped = True
        elif classification in ("auto_fixable", "done"):
            unscoped = False
        summary[classification] += 1
        model_findings.append({
            "label": model._meta.label,
            "table": model._meta.db_table,
            "classification": classification,
            "problems": problems,
            "unscoped_rows": unscoped,
            "remedy": remedy_for[classification],
            "step": step_for[classification],
        })

    # Registered external tables (TENANT_RLS_EXTERNAL_TABLES): contrib/third-party
    # /M2M tables that cannot subclass TenantRLSModel and so never appear in the
    # per-model loop above. Classify each with the same table-name introspection
    # verify_rls / W008 use (classify_external_table) so a green scan covers them
    # too. A non-done entry is folded into an error-level settings finding below so
    # the command's exit-code rule (which fails on any error-level setting) gates
    # on it -- the command itself needs no change.
    external_step = 7  # docs/rls_migration.rst "Third-party / non-policied tables"
    external_remedy = (
        "Isolate the table with the IsolateExternalTable migration operation (or "
        "apply scaffold.isolate_external_table_sql): ENABLE/FORCE ROW LEVEL "
        "SECURITY, add a tenant-isolation policy and make its tenant column NOT "
        "NULL, then re-run 'manage.py verify_rls'."
    )
    external_findings = []
    for table in conf.external_tables():
        classification, problems = classify_external_table(
            table, connection, force=force
        )
        external_findings.append({
            "table": table,
            "classification": classification,
            "problems": problems,
            "remedy": "" if classification == "done" else external_remedy,
            "step": external_step,
        })

    # Optional, best-effort static scan for an unsafe UNAPPLIED tenant-FK AddField
    # (the default=1 / preserve_default=False landmine). Non-fatal: warning-level
    # findings only, so it never changes the exit code -- it catches the landmine
    # BEFORE migrate runs on prod, where the live-DB introspection above cannot.
    settings_findings.extend(
        unsafe_tenant_fk_migration_findings(connection)
    )

    not_done_external = [
        f for f in external_findings if f["classification"] != "done"
    ]
    if not_done_external:
        offenders = ", ".join(sorted(f["table"] for f in not_done_external))
        settings_findings.append({
            "id": checks.W008_ID,
            "level": "error",
            "title": "External tables not isolated (W008)",
            "detail": (
                "%d registered external table(s) in TENANT_RLS_EXTERNAL_TABLES "
                "are not RLS-isolated (RLS off / unforced / no policy / nullable "
                "tenant column, or the role bypasses RLS): %s. Their rows are "
                "shared across all tenants." % (len(not_done_external), offenders)
            ),
            "remedy": external_remedy,
            "step": external_step,
        })

    return {
        "rls_enabled": conf.rls_enabled(),
        "database": alias,
        "settings": settings_findings,
        "models": model_findings,
        "external_tables": external_findings,
        "summary": summary,
        "blocked": blocked,
    }
