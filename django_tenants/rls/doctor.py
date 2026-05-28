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
_RLS_STORAGE = "django_tenants.rls.storage.RLSTenantFileSystemStorage"


def _role_bypasses_rls(connection):
    """Best-effort: does ``connection``'s current role bypass RLS (W003)?

    Returns True only when we can positively confirm the role is a superuser or
    has the BYPASSRLS attribute. Any inability to check (non-PostgreSQL, DB not
    reachable, permission denied) returns False -- if we cannot prove the role
    bypasses RLS we must not falsely declare every model ``blocked``. This mirrors
    the best-effort posture of :func:`checks.check_rls_role`, but operates on the
    caller-owned connection (so ``scan(database=...)`` can target any alias).
    """
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
    """
    field = conf.tenant_field()
    problems = []
    for label, fields in checks._unique_fieldsets(model):
        if field in fields:
            continue
        problems.append(
            "UNIQUE constraint %s spans %r and omits the tenant field %r "
            "(checked with RLS BYPASSED -> cross-tenant uniqueness/leak)"
            % (label, tuple(fields), field)
        )
    return problems


def _has_tenant_field(model):
    """Whether ``model`` declares the configured tenant field (W002 inverse)."""
    try:
        model._meta.get_field(conf.tenant_field())
        return True
    except Exception:
        return False


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
    3. ``generate_migration`` -- a schema change is owed that must go through a
       migration/scaffold (never auto-run): no tenant FK at all (Step 3), a
       nullable tenant column (Steps 3/5), or a UNIQUE constraint omitting the
       tenant (Step 8). The nullable-column signal is taken from
       ``rls_live_problems`` (the word "NULLABLE" in a problem string) so we do
       not duplicate its information_schema query.
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
    try:
        unscoped = model.has_unscoped_rows()
    except Exception:
        # has_unscoped_rows is itself defensive and returns False on a missing
        # table, so a raise here is unexpected; be conservative and require a
        # human rather than auto-enabling against an unknown state.
        return "manual", list(live_problems) + [
            "could not determine whether the table has unscoped (NULL tenant) "
            "rows; backfill and verify before enabling RLS (Step 4)"
        ]

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

    if backend == _SCHEMA_BASED_STORAGE:
        return {
            "id": "django_tenants_rls.storage",
            "level": "warning",
            "title": "Default file storage",
            "detail": (
                "The default file storage is %r, which derives the per-tenant "
                "media path from connection.schema_name. Under RLS that is pinned "
                "to 'public' for every tenant, so all tenants' files share one "
                "directory (a cross-tenant file leak)." % _SCHEMA_BASED_STORAGE
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
            "The default file storage is not the schema-name-based "
            "%r." % _SCHEMA_BASED_STORAGE
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


def _settings_findings():
    """Assemble the ``settings`` section by composing the check predicates + the
    two new introspections. Each entry follows the shared contract shape.
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
        _setting_entry(
            checks.check_rls_role(None),
            ok_title="Database role (W003)",
            ok_detail=(
                "The connecting role does not bypass RLS (not a superuser and no "
                "BYPASSRLS attribute), so policies are actually enforced."
            ),
            step=1,
        ),
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
          "summary":  {done, auto_fixable, generate_migration, manual, blocked},
          "blocked":  bool,   # True if the role bypasses RLS (W003) -> --fix refuses
        }

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

    settings_findings = _settings_findings()

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

    return {
        "rls_enabled": conf.rls_enabled(),
        "database": alias,
        "settings": settings_findings,
        "models": model_findings,
        "summary": summary,
        "blocked": blocked,
    }
