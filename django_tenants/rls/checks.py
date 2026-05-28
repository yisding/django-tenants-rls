"""Django system checks for the django-tenants RLS subpackage.

All checks are gated on ``conf.rls_enabled()`` so that installs which have not
opted into RLS see no warnings or errors at all. The checks are registered via
the ``@register`` decorators below; they are wired into Django by importing this
module from ``DjangoTenantsRLSConfig.ready()``.
"""

from django.core.checks import Error, Tags, Warning, register

from . import conf


# Stable identifiers for each message, referenced from the docs and tests.
W001_ID = "django_tenants_rls.W001"   # RLS enabled but backend is not the RLS wrapper
W002_ID = "django_tenants_rls.W002"   # TENANT_RLS_TENANT_FIELD not present on a TenantRLSModel
W003_ID = "django_tenants_rls.W003"   # DB role bypasses RLS (superuser / BYPASSRLS)
W004_ID = "django_tenants_rls.W004"   # RLS not actually live on a tenant table (drift)
W005_ID = "django_tenants_rls.W005"   # UNIQUE constraint omits the tenant (cross-tenant leak)
E001_ID = "django_tenants_rls.E001"   # session/bypass var names invalid (bad GUC format)
E002_ID = "django_tenants_rls.E002"   # tenant PK type cannot be cast for RLS comparison

# The database ENGINE that wires up the RLS-aware DatabaseWrapper / schema editor.
RLS_BACKEND_ENGINE = "django_tenants.rls.backend"

# Dotted path of the optional fallback middleware that sets the tenant session
# variable when the stock backend is in use.
RLS_MIDDLEWARE_PATH = "django_tenants.rls.middleware.TenantRLSMiddleware"


def _iter_concrete_rls_models():
    """Yield every concrete (non-abstract) ``TenantRLSModel`` subclass.

    This mirrors the iteration used by :func:`check_tenant_field`: walk the app
    registry and keep only concrete subclasses of ``TenantRLSModel``. Importing
    ``TenantRLSModel`` and the app registry lazily keeps this module import-light.
    """
    from django.apps import apps as django_apps

    from .models import TenantRLSModel

    for model in django_apps.get_models():
        if not issubclass(model, TenantRLSModel):
            continue
        if getattr(model._meta, "abstract", False):
            continue
        yield model


def rls_live_problems(model, connection, *, force):
    """Introspect ``connection`` for the live RLS state of ``model``'s table.

    Returns a list of human-readable problem strings (empty when the table is
    fully protected). This is the reusable per-model check shared by the W004
    system check and the ``verify_rls`` management command.

    The caller owns the connection and error handling. This function does NOT
    swallow database errors -- it runs four cheap catalog queries on the table
    and lets any failure propagate so the caller can decide whether to treat it
    as "cannot check" (the system check) or a hard failure (the command). The
    queries verify that:

    * ``pg_class.relrowsecurity`` is true (RLS is ENABLED on the table);
    * when ``force`` is true, ``pg_class.relforcerowsecurity`` is true (so the
      table owner is policed too -- otherwise the owner role bypasses RLS);
    * at least one policy exists in ``pg_policies`` for the table (an
      RLS-enabled table with no policy denies all rows, i.e. silent breakage);
    * the tenant column (``<tenant_field>_id``) is NOT NULL -- a nullable tenant
      column lets a row be written with no tenant, which then becomes invisible
      to every tenant once RLS is on (an unscoped, leaking row source).
    """
    table = model._meta.db_table
    field = conf.tenant_field()
    attname = "%s_id" % field
    problems = []

    with connection.cursor() as cursor:
        # RLS enabled / forced. regclass resolves the (possibly schema-qualified)
        # table name to its pg_class row; an unknown table raises (caller handles).
        cursor.execute(
            "SELECT relrowsecurity, relforcerowsecurity "
            "FROM pg_class WHERE oid = %s::regclass",
            [table],
        )
        row = cursor.fetchone()
        if not row:
            problems.append(
                "table %r not found in pg_class (cannot verify RLS)" % table
            )
        else:
            relrowsecurity, relforcerowsecurity = row
            if not relrowsecurity:
                problems.append("RLS not enabled on table %r" % table)
            if force and not relforcerowsecurity:
                problems.append(
                    "RLS not forced on table %r (TENANT_RLS_FORCE is on; the "
                    "table owner bypasses unforced RLS)" % table
                )

        # At least one policy. pg_policies is unqualified by schema name in its
        # tablename column, so match on the bare table name.
        cursor.execute(
            "SELECT COUNT(*) FROM pg_policies WHERE tablename = %s",
            [table],
        )
        policy_count = cursor.fetchone()[0]
        if not policy_count:
            problems.append("no RLS policy exists for table %r" % table)

        # Tenant column NOT NULL. A schema-qualified db_table ("schema.table")
        # is split so information_schema can match table_schema/table_name; a
        # bare name falls through to whatever schema the search_path resolves.
        if "." in table:
            schema_name, table_name = table.split(".", 1)
            cursor.execute(
                "SELECT is_nullable FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = %s "
                "AND column_name = %s",
                [schema_name.strip('"'), table_name.strip('"'), attname],
            )
        else:
            cursor.execute(
                "SELECT is_nullable FROM information_schema.columns "
                "WHERE table_name = %s AND column_name = %s",
                [table.strip('"'), attname],
            )
        col = cursor.fetchone()
        if col is not None and col[0] == "YES":
            problems.append(
                "tenant column %r on table %r is NULLABLE (a row with no tenant "
                "becomes invisible to every tenant under RLS)" % (attname, table)
            )

    return problems


def _engine_is_rls_backend(engine):
    """Return True if ``engine`` resolves to (or subclasses) the RLS backend.

    A legitimate drop-in pattern is for a project to define its own ENGINE module
    whose ``DatabaseWrapper`` subclasses
    ``django_tenants.rls.backend.base.DatabaseWrapper`` (for example to add an
    ``EXTRA_SET_TENANT_METHOD`` or a custom psycopg layer). Such a backend fully
    applies RLS, so we try to import the configured engine's ``base`` module and
    check the subclass relationship. If the import fails (e.g. the engine cannot
    be imported during checks) we fall back to the plain string match so the
    check never raises.
    """
    if not engine:
        return False
    if engine == RLS_BACKEND_ENGINE or engine.startswith(RLS_BACKEND_ENGINE + "."):
        return True
    try:
        from importlib import import_module

        from django_tenants.rls.backend.base import DatabaseWrapper as RLSWrapper

        module = import_module(engine + ".base")
        wrapper = getattr(module, "DatabaseWrapper", None)
        if wrapper is not None and issubclass(wrapper, RLSWrapper):
            return True
    except Exception:
        # Importing the engine (or the RLS backend) can fail for many reasons
        # during a check; treat that as "not the RLS backend" rather than error.
        pass
    return False


@register(Tags.database)
def check_rls_backend(app_configs, **kwargs):
    """Warn when RLS is enabled but nothing will actually apply the policies.

    RLS isolation is applied either by the RLS ``DatabaseWrapper`` (when the
    tenant database ``ENGINE`` is ``django_tenants.rls.backend``) or by the
    fallback ``TenantRLSMiddleware``. If neither is configured the policies will
    be created on the tables but the tenant session variable will never be set,
    so every query evaluates the policy against an unset variable and silently
    returns nothing.
    """
    errors = []
    if not conf.rls_enabled():
        return errors

    from django.conf import settings
    from django_tenants.utils import get_tenant_database_alias

    alias = get_tenant_database_alias()
    databases = getattr(settings, "DATABASES", {}) or {}
    engine = (databases.get(alias, {}) or {}).get("ENGINE", "")

    backend_in_use = _engine_is_rls_backend(engine)

    middleware = list(getattr(settings, "MIDDLEWARE", None) or [])
    middleware_installed = RLS_MIDDLEWARE_PATH in middleware

    if not backend_in_use and not middleware_installed:
        errors.append(
            Warning(
                "TENANT_RLS_ENABLED is True but the database ENGINE is not "
                "'%s' and TenantRLSMiddleware is not installed; RLS isolation "
                "will NOT be applied." % RLS_BACKEND_ENGINE,
                hint=(
                    "Set DATABASES['%s']['ENGINE'] = '%s' (keeping "
                    "ORIGINAL_BACKEND), or add '%s' to MIDDLEWARE after "
                    "TenantMainMiddleware." % (alias, RLS_BACKEND_ENGINE, RLS_MIDDLEWARE_PATH)
                ),
                id=W001_ID,
            )
        )
    return errors


@register(Tags.database)
def check_rls_role(app_configs, **kwargs):
    """Error when the tenant DB role bypasses RLS (superuser or BYPASSRLS).

    This is the single most dangerous RLS misconfiguration: PostgreSQL silently
    ignores ALL row-security policies for a superuser or a role with the
    BYPASSRLS attribute -- even with ``FORCE ROW LEVEL SECURITY`` set. The tables
    look protected (``relrowsecurity``/``relforcerowsecurity`` are true and the
    policies exist), every query succeeds, and yet there is ZERO tenant
    isolation. It is extremely easy to hit because the default Postgres
    superuser (e.g. the ``postgres`` role, or the ``POSTGRES_USER`` of a Docker
    image) bypasses RLS, so a setup can pass every other check and still leak.

    Because a bypassing role means there is effectively no isolation at all, this
    is reported as an ``Error`` (it blocks startup / ``manage.py`` commands that
    run system checks) rather than a soft warning. The deliberate, documented
    opt-out is ``TENANT_RLS_ALLOW_BYPASS_ROLE = True`` (``conf.allow_bypass_role()``):
    when set, no finding is emitted at all.

    The check is best-effort: it opens a connection on the tenant alias and reads
    ``current_user``'s ``rolsuper`` / ``rolbypassrls``. Any failure (database not
    created yet, not connectable, non-PostgreSQL, permission denied) returns no
    findings rather than a false alarm -- if we cannot check, we cannot block.
    """
    errors = []
    if not conf.rls_enabled():
        return errors

    # Explicit, documented opt-out: the operator has acknowledged that the role
    # bypasses RLS (e.g. isolation enforced by another mechanism). Emit nothing.
    if conf.allow_bypass_role():
        return errors

    from django.db import connections
    from django_tenants.utils import get_tenant_database_alias

    alias = get_tenant_database_alias()
    try:
        connection = connections[alias]
        if connection.vendor != "postgresql":
            return errors
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT rolname, rolsuper, rolbypassrls "
                "FROM pg_roles WHERE rolname = current_user"
            )
            row = cursor.fetchone()
    except Exception:
        # DB not available / not introspectable during checks -> stay silent.
        # If we cannot check, we cannot block.
        return errors

    if not row:
        return errors

    rolname, is_super, is_bypass = row
    if is_super or is_bypass:
        reason = "is a superuser" if is_super else "has the BYPASSRLS attribute"
        errors.append(
            Error(
                "TENANT_RLS_ENABLED is True but the database role %r %s, so "
                "PostgreSQL bypasses ALL row-security policies: tenant isolation "
                "is NOT enforced for this connection (even with FORCE ROW LEVEL "
                "SECURITY)." % (rolname, reason),
                hint=(
                    "Connect django-tenants as a dedicated role that is NOT a "
                    "superuser and does NOT have BYPASSRLS, e.g.:\n"
                    "    CREATE ROLE app LOGIN PASSWORD '...' NOSUPERUSER NOBYPASSRLS;\n"
                    "    GRANT ... ON ALL TABLES IN SCHEMA public TO app;\n"
                    "Keep a separate superuser only for migrations / admin tasks.\n"
                    "To deliberately allow a bypassing role (isolation guaranteed "
                    "by another mechanism), set TENANT_RLS_ALLOW_BYPASS_ROLE = True "
                    "-- this disables the safety net, so use it knowingly."
                ),
                id=W003_ID,
            )
        )
    return errors


@register()
def check_rls_var_names(app_configs, **kwargs):
    """Error when the configured GUC variable names are malformed.

    The session and bypass variable names are embedded into policy DDL (they
    cannot be bound parameters there), so a malformed name is both a correctness
    and a security problem. ``conf.session_variable()`` / ``conf.bypass_variable()``
    raise ``ImproperlyConfigured`` on a bad name; we surface that as a check error.
    """
    errors = []
    if not conf.rls_enabled():
        return errors

    from django.core.exceptions import ImproperlyConfigured

    for getter in (conf.session_variable, conf.bypass_variable):
        try:
            getter()
        except ImproperlyConfigured as exc:
            errors.append(
                Error(
                    str(exc),
                    hint=(
                        "GUC variable names must match '<class>.<name>' using "
                        "letters, digits and underscores (exactly one dot)."
                    ),
                    id=E001_ID,
                )
            )
    return errors


@register()
def check_tenant_pk_cast(app_configs, **kwargs):
    """Error when the tenant model PK type cannot be cast for the RLS comparison.

    The tenant policy compares ``<tenant_field>_id`` against the session GUC by
    casting the GUC text to the tenant PK's Postgres type (integer, bigint, uuid
    or text). ``conf.get_tenant_pk_cast()`` raises ``ImproperlyConfigured`` for
    any other PK type rather than silently falling back to ``text`` (a text cast
    would miscompare integer columns and break every query). We surface that as a
    check error so the misconfiguration is caught at startup instead of failing
    every tenant query at runtime.
    """
    errors = []
    if not conf.rls_enabled():
        return errors

    from django.core.exceptions import ImproperlyConfigured

    try:
        conf.get_tenant_pk_cast()
    except ImproperlyConfigured as exc:
        errors.append(
            Error(
                str(exc),
                hint=(
                    "The tenant model primary key must be an integer-family, "
                    "UUID or text-like field for the RLS policy comparison. "
                    "Use a supported PK type, or set a matching "
                    "TenantPolicy(pk_cast=...) on each model's tenant policy."
                ),
                id=E002_ID,
            )
        )
    return errors


@register()
def check_tenant_field(app_configs, **kwargs):
    """Warn when a TenantRLSModel subclass lacks the configured tenant field.

    The default tenant policy filters on ``<tenant_field>_id``; if the field is
    missing the generated policy SQL would reference a non-existent column and
    every query against the table would error.
    """
    errors = []
    if not conf.rls_enabled():
        return errors

    from django.apps import apps as django_apps

    from .models import TenantRLSModel

    field = conf.tenant_field()
    for model in django_apps.get_models():
        if not issubclass(model, TenantRLSModel):
            continue
        if getattr(model._meta, "abstract", False):
            continue
        try:
            model._meta.get_field(field)
        except Exception:
            errors.append(
                Warning(
                    "TenantRLSModel '%s' has no field named '%s' "
                    "(TENANT_RLS_TENANT_FIELD); its tenant RLS policy will "
                    "reference a missing column." % (model._meta.label, field),
                    hint=(
                        "Add a ForeignKey named '%s' to the tenant model, or set "
                        "TENANT_RLS_TENANT_FIELD to the correct field name and use "
                        "a matching TenantPolicy(tenant_field=...)." % field
                    ),
                    obj=model,
                    id=W002_ID,
                )
            )
    return errors


@register(Tags.database)
def check_rls_live(app_configs, **kwargs):
    """Warn when RLS is not actually LIVE on a tenant table (drift detection).

    Policies and ``ALTER TABLE ... ENABLE ROW LEVEL SECURITY`` are applied by
    ``enable_rls`` / post-migrate auto-enable, but a table created by an external
    migration, a manual ``DISABLE ROW LEVEL SECURITY``, or a dropped policy can
    leave a ``TenantRLSModel`` table unprotected while everything else looks fine.
    This check introspects the actual Postgres catalogs on the tenant alias and
    warns about any gap: RLS not enabled, RLS not forced (when ``TENANT_RLS_FORCE``
    is on), no policy present, or a nullable tenant column.

    BEST-EFFORT: it opens a connection on the tenant alias and runs catalog
    queries per model. Any database failure (DB not created yet, not connectable,
    non-PostgreSQL, permission denied, table missing) is swallowed and yields NO
    findings rather than a false alarm -- if we cannot introspect, we do not warn.
    The per-model introspection itself is factored into :func:`rls_live_problems`,
    which the ``verify_rls`` management command reuses.
    """
    errors = []
    if not conf.rls_enabled():
        return errors

    from django.db import connections
    from django_tenants.utils import get_tenant_database_alias

    alias = get_tenant_database_alias()
    force = conf.force_rls()
    try:
        connection = connections[alias]
        if connection.vendor != "postgresql":
            return errors
        for model in _iter_concrete_rls_models():
            for problem in rls_live_problems(model, connection, force=force):
                errors.append(
                    Warning(
                        "RLS is not fully live for TenantRLSModel '%s' "
                        "(table %r): %s" % (model._meta.label, model._meta.db_table, problem),
                        hint=(
                            "Run 'manage.py enable_rls' (or 'manage.py verify_rls' "
                            "in CI) to (re)apply RLS, FORCE ROW LEVEL SECURITY and "
                            "the tenant-isolation policy on this table."
                        ),
                        obj=model,
                        id=W004_ID,
                    )
                )
    except Exception:
        # DB not available / not introspectable during checks -> stay silent.
        # If we cannot check, we cannot warn (best-effort by design).
        return []
    return errors


def _unique_fieldsets(model):
    """Yield ``(label, fields)`` for every UNIQUE declaration on ``model``.

    ``label`` is a short human description of where the uniqueness comes from and
    ``fields`` is the tuple of field names it spans. Covers:

    * a single field declared ``unique=True``;
    * each ``Meta.unique_together`` group (normalized to a list of tuples);
    * each ``Meta.constraints`` entry that is a ``UniqueConstraint`` with an
      explicit ``fields`` list (expression-based constraints have no ``fields``).
    """
    from django.db.models import UniqueConstraint

    meta = model._meta
    for field in meta.local_fields:
        # Skip the tenant FK itself and the PK; we care about *other* unique cols.
        if getattr(field, "unique", False) and not getattr(field, "primary_key", False):
            yield ("field %r (unique=True)" % field.name, (field.name,))

    unique_together = meta.unique_together or ()
    # unique_together may be a single tuple of field names or a tuple of tuples.
    if unique_together and isinstance(unique_together[0], str):
        unique_together = (unique_together,)
    for group in unique_together:
        yield ("Meta.unique_together %r" % (tuple(group),), tuple(group))

    for constraint in getattr(meta, "constraints", None) or ():
        if isinstance(constraint, UniqueConstraint) and constraint.fields:
            yield (
                "UniqueConstraint %r" % (constraint.name or tuple(constraint.fields),),
                tuple(constraint.fields),
            )


@register()
def check_tenant_unique_constraints(app_configs, **kwargs):
    """Warn about UNIQUE constraints on a TenantRLSModel that omit the tenant.

    PostgreSQL evaluates UNIQUE (and PK/FK) constraint checks with RLS policies
    BYPASSED. A global ``unique=True`` field (or a ``unique_together`` /
    ``UniqueConstraint`` whose field set does not include the tenant) therefore
    enforces uniqueness across ALL tenants: an INSERT that collides with a row
    owned by a DIFFERENT tenant raises a unique-violation, leaking the existence
    of that other tenant's row (a cross-tenant existence covert channel) -- even
    though RLS otherwise hides it.

    This is a model-level check (no database access): it inspects the declared
    constraints of each concrete ``TenantRLSModel`` and warns about any UNIQUE
    field set that does not include ``TENANT_RLS_TENANT_FIELD``.
    """
    errors = []
    if not conf.rls_enabled():
        return errors

    field = conf.tenant_field()
    for model in _iter_concrete_rls_models():
        for label, fields in _unique_fieldsets(model):
            if field in fields:
                continue
            errors.append(
                Warning(
                    "TenantRLSModel '%s' has a UNIQUE constraint that does not "
                    "include the tenant field '%s': %s spans %r. PostgreSQL "
                    "checks UNIQUE constraints with RLS BYPASSED, so this enforces "
                    "uniqueness across ALL tenants and leaks cross-tenant row "
                    "existence." % (model._meta.label, field, label, tuple(fields)),
                    hint=(
                        "Make the constraint tenant-scoped, e.g. "
                        "models.UniqueConstraint(fields=['%s', %s], name=...), and "
                        "drop the global unique=True / unique_together." % (
                            field,
                            ", ".join(repr(f) for f in fields),
                        )
                    ),
                    obj=model,
                    id=W005_ID,
                )
            )
    return errors
