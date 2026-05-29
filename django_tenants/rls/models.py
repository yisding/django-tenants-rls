"""
Abstract base model and metaclass for django-tenants shared-schema RLS mode.

``TenantRLSModel`` is the drop-in base class for tenant-isolated models in RLS
(row-level security) mode. Unlike schema-per-tenant mode there is a single
``public`` schema; isolation is enforced by Postgres RLS policies on a ``tenant``
foreign key.

Subclasses gain:

* a ``tenant`` ``ForeignKey`` to ``settings.TENANT_MODEL`` (the attribute name is
  literally ``tenant``; if you override ``TENANT_RLS_TENANT_FIELD`` you must define
  your own FK with that name and a matching ``TenantPolicy``);
* automatic population of ``tenant_id`` from the active connection's tenant. The
  stamp happens in ``full_clean()`` (so a model validated before it is saved does
  not trip "tenant cannot be null"), again in ``save()`` (idempotent, for code
  that never validates), and in the default manager's ``bulk_create()`` (which
  bypasses ``save()`` entirely), so existing code that never passes ``tenant``
  keeps working;
* ``enable_rls()`` / ``disable_rls()`` classmethods that apply RLS + policies.

Policies are collected from ``Meta.rls_policies`` if present; otherwise a single
default :class:`~django_tenants.rls.policies.TenantPolicy` is built lazily at
enable time (so ``conf.*`` settings are read then, not at class-definition time).

The default manager does NOT filter rows -- the database enforces tenant
filtering via RLS, so no tenant-filtering manager is added. The only behavior the
default :class:`TenantRLSManager` adds over a plain ``Manager`` is auto-stamping
``tenant_id`` on the unsaved instances passed to ``bulk_create()`` (which never
calls ``save()`` and so would otherwise leave the FK NULL).
"""

import hashlib
import logging

from django.conf import settings
from django.db import models

from django_tenants.utils import get_tenant_database_alias

from . import conf

logger = logging.getLogger("django_tenants.rls")

# A Postgres identifier is at most 63 BYTES (NAMEDATALEN - 1). Policy names are
# identifiers, so the auto-generated default name must never exceed this.
_MAX_IDENTIFIER_BYTES = 63
_POLICY_NAME_SUFFIX = "_tenant_isolation"


def _default_policy_name(db_table):
    """Return the default tenant-isolation policy name for ``db_table``.

    The natural name is ``"<db_table>_tenant_isolation"``. Postgres identifiers
    are capped at 63 bytes, so if that exceeds the limit we deterministically
    shorten it: keep a readable prefix of ``db_table``, append a short hex hash of
    the *full* db_table (so distinct long tables stay unique), and a trimmed
    suffix. The result is stable across runs (no randomness) and <= 63 bytes.
    """
    natural = "%s%s" % (db_table, _POLICY_NAME_SUFFIX)
    if len(natural.encode("utf-8")) <= _MAX_IDENTIFIER_BYTES:
        return natural

    # Deterministic 8-char hash of the full table name keeps long names unique.
    digest = hashlib.sha1(db_table.encode("utf-8")).hexdigest()[:8]
    # Reserve room for "_" + digest + suffix; spend the rest on a readable prefix.
    suffix = "%s_%s%s" % ("_", digest, _POLICY_NAME_SUFFIX)
    prefix_budget = _MAX_IDENTIFIER_BYTES - len(suffix.encode("utf-8"))
    if prefix_budget < 0:
        # Pathological: even the hash + suffix overflow. Fall back to a minimal,
        # still-unique name truncated to the byte limit.
        minimal = "%s%s" % (digest, _POLICY_NAME_SUFFIX)
        return minimal.encode("utf-8")[:_MAX_IDENTIFIER_BYTES].decode(
            "utf-8", "ignore"
        )
    prefix = db_table.encode("utf-8")[:prefix_budget].decode("utf-8", "ignore")
    name = "%s%s" % (prefix, suffix)
    # Final guard: truncated multibyte decode could leave us a byte under budget,
    # never over, but assert the invariant defensively.
    return name.encode("utf-8")[:_MAX_IDENTIFIER_BYTES].decode("utf-8", "ignore")


def _validate_policies(policies):
    """
    Ensure ``policies`` is a list of :class:`BasePolicy` instances.

    Imported locally to keep the import graph light and avoid importing the
    policy/ABC machinery at module-import time.
    """
    from .policies import BasePolicy, PolicyError

    if not isinstance(policies, (list, tuple)):
        raise PolicyError(
            "Meta.rls_policies must be a list of BasePolicy instances, got %r."
            % type(policies).__name__
        )
    for policy in policies:
        if not isinstance(policy, BasePolicy):
            raise PolicyError(
                "Meta.rls_policies entries must be BasePolicy instances, got %r."
                % type(policy).__name__
            )


def _resolve_active_tenant_id(using):
    """Resolve the active tenant pk/id from the ``using`` connection, or None.

    Shared source-of-truth resolution used by ``TenantRLSModel.full_clean()``,
    ``TenantRLSModel.save()`` and ``TenantRLSManager.bulk_create()`` so all three
    auto-stamp paths agree on where the tenant comes from. The GUC is the source
    of truth -- it is what actually scopes the row in the database, and
    ``rls_context()``/``bypass_rls()`` set it without ever touching
    ``connection.tenant``:

    1. ``connection._rls_tenant_id`` -- the value pushed into the Postgres session
       GUC by the RLS backend -- if it is a non-empty string;
    2. otherwise ``connection.tenant.pk`` if a tenant object is bound;
    3. otherwise ``None`` (no active tenant; callers leave the FK unset).

    ``using`` is the database alias of the connection to read; callers resolve it
    (explicit ``using=`` > the instance's bound ``self._state.db`` > the tenant
    database alias) so a multi-database write is stamped from the right connection.
    """
    from django.db import connections

    conn = connections[using]
    # (a) GUC source of truth first: rls_context()+create() sets this but never
    # connection.tenant, so this must win over the bound object.
    rls_tenant_id = getattr(conn, "_rls_tenant_id", None)
    if isinstance(rls_tenant_id, str) and rls_tenant_id != "":
        return rls_tenant_id
    # (b) fall back to the bound tenant object's pk.
    tenant = getattr(conn, "tenant", None)
    return getattr(tenant, "pk", None)


class TenantRLSManager(models.Manager):
    """Default manager for :class:`TenantRLSModel`.

    Deliberately does NOT filter querysets by tenant -- isolation is enforced by
    the database RLS policies, so the base queryset is the stock unfiltered one
    (preserving the "default manager is unchanged" contract). The single behavior
    it adds is auto-stamping ``tenant_id`` in :meth:`bulk_create`, which bypasses
    ``save()`` (and therefore the ``save()``/``full_clean()`` auto-stamp) entirely
    and would otherwise insert rows with a NULL tenant FK.
    """

    def bulk_create(self, objs, *args, **kwargs):
        """Stamp ``tenant_id`` on each unsaved instance, then bulk insert.

        ``bulk_create()`` does not call ``Model.save()``, so the ordinary
        auto-stamp never runs; we replicate it here on each instance whose tenant
        FK is unset. An explicitly-set tenant is preserved and an explicit
        ``using=`` is honored (it overrides the per-instance bound db). When RLS is
        disabled this is a no-op and the call is a plain ``bulk_create()``.

        ``objs`` may be any iterable; Django materializes it to a list internally,
        so we materialize once up front to both stamp and forward the same list.
        """
        objs = list(objs)
        if conf.rls_enabled():
            field = conf.tenant_field()
            attname = "%s_id" % field
            explicit_using = kwargs.get("using")
            for obj in objs:
                if getattr(obj, attname, None) not in (None, ""):
                    continue
                using = (
                    explicit_using
                    or obj._state.db
                    or get_tenant_database_alias()
                )
                tenant_id = _resolve_active_tenant_id(using)
                if tenant_id is not None:
                    setattr(obj, attname, tenant_id)
        return super().bulk_create(objs, *args, **kwargs)


class RLSModelMeta(models.base.ModelBase):
    """
    Metaclass for :class:`TenantRLSModel`.

    Collects ``Meta.rls_policies`` (a list of ``BasePolicy``) and removes it from
    the Django ``Meta`` (Django's options machinery must not see the unknown
    attribute). If no explicit policies are given for a concrete model, a sentinel
    (``None``) is stored so a default :class:`TenantPolicy` can be built lazily at
    enable time via :meth:`TenantRLSModel.get_rls_policies` -- after ``conf.*``
    settings are loaded.
    """

    def __new__(mcs, name, bases, namespace, **kwargs):
        meta = namespace.get("Meta")
        explicit = []
        if meta is not None:
            # Read/clear via the Meta class's OWN __dict__ rather than the
            # inheritance-aware getattr/hasattr: an inherited ``rls_policies``
            # makes hasattr() true but delattr() would raise AttributeError, and
            # Django's options machinery must never see the attribute. Using
            # __dict__ both leaves an inherited attribute alone (Django ignores
            # inherited Meta attributes anyway) and only strips one declared
            # directly on this Meta.
            explicit = list(meta.__dict__.get("rls_policies", []) or [])
            if "rls_policies" in meta.__dict__:
                delattr(meta, "rls_policies")

        new_class = super().__new__(mcs, name, bases, namespace, **kwargs)

        if getattr(new_class._meta, "abstract", False):
            new_class._rls_policies = explicit
            return new_class

        if explicit:
            _validate_policies(explicit)
            new_class._rls_policies = explicit
        else:
            # No own ``Meta.rls_policies``. Before falling back to the default
            # policy, inherit a *non-empty* ``_rls_policies`` from an abstract
            # base that declared its own policies (e.g. a shared abstract parent
            # carrying a CustomPolicy set). Only a non-empty inherited list wins;
            # an empty/None base keeps the None sentinel so the default policy is
            # built lazily. ``TenantRLSModel`` itself has ``[]``, so a direct
            # concrete subclass with no policies still gets the default.
            inherited = None
            for base in new_class.__mro__[1:]:
                base_policies = base.__dict__.get("_rls_policies")
                if base_policies:
                    inherited = list(base_policies)
                    break
            if inherited:
                new_class._rls_policies = inherited
            else:
                # Sentinel: build the default TenantPolicy lazily at enable time.
                new_class._rls_policies = None

        return new_class


class TenantRLSModel(models.Model, metaclass=RLSModelMeta):
    """
    Abstract base for tenant-isolated models in shared-schema RLS mode.

    The ``tenant`` foreign key attribute name is hard-coded to ``tenant`` on this
    base, which matches the default ``TENANT_RLS_TENANT_FIELD`` value. If a subclass
    needs a different field name it must set ``TENANT_RLS_TENANT_FIELD`` and define
    its own FK plus a ``TenantPolicy(tenant_field=...)``.
    """

    tenant = models.ForeignKey(
        settings.TENANT_MODEL,
        on_delete=models.CASCADE,
        db_index=True,
        related_name="+",
    )

    # Default manager. It does not filter (RLS does) -- it only adds bulk_create()
    # tenant auto-stamping. Set as the default so bulk_create() picks up stamping
    # without subclasses having to opt in; subclasses are still free to declare
    # their own ``objects``.
    objects = TenantRLSManager()

    class Meta:
        abstract = True

    @classmethod
    def get_rls_policies(cls):
        """
        Return the list of policies for this model.

        If no explicit ``Meta.rls_policies`` were given, a single default
        :class:`~django_tenants.rls.policies.TenantPolicy` is built (and cached)
        the first time this is called. Building lazily ensures ``conf.*`` (session
        var names, PK cast) are read at enable time, after settings are loaded.

        Note: the default policy is cached on the class in ``_rls_policies`` (it is
        rebuilt only when ``_rls_policies`` is reset back to ``None``). Tests that
        use ``override_settings`` to change RLS conf must reset
        ``cls._rls_policies`` so the cached default is rebuilt with the new values.

        The default policy name is ``"<db_table>_tenant_isolation"`` (see
        :func:`_default_policy_name`, which shortens it if it would exceed the
        63-byte Postgres identifier limit).
        """
        if cls._rls_policies is None:
            from .policies import TenantPolicy

            cls._rls_policies = [
                TenantPolicy(
                    name=_default_policy_name(cls._meta.db_table),
                    tenant_field=conf.tenant_field(),
                )
            ]
        return cls._rls_policies

    @classmethod
    def has_unscoped_rows(cls):
        """
        Return True if the table has any row with the tenant FK set to NULL.

        Such rows are "unscoped": once RLS is enabled they become invisible to
        every tenant (``NULL = <pk>`` is NULL, never true), so callers
        (``apps.py`` post-migrate auto-enable, ``manage.py enable_rls``) check this
        before/while enabling to warn or skip rather than silently hiding data.

        Uses the tenant DB alias connection and a cheap ``SELECT EXISTS(...)``. It
        is defensive: if the table does not exist yet (fresh DB, table created in a
        later migration, programming error reading the relation) it returns False
        -- "no unscoped rows" -- so a missing table never blocks or warns.
        """
        from django.db import connections

        field = conf.tenant_field()
        attname = "%s_id" % field
        table = cls._meta.db_table
        conn = connections[get_tenant_database_alias()]
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    'SELECT EXISTS(SELECT 1 FROM %s WHERE %s IS NULL)'
                    % (
                        conn.ops.quote_name(table),
                        conn.ops.quote_name(attname),
                    )
                )
                row = cursor.fetchone()
            return bool(row and row[0])
        except Exception:
            # Table missing / not yet created / unreadable: treat as no unscoped
            # rows so a non-existent relation never blocks migrate or the command.
            return False

    def _autostamp_tenant(self, using=None):
        """Populate the tenant FK from the active connection when it is unset.

        Shared by :meth:`full_clean` and :meth:`save` so both stamp from the same
        source of truth (see :func:`_resolve_active_tenant_id`). It is idempotent
        and never overwrites an explicitly-set tenant, so calling it from both
        ``full_clean()`` and ``save()`` is safe. When RLS is disabled it is a
        no-op: the connection is not even consulted (behavior identical to a plain
        model). Returns ``None``.

        ``using`` (if given) overrides the connection-resolution order; otherwise
        the instance's bound db (``self._state.db``) then the tenant database alias
        are used, so a multi-database write is stamped from the right connection.

        The resolved value (e.g. the string ``"5"``) is assigned to ``<fk>_id``;
        Django coerces it via the FK target field on save.
        """
        field = conf.tenant_field()
        attname = "%s_id" % field
        if not conf.rls_enabled() or getattr(self, attname, None) not in (None, ""):
            return
        using = using or self._state.db or get_tenant_database_alias()
        tenant_id = _resolve_active_tenant_id(using)
        if tenant_id is not None:
            setattr(self, attname, tenant_id)

    def full_clean(self, *args, **kwargs):
        """Auto-stamp the tenant FK *before* validating.

        A model whose code calls ``full_clean()`` before ``save()`` (e.g. a
        ``ModelForm`` or an explicit validation step) would otherwise fail with
        "tenant cannot be null", because the ``save()``-time stamp comes too late
        for validation. Stamping here -- from the same source of truth ``save()``
        uses -- makes the FK present when ``super().full_clean()`` runs. The
        ``save()`` stamp is kept too (idempotent) for code that never validates.
        An explicitly-set tenant is preserved and RLS-disabled is a no-op.
        """
        self._autostamp_tenant()
        super().full_clean(*args, **kwargs)

    def save(self, *args, **kwargs):
        """
        Auto-populate the tenant FK from the active connection when unset.

        This keeps existing application code that never passes ``tenant`` working
        as a drop-in: the tenant is inferred from the connection that the request /
        management command established. An explicitly-set tenant is never
        overwritten. When RLS is disabled this is a no-op (behavior identical to a
        plain model).

        The stamp also runs in :meth:`full_clean` (so validation before save does
        not trip "tenant cannot be null"); doing it again here is idempotent and
        covers code that saves without validating.
        """
        self._autostamp_tenant(using=kwargs.get("using"))
        super().save(*args, **kwargs)

    @classmethod
    def enable_rls(cls):
        """
        Enable RLS on this model's table and create its policies.

        Respects ``get_tenant_database_alias()`` (never hardcodes ``default``),
        applies ``FORCE ROW LEVEL SECURITY`` when ``TENANT_RLS_FORCE`` is true, and
        is idempotent: each policy is dropped (``DROP POLICY IF EXISTS``) and then
        re-created, so re-running ``enable_rls`` never fails on a pre-existing
        policy. This drop-then-create approach is locale-independent (it does not
        depend on parsing a translated "already exists" error message). A backend
        without an RLS-capable schema editor is a no-op (logged warning).
        """
        from django.db import connections

        conn = connections[get_tenant_database_alias()]
        with conn.schema_editor() as schema_editor:
            if not hasattr(schema_editor, "enable_rls"):
                logger.warning(
                    "Backend %s has no RLS schema editor; "
                    "set ENGINE='django_tenants.rls.backend'.",
                    conn.vendor,
                )
                return
            schema_editor.enable_rls(cls)
            if conf.force_rls() and hasattr(schema_editor, "force_rls"):
                schema_editor.force_rls(cls)
            for policy in cls.get_rls_policies():
                # Idempotent: drop first (IF EXISTS) then create. This avoids
                # depending on a locale-specific "already exists" message text
                # to decide between create and alter.
                if hasattr(schema_editor, "drop_policy"):
                    schema_editor.drop_policy(cls, policy.name)
                schema_editor.create_policy(cls, policy)

    @classmethod
    def disable_rls(cls):
        """
        Drop this model's policies and disable RLS on its table.

        Best-effort: each policy is dropped with ``DROP POLICY IF EXISTS``; if
        ``TENANT_RLS_FORCE`` is on the table is un-forced before RLS is disabled.
        A backend without an RLS-capable schema editor is a no-op (logged warning).
        """
        from django.db import connections

        conn = connections[get_tenant_database_alias()]
        with conn.schema_editor() as schema_editor:
            if not hasattr(schema_editor, "disable_rls"):
                logger.warning(
                    "Backend %s has no RLS schema editor; "
                    "set ENGINE='django_tenants.rls.backend'.",
                    conn.vendor,
                )
                return
            for policy in cls.get_rls_policies():
                if hasattr(schema_editor, "drop_policy"):
                    schema_editor.drop_policy(cls, policy.name)
            if conf.force_rls() and hasattr(schema_editor, "unforce_rls"):
                schema_editor.unforce_rls(cls)
            schema_editor.disable_rls(cls)
