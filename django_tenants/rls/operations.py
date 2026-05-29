"""Django migration operations for shared-schema Row Level Security (RLS).

These operations emit pure DDL (``ALTER TABLE ... ENABLE/DISABLE/FORCE ROW LEVEL
SECURITY`` and ``CREATE/DROP POLICY``) against the RLS-aware schema editor. They
make no change to the migration *state* (they do not add/remove model fields),
only to the database, so :meth:`state_forwards` is a no-op for all of them.

Every operation resolves its model via ``from_state.apps.get_model(...)`` -- this
is the correct, registry-backed lookup. (The django-rls ``RLSOperation.get_model``
helper is broken: it calls ``router.db_for_write`` on a list of tables, so it is
deliberately NOT ported here.)

All database methods are guarded by ``hasattr(schema_editor, "<method>")`` so that
running them against a non-RLS schema editor (for example when the project still
uses the stock ``django_tenants.postgresql_backend`` engine) is a safe no-op
rather than an error.
"""

from django.db.migrations.operations.base import Operation

from . import conf


class _RLSOperationBase(Operation):
    """Common behavior for RLS migration operations.

    RLS operations are reversible and reduce to SQL, and they never mutate the
    in-memory model state.
    """

    reversible = True
    reduces_to_sql = True

    def state_forwards(self, app_label, state):
        # RLS operations do not change model state, only the database.
        pass


class EnableRLS(_RLSOperationBase):
    """Enable Row Level Security on a model's table.

    When ``TENANT_RLS_FORCE`` is true the table is additionally switched to
    ``FORCE ROW LEVEL SECURITY`` so the policy applies even to the table owner
    (the role Django connects as); otherwise the owner silently bypasses RLS and
    isolation is an illusion.
    """

    def __init__(self, model_name):
        self.model_name = model_name

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "enable_rls"):
            model = from_state.apps.get_model(app_label, self.model_name)
            schema_editor.enable_rls(model)
            if conf.force_rls() and hasattr(schema_editor, "force_rls"):
                schema_editor.force_rls(model)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "disable_rls"):
            model = from_state.apps.get_model(app_label, self.model_name)
            # FORCE is a persistent table attribute in Postgres; un-force it
            # before disabling so a later re-enable does not inherit stale FORCE
            # state (mirrors TenantRLSModel.disable_rls()).
            if conf.force_rls() and hasattr(schema_editor, "unforce_rls"):
                schema_editor.unforce_rls(model)
            schema_editor.disable_rls(model)

    def describe(self):
        return "Enable RLS on %s" % self.model_name

    def deconstruct(self):
        return (self.__class__.__name__, [self.model_name], {})


class DisableRLS(_RLSOperationBase):
    """Disable Row Level Security on a model's table.

    The reverse re-enables RLS (and ``FORCE`` when ``TENANT_RLS_FORCE`` is true),
    mirroring :class:`EnableRLS`.
    """

    def __init__(self, model_name):
        self.model_name = model_name

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "disable_rls"):
            model = from_state.apps.get_model(app_label, self.model_name)
            # Un-force before disabling so the persistent FORCE attribute does
            # not survive to a later re-enable (mirrors EnableRLS.database_backwards
            # and TenantRLSModel.disable_rls()).
            if conf.force_rls() and hasattr(schema_editor, "unforce_rls"):
                schema_editor.unforce_rls(model)
            schema_editor.disable_rls(model)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "enable_rls"):
            model = from_state.apps.get_model(app_label, self.model_name)
            schema_editor.enable_rls(model)
            if conf.force_rls() and hasattr(schema_editor, "force_rls"):
                schema_editor.force_rls(model)

    def describe(self):
        return "Disable RLS on %s" % self.model_name

    def deconstruct(self):
        return (self.__class__.__name__, [self.model_name], {})


class CreateTenantPolicy(_RLSOperationBase):
    """Create the default tenant-isolation policy for a model.

    Convenience wrapper that builds a :class:`~django_tenants.rls.policies.TenantPolicy`
    bound to the model's tenant field and creates it.

    All ``TenantPolicy`` parameters are explicit named arguments rather than
    ``**kwargs``. This is required for the migration writer to round-trip the
    operation: Django's ``OperationWriter`` only serialises kwargs that are
    explicit ``__init__`` parameters (a ``**VAR_KEYWORD`` catch-all is silently
    dropped from the rendered migration), so any value passed through a
    ``**kwargs`` would be lost on replay.

    The ``pk_cast`` is snapshotted at authoring time (when the operation is
    constructed) rather than resolved lazily at apply time. Capturing it makes
    the migration a deterministic, reproducible record of the policy DDL: a later
    change to the tenant model's PK type cannot silently alter the cast baked
    into an already-written migration.

    The policy ``name``, by contrast, is resolved lazily at apply time when it is
    not given explicitly: it defaults to ``"<db_table>_tenant_isolation"`` derived
    from the model's ``_meta.db_table`` (via :func:`~django_tenants.rls.models._default_policy_name`),
    exactly matching the name the models auto-enable path creates. Deriving it
    from ``db_table`` rather than ``model_name`` ensures ``disable_rls`` /
    ``drop_policy`` target the *same* policy that was created, instead of
    orphaning it under a divergent name.
    """

    def __init__(self, model_name, name=None, tenant_field=None,
                 session_variable=None, bypass_variable=None, pk_cast=None,
                 operation=None, permissive=None, roles=None):
        self.model_name = model_name
        # When None, the name is resolved at apply time from the model's db_table
        # (see _resolve_name); we keep None here so deconstruct only emits an
        # explicit name and the default stays in lockstep with the models path.
        self.name = name
        self.tenant_field = tenant_field if tenant_field is not None else conf.tenant_field()
        self.session_variable = session_variable
        self.bypass_variable = bypass_variable
        # Snapshot the cast at authoring time for a reproducible migration.
        self.pk_cast = pk_cast if pk_cast is not None else conf.get_tenant_pk_cast()
        self.operation = operation
        self.permissive = permissive
        self.roles = roles

    def _resolve_name(self, model):
        """Resolve the policy name from the model at apply time.

        When ``self.name`` is explicit, use it verbatim; otherwise default to
        ``"<db_table>_tenant_isolation"`` derived from ``model._meta.db_table``,
        matching the models auto-enable path so enable/disable target the same
        policy.
        """
        if self.name is not None:
            return self.name
        # Imported lazily to keep the migration module import-light and to avoid
        # importing the models module (which touches the app registry) at the
        # top of this migration-operations module.
        from .models import _default_policy_name

        return _default_policy_name(model._meta.db_table)

    def _policy(self, model):
        # Imported lazily to keep the migration module import-light.
        from .policies import TenantPolicy

        kwargs = {
            "name": self._resolve_name(model),
            "tenant_field": self.tenant_field,
            "session_variable": self.session_variable,
            "bypass_variable": self.bypass_variable,
            "pk_cast": self.pk_cast,
        }
        # Only forward the optional BasePolicy kwargs when explicitly set so the
        # policy's own defaults apply otherwise.
        if self.operation is not None:
            kwargs["operation"] = self.operation
        if self.permissive is not None:
            kwargs["permissive"] = self.permissive
        if self.roles is not None:
            kwargs["roles"] = self.roles
        return TenantPolicy(**kwargs)

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "create_policy"):
            model = from_state.apps.get_model(app_label, self.model_name)
            schema_editor.create_policy(model, self._policy(model))

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "drop_policy"):
            model = from_state.apps.get_model(app_label, self.model_name)
            schema_editor.drop_policy(model, self._resolve_name(model))

    def describe(self):
        return "Create tenant RLS policy on %s" % self.model_name

    def deconstruct(self):
        # Emit only non-None / non-default values so makemigrations stays stable,
        # but always include the snapshotted pk_cast so the migration is a
        # deterministic record of the policy DDL. Every key here is an explicit
        # __init__ parameter, so OperationWriter round-trips all of them.
        #
        # name is emitted ONLY when it was set explicitly; when left to default
        # it stays None so it is resolved from the model's db_table at apply time
        # (keeping the default in lockstep with the models auto-enable path).
        kwargs = {
            "tenant_field": self.tenant_field,
            "pk_cast": self.pk_cast,
        }
        if self.name is not None:
            kwargs["name"] = self.name
        if self.session_variable is not None:
            kwargs["session_variable"] = self.session_variable
        if self.bypass_variable is not None:
            kwargs["bypass_variable"] = self.bypass_variable
        if self.operation is not None:
            kwargs["operation"] = self.operation
        if self.permissive is not None:
            kwargs["permissive"] = self.permissive
        if self.roles is not None:
            kwargs["roles"] = self.roles
        return (self.__class__.__name__, [self.model_name], kwargs)


class CreatePolicy(_RLSOperationBase):
    """Create an arbitrary :class:`~django_tenants.rls.policies.BasePolicy` instance."""

    def __init__(self, model_name, policy):
        self.model_name = model_name
        self.policy = policy

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "create_policy"):
            model = from_state.apps.get_model(app_label, self.model_name)
            schema_editor.create_policy(model, self.policy)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "drop_policy"):
            model = from_state.apps.get_model(app_label, self.model_name)
            schema_editor.drop_policy(model, self.policy.name)

    def describe(self):
        return "Create RLS policy %s on %s" % (self.policy.name, self.model_name)

    def deconstruct(self):
        return (self.__class__.__name__, [self.model_name, self.policy], {})


class DropPolicy(_RLSOperationBase):
    """Drop a named policy from a model's table.

    Irreversible: the original policy definition is not retained, so it cannot be
    recreated by the reverse migration.
    """

    reversible = False

    def __init__(self, model_name, policy_name):
        self.model_name = model_name
        self.policy_name = policy_name

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "drop_policy"):
            model = from_state.apps.get_model(app_label, self.model_name)
            schema_editor.drop_policy(model, self.policy_name)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        raise NotImplementedError("DropPolicy is irreversible: the original policy "
                                  "definition is not retained.")

    def describe(self):
        return "Drop RLS policy %s on %s" % (self.policy_name, self.model_name)

    def deconstruct(self):
        return (self.__class__.__name__, [self.model_name, self.policy_name], {})


# Postgres column type for each tenant-PK cast suffix (see conf.ALLOWED_PK_CASTS /
# conf.get_tenant_pk_cast). The tenant column we add to an external table must be
# the SAME type as the tenant model's PK so the FK and the policy comparison are
# well-typed.
_PK_CAST_TO_COLUMN_TYPE = {
    "integer": "integer",
    "bigint": "bigint",
    "uuid": "uuid",
    "text": "text",
}


class IsolateExternalTable(_RLSOperationBase):
    """Tenant-isolate a table NOT owned by a :class:`~django_tenants.rls.models.TenantRLSModel`.

    This is for tables you cannot make inherit ``TenantRLSModel`` -- contrib /
    third-party / vendored tables (``auth_user``, ``django_session``, an external
    package's table, an M2M *through* table). Such a table lands unpolicied in the
    single shared ``public`` schema and silently shares its rows across every
    tenant. Today the only helper for these is
    :func:`~django_tenants.rls.scaffold.third_party_policy_sql`, which emits the
    *policy* only and assumes the tenant column already exists; the operator must
    hand-write the column + FK + ENABLE/FORCE + UNIQUE-rewrite DDL. This operation
    performs that full prerequisite sequence as one reversible migration step.

    On PostgreSQL (other vendors are a no-op via the ``vendor`` guard), forwards:

    1. ``ADD COLUMN <tenant_field>_id`` of the tenant PK type, with a column
       ``DEFAULT`` reading the tenant GUC
       (``NULLIF(current_setting('<session var>', true), '')::<cast>``) and a
       ``REFERENCES <tenant table>(<tenant pk>) ON DELETE CASCADE`` FK. The GUC
       default means rows inserted while a tenant is active are auto-stamped, so
       the policy's ``WITH CHECK`` is satisfied without app changes.
    2. when ``not_null=True``, ``ALTER COLUMN ... SET NOT NULL`` -- this REQUIRES a
       prior backfill (existing rows have a NULL ``<tenant_field>_id``), so run a
       backfill in an earlier step and only pass ``not_null=True`` once zero rows
       are NULL (see :func:`~django_tenants.rls.scaffold.isolate_external_table_sql`).
    3. each ``unique_rewrites`` entry ``(old_constraint_name, [new_columns])``:
       ``DROP CONSTRAINT <old>`` then ``ADD CONSTRAINT ... UNIQUE (<new_columns>)``.
       Postgres checks UNIQUE with RLS bypassed, so every global UNIQUE on the
       table is a covert cross-tenant channel; rewrite each to be tenant-scoped
       (typically prepend ``<tenant_field>_id`` to ``new_columns``).
    4. ``ENABLE ROW LEVEL SECURITY`` and -- when ``TENANT_RLS_FORCE`` is true --
       ``FORCE ROW LEVEL SECURITY`` so the policy binds the table owner too.
    5. ``CREATE POLICY`` byte-identical to the framework's default
       :class:`~django_tenants.rls.policies.TenantPolicy`: the USING / WITH CHECK
       expressions come straight from
       :meth:`~django_tenants.rls.policies.TenantPolicy.get_using_expression` /
       :meth:`~django_tenants.rls.policies.TenantPolicy.get_check_expression`,
       exactly as :class:`CreateTenantPolicy` does, so the external table is
       policed identically to a first-party one.

    Backwards reverses it: drop the policy, un-force + disable RLS, restore the
    rewritten UNIQUEs to their original columns (best effort -- the original
    constraint *definition* is not retained, so the reverse re-adds a UNIQUE on the
    old column names), and drop the tenant column.

    Like the other operations this is a pure-DDL, state-neutral migration step: it
    adds no model field to the migration state (the table is not a Django model in
    this project), only changes the database. All parameters are explicit
    ``__init__`` arguments so Django's ``OperationWriter`` round-trips them, and
    ``pk_cast`` is snapshotted at authoring time (defaulting from
    :func:`~django_tenants.rls.conf.get_tenant_pk_cast`) for a deterministic
    migration, mirroring :class:`CreateTenantPolicy`.
    """

    def __init__(self, table, tenant_field=None, pk_cast=None, not_null=False,
                 unique_rewrites=None):
        self.table = table
        self.tenant_field = tenant_field if tenant_field is not None else conf.tenant_field()
        # Snapshot the cast at authoring time for a reproducible migration.
        self.pk_cast = pk_cast if pk_cast is not None else conf.get_tenant_pk_cast()
        self.not_null = not_null
        # Normalise to a list of (old_name, [new_columns]) tuples; None -> [].
        self.unique_rewrites = list(unique_rewrites) if unique_rewrites else []

    # -- helpers ----------------------------------------------------------------

    @property
    def _column(self):
        """The tenant FK column name, ``<tenant_field>_id`` (Django convention)."""
        return "%s_id" % self.tenant_field

    def _policy_name(self):
        # Match the framework / scaffold default: "<table>_tenant_isolation",
        # shortened to the 63-byte Postgres identifier limit, so it is the same
        # name third_party_policy_sql and the models path would use.
        from .models import _default_policy_name

        return _default_policy_name(self.table)

    def _policy(self):
        from .policies import TenantPolicy

        return TenantPolicy(
            name=self._policy_name(),
            tenant_field=self.tenant_field,
            pk_cast=self.pk_cast,
        )

    def _column_type(self):
        col_type = _PK_CAST_TO_COLUMN_TYPE.get(self.pk_cast)
        if col_type is None:
            # pk_cast is validated against ALLOWED_PK_CASTS when the policy is
            # built, but guard here too so a bad value fails loudly rather than
            # emitting a malformed column type.
            raise ValueError(
                "Unsupported pk_cast %r for IsolateExternalTable on %r: expected "
                "one of %s" % (self.pk_cast, self.table,
                               ", ".join(sorted(_PK_CAST_TO_COLUMN_TYPE)))
            )
        return col_type

    def _tenant_table_idents(self, schema_editor):
        """Return ``(quoted_table, quoted_pk_column)`` for the TENANT_MODEL table.

        Resolved from the tenant model's ``_meta`` so the FK references the real
        table / PK column regardless of custom ``db_table`` / PK names. Quoted with
        the connection's own quoter so it is safe to embed in the FK clause.
        """
        from django_tenants.utils import get_tenant_model

        tenant_model = get_tenant_model()
        meta = tenant_model._meta
        quote = schema_editor.connection.ops.quote_name
        return quote(meta.db_table), quote(meta.pk.column)

    @staticmethod
    def _is_postgresql(schema_editor):
        return getattr(schema_editor.connection, "vendor", None) == "postgresql"

    def _guc_default_expr(self):
        """The column ``DEFAULT`` expression reading the tenant GUC.

        Identical in shape to the policy comparison's right-hand side so a row
        inserted under an active tenant is auto-stamped with that tenant and
        satisfies the policy's WITH CHECK.
        """
        return "NULLIF(current_setting(%s, true), '')::%s" % (
            conf._quote_literal(conf.session_variable()),
            self.pk_cast,
        )

    # -- forwards ---------------------------------------------------------------

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if not self._is_postgresql(schema_editor):
            # Non-PostgreSQL backends have no RLS / GUC; nothing to do.
            return
        from .scaffold import _quote_ident

        q_table = _quote_ident(self.table)
        q_col = _quote_ident(self._column)
        col_type = self._column_type()
        q_tenant_table, q_tenant_pk = self._tenant_table_idents(schema_editor)

        # (1) Add the tenant column with the GUC-reading DEFAULT and the FK.
        schema_editor.execute(
            "ALTER TABLE %s ADD COLUMN %s %s DEFAULT (%s) "
            "REFERENCES %s (%s) ON DELETE CASCADE"
            % (q_table, q_col, col_type, self._guc_default_expr(),
               q_tenant_table, q_tenant_pk)
        )

        # (2) Optionally tighten to NOT NULL (requires a prior backfill).
        if self.not_null:
            schema_editor.execute(
                "ALTER TABLE %s ALTER COLUMN %s SET NOT NULL" % (q_table, q_col)
            )

        # (3) Tenant-scope each leaky UNIQUE: drop the old, add the new.
        for old_name, new_columns in self.unique_rewrites:
            schema_editor.execute(
                "ALTER TABLE %s DROP CONSTRAINT %s"
                % (q_table, _quote_ident(old_name))
            )
            schema_editor.execute(
                "ALTER TABLE %s ADD CONSTRAINT %s UNIQUE (%s)"
                % (q_table, _quote_ident(self._rewrite_name(old_name)),
                   ", ".join(_quote_ident(c) for c in new_columns))
            )

        # (4) Enable (+ force) RLS.
        schema_editor.execute("ALTER TABLE %s ENABLE ROW LEVEL SECURITY" % q_table)
        if conf.force_rls():
            schema_editor.execute("ALTER TABLE %s FORCE ROW LEVEL SECURITY" % q_table)

        # (5) Create the framework-identical tenant-isolation policy.
        self._create_policy(schema_editor, q_table)

    # -- backwards --------------------------------------------------------------

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        if not self._is_postgresql(schema_editor):
            return
        from .scaffold import _quote_ident

        q_table = _quote_ident(self.table)
        q_col = _quote_ident(self._column)

        # Reverse order of forwards. (5) drop the policy.
        schema_editor.execute(
            "DROP POLICY IF EXISTS %s ON %s"
            % (_quote_ident(self._policy_name()), q_table)
        )

        # (4) un-force (FORCE is a persistent table attribute) + disable RLS.
        if conf.force_rls():
            schema_editor.execute("ALTER TABLE %s NO FORCE ROW LEVEL SECURITY" % q_table)
        schema_editor.execute("ALTER TABLE %s DISABLE ROW LEVEL SECURITY" % q_table)

        # (3) restore the rewritten UNIQUEs to their original column. The original
        # constraint *definition* is not retained, so this re-adds a UNIQUE on the
        # old constraint's name over the columns implied by it (best effort: the
        # old name with the tenant column stripped from the new columns).
        for old_name, new_columns in reversed(self.unique_rewrites):
            schema_editor.execute(
                "ALTER TABLE %s DROP CONSTRAINT %s"
                % (q_table, _quote_ident(self._rewrite_name(old_name)))
            )
            old_columns = [c for c in new_columns if c != self._column] or list(new_columns)
            schema_editor.execute(
                "ALTER TABLE %s ADD CONSTRAINT %s UNIQUE (%s)"
                % (q_table, _quote_ident(old_name),
                   ", ".join(_quote_ident(c) for c in old_columns))
            )

        # (1) drop the tenant column (drops the FK + its DEFAULT with it).
        schema_editor.execute("ALTER TABLE %s DROP COLUMN %s" % (q_table, q_col))

    # -- shared DDL builders ----------------------------------------------------

    def _rewrite_name(self, old_name):
        """Name for the tenant-scoped replacement of constraint ``old_name``.

        Deterministic and kept under the 63-byte Postgres identifier limit so the
        reverse migration can find and drop it.
        """
        return ("%s_per_tenant" % old_name)[:63]

    def _create_policy(self, schema_editor, q_table):
        policy = self._policy()
        q_policy = self._quote_ident(policy.name)
        using = policy.get_using_expression()
        check = policy.get_check_expression()
        # Drop any same-named policy first so the step is re-runnable, then create
        # PERMISSIVE FOR ALL TO public with the framework USING / WITH CHECK -- the
        # exact DDL RLSSchemaEditorMixin.create_policy emits.
        schema_editor.execute(
            "DROP POLICY IF EXISTS %s ON %s" % (q_policy, q_table)
        )
        schema_editor.execute(
            "CREATE POLICY %s ON %s AS PERMISSIVE FOR ALL TO public "
            "USING (%s) WITH CHECK (%s)" % (q_policy, q_table, using, check)
        )

    @staticmethod
    def _quote_ident(name):
        from .scaffold import _quote_ident

        return _quote_ident(name)

    # -- migration plumbing -----------------------------------------------------

    def describe(self):
        return "Tenant-isolate external table %s under RLS" % self.table

    def deconstruct(self):
        # Emit only non-default kwargs so makemigrations stays stable, but always
        # include the snapshotted pk_cast so the migration is a deterministic
        # record of the DDL (mirrors CreateTenantPolicy). Every key is an explicit
        # __init__ parameter, so OperationWriter round-trips all of them.
        kwargs = {
            "tenant_field": self.tenant_field,
            "pk_cast": self.pk_cast,
        }
        if self.not_null:
            kwargs["not_null"] = self.not_null
        if self.unique_rewrites:
            # Normalise the column lists to lists for a stable rendered migration.
            kwargs["unique_rewrites"] = [
                (name, list(cols)) for name, cols in self.unique_rewrites
            ]
        return (self.__class__.__name__, [self.table], kwargs)
